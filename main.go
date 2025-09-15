//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	flagTunName   = flag.String("tun", "tun0", "TUN device name")
	flagLocal4Str = flag.String("local4", "", "local IPv4 (source for outer IPv4 header)")
	flagRemote4   = flag.String("remote4", "", "remote HE server IPv4")
	flagLocal6Str = flag.String("local6", "", "local IPv6 address (assigned to TUN)")
	flagVerbose   = flag.Bool("v", false, "verbose logging")
)

const (
	defaultMTU = 1420
)

func main() {
	flag.Parse()

	logger := log.New(os.Stderr, "he-tunnel: ", log.LstdFlags)
	if !*flagVerbose {
		logger.SetOutput(os.Stderr)
	}

	if *flagLocal4Str == "" || *flagRemote4 == "" || *flagLocal6Str == "" {
		flag.Usage()
		os.Exit(2)
	}

	local4 := mustParseIPv4(*flagLocal4Str, "local4")
	remote4 := mustParseIPv4(*flagRemote4, "remote4")
	local6, err := parseIPv6CIDROrHost(*flagLocal6Str)
	if err != nil {
		logger.Fatalf("invalid local6: %v", err)
	}

	tun, err := setupTun(*flagTunName)
	if err != nil {
		logger.Fatalf("tun: %v", err)
	}

	if err := configureTunInterface(tun.Name(), *flagLocal6Str); err != nil {
		logger.Fatalf("configure tun: %v", err)
	}

	fd, err := setupRawSocket(remote4)
	if err != nil {
		logger.Fatalf("raw socket: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		rawToTun(ctx, logger, fd, tun)
	}()
	go func() {
		defer wg.Done()
		tunToRaw(ctx, logger, fd, tun, local4, remote4)
	}()

	logger.Printf("running: tun=%s local4=%s remote4=%s local6=%s", tun.Name(), local4, remote4, local6)

	<-ctx.Done()
	logger.Println("shutdown requested")

	// Proactively close descriptors to unblock goroutines before waiting.
	_ = syscall.Shutdown(fd, syscall.SHUT_RDWR)
	_ = tun.Close()
	_ = syscall.Close(fd)

	wg.Wait()
}

func mustParseIPv4(s, name string) net.IP {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		log.Fatalf("invalid %s IPv4: %q", name, s)
	}
	return ip
}

func setupTun(name string) (*water.Interface, error) {
	cfg := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	}
	return water.New(cfg)
}

func parseIPv6CIDROrHost(s string) (*net.IPNet, error) {
	if strings.Contains(s, "/") {
		ip, ipn, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		ipn.IP = ip
		return ipn, nil
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return nil, fmt.Errorf("invalid IPv6 address: %q", s)
	}
	mask := net.CIDRMask(128, 128)
	return &net.IPNet{IP: ip, Mask: mask}, nil
}

func configureTunInterface(name, local6 string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}

	if err := netlink.LinkSetMTU(link, defaultMTU); err != nil {
		return fmt.Errorf("set MTU: %w", err)
	}

	ipn, err := parseIPv6CIDROrHost(local6)
	if err != nil {
		return fmt.Errorf("parse local6: %w", err)
	}
	addr := &netlink.Addr{IPNet: ipn}
	if err := netlink.AddrAdd(link, addr); err != nil {
		// Ignore EEXIST if address already present.
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("addr add: %w", err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	return nil
}

func setupRawSocket(remote net.IP) (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, 41)
	if err != nil {
		return -1, fmt.Errorf("socket: %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("setsockopt IP_HDRINCL: %w", err)
	}
	// Make I/O interruptible by adding small timeouts so Recvfrom/Sendto return periodically.
	tv := unix.NsecToTimeval(int64(500 * time.Millisecond))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("setsockopt SO_RCVTIMEO: %w", err)
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("setsockopt SO_SNDTIMEO: %w", err)
	}
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], remote.To4())
	if err := syscall.Connect(fd, &sa); err != nil {
		// Not fatal; we can still receive all proto-41
	}
	return fd, nil
}

func rawToTun(ctx context.Context, logger *log.Logger, fd int, tun *water.Interface) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			// Likely due to timeout or shutdown/close.
			if ctx.Err() != nil {
				return
			}
			if isTimeoutLike(err) {
				continue
			}
			logger.Printf("recvfrom: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if n <= 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		pkt := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)
		ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok || ip4.Protocol != layers.IPProtocolIPv6 {
			continue
		}
		hlen := int(ip4.IHL) * 4
		if hlen >= n {
			continue
		}
		if _, err := tun.Write(buf[hlen:n]); err != nil {
			// On shutdown, write may fail if tun is closed.
			if ctx.Err() != nil {
				return
			}
			logger.Printf("tun write: %v", err)
		}
	}
}

func tunToRaw(ctx context.Context, logger *log.Logger, fd int, tun *water.Interface, src4, dst4 net.IP) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := tun.Read(buf)
		if err != nil {
			// Likely due to shutdown/close.
			if ctx.Err() != nil {
				return
			}
			logger.Printf("tun read: %v", err)
			return
		}
		if n == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		if err := sendIPv4Encap(fd, src4, dst4, buf[:n]); err != nil {
			if ctx.Err() != nil {
				return
			}
			if isTimeoutLike(err) {
				continue
			}
			logger.Printf("send: %v", err)
		}
	}
}

func sendIPv4Encap(fd int, src4, dst4 net.IP, ipv6payload []byte) error {
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolIPv6,
		SrcIP:    src4,
		DstIP:    dst4,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip4, gopacket.Payload(ipv6payload)); err != nil {
		return fmt.Errorf("serialize: %w", err)
	}
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], dst4.To4())
	return syscall.Sendto(fd, buf.Bytes(), 0, &sa)
}

func isTimeoutLike(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ETIMEDOUT)
}
