# usit

Userspace SIT (IPv6-in-IPv4, protocol 41) tunnel.

- Purpose: small userspace implementation of SIT for cases where the kernel SIT driver cannot be used (e.g., inside LXC) but TUN is available.
- Origin: built for Hurricane Electric's [Tunnelbroker](https://tunnelbroker.net/), but generic for any static SIT endpoint pair.
- Root required: otherwise, protocol 41 packets may be dropped.
- Container focus: Docker only (no Podman); host network is used.
- Platform: Linux only.
- Tested: [tunnelbroker.net](https://tunnelbroker.net/).

## Overview
`usit` creates a TUN interface and forwards IPv6 packets over IPv4 using protocol 41, acting as a userspace alternative to the kernel `sit` module. This is useful when you:
- Run inside containers/VMs without access to the kernel SIT driver (e.g., LXC)
- Have `/dev/net/tun` and the needed capabilities
- Want to terminate an IPv6 tunnel in userspace

Host networking is intentionally used in Docker, because it matched the target environment and simplifies protocol 41 handling.

## Features
- Userspace encapsulation of IPv6 over IPv4 (proto 41)
- TUN interface management (address, MTU)
- Works with static tunnel endpoints (local/remote IPv4)
- Minimal dependencies

## Requirements
- Linux with `/dev/net/tun`
- Root (or CAP_NET_ADMIN + CAP_NET_RAW) and permission to open proto-41 sockets
- Docker and Docker Compose (if running containerized)
- Public IPv4 that can send/receive proto 41, and a routed IPv6 prefix

## Usage
Run as root with your tunnel parameters:

```
sudo ./usit \
  -tun tun0 \
  -local4 192.168.1.2 \
  -remote4 216.66.80.26 \
  -local6 2001:db8:abcd:1234::2/64
```

You should be able to ping `2001:db8:abcd:1234::1` once the tunnel is up. **If you need additional routes, you can do so manually.** The compose setup does that automatically inside the [entrypoint script](./entrypoint.sh).

Notes
- `-local4`: the IPv4 address that the interface has where your sit traffic should go to (usually equal to default route)
- `-remote4`: remote server IPv4 (e.g., provider tunnel endpoint)
- `-local6`: the IPv6 address/prefix to assign to the TUN device

## Docker Compose
Host networking is used. Adjust the env vars to match your tunnel addresses.

Important
- Update `LOCAL4`, `REMOTE4`, `LOCAL6` to match your tunnel provider settings.
- Host network is used by design (fits the LXC/host use case).
- Root/privileged needed to open proto-41 and manage TUN.
- Docker only; no Podman support here as it didn't seem to work with shared namespaces. Pods would *maybe* work, but I didn't need it.

## Environment variables
- `LOCAL4`: local public IPv4 address that will carry proto 41.
- `REMOTE4`: remote tunnel server IPv4 address.
- `LOCAL6`: IPv6 address/prefix to assign on the TUN (e.g., `2001:db8:abcd:1234::2/64`).

## Client example

An example is provided that runs `ping` to demonstrate the tunnel works. Find it in the [`client` directory](./client). Feel free to adjust if needed. It's automatically pulled in by [Docker Compose](./compose.yml).

## Limitations
- Linux only
- Docker only; no Podman support
- Host networking only
- Requires root privileges
- Assumes proto 41 is not blocked or NATed en route

### Tunnelbroker limitations

- If you don't get responses to your pings or in general the tunnel doesn't respond check if the source IPv4 on the tunnelbroker side is correct. If not, you can go to their web interface, then to *Advanced*, take the *Example Update URL* and do a `curl "<addresshere>"` call. Then start pinging `ipv6.google.com` or similar and it should start working after a while.
- If you are inactive for a while, the remote side won't respond to your packets. You can just keep pinging `ipv6.google.com` and it will come back up. It can take several minutes.
- If you keep a `ping -i 10 ipv6.google.com` running in the background, it will most likely keep the tunnel alive forever and these problems won't occur.

## Why userspace?
Originally built to run inside an LXC container where the kernel SIT driver wasn’t available, but TUN was. Userspace encapsulation made it possible to terminate the tunnel without kernel modules.

## Providers
usit is generic and should work with static SIT endpoints. It has been tested with tunnelbroker.net.

## Why did you build specifically this?

As I mentioned earlier, I got a generous LXC container running on a Proxmox host where I can totally run my own stuff with root privileges and I can even run regular userspace VPNs since tun support is there. However I wanted to have some IPv6 connectivity and there was no way for me to load the ipv6 kernel module or the sit one. So I figured that I can just build my own weird userspace sit implementation since we just need to wrap IPv6 packets inside IPv4 ones using protocol 41 and send them to the remote endpoint. The rest is just managing the tun interface and routing.

I actually had my stuff running in docker on that LXC container, so what you see here is a generalized version of what I built for myself.

## Alternatives
- [puxxustc/sit](https://github.com/puxxustc/sit) - Lightweight userspace SIT tunnel implementation in C done for a similar purpose.
- [Linux kernel](https://github.com/torvalds/linux) - Native SIT support in the Linux kernel, which is more efficient but requires kernel module access.