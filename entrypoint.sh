#!/bin/sh
set -e

INTERFACE=$(ip -4 route | awk '/default/ {print $5}')
LOCAL4=$(ip -4 addr show dev "$INTERFACE" | awk '/inet / {print $2}' | cut -d/ -f1)

echo "Detected local IPv4: $LOCAL4"

REMOTE4="${REMOTE4:?REMOTE4 environment variable is required}"
echo "Using remote IPv4: $REMOTE4"

LOCAL6="${LOCAL6:?LOCAL6 environment variable is required}"
echo "Using local IPv6: $LOCAL6"

/usr/local/bin/usit --local4 "$LOCAL4" --local6 "$LOCAL6" --remote4 "$REMOTE4" &

while [ ! -d /sys/class/net/tun0 ]; do
    sleep 1
done

ip link set tun0 up
MTU="${MTU:-1420}"
ip link set tun0 mtu "$MTU"
ip -6 route add ::/0 dev tun0

wait -n
