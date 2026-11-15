#!/usr/bin/env bash
# ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
IFACE=${1:-wlp0s20u5}
ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
rm -rf /sys/fs/bpf/zero_shield /tmp/zero_dynamic_shield.o
echo "[OK] КПП снят с интерфейса $IFACE"
