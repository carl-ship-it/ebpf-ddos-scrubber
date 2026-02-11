#!/usr/bin/env bash
# uninstall.sh — Remove DDoS Scrubber from the host.
set -euo pipefail

echo "=== DDoS Scrubber Uninstaller ==="

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# Stop and disable service
echo "[1/4] Stopping service..."
systemctl stop ddos-scrubber 2>/dev/null || true
systemctl disable ddos-scrubber 2>/dev/null || true

# Detach XDP from all interfaces
echo "[2/4] Detaching XDP programs..."
for iface in $(ip -j link show | python3 -c "
import sys,json
for i in json.load(sys.stdin):
    if 'xdp' in str(i.get('xdp',{})):
        print(i['ifname'])
" 2>/dev/null); do
    echo "  Detaching from $iface..."
    ip link set dev "$iface" xdp off 2>/dev/null || true
    ip link set dev "$iface" xdpgeneric off 2>/dev/null || true
done

# Remove files
echo "[3/4] Removing files..."
rm -rf /opt/ddos-scrubber
rm -f /etc/systemd/system/ddos-scrubber.service
systemctl daemon-reload

echo "[4/4] Done."
echo ""
echo "Note: Config at /etc/ddos-scrubber/ was preserved."
echo "  To remove: rm -rf /etc/ddos-scrubber"
