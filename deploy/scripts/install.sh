#!/usr/bin/env bash
# install.sh — Install DDoS Scrubber on a bare-metal Linux host.
#
# Usage:
#   sudo ./deploy/scripts/install.sh [--interface eth0] [--mode native]

set -euo pipefail

INSTALL_DIR="/opt/ddos-scrubber"
CONFIG_DIR="/etc/ddos-scrubber"
BUILD_DIR="build"
IFACE="${IFACE:-eth0}"
XDP_MODE="${XDP_MODE:-native}"

# ---- Parse args ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface) IFACE="$2"; shift 2 ;;
        --mode)      XDP_MODE="$2"; shift 2 ;;
        *)           echo "Unknown arg: $1"; exit 1 ;;
    esac
done

echo "=== DDoS Scrubber Installer ==="
echo "Interface: $IFACE"
echo "XDP Mode:  $XDP_MODE"
echo ""

# ---- Check root ----
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# ---- Check prerequisites ----
echo "[1/6] Checking prerequisites..."
for cmd in ip bpftool; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "  Missing: $cmd"
        echo "  Install: apt install iproute2 bpftool"
        exit 1
    fi
done

# Check interface exists
if ! ip link show "$IFACE" &>/dev/null; then
    echo "Error: Interface $IFACE not found."
    echo "Available interfaces:"
    ip -brief link show
    exit 1
fi

# ---- Check build artifacts ----
echo "[2/6] Checking build artifacts..."
BPF_OBJ="$BUILD_DIR/obj/xdp_ddos_scrubber.o"
GO_BIN="$BUILD_DIR/ddos-scrubber"

if [[ ! -f "$BPF_OBJ" ]]; then
    echo "Error: BPF object not found at $BPF_OBJ"
    echo "Run 'make all' first."
    exit 1
fi

if [[ ! -f "$GO_BIN" ]]; then
    echo "Error: Go binary not found at $GO_BIN"
    echo "Run 'cd src/control-plane && make build' first."
    exit 1
fi

# ---- Create directories ----
echo "[3/6] Creating directories..."
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$INSTALL_DIR/bpf"
mkdir -p "$CONFIG_DIR"

# ---- Copy files ----
echo "[4/6] Copying files..."
cp "$BPF_OBJ" "$INSTALL_DIR/bpf/"
cp "$GO_BIN"  "$INSTALL_DIR/bin/"
chmod +x "$INSTALL_DIR/bin/ddos-scrubber"

# Install config (don't overwrite existing)
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    cp configs/config.yaml "$CONFIG_DIR/config.yaml"
    # Patch interface and BPF path
    sed -i "s|interface: eth0|interface: $IFACE|g" "$CONFIG_DIR/config.yaml"
    sed -i "s|bpf_object: build/obj/xdp_ddos_scrubber.o|bpf_object: $INSTALL_DIR/bpf/xdp_ddos_scrubber.o|g" "$CONFIG_DIR/config.yaml"
    sed -i "s|xdp_mode: native|xdp_mode: $XDP_MODE|g" "$CONFIG_DIR/config.yaml"
    echo "  Config installed: $CONFIG_DIR/config.yaml"
else
    echo "  Config already exists, skipping."
fi

# ---- Install systemd service ----
echo "[5/6] Installing systemd service..."
cp deploy/systemd/ddos-scrubber.service /etc/systemd/system/
systemctl daemon-reload
echo "  Service installed. Enable with: systemctl enable ddos-scrubber"

# ---- Verify ----
echo "[6/6] Verifying installation..."
"$INSTALL_DIR/bin/ddos-scrubber" -version

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Review config:    vi $CONFIG_DIR/config.yaml"
echo "  2. Start service:    systemctl start ddos-scrubber"
echo "  3. Enable on boot:   systemctl enable ddos-scrubber"
echo "  4. Check status:     systemctl status ddos-scrubber"
echo "  5. View logs:        journalctl -u ddos-scrubber -f"
