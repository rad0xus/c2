#!/usr/bin/env bash
# ligolo-setup.sh — download latest ligolo-ng and configure the TUN interface
# Usage: ./ligolo-setup.sh <target-subnet>   e.g. ./ligolo-setup.sh 192.168.98.0/24

set -euo pipefail

REPO="nicocha30/ligolo-ng"
API="https://api.github.com/repos/${REPO}/releases/latest"
IFACE="ligolo"
TARGET_SUBNET="${1:-}"

# --- 1. Fetch latest release metadata -----------------------------------
echo "[*] Querying latest release..."
TAG=$(curl -s "$API" | grep -oP '"tag_name":\s*"\K[^"]+')
echo "[*] Latest tag: $TAG"

PROXY_URL=$(curl -s "$API" | grep -oP '"browser_download_url":\s*"\K[^"]*proxy[^"]*linux_amd64[^"]*')
AGENT_URL=$(curl -s "$API" | grep -oP '"browser_download_url":\s*"\K[^"]*agent[^"]*linux_amd64[^"]*')

# --- 2. Download & extract ----------------------------------------------
for url in "$PROXY_URL" "$AGENT_URL"; do
    fname=$(basename "$url")
    if [[ -f "$fname" ]]; then
        echo "[*] Already have $fname, skipping download"
    else
        echo "[*] Downloading $fname"
        wget -q --show-progress "$url"
    fi
    tar -xzf "$fname"
done

# --- 3. Clean up any existing TUN interface -----------------------------
if ip link show "$IFACE" &>/dev/null; then
    echo "[*] Removing existing $IFACE interface"
    sudo ip link set "$IFACE" down
    sudo ip tuntap del dev "$IFACE" mode tun
fi

# --- 4. Create and bring up the TUN interface ---------------------------
echo "[*] Creating TUN interface $IFACE"
sudo ip tuntap add user "$(id -un)" mode tun "$IFACE"
sudo ip link set "$IFACE" up

# --- 5. Fix routing ------------------------------------------------------
if [[ -n "$TARGET_SUBNET" ]]; then
    # Remove a conflicting route via tun0 if it exists (ignore if not)
    sudo ip route del "$TARGET_SUBNET" dev tun0 2>/dev/null || true
    # Route the target subnet through ligolo
    sudo ip route add "$TARGET_SUBNET" dev "$IFACE"
    echo "[*] Routed $TARGET_SUBNET via $IFACE"
else
    echo "[!] No target subnet given. Add routes manually:"
    echo "    sudo ip route add <CIDR> dev $IFACE"
fi

# --- 6. Show result ------------------------------------------------------
echo
echo "[*] Done. Current routes:"
ip route | grep -E "$IFACE|tun0" || true
echo
echo "[*] Binaries extracted in $(pwd):"
ls -1 ligolo-ng_* 2>/dev/null || true
