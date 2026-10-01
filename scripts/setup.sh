#!/bin/bash

set -e

echo "================================="
echo "       PiServer Setup"
echo "================================="
echo

# ============================================================
# Require root
# ============================================================

if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo:"
    echo "  sudo ./scripts/setup.sh"
    exit 1
fi

# ============================================================
# Find repository
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "PiServer repository:"
echo "  $REPO_DIR"
echo

# ============================================================
# Ask for installation path
# ============================================================

read -rp "Installation path [$REPO_DIR]: " INSTALL_DIR
INSTALL_DIR="${INSTALL_DIR:-$REPO_DIR}"

echo
echo "Installing PiServer to:"
echo "  $INSTALL_DIR"
echo

# ============================================================
# Copy repository if needed
# ============================================================

if [ "$INSTALL_DIR" != "$REPO_DIR" ]; then

    mkdir -p "$INSTALL_DIR"

    echo "Copying PiServer files..."

    cp -a "$REPO_DIR"/. "$INSTALL_DIR"/

fi

# ============================================================
# Verify required PiServer files
# ============================================================

echo
echo "Checking PiServer files..."

REQUIRED_FILES=(
    "requirements.txt"
    "configs/hostapd.conf.example"
    "configs/dnsmasq.conf.example"
    "configs/99-piserver-router.conf"
    "src/network_gui.py"
)

for FILE in "${REQUIRED_FILES[@]}"; do

    if [ ! -f "$INSTALL_DIR/$FILE" ]; then
        echo "ERROR: Missing:"
        echo "  $INSTALL_DIR/$FILE"
        exit 1
    fi

done

echo "PiServer files OK."

# ============================================================
# Install system packages
# ============================================================

echo
echo "Installing required system packages..."

apt-get update

apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-flask \
    hostapd \
    dnsmasq \
    nftables \
    iproute2 \
    network-manager \
    iw \
    rfkill \
    curl \
    procps \
    iputils-ping

echo
echo "System packages installed."

# ============================================================
# Install Python requirements
# ============================================================

echo
echo "Installing Python requirements..."

python3 -m pip install \
    --break-system-packages \
    -r "$INSTALL_DIR/requirements.txt"

echo
echo "Python requirements installed."

# ============================================================
# Verify Flask
# ============================================================

echo
echo "Checking Flask..."

python3 -c "import flask; print('Flask:', flask.__version__)"

echo "Flask OK."

# ============================================================
# Configure NetworkManager
# ============================================================

echo
echo "Configuring NetworkManager..."

mkdir -p /etc/NetworkManager/conf.d

cat > /etc/NetworkManager/conf.d/piserver.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:wlan0
EOF

echo "NetworkManager configuration written."

echo "wlan0 will be unmanaged by NetworkManager."
echo "eth0 remains managed for WAN and SSH access."

# ============================================================
# Disable wpa_supplicant
# ============================================================

echo
echo "Configuring wpa_supplicant..."

systemctl disable --now wpa_supplicant.service 2>/dev/null || true
systemctl disable --now wpa_supplicant@wlan0.service 2>/dev/null || true

# ============================================================
# Configure hostapd
# ============================================================

echo
echo "Configuring hostapd..."

read -rsp "Enter PiServer Wi-Fi password: " WIFI_PASSWORD
echo

if [ -z "$WIFI_PASSWORD" ]; then
    echo
    echo "ERROR: Wi-Fi password cannot be empty."
    exit 1
fi

if [ "${#WIFI_PASSWORD}" -lt 8 ]; then
    echo
    echo "ERROR: Wi-Fi password must be at least 8 characters."
    exit 1
fi

HOSTAPD_CONFIG="/etc/hostapd/hostapd.conf"

cp \
    "$INSTALL_DIR/configs/hostapd.conf.example" \
    "$HOSTAPD_CONFIG"

sed -i \
    "s|^wpa_passphrase=.*|wpa_passphrase=$WIFI_PASSWORD|" \
    "$HOSTAPD_CONFIG"

chmod 600 "$HOSTAPD_CONFIG"

echo "hostapd configured."

# ============================================================
# Configure dnsmasq
# ============================================================

echo
echo "Configuring dnsmasq..."

cp \
    "$INSTALL_DIR/configs/dnsmasq.conf.example" \
    /etc/dnsmasq.d/pi-gateway.conf

echo
echo "Testing dnsmasq configuration..."

dnsmasq --test

echo "dnsmasq configuration OK."

# ============================================================
# Configure IPv4 forwarding
# ============================================================

echo
echo "Configuring IPv4 forwarding..."

cp \
    "$INSTALL_DIR/configs/99-piserver-router.conf" \
    /etc/sysctl.d/99-piserver-router.conf

sysctl --system

if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    echo "ERROR: IPv4 forwarding is not enabled."
    exit 1
fi

echo "IPv4 forwarding enabled."

# ============================================================
# Configure PiServer LAN service
# ============================================================

echo
echo "Installing PiServer LAN service..."

cat > /etc/systemd/system/piserver-lan.service <<EOF
[Unit]
Description=Configure PiServer LAN interface
After=hostapd.service
Wants=hostapd.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set wlan0 up
ExecStart=/usr/sbin/ip addr replace 192.168.50.1/24 dev wlan0
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# ============================================================
# Configure PiServer GUI service
# ============================================================

echo
echo "Installing PiServer GUI service..."

cat > /etc/systemd/system/pi-gateway.service <<EOF
[Unit]
Description=PiServer Network Gateway GUI
After=network-online.target piserver-lan.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/src/network_gui.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# ============================================================
# Reload systemd
# ============================================================

echo
echo "Reloading systemd..."

systemctl daemon-reload

# ============================================================
# Enable services
# ============================================================

echo
echo "Enabling services..."

systemctl unmask hostapd 2>/dev/null || true

systemctl enable hostapd
systemctl enable dnsmasq
systemctl enable piserver-lan.service
systemctl enable pi-gateway.service

# ============================================================
# Start services
# ============================================================

echo
echo "Starting services..."

systemctl restart piserver-lan.service
systemctl restart hostapd
systemctl restart dnsmasq
systemctl restart pi-gateway.service

# ============================================================
# Verify services
# ============================================================

echo
echo "Checking services..."

SERVICES=(
    "hostapd"
    "dnsmasq"
    "piserver-lan.service"
    "pi-gateway.service"
)

for SERVICE in "${SERVICES[@]}"; do

    if systemctl is-active --quiet "$SERVICE"; then
        echo "  OK: $SERVICE"
    else
        echo "  ERROR: $SERVICE failed"
        echo
        echo "Recent logs:"
        journalctl -u "$SERVICE" -n 20 --no-pager
        exit 1
    fi

done

# ============================================================
# Verify wlan0
# ============================================================

echo
echo "Checking wlan0..."

if ! ip link show wlan0 >/dev/null 2>&1; then
    echo "ERROR: wlan0 does not exist."
    exit 1
fi

if ! ip -4 addr show wlan0 | grep -q "192.168.50.1/24"; then
    echo "ERROR: wlan0 does not have 192.168.50.1/24."
    exit 1
fi

echo "wlan0 OK."

# ============================================================
# Verify GUI
# ============================================================

echo
echo "Checking PiServer GUI..."

if ! ss -lntp | grep -q ":80 "; then
    echo "ERROR: PiServer GUI is not listening on port 80."
    echo
    echo "PiServer logs:"
    journalctl -u pi-gateway.service -n 30 --no-pager
    exit 1
fi

echo "PiServer GUI is listening on port 80."

# ============================================================
# Final status
# ============================================================

echo
echo "================================="
echo "       Setup Complete"
echo "================================="
echo

echo "Installation directory:"
echo "  $INSTALL_DIR"

echo
echo "Wi-Fi:"
grep '^ssid=' /etc/hostapd/hostapd.conf

echo
echo "LAN address:"
ip -4 addr show wlan0

echo
echo "IPv4 forwarding:"
cat /proc/sys/net/ipv4/ip_forward

echo
echo "NetworkManager:"
nmcli device status 2>/dev/null || true

echo
echo "Services:"
echo "hostapd:          $(systemctl is-active hostapd)"
echo "dnsmasq:          $(systemctl is-active dnsmasq)"
echo "piserver-lan:     $(systemctl is-active piserver-lan.service)"
echo "pi-gateway:       $(systemctl is-active pi-gateway.service)"

echo
echo "PiServer GUI:"
echo "  http://192.168.50.1"

echo
echo "PiServer setup completed successfully."

echo
echo "A reboot is recommended to fully apply the"
echo "NetworkManager configuration."
