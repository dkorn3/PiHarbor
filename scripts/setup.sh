
#!/bin/bash
set -e

echo "================================="
echo "       PiHarbor Setup"
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

echo "PiHarbor repository:"
echo "  $REPO_DIR"
echo

# ============================================================
# Ask for installation path
# ============================================================

read -rp "Installation path [$REPO_DIR]: " INSTALL_DIR
INSTALL_DIR="${INSTALL_DIR:-$REPO_DIR}"
INSTALL_DIR="$(mkdir -p "$INSTALL_DIR" && cd "$INSTALL_DIR" && pwd)"

echo
echo "Installing PiHarbor to:"
echo "  $INSTALL_DIR"
echo

# ============================================================
# Copy repository if needed
# ============================================================

if [ "$INSTALL_DIR" != "$REPO_DIR" ]; then
    echo "Copying PiHarbor files..."
    cp -a "$REPO_DIR"/. "$INSTALL_DIR"/
fi

# ============================================================
# Verify required files
# ============================================================

echo
echo "Checking PiHarbor files..."

REQUIRED_FILES=(
    "requirements.txt"
    "configs/hostapd.conf.example"
    "configs/dnsmasq.conf.example"
    "configs/99-piharbor-router.conf"
    "src/main.py"
    "src/config.py"
)

for FILE in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$INSTALL_DIR/$FILE" ]; then
        echo "ERROR: Missing:"
        echo "  $INSTALL_DIR/$FILE"
        exit 1
    fi
done

echo "PiHarbor files OK."

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
    python3-yaml \
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

echo "System packages installed."

# ============================================================
# Install Python requirements
# ============================================================

echo
echo "Installing Python requirements..."

python3 -m pip install \
    --break-system-packages \
    -r "$INSTALL_DIR/requirements.txt"

echo "Python requirements installed."

# ============================================================
# Verify Flask
# ============================================================

echo
echo "Checking Flask..."

python3 -c "import flask; print('Flask:', flask.__version__)"

echo "Flask OK."

# ============================================================
# Initialize and validate configuration
# ============================================================

echo
echo "Initializing PiHarbor configuration..."

mkdir -p "$INSTALL_DIR/config"

CONFIG_FILE="$INSTALL_DIR/config/gateway.yaml"

# Migrate an existing configuration if the main file is missing.
if [ ! -f "$CONFIG_FILE" ]; then

    LEGACY_CONFIG=""

    if [ -f "$INSTALL_DIR/src/config/gateway.yaml" ]; then
        LEGACY_CONFIG="$INSTALL_DIR/src/config/gateway.yaml"
    else
        LEGACY_CONFIG=$(find "$INSTALL_DIR/src/config" \
            -maxdepth 1 \
            -type f \
            -name 'gateway-*.yaml' \
            -printf '%T@ %p\n' 2>/dev/null \
            | sort -nr \
            | head -n 1 \
            | cut -d' ' -f2-)
    fi

    if [ -n "$LEGACY_CONFIG" ]; then
        echo "Migrating existing configuration..."
        cp "$LEGACY_CONFIG" "$CONFIG_FILE"
    fi
fi

# Always run configuration loading from the installation root.
cd "$INSTALL_DIR"

PYTHONPATH="$INSTALL_DIR/src" python3 - <<'PY'
import config

settings = config.load_config()
config.validate_config(settings)

print("Configuration loaded and validated.")

import main
import adblock
import dhcp
import dns
import firewall
import gateway_logger
import metrics_history
import monitoring
import nat
import network_gui
import topology_tree
import traffic

print("All PiHarbor Python modules imported successfully.")
PY

chmod 700 "$INSTALL_DIR/config"
chmod 600 "$CONFIG_FILE"
chown root:root "$CONFIG_FILE"

echo "Configuration initialized successfully."

# ============================================================
# Configure NetworkManager
# ============================================================

echo
echo "Configuring NetworkManager..."

mkdir -p /etc/NetworkManager/conf.d

cat > /etc/NetworkManager/conf.d/piharbor.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:wlan0
EOF

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

read -rsp "Enter PiHarbor Wi-Fi password: " WIFI_PASSWORD
echo

if [ "${#WIFI_PASSWORD}" -lt 8 ] || [ "${#WIFI_PASSWORD}" -gt 63 ]; then
    echo "ERROR: Wi-Fi password must contain 8-63 characters."
    exit 1
fi

HOSTAPD_CONFIG="/etc/hostapd/hostapd.conf"

cp "$INSTALL_DIR/configs/hostapd.conf.example" "$HOSTAPD_CONFIG"

WIFI_PASSWORD="$WIFI_PASSWORD" python3 - "$HOSTAPD_CONFIG" <<'PY'
import os
import sys

path = sys.argv[1]
password = os.environ["WIFI_PASSWORD"]

with open(path, "r", encoding="utf-8") as file:
    lines = file.readlines()

found = False

for index, line in enumerate(lines):
    if line.startswith("wpa_passphrase="):
        lines[index] = f"wpa_passphrase={password}\n"
        found = True
        break

if not found:
    raise SystemExit("ERROR: wpa_passphrase setting missing from hostapd template.")

with open(path, "w", encoding="utf-8") as file:
    file.writelines(lines)
PY

unset WIFI_PASSWORD
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

echo "Testing dnsmasq configuration..."

dnsmasq --test

echo "dnsmasq configuration OK."

# ============================================================
# Configure IPv4 forwarding
# ============================================================

echo
echo "Configuring IPv4 forwarding..."

cp \
    "$INSTALL_DIR/configs/99-piharbor-router.conf" \
    /etc/sysctl.d/99-piharbor-router.conf

sysctl --system

if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    echo "ERROR: IPv4 forwarding is not enabled."
    exit 1
fi

echo "IPv4 forwarding enabled."

# ============================================================
# Configure PiHarbor LAN service
# ============================================================

echo
echo "Installing PiHarbor LAN service..."

cat > /etc/systemd/system/piharbor-lan.service <<EOF
[Unit]
Description=Configure PiHarbor LAN interface
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
# Configure PiHarbor GUI service
# ============================================================

echo
echo "Installing PiHarbor GUI service..."

cat > /etc/systemd/system/pi-gateway.service <<EOF
[Unit]
Description=Raspberry Pi Network Gateway GUI
After=network-online.target piharbor-lan.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/src/main.py
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
systemctl enable piharbor-lan.service
systemctl enable pi-gateway.service

# ============================================================
# Start services
# ============================================================

echo
echo "Starting services..."

systemctl restart piharbor-lan.service
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
    "piharbor-lan.service"
    "pi-gateway.service"
)

for SERVICE in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$SERVICE"; then
        echo "  OK: $SERVICE"
    else
        echo "  ERROR: $SERVICE failed"
        journalctl -u "$SERVICE" -n 30 --no-pager
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
# Verify PiHarbor GUI
# ============================================================

echo
echo "Checking PiHarbor GUI..."

if ! curl -fsS http://127.0.0.1/ >/dev/null; then
    echo "ERROR: PiHarbor GUI is not responding."
    journalctl -u pi-gateway.service -n 30 --no-pager
    exit 1
fi

# Also verify the dashboard API.
if ! curl -fsS http://127.0.0.1/api/dashboard >/dev/null; then
    echo "ERROR: Dashboard API is not responding correctly."
    journalctl -u pi-gateway.service -n 30 --no-pager
    exit 1
fi

echo "PiHarbor GUI and dashboard API are responding."

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
echo "Configuration:"
echo "  $CONFIG_FILE"

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
echo "piharbor-lan:     $(systemctl is-active piharbor-lan.service)"
echo "pi-gateway:       $(systemctl is-active pi-gateway.service)"

echo
echo "PiHarbor GUI:"
echo "  http://192.168.50.1"

echo
echo "PiHarbor setup completed successfully."

echo
echo "A reboot is recommended to fully apply the"
echo "NetworkManager configuration."
