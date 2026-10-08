from flask import (
    Flask,
    jsonify,
    redirect,
    render_template_string,
    request,
    url_for,
)
from datetime import datetime
import ipaddress
import os
import subprocess
import threading
import time

import config as gateway_config
import monitoring
import nat as nat_backend
import topology_tree
import traffic


try:
    import dhcp as dhcp_backend
except ImportError:
    dhcp_backend = None


try:
    import dns as dns_backend
except ImportError:
    dns_backend = None


try:
    import adblock as adblock_backend
except ImportError:
    adblock_backend = None


try:
    import firewall as firewall_backend
except ImportError:
    firewall_backend = None


try:
    import vpn as vpn_backend
except ImportError:
    vpn_backend = None


try:
    import gateway_logger as gateway_logging
except ImportError:
    gateway_logging = None


app = Flask(__name__)


# ============================================================
# Device Tracking
# ============================================================

DEVICE_TRACKING = {}

DEVICE_TRACKING_LOCK = threading.Lock()


# ============================================================
# Traffic Activity Tracking
# ============================================================

TRAFFIC_ACTIVITY_TRACKING = {}

TRAFFIC_ACTIVITY_LOCK = threading.Lock()

TRAFFIC_ACTIVITY_THRESHOLD = 1024


# ============================================================
# Configuration
# ============================================================

def get_config():
    """
    Load the current PiHarbor configuration.
    """

    return gateway_config.load_config()


def get_network_config():
    """
    Return network configuration with safe defaults.
    """

    config = get_config()

    return config.get(
        "network",
        {}
    )


# ============================================================
# Helpers
# ============================================================

def command_exists(command):
    """
    Check whether a system command exists.
    """

    result = subprocess.run(
        ["which", command],
        capture_output=True,
        text=True,
        check=False,
    )

    return result.returncode == 0


def run_command(command, timeout=5):
    """
    Execute a system command.
    """

    try:

        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )

    except (
        OSError,
        subprocess.TimeoutExpired,
    ):
        return None


def get_local_ip(interface):
    """
    Return the IPv4 address of an interface.
    """

    return monitoring.get_interface_ip(
        interface
    )


def format_bytes(value):
    """
    Human-readable byte formatting.
    """

    if value is None:
        return "N/A"

    try:

        value = float(value)

        if value < 0:
            return "N/A"

    except (
        ValueError,
        TypeError,
    ):

        return "N/A"

    units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
    ]

    index = 0

    while value >= 1024 and index < len(units) - 1:

        value /= 1024
        index += 1

    if index == 0:

        return f"{int(value)} {units[index]}"

    return f"{value:.1f} {units[index]}"


def format_timestamp(timestamp):
    """
    Convert a Unix timestamp into a readable
    local date/time.
    """

    if timestamp in (
        None,
        "",
        0,
        "0",
    ):
        return "N/A"

    try:

        return datetime.fromtimestamp(
            float(timestamp)
        ).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except (
        ValueError,
        TypeError,
        OSError,
    ):
        return "N/A"


def format_duration(seconds):
    """
    Convert seconds into a readable duration.
    """

    if seconds is None:
        return "N/A"

    try:

        seconds = max(
            0,
            int(seconds)
        )

    except (
        ValueError,
        TypeError,
    ):
        return "N/A"

    days, remainder = divmod(
        seconds,
        86400,
    )

    hours, remainder = divmod(
        remainder,
        3600,
    )

    minutes, seconds = divmod(
        remainder,
        60,
    )

    parts = []

    if days:
        parts.append(
            f"{days}d"
        )

    if hours:
        parts.append(
            f"{hours}h"
        )

    if minutes:
        parts.append(
            f"{minutes}m"
        )

    if not parts:
        parts.append(
            f"{seconds}s"
        )

    return " ".join(parts)


def format_lease_remaining(expiry):
    """
    Return the amount of time remaining on a DHCP lease.
    """

    if expiry in (
        None,
        "",
        0,
        "0",
    ):
        return "N/A"

    try:

        remaining = int(
            float(expiry)
        ) - int(
            time.time()
        )

    except (
        ValueError,
        TypeError,
    ):
        return "N/A"

    if remaining <= 0:
        return "Expired"

    return format_duration(
        remaining
    )


# ============================================================
# Device Identification
# ============================================================

def get_device_identity(
    ip,
    mac=None,
    hostname=None,
):
    """
    Best-effort device type and OS identification.

    This does not actively scan the client. It uses
    information already available from DHCP/ARP and
    common hostname patterns.
    """

    hostname_text = (
        hostname or ""
    ).strip().lower()

    device_type = "Unknown"
    operating_system = "Unknown"

    # --------------------------------------------------------
    # Mobile devices
    # --------------------------------------------------------

    if any(
        value in hostname_text
        for value in (
            "iphone",
            "ipad",
        )
    ):

        device_type = "Mobile"
        operating_system = "iOS"

    elif any(
        value in hostname_text
        for value in (
            "android",
            "galaxy",
            "pixel",
            "oneplus",
            "xiaomi",
            "redmi",
            "moto",
        )
    ):

        device_type = "Mobile"
        operating_system = "Android"

    # --------------------------------------------------------
    # Apple computers
    # --------------------------------------------------------

    elif any(
        value in hostname_text
        for value in (
            "macbook",
            "imac",
            "mac-mini",
            "macmini",
        )
    ):

        device_type = "Computer"
        operating_system = "macOS"

    # --------------------------------------------------------
    # Windows
    # --------------------------------------------------------

    elif any(
        value in hostname_text
        for value in (
            "windows",
            "desktop",
            "laptop",
            "pc",
        )
    ):

        device_type = "Computer"
        operating_system = "Windows"

    # --------------------------------------------------------
    # Linux
    # --------------------------------------------------------

    elif any(
        value in hostname_text
        for value in (
            "ubuntu",
            "debian",
            "linux",
            "raspberry",
            "raspberrypi",
            "pi",
        )
    ):

        device_type = "Computer"
        operating_system = "Linux"

    # --------------------------------------------------------
    # Printers
    # --------------------------------------------------------

    elif any(
        value in hostname_text
        for value in (
            "printer",
            "epson",
            "canon",
            "brother",
            "hp-",
        )
    ):

        device_type = "Printer"

    # --------------------------------------------------------
    # TVs / Media
    # --------------------------------------------------------

    elif any(
        value in hostname_text
        for value in (
            "tv",
            "roku",
            "firetv",
            "chromecast",
            "apple-tv",
            "appletv",
        )
    ):

        device_type = "TV / Media"

    # --------------------------------------------------------
    # Smart Home
    # --------------------------------------------------------

    elif any(
        value in hostname_text
        for value in (
            "echo",
            "alexa",
            "google-home",
            "homepod",
        )
    ):

        device_type = "Smart Home"

    # --------------------------------------------------------
    # Cameras
    # --------------------------------------------------------

    elif any(
        value in hostname_text
        for value in (
            "camera",
            "cam",
            "doorbell",
        )
    ):

        device_type = "Camera"

    # --------------------------------------------------------
    # Generic fallback
    # --------------------------------------------------------

    if device_type == "Unknown":

        if hostname_text:

            device_type = "Network Client"

        else:

            device_type = "Unknown"

    return {
        "device_type": device_type,
        "os": operating_system,
    }


# ============================================================
# Connection Tracking
# ============================================================

def update_device_tracking(devices):
    """
    Track when devices were first observed as connected.

    Tracking is kept in memory and therefore resets if the
    Flask application restarts.
    """

    now = time.time()

    with DEVICE_TRACKING_LOCK:

        for device in devices:

            ip = device.get("ip")

            if not ip:
                continue

            if device.get("connected"):

                if ip not in DEVICE_TRACKING:

                    DEVICE_TRACKING[ip] = {
                        "connected_since": now,
                    }

                connected_since = (
                    DEVICE_TRACKING[ip]
                    .get(
                        "connected_since",
                        now,
                    )
                )

                device["connected_since"] = (
                    connected_since
                )

                device["connected_since_text"] = (
                    format_timestamp(
                        connected_since
                    )
                )

                device["connected_duration"] = (
                    format_duration(
                        now - connected_since
                    )
                )

            else:

                device["connected_since"] = None
                device["connected_since_text"] = "N/A"
                device["connected_duration"] = "N/A"

                DEVICE_TRACKING.pop(
                    ip,
                    None,
                )


# ============================================================
# Per-Device Traffic
# ============================================================

def get_device_traffic(device_ips):
    """
    Get per-device traffic from the nftables accounting
    backend.

    The traffic module is responsible for creating and
    reading the nftables counters.
    """

    if not device_ips:
        return {}

    try:

        return traffic.get_all_device_traffic(
            device_ips
        )

    except Exception:

        return {}


def get_traffic_activity(
    ip,
    download_bytes,
    upload_bytes,
):
    """
    Determine whether a device is actively downloading,
    uploading, both, or idle.

    Activity is based on changes in nftables byte counters
    between dashboard refreshes.
    """

    if (
        download_bytes is None
        or upload_bytes is None
    ):
        return "N/A"

    try:

        download_bytes = int(
            download_bytes
        )

        upload_bytes = int(
            upload_bytes
        )

    except (
        ValueError,
        TypeError,
    ):

        return "N/A"

    now = time.time()

    with TRAFFIC_ACTIVITY_LOCK:

        previous = (
            TRAFFIC_ACTIVITY_TRACKING.get(
                ip
            )
        )

        TRAFFIC_ACTIVITY_TRACKING[ip] = {
            "download_bytes": download_bytes,
            "upload_bytes": upload_bytes,
            "timestamp": now,
        }

    if previous is None:
        return "Idle"

    download_delta = (
        download_bytes
        - previous.get(
            "download_bytes",
            download_bytes,
        )
    )

    upload_delta = (
        upload_bytes
        - previous.get(
            "upload_bytes",
            upload_bytes,
        )
    )

    # Counter reset / nftables restart.
    if (
        download_delta < 0
        or upload_delta < 0
    ):
        return "Idle"

    downloading = (
        download_delta
        >= TRAFFIC_ACTIVITY_THRESHOLD
    )

    uploading = (
        upload_delta
        >= TRAFFIC_ACTIVITY_THRESHOLD
    )

    if downloading and uploading:
        return "Active"

    if downloading:
        return "Downloading"

    if uploading:
        return "Uploading"

    return "Idle"


def cleanup_traffic_activity(active_ips):
    """
    Remove traffic activity state for devices that are no
    longer visible.
    """

    active_ips = set(
        active_ips
    )

    with TRAFFIC_ACTIVITY_LOCK:

        stale_ips = [
            ip
            for ip in TRAFFIC_ACTIVITY_TRACKING
            if ip not in active_ips
        ]

        for ip in stale_ips:

            TRAFFIC_ACTIVITY_TRACKING.pop(
                ip,
                None,
            )


# ============================================================
# DHCP / Device Discovery
# ============================================================

def get_dhcp_leases():
    """
    Read dnsmasq DHCP lease information.
    """

    lease_files = [
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/dnsmasq/dnsmasq.leases",
    ]

    lease_file = None

    for path in lease_files:

        if os.path.exists(path):

            lease_file = path
            break

    if lease_file is None:
        return {}

    leases = {}

    try:

        with open(
            lease_file,
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:

                parts = line.split()

                if len(parts) < 4:
                    continue

                expiry = parts[0]
                mac = parts[1]
                ip = parts[2]
                hostname = parts[3]

                leases[ip] = {
                    "hostname": (
                        hostname
                        if hostname != "*"
                        else "Unknown"
                    ),
                    "ip": ip,
                    "mac": mac,
                    "expiry": expiry,
                    "expiry_text":
                        format_timestamp(
                            expiry
                        ),
                    "lease_remaining":
                        format_lease_remaining(
                            expiry
                        ),
                    "connected": True,
                    "interface":
                        get_network_config().get(
                            "lan_interface",
                            "wlan0",
                        ),
                }

    except (
        OSError,
        ValueError,
    ):

        return {}

    return leases


def get_arp_devices():
    """
    Return devices currently visible through
    the LAN interface.
    """

    network = get_network_config()

    lan_interface = network.get(
        "lan_interface",
        "wlan0",
    )

    result = run_command(
        [
            "ip",
            "neigh",
            "show",
            "dev",
            lan_interface,
        ]
    )

    if result is None:
        return {}

    devices = {}

    for line in result.stdout.splitlines():

        parts = line.split()

        if not parts:
            continue

        ip = parts[0]

        try:

            if (
                ipaddress.ip_address(ip).version
                != 4
            ):
                continue

        except ValueError:

            continue

        mac = None
        state = "unknown"

        for index, value in enumerate(parts):

            if (
                value == "lladdr"
                and index + 1 < len(parts)
            ):

                mac = parts[
                    index + 1
                ]

            if value in (
                "REACHABLE",
                "STALE",
                "DELAY",
                "PROBE",
                "FAILED",
                "INCOMPLETE",
            ):

                state = value.lower()

        devices[ip] = {
            "ip": ip,
            "mac": mac,
            "state": state,
            "connected": state not in (
                "failed",
                "incomplete",
            ),
        }

    return devices


def get_connected_devices():
    """
    Combine DHCP lease information with ARP information,
    nftables traffic accounting, device metadata, DHCP
    information, and connection tracking.
    """

    leases = get_dhcp_leases()

    arp = get_arp_devices()

    devices = {}

    # --------------------------------------------------------
    # DHCP devices
    # --------------------------------------------------------

    for ip, lease in leases.items():

        device = dict(
            lease
        )

        if ip in arp:

            arp_device = arp[ip]

            if arp_device.get("mac"):

                device["mac"] = (
                    arp_device["mac"]
                )

            device["state"] = (
                arp_device.get(
                    "state",
                    "unknown",
                )
            )

            device["connected"] = (
                arp_device.get(
                    "connected",
                    True,
                )
            )

        devices[ip] = device

    # --------------------------------------------------------
    # ARP-only devices
    # --------------------------------------------------------

    for ip, arp_device in arp.items():

        if ip in devices:
            continue

        devices[ip] = {
            "hostname": "Unknown",
            "ip": ip,
            "mac": arp_device.get(
                "mac"
            ),
            "expiry": None,
            "expiry_text": "N/A",
            "lease_remaining": "N/A",
            "connected":
                arp_device.get(
                    "connected",
                    False,
                ),
            "state":
                arp_device.get(
                    "state",
                    "unknown",
                ),
            "interface":
                get_network_config().get(
                    "lan_interface",
                    "wlan0",
                ),
        }

    # --------------------------------------------------------
    # Get traffic for discovered devices
    # --------------------------------------------------------

    device_ips = list(
        devices.keys()
    )

    traffic_data = get_device_traffic(
        device_ips
    )

    # --------------------------------------------------------
    # Add device information
    # --------------------------------------------------------

    for ip, device in devices.items():

        identity = get_device_identity(
            ip=ip,
            mac=device.get("mac"),
            hostname=device.get("hostname"),
        )

        device["device_type"] = (
            identity["device_type"]
        )

        device["os"] = (
            identity["os"]
        )

        # ----------------------------------------------------
        # Traffic
        # ----------------------------------------------------

        device_traffic = (
            traffic_data.get(
                ip
            )
        )

        if device_traffic is None:

            device["download_bytes"] = None
            device["upload_bytes"] = None

            device["download_human"] = "N/A"
            device["upload_human"] = "N/A"

            device["activity"] = "N/A"

        else:

            download_bytes = (
                device_traffic.get(
                    "download_bytes"
                )
            )

            upload_bytes = (
                device_traffic.get(
                    "upload_bytes"
                )
            )

            device["download_bytes"] = (
                download_bytes
            )

            device["upload_bytes"] = (
                upload_bytes
            )

            device["download_human"] = (
                format_bytes(
                    download_bytes
                )
            )

            device["upload_human"] = (
                format_bytes(
                    upload_bytes
                )
            )

            device["activity"] = (
                get_traffic_activity(
                    ip,
                    download_bytes,
                    upload_bytes,
                )
            )

        # ----------------------------------------------------
        # DHCP lease
        # ----------------------------------------------------

        if device.get("expiry"):

            device["lease_remaining"] = (
                format_lease_remaining(
                    device["expiry"]
                )
            )

        else:

            device["lease_remaining"] = "N/A"

    cleanup_traffic_activity(
        device_ips
    )

    devices_list = list(
        devices.values()
    )

    update_device_tracking(
        devices_list
    )

    return devices_list


# ============================================================
# Services
# ============================================================

def service_active(service):
    """
    Return True if a systemd service is active.
    """

    status = monitoring.get_service_status(
        service
    )

    return status == "active"


def get_service_statuses():
    """
    Return the services displayed on the dashboard.
    """

    nat_status = nat_backend.get_nat_status()

    return {
        "dhcp": {
            "enabled":
                service_active(
                    "dnsmasq.service"
                ),
            "label": "DHCP",
        },

        "dns": {
            "enabled":
                service_active(
                    "dnsmasq.service"
                ),
            "label": "DNS",
        },

        "nat": {
            "enabled":
                bool(
                    nat_status.get(
                        "enabled",
                        False,
                    )
                ),
            "label": "NAT",
        },

        "firewall": {
            "enabled":
                get_firewall_enabled(),
            "label": "Firewall",
        },

        "vpn": {
            "enabled":
                monitoring.get_vpn_status()
                == "active",
            "label": "VPN",
        },
    }


def get_firewall_enabled():
    """
    Determine current firewall state.
    """

    if firewall_backend is None:
        return False

    try:

        status = (
            firewall_backend
            .get_firewall_status()
        )

        if isinstance(
            status,
            dict,
        ):

            return bool(
                status.get(
                    "enabled",
                    False,
                )
            )

        if isinstance(
            status,
            bool,
        ):

            return status

        return str(
            status
        ).lower() in (
            "active",
            "enabled",
            "running",
            "true",
        )

    except (
        AttributeError,
        OSError,
        RuntimeError,
    ):

        return False


# ============================================================
# Ad Blocking
# ============================================================

def get_adblock_status():
    """
    Return current ad-blocking status.
    """

    if adblock_backend is None:

        return {
            "enabled": False,
            "blocked_domains": 0,
            "size_bytes": 0,
            "last_update": None,
            "path": None,
        }

    try:

        return adblock_backend.get_status()

    except Exception:

        return {
            "enabled": False,
            "blocked_domains": 0,
            "size_bytes": 0,
            "last_update": None,
            "path": None,
        }


def update_adblock():
    """
    Download and install the latest ad-blocking
    blocklist.
    """

    if adblock_backend is None:

        return {
            "success": False,
            "message":
                "Adblock backend is unavailable.",
        }

    return adblock_backend.update_blocklist()


def enable_adblock():
    """
    Enable PiHarbor ad blocking.
    """

    if adblock_backend is None:
        return False

    return adblock_backend.enable()


def disable_adblock():
    """
    Disable PiHarbor ad blocking.
    """

    if adblock_backend is None:
        return False

    return adblock_backend.disable()


def get_custom_blocked_domains():
    """
    Return custom domains added through the GUI.
    """

    if adblock_backend is None:
        return []

    try:

        return (
            adblock_backend
            .get_custom_domains()
        )

    except Exception:

        return []


def add_custom_blocked_domain(domain):
    """
    Add a custom domain.
    """

    if adblock_backend is None:

        return {
            "success": False,
            "message":
                "Adblock backend is unavailable.",
        }

    try:

        return (
            adblock_backend
            .add_custom_domain(
                domain
            )
        )

    except Exception as exc:

        return {
            "success": False,
            "message": str(exc),
        }


def remove_custom_blocked_domain(domain):
    """
    Remove a custom domain.
    """

    if adblock_backend is None:

        return {
            "success": False,
            "message":
                "Adblock backend is unavailable.",
        }

    try:

        return (
            adblock_backend
            .remove_custom_domain(
                domain
            )
        )

    except Exception as exc:

        return {
            "success": False,
            "message": str(exc),
        }


# ============================================================
# NAT Controls
# ============================================================

def enable_nat():
    """
    Enable NAT using the PiHarbor NAT backend.
    """

    return nat_backend.configure_nat()


def disable_nat():
    """
    Disable NAT using the PiHarbor NAT backend.
    """

    return nat_backend.disable_nat()


# ============================================================
# Dashboard
# ============================================================

def get_dashboard_data():
    """
    Build the complete dashboard data structure.
    """

    network = get_network_config()

    wan_interface = network.get(
        "wan_interface",
        "eth0",
    )

    lan_interface = network.get(
        "lan_interface",
        "wlan0",
    )

    metrics = (
        monitoring.get_dashboard_metrics(
            wan_interface=wan_interface,
            lan_interface=lan_interface,
        )
    )

    devices = get_connected_devices()

    return {
        "system": metrics.get(
            "system",
            {},
        ),

        "network": metrics.get(
            "network",
            {},
        ),

        "devices": devices,

        "services":
            get_service_statuses(),

        "vpn": metrics.get(
            "vpn",
            {},
        ),

        "dns": metrics.get(
            "dns",
            {},
        ),

        "dhcp": metrics.get(
            "dhcp",
            {},
        ),

        "firewall": metrics.get(
            "firewall",
            {},
        ),

        "nat": metrics.get(
            "nat",
            {},
        ),

        "adblock":
            get_adblock_status(),

        "timestamp":
            metrics.get(
                "timestamp",
                time.time(),
            ),
    }


# ============================================================
# Dashboard HTML
# ============================================================

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>PiHarbor Dashboard</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #0b0e12;
    color: #f3f4f6;
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

.sidebar {
    position: fixed;
    left: 0;
    top: 0;
    bottom: 0;
    width: 220px;
    background: #12161c;
    border-right: 1px solid #252b34;
    padding: 24px 16px;
}

.logo {
    font-size: 24px;
    font-weight: 700;
    margin-bottom: 30px;
}

.logo span {
    display: block;
    margin-top: 4px;
    color: #7f8793;
    font-size: 13px;
}

.nav a {
    display: block;
    padding: 11px 13px;
    margin-bottom: 5px;
    border-radius: 8px;
    color: #aeb5bf;
    text-decoration: none;
}

.nav a:hover,
.nav a.active {
    background: #222831;
    color: #fff;
}

.main {
    margin-left: 220px;
    padding: 30px;
    max-width: 1600px;
}

.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
}

.header h1 {
    margin: 0;
    font-size: 28px;
}

.header-sub {
    color: #7f8793;
    font-size: 13px;
    margin-top: 5px;
}

.status {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    border-radius: 20px;
    background: #171c23;
    border: 1px solid #252b34;
    font-size: 13px;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(4, minmax(180px, 1fr));
    gap: 14px;
    margin-bottom: 14px;
}

.card {
    background: #12161c;
    border: 1px solid #252b34;
    border-radius: 12px;
    padding: 18px;
}

.card h3 {
    margin: 0 0 8px;
    color: #8f98a5;
    font-size: 13px;
    font-weight: 500;
}

.metric {
    font-size: 27px;
    font-weight: 700;
    letter-spacing: -0.4px;
}

.sub {
    color: #737c89;
    font-size: 12px;
    margin-top: 5px;
}

.summary {
    display: grid;
    grid-template-columns:
        1.2fr 1fr 1fr 1fr;
    gap: 14px;
    margin-bottom: 14px;
}

.summary-card {
    background: #151a21;
    border: 1px solid #252b34;
    border-radius: 12px;
    padding: 18px;
}

.summary-label {
    color: #7f8793;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .08em;
}

.summary-value {
    font-size: 30px;
    font-weight: 700;
    margin-top: 5px;
}

.network-card {
    min-height: 126px;
}

.network-line {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
    margin-top: 10px;
}

.network-name {
    font-size: 13px;
    color: #8f98a5;
}

.network-ip {
    font-family: monospace;
    font-size: 14px;
}

.state {
    font-size: 12px;
    color: #65d985;
}

.state.offline {
    color: #d96868;
}

.progress {
    height: 5px;
    background: #252b34;
    border-radius: 99px;
    overflow: hidden;
    margin-top: 12px;
}

.progress > div {
    height: 100%;
    width: 0;
    background: #7aa2f7;
    transition: width .25s ease;
}

.section-title {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
}

.section-title h2 {
    margin: 0;
    font-size: 17px;
}

.section-title span {
    color: #727b88;
    font-size: 12px;
}

.service {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 11px 0;
    border-bottom: 1px solid #252b34;
}

.service:last-child {
    border-bottom: none;
}

.dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 8px;
    background: #626b77;
}

.dot.active {
    background: #55d17a;
}

.dot.inactive {
    background: #d65c5c;
}

.service-name {
    display: flex;
    align-items: center;
    color: #d8dce2;
    font-size: 13px;
}

.badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 6px;
    background: #202630;
    color: #aeb5bf;
    font-size: 11px;
}

.devices-card {
    padding: 0;
    overflow: hidden;
}

.devices-head {
    padding: 18px;
    border-bottom: 1px solid #252b34;
}

.device {
    display: grid;
    grid-template-columns:
        1.5fr
        .9fr
        .9fr
        1fr
        1fr
        1fr
        1.1fr
        1.1fr
        1fr
        90px;
    gap: 12px;
    align-items: center;
    padding: 13px 18px;
    border-bottom: 1px solid #20252d;
    font-size: 13px;
    min-width: 1250px;
}

.device:last-child {
    border-bottom: none;
}

.device:hover {
    background: #171c23;
}

.device a {
    color: #f3f4f6;
    text-decoration: none;
    font-weight: 600;
}

.device a:hover {
    text-decoration: underline;
}

.table-header {
    color: #6f7885;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .06em;
}

.device-status {
    display: flex;
    align-items: center;
    gap: 6px;
    color: #65d985;
    font-size: 12px;
}

.device-status.offline {
    color: #d96868;
}

.mono {
    font-family: monospace;
    color: #b8bec7;
}

.traffic {
    display: flex;
    flex-direction: column;
    gap: 2px;
}

.traffic-download {
    color: #8fc7ff;
}

.traffic-upload {
    color: #d0a7ff;
}

.activity {
    font-size: 12px;
    font-weight: 600;
}

.activity.downloading {
    color: #8fc7ff;
}

.activity.uploading {
    color: #d0a7ff;
}

.activity.active {
    color: #65d985;
}

.activity.idle {
    color: #737c89;
}

.activity.na {
    color: #737c89;
}

.connected-time {
    display: flex;
    flex-direction: column;
    gap: 2px;
}

.footer {
    color: #5f6875;
    font-size: 11px;
    margin-top: 18px;
    text-align: right;
}

.device-scroll {
    overflow-x: auto;
}

@media (max-width: 1400px) {

    .main {
        max-width: none;
    }

    .device {
        grid-template-columns:
            1.4fr
            .8fr
            .8fr
            1fr
            1fr
            1fr
            1fr
            1fr
            1fr
            80px;
    }
}

@media (max-width: 1050px) {

    .grid {
        grid-template-columns:
            repeat(2, 1fr);
    }

    .summary {
        grid-template-columns:
            repeat(2, 1fr);
    }
}

@media (max-width: 800px) {

    .sidebar {
        position: static;
        width: 100%;
        height: auto;
    }

    .main {
        margin-left: 0;
        padding: 16px;
    }

    .grid,
    .summary {
        grid-template-columns: 1fr;
    }

    .device-scroll {
        overflow-x: auto;
    }

    .device {
        min-width: 1250px;
    }
}

</style>

</head>

<body>

<div class="sidebar">

    <div class="logo">
        PiHarbor
        <span>Network Gateway</span>
    </div>

    <div class="nav">

        <a href="/" class="active">
            Dashboard
        </a>

        <a href="/health">
            Device Health
        </a>
        
        <a href="/topology">
            Topology
        </a>
        
        <a href="/network">
            Network
        </a>

        <a href="/dns">
            DNS
        </a>

    </div>

</div>

<div class="main">

    <div class="header">

        <div>

            <h1>Dashboard</h1>

            <div class="header-sub">
                Live gateway and LAN overview
            </div>

        </div>

        <div class="status">

            <span
                class="dot active"
                id="gateway-dot"
            ></span>

            <span id="gateway-status">
                PiHarbor Online
            </span>

        </div>

    </div>


    <!-- QUICK SUMMARY -->

    <div class="summary">

        <div class="summary-card">

            <div class="summary-label">
                Connected Devices
            </div>

            <div
                class="summary-value"
                id="device-count"
            >
                0
            </div>

            <div class="sub">
                LAN clients currently visible
            </div>

        </div>


        <div class="summary-card">

            <div class="summary-label">
                TCP Connections
            </div>

            <div
                class="summary-value"
                id="connections"
            >
                --
            </div>

            <div class="sub">
                Active network connections
            </div>

        </div>


        <div class="summary-card">

            <div class="summary-label">
                Internet
            </div>

            <div
                class="summary-value"
                id="internet"
            >
                --
            </div>

            <div class="sub">
                WAN connectivity
            </div>

        </div>


        <div class="summary-card">

            <div class="summary-label">
                Uptime
            </div>

            <div
                class="summary-value"
                id="uptime"
            >
                --
            </div>

            <div class="sub">
                System uptime
            </div>

        </div>

    </div>


    <!-- WAN / LAN -->

    <div class="grid">

        <div class="card network-card">

            <h3>WAN</h3>

            <div class="network-line">

                <span
                    class="network-name"
                    id="wan-interface"
                >
                    --
                </span>

                <span
                    class="state"
                    id="wan-state"
                >
                    --
                </span>

            </div>

            <div class="network-line">

                <span class="network-name">
                    IP Address
                </span>

                <span
                    class="network-ip"
                    id="wan-ip"
                >
                    --
                </span>

            </div>

        </div>


        <div class="card network-card">

            <h3>LAN</h3>

            <div class="network-line">

                <span
                    class="network-name"
                    id="lan-interface"
                >
                    --
                </span>

                <span
                    class="state"
                    id="lan-state"
                >
                    --
                </span>

            </div>

            <div class="network-line">

                <span class="network-name">
                    IP Address
                </span>

                <span
                    class="network-ip"
                    id="lan-ip"
                >
                    --
                </span>

            </div>

        </div>


        <div class="card">

            <h3>Network Traffic</h3>

            <div class="network-line">

                <span class="network-name">
                    RX
                </span>

                <span
                    class="network-ip"
                    id="network-rx"
                >
                    --
                </span>

            </div>

            <div class="network-line">

                <span class="network-name">
                    TX
                </span>

                <span
                    class="network-ip"
                    id="network-tx"
                >
                    --
                </span>

            </div>

        </div>


        <div class="card">

            <h3>Services</h3>

            <div class="service">

                <span class="service-name">

                    <span
                        class="dot"
                        id="dhcp-dot"
                    ></span>

                    DHCP

                </span>

                <span
                    class="badge"
                    id="dhcp-status"
                >
                    --
                </span>

            </div>


            <div class="service">

                <span class="service-name">

                    <span
                        class="dot"
                        id="dns-dot"
                    ></span>

                    DNS

                </span>

                <span
                    class="badge"
                    id="dns-status"
                >
                    --
                </span>

            </div>


            <div class="service">

                <span class="service-name">

                    <span
                        class="dot"
                        id="nat-dot"
                    ></span>

                    NAT

                </span>

                <span
                    class="badge"
                    id="nat-status"
                >
                    --
                </span>

            </div>

        </div>

    </div>


    <!-- DEVICES -->

    <div class="card devices-card">

        <div class="devices-head">

            <div class="section-title">

                <h2>
                    Connected Devices
                </h2>

                <span id="device-updated">
                    Updating...
                </span>

            </div>

            <div class="sub">
                DHCP leases, ARP neighbors, and
                real network traffic detected on the LAN
            </div>

        </div>


        <div class="device-scroll">

            <div class="device table-header">

                <div>
                    Device
                </div>

                <div>
                    Type
                </div>

                <div>
                    OS
                </div>

                <div>
                    IP Address
                </div>

                <div>
                    DHCP Lease
                </div>

                <div>
                    Activity
                </div>

                <div>
                    Connected
                </div>

                <div>
                    Download
                </div>

                <div>
                    Upload
                </div>

                <div>
                    Status
                </div>

            </div>


            <div id="devices">

                <div
                    class="sub"
                    style="padding:18px;"
                >
                    Loading devices...
                </div>

            </div>

        </div>

    </div>


    <!-- AD BLOCKING -->

    <div
        class="card"
        style="margin-top:14px;"
    >

        <div class="section-title">

            <h2>
                Ad Blocking
            </h2>

            <span>

                <span
                    class="dot"
                    id="adblock-dot"
                ></span>

                <span id="adblock-status">
                    --
                </span>

            </span>

        </div>

        <div class="sub">

            <strong id="adblock-count">
                0
            </strong>

            domains blocked

        </div>

    </div>


    <div class="footer">
        Live data refreshes every 3 seconds
    </div>

</div>


<script>

function setService(service, enabled) {

    const dot =
        document.getElementById(
            service + "-dot"
        );

    const status =
        document.getElementById(
            service + "-status"
        );

    if (!dot || !status) {
        return;
    }

    dot.className =
        enabled
            ? "dot active"
            : "dot inactive";

    status.textContent =
        enabled
            ? "Active"
            : "Inactive";
}


function activityClass(activity) {

    if (!activity) {
        return "na";
    }

    const value =
        activity.toLowerCase();

    if (value === "downloading") {
        return "downloading";
    }

    if (value === "uploading") {
        return "uploading";
    }

    if (value === "active") {
        return "active";
    }

    if (value === "idle") {
        return "idle";
    }

    return "na";
}


function renderDevices(devices) {

    const container =
        document.getElementById(
            "devices"
        );

    const count =
        document.getElementById(
            "device-count"
        );

    count.textContent =
        devices.length;


    if (!devices.length) {

        container.innerHTML =
            '<div class="sub" style="padding:18px;">No connected devices detected</div>';

        return;
    }


    container.innerHTML =
        devices.map(
            function(device) {

                const hostname =
                    device.hostname ||
                    "Unknown";

                const ip =
                    device.ip ||
                    "--";

                const type =
                    device.device_type ||
                    "Unknown";

                const os =
                    device.os ||
                    "Unknown";

                const lease =
                    device.lease_remaining ||
                    "N/A";

                const activity =
                    device.activity ||
                    "N/A";

                const connectedSince =
                    device.connected_since_text ||
                    "N/A";

                const connectedDuration =
                    device.connected_duration ||
                    "N/A";

                const download =
                    device.download_human ||
                    "N/A";

                const upload =
                    device.upload_human ||
                    "N/A";

                const online =
                    device.connected !== false;


                return `

                    <div class="device">

                        <div>

                            <a href="/device/${ip}">
                                ${hostname}
                            </a>

                            <div class="sub">
                                ${device.mac || "--"}
                            </div>

                        </div>


                        <div>
                            ${type}
                        </div>


                        <div>
                            ${os}
                        </div>


                        <div class="mono">
                            ${ip}
                        </div>


                        <div>
                            ${lease}
                        </div>


                        <div
                            class="activity
                            ${activityClass(activity)}"
                        >
                            ${activity}
                        </div>


                        <div class="connected-time">

                            <span>
                                ${connectedDuration}
                            </span>

                            <span class="sub">
                                ${connectedSince}
                            </span>

                        </div>


                        <div class="traffic">

                            <span class="traffic-download">
                                ↓ ${download}
                            </span>

                        </div>


                        <div class="traffic">

                            <span class="traffic-upload">
                                ↑ ${upload}
                            </span>

                        </div>


                        <div
                            class="device-status
                            ${online ? "" : "offline"}"
                        >

                            <span
                                class="dot
                                ${online
                                    ? "active"
                                    : "inactive"}"
                            ></span>

                            ${online
                                ? "Online"
                                : "Offline"}

                        </div>

                    </div>

                `;
            }
        ).join("");
}


async function refreshDashboard() {

    try {

        const response =
            await fetch(
                "/api/dashboard",
                {
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                "Dashboard request failed"
            );

        }


        const data =
            await response.json();


        const network =
            data.network || {};

        const wan =
            network.wan || {};

        const lan =
            network.lan || {};


        document.getElementById(
            "wan-ip"
        ).textContent =
            wan.ip || "N/A";


        document.getElementById(
            "wan-interface"
        ).textContent =
            wan.interface || "WAN";


        document.getElementById(
            "wan-state"
        ).textContent =
            wan.state || "unknown";


        document.getElementById(
            "lan-ip"
        ).textContent =
            lan.ip || "N/A";


        document.getElementById(
            "lan-interface"
        ).textContent =
            lan.interface || "LAN";


        document.getElementById(
            "lan-state"
        ).textContent =
            lan.state || "unknown";


        const internet =
            Boolean(
                network.internet
            );

        const internetElement =
            document.getElementById(
                "internet"
            );


        internetElement.textContent =
            internet
                ? "Online"
                : "Offline";


        internetElement.style.color =
            internet
                ? "#65d985"
                : "#d96868";


        document.getElementById(
            "connections"
        ).textContent =

            network.connections !== null &&
            network.connections !== undefined

                ? network.connections
                : "N/A";


        document.getElementById(
            "network-rx"
        ).textContent =
            network.rx_human ||
            network.rx ||
            "--";


        document.getElementById(
            "network-tx"
        ).textContent =
            network.tx_human ||
            network.tx ||
            "--";


        document.getElementById(
            "uptime"
        ).textContent =
            data.system?.uptime_text ||
            "N/A";


        const services =
            data.services || {};


        setService(
            "dhcp",
            services.dhcp?.enabled
        );

        setService(
            "dns",
            services.dns?.enabled
        );

        setService(
            "nat",
            services.nat?.enabled
        );


        const adblock =
            data.adblock || {};


        const adblockDot =
            document.getElementById(
                "adblock-dot"
            );


        const adblockStatus =
            document.getElementById(
                "adblock-status"
            );


        if (adblock.enabled) {

            adblockDot.className =
                "dot active";

            adblockStatus.textContent =
                "Active";

        } else {

            adblockDot.className =
                "dot inactive";

            adblockStatus.textContent =
                "Inactive";

        }


        document.getElementById(
            "adblock-count"
        ).textContent =

            adblock.blocked_domains !==
            undefined

                ? adblock.blocked_domains
                : "0";


        renderDevices(
            data.devices || []
        );


        document.getElementById(
            "device-updated"
        ).textContent =
            "Updated " +
            new Date().toLocaleTimeString();


        document.getElementById(
            "gateway-dot"
        ).className =
            "dot active";


        document.getElementById(
            "gateway-status"
        ).textContent =
            "PiHarbor Online";


    } catch (error) {

        console.error(
            "Dashboard refresh failed:",
            error
        );


        document.getElementById(
            "gateway-dot"
        ).className =
            "dot inactive";


        document.getElementById(
            "gateway-status"
        ).textContent =
            "Dashboard Error";

    }

}


refreshDashboard();

setInterval(
    refreshDashboard,
    3000
);

</script>

</body>
</html>
"""


# ============================================================
# Device Details
# ============================================================

DEVICE_TEMPLATE = """
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>
    {{ device.hostname }} - PiHarbor
</title>

<style>

body {
    margin: 0;
    background: #0f1115;
    color: #f1f1f1;
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
    padding: 30px;
}

.card {
    max-width: 800px;
    margin: auto;
    background: #171a21;
    border: 1px solid #282c35;
    border-radius: 12px;
    padding: 24px;
}

h1 {
    margin-top: 0;
}

.row {
    display: flex;
    justify-content: space-between;
    gap: 20px;
    padding: 14px 0;
    border-bottom: 1px solid #282c35;
}

.label {
    color: #888;
}

.value {
    font-family: monospace;
    text-align: right;
}

a {
    color: white;
}

.download {
    color: #8fc7ff;
}

.upload {
    color: #d0a7ff;
}

.activity {
    font-family: monospace;
}

</style>

</head>

<body>

<div class="card">

    <p>
        <a href="/">
            ← Back to Dashboard
        </a>
    </p>


    <h1>
        {{ device.hostname }}
    </h1>


    <div class="row">

        <span class="label">
            Device Type
        </span>

        <span class="value">
            {{ device.device_type or "Unknown" }}
        </span>

    </div>


    <div class="row">

        <span class="label">
            Operating System
        </span>

        <span class="value">
            {{ device.os or "Unknown" }}
        </span>

    </div>


    <div class="row">

        <span class="label">
            IP Address
        </span>

        <span class="value">
            {{ device.ip }}
        </span>

    </div>


    <div class="row">

        <span class="label">
            MAC Address
        </span>

        <span class="value">
            {{ device.mac or "Unknown" }}
        </span>

    </div>


    <div class="row">

        <span class="label">
            Interface
        </span>

        <span class="value">
            {{ device.interface }}
        </span>

    </div>


    <div class="row">

        <span class="label">
            Connection State
        </span>

        <span class="value">
            {{ device.state or "Unknown" }}
        </span>

    </div>


    <div class="row">

        <span class="label">
            Connection
        </span>

        <span class="value">

            {% if device.connected %}

                Online

            {% else %}

                Offline

            {% endif %}

        </span>

    </div>


    <div class="row">

        <span class="label">
            Activity
        </span>

        <span class="value activity">
            {{ device.activity or "N/A" }}
        </span>

    </div>


    <div class="row">

        <span class="label">
            Connected Since
        </span>

        <span class="value">
            {{ device.connected_since_text }}
        </span>

    </div>


    <div class="row">

        <span class="label">
            Connected Duration
        </span>

        <span class="value">
            {{ device.connected_duration }}
        </span>

    </div>


    <div class="row">

        <span class="label">
            DHCP Lease Remaining
        </span>

        <span class="value">
            {{ device.lease_remaining }}
        </span>

    </div>


    <div class="row">

        <span class="label">
            Download
        </span>

        <span class="value download">
            ↓ {{ device.download_human }}
        </span>

    </div>


    <div class="row">

        <span class="label">
            Upload
        </span>

        <span class="value upload">
            ↑ {{ device.upload_human }}
        </span>

    </div>


    <br>


    <p style="color:#777;">

        Traffic totals are collected from nftables
        per-device counters.

        Activity is determined by changes in the
        traffic counters between dashboard refreshes.

        Device type and operating system detection
        are best-effort and may show Unknown when the
        client does not identify itself through DHCP.

    </p>


</div>

</body>

</html>
"""


# ============================================================
# Routes
# ============================================================

@app.route("/")
def dashboard():

    return render_template_string(
        DASHBOARD_TEMPLATE
    )


@app.route("/api/dashboard")
def dashboard_api():

    try:

        return jsonify(
            get_dashboard_data()
        )

    except Exception as exc:

        return jsonify(
            {
                "error": str(exc)
            }
        ), 500
# ============================================================
# Network Topology
# ============================================================

@app.route("/topology")
def topology_page():

    topology = topology_tree.get_topology()

    return render_template_string(
        """
        <!DOCTYPE html>
        <html>

        <head>

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <title>Network Topology - PiServer</title>

        <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: #0b0e12;
            color: #f3f4f6;
            font-family:
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;
            padding: 30px;
        }

        .page {
            max-width: 1200px;
            margin: auto;
        }

        .header {
            margin-bottom: 24px;
        }

        .header h1 {
            margin: 0;
            font-size: 28px;
        }

        .header-sub {
            color: #7f8793;
            font-size: 13px;
            margin-top: 5px;
        }

        .back {
            display: inline-block;
            color: #fff;
            text-decoration: none;
            margin-bottom: 20px;
        }

        .back:hover {
            text-decoration: underline;
        }

        .card {
            background: #12161c;
            border: 1px solid #252b34;
            border-radius: 12px;
            padding: 22px;
        }

        .summary {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 24px;
        }

        .summary-item {
            background: #171c23;
            border: 1px solid #252b34;
            border-radius: 8px;
            padding: 10px 14px;
            color: #9da5b1;
            font-size: 12px;
        }

        .summary-item strong {
            color: #f3f4f6;
        }

        .tree,
        .tree ul {
            list-style: none;
            margin: 0;
            padding: 0;
        }

        .tree ul {
            margin-left: 24px;
            padding-left: 24px;
            border-left: 1px solid #343b46;
        }

        .tree-node {
            position: relative;
            margin: 10px 0;
        }

        .tree-node::before {
            content: "";
            position: absolute;
            left: -24px;
            top: 27px;
            width: 24px;
            border-top: 1px solid #343b46;
        }

        .tree > .tree-node::before {
            display: none;
        }

        .node-card {
            background: #171c23;
            border: 1px solid #292f39;
            border-radius: 10px;
            padding: 13px 15px;
        }

        .node-title {
            display: flex;
            align-items: center;
            gap: 9px;
            font-size: 14px;
            font-weight: 600;
        }

        .node-details {
            margin-top: 5px;
            color: #727b88;
            font-family: monospace;
            font-size: 12px;
        }

        .node-status {
            margin-left: auto;
            color: #65d985;
            font-size: 11px;
            font-weight: 500;
        }

        .node-status.offline {
            color: #d96868;
        }

        .node-icon {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #7aa2f7;
            flex-shrink: 0;
        }

        .node-icon.offline {
            background: #d96868;
        }

        .empty {
            color: #727b88;
            font-size: 13px;
            padding: 10px 0;
        }

        </style>

        </head>

        <body>

        <div class="page">

            <a class="back" href="/">
                ← Dashboard
            </a>

            <div class="header">
                <h1>Network Topology</h1>
                <div class="header-sub">
                    Current gateway and LAN device layout
                </div>
            </div>

            <div class="summary">

                <div class="summary-item">
                    WAN:
                    <strong>
                        {{ topology.metadata.wan_interface }}
                    </strong>
                    —
                    <strong>
                        {{ topology.metadata.wan_ip or "N/A" }}
                    </strong>
                </div>

                <div class="summary-item">
                    LAN:
                    <strong>
                        {{ topology.metadata.lan_interface }}
                    </strong>
                    —
                    <strong>
                        {{ topology.metadata.lan_ip }}
                    </strong>
                </div>

                <div class="summary-item">
                    Clients:
                    <strong>
                        {{ topology.metadata.client_count }}
                    </strong>
                </div>

                {% if topology.metadata.wireguard_present %}
                <div class="summary-item">
                    WireGuard:
                    <strong>
                        {{ "Active" if topology.metadata.wireguard_active else "Inactive" }}
                    </strong>
                </div>
                {% endif %}

            </div>

            <div class="card">

                {% macro render_node(node, root=false) %}

                <li class="tree-node">

                    <div class="node-card">

                        <div class="node-title">

                            <span
                                class="node-icon
                                {% if node.status in ['Offline', 'Inactive'] %}
                                    offline
                                {% endif %}"
                            ></span>

                            <span>
                                {{ node.label }}
                            </span>

                            <span
                                class="node-status
                                {% if node.status in ['Offline', 'Inactive'] %}
                                    offline
                                {% endif %}"
                            >
                                {{ node.status }}
                            </span>

                        </div>

                        {% if node.details %}
                        <div class="node-details">
                            {{ node.details }}
                        </div>
                        {% endif %}

                    </div>

                    {% if node.children %}

                    <ul>

                        {% for child in node.children %}
                            {{ render_node(child) }}
                        {% endfor %}

                    </ul>

                    {% endif %}

                </li>

                {% endmacro %}


                <ul class="tree">

                    {{ render_node(topology, true) }}

                </ul>

                {% if topology.metadata.client_count == 0 %}
                <div class="empty">
                    No LAN clients are currently visible.
                </div>
                {% endif %}

            </div>

        </div>

        </body>
        </html>
        """,
        topology=topology,
    )

# ============================================================
# Device Health
# ============================================================

@app.route("/health")
def device_health_page():

    return render_template_string(
        """
        <!DOCTYPE html>
        <html>

        <head>

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <title>
            Device Health - PiHarbor
        </title>

        <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: #0b0e12;
            color: #f3f4f6;
            font-family:
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;
        }

        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            bottom: 0;
            width: 220px;
            background: #12161c;
            border-right: 1px solid #252b34;
            padding: 24px 16px;
        }

        .logo {
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 30px;
        }

        .logo span {
            display: block;
            margin-top: 4px;
            color: #7f8793;
            font-size: 13px;
        }

        .nav a {
            display: block;
            padding: 11px 13px;
            margin-bottom: 5px;
            border-radius: 8px;
            color: #aeb5bf;
            text-decoration: none;
        }

        .nav a:hover,
        .nav a.active {
            background: #222831;
            color: #fff;
        }

        .main {
            margin-left: 220px;
            padding: 30px;
            max-width: 1500px;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }

        .header h1 {
            margin: 0;
            font-size: 28px;
        }

        .header-sub {
            color: #7f8793;
            font-size: 13px;
            margin-top: 5px;
        }

        .card {
            background: #12161c;
            border: 1px solid #252b34;
            border-radius: 12px;
            padding: 18px;
        }

        .grid {
            display: grid;
            grid-template-columns:
                repeat(4, minmax(180px, 1fr));
            gap: 14px;
        }

        .card h3 {
            margin: 0 0 8px;
            color: #8f98a5;
            font-size: 13px;
            font-weight: 500;
        }

        .metric {
            font-size: 27px;
            font-weight: 700;
            letter-spacing: -0.4px;
        }

        .sub {
            color: #737c89;
            font-size: 12px;
            margin-top: 5px;
        }

        .progress {
            height: 5px;
            background: #252b34;
            border-radius: 99px;
            overflow: hidden;
            margin-top: 12px;
        }

        .progress > div {
            height: 100%;
            width: 0;
            background: #7aa2f7;
            transition: width .25s ease;
        }

        .health-status {
            margin-top: 14px;
            padding: 14px 16px;
            background: #151a21;
            border: 1px solid #252b34;
            border-radius: 10px;
            color: #8f98a5;
            font-size: 13px;
        }

        @media (max-width: 1050px) {

            .grid {
                grid-template-columns:
                    repeat(2, 1fr);
            }

        }

        @media (max-width: 800px) {

            .sidebar {
                position: static;
                width: 100%;
                height: auto;
            }

            .main {
                margin-left: 0;
                padding: 16px;
            }

            .grid {
                grid-template-columns: 1fr;
            }

        }

        </style>

        </head>

        <body>

        <div class="sidebar">

            <div class="logo">

                PiHarbor

                <span>
                    Network Gateway
                </span>

            </div>

            <div class="nav">

                <a href="/">
                    Dashboard
                </a>

                <a
                    href="/health"
                    class="active"
                >
                    Device Health
                </a>

                <a href="/network">
                    Network
                </a>

                <a href="/dns">
                    DNS
                </a>

            </div>

        </div>


        <div class="main">

            <div class="header">

                <div>

                    <h1>
                        Device Health
                    </h1>

                    <div class="header-sub">
                        Raspberry Pi system health
                        and resources
                    </div>

                </div>

            </div>


            <div class="grid">

                <div class="card">

                    <h3>
                        CPU Usage
                    </h3>

                    <div
                        class="metric"
                        id="cpu"
                    >
                        --
                    </div>

                    <div class="progress">

                        <div id="cpu-bar"></div>

                    </div>

                    <div class="sub">
                        Processor utilization
                    </div>

                </div>


                <div class="card">

                    <h3>
                        Memory
                    </h3>

                    <div
                        class="metric"
                        id="memory"
                    >
                        --
                    </div>

                    <div class="progress">

                        <div id="memory-bar"></div>

                    </div>

                    <div class="sub">
                        RAM utilization
                    </div>

                </div>


                <div class="card">

                    <h3>
                        Temperature
                    </h3>

                    <div
                        class="metric"
                        id="temperature"
                    >
                        --
                    </div>

                    <div class="sub">
                        CPU temperature
                    </div>

                </div>


                <div class="card">

                    <h3>
                        Storage
                    </h3>

                    <div
                        class="metric"
                        id="storage"
                    >
                        --
                    </div>

                    <div class="progress">

                        <div id="storage-bar"></div>

                    </div>

                    <div class="sub">
                        Root filesystem usage
                    </div>

                </div>

            </div>


            <div class="health-status">

                Uptime:

                <strong id="uptime">
                    --
                </strong>

                <span style="margin-left:20px;">

                    Last updated:

                    <strong id="updated">
                        --
                    </strong>

                </span>

            </div>

        </div>


        <script>

        function setProgress(id, value) {

            const bar =
                document.getElementById(id);

            if (!bar) {
                return;
            }

            const numeric =
                Number(value);

            if (!Number.isFinite(numeric)) {

                bar.style.width =
                    "0%";

                return;

            }

            bar.style.width =
                Math.max(
                    0,
                    Math.min(
                        100,
                        numeric
                    )
                ) + "%";

        }


        async function refreshHealth() {

            try {

                const response =
                    await fetch(
                        "/api/dashboard",
                        {
                            cache: "no-store"
                        }
                    );


                if (!response.ok) {

                    throw new Error(
                        "Health request failed"
                    );

                }


                const data =
                    await response.json();


                const system =
                    data.system || {};


                const cpu =
                    system.cpu_usage;

                const memory =
                    system.memory_usage;

                const storage =
                    system.storage_usage;


                document.getElementById(
                    "cpu"
                ).textContent =

                    cpu !== null &&
                    cpu !== undefined

                        ? cpu + "%"

                        : "N/A";


                document.getElementById(
                    "memory"
                ).textContent =

                    memory !== null &&
                    memory !== undefined

                        ? memory + "%"

                        : "N/A";


                document.getElementById(
                    "temperature"
                ).textContent =

                    system.temperature !== null &&
                    system.temperature !== undefined

                        ? system.temperature + "°C"

                        : "N/A";


                document.getElementById(
                    "storage"
                ).textContent =

                    storage !== null &&
                    storage !== undefined

                        ? storage + "%"

                        : "N/A";


                document.getElementById(
                    "uptime"
                ).textContent =
                    system.uptime_text ||
                    "Unknown";


                document.getElementById(
                    "updated"
                ).textContent =
                    new Date().toLocaleTimeString();


                setProgress(
                    "cpu-bar",
                    cpu
                );

                setProgress(
                    "memory-bar",
                    memory
                );

                setProgress(
                    "storage-bar",
                    storage
                );


            } catch (error) {

                console.error(
                    "Device health refresh failed:",
                    error
                );

            }

        }


        refreshHealth();

        setInterval(
            refreshHealth,
            3000
        );

        </script>

        </body>

        </html>
        """
    )


# ============================================================
# Device Details Route
# ============================================================

@app.route("/device/<ip>")
def device_details(ip):

    try:

        ipaddress.ip_address(ip)

    except ValueError:

        return (
            "Invalid IP address",
            400,
        )


    devices = (
        get_connected_devices()
    )


    device = None


    for candidate in devices:

        if candidate.get("ip") == ip:

            device = candidate
            break


    if device is None:

        device = {

            "hostname": "Unknown",

            "ip": ip,

            "mac": None,

            "interface":
                get_network_config().get(
                    "lan_interface",
                    "wlan0",
                ),

            "state": "unknown",

            "connected": False,

            "device_type": "Unknown",

            "os": "Unknown",

            "activity": "N/A",

            "lease_remaining": "N/A",

            "connected_since_text": "N/A",

            "connected_duration": "N/A",

            "download_human": "N/A",

            "upload_human": "N/A",

            "expiry_text": "N/A",

        }


    return render_template_string(
        DEVICE_TEMPLATE,
        device=device,
    )


# ============================================================
# Network Page
# ============================================================

@app.route(
    "/network",
    methods=["GET", "POST"],
)
def network_page():

    if request.method == "POST":

        action = request.form.get(
            "nat_action"
        )

        try:

            if action == "enable":

                enable_nat()

            elif action == "disable":

                disable_nat()

        except Exception as exc:

            return (
                f"NAT operation failed: {exc}",
                500,
            )

        return redirect(
            url_for("network_page")
        )


    network = get_network_config()


    wan_interface = network.get(
        "wan_interface",
        "eth0",
    )


    lan_interface = network.get(
        "lan_interface",
        "wlan0",
    )


    wan = monitoring.get_interface_health(
        wan_interface
    )


    lan = monitoring.get_interface_health(
        lan_interface
    )


    nat = nat_backend.get_nat_status()


    return render_template_string(
        """
        <!DOCTYPE html>

        <html>

        <head>

        <meta
            name="viewport"
            content="width=device-width"
        >

        <title>
            Network - PiHarbor
        </title>

        <style>

        body {
            background:#0f1115;
            color:#f1f1f1;
            font-family:Arial,sans-serif;
            padding:30px;
        }

        .card {
            background:#171a21;
            border:1px solid #282c35;
            border-radius:12px;
            padding:20px;
            margin-bottom:20px;
        }

        a {
            color:white;
        }

        button {
            padding:9px 14px;
            background:#252a34;
            color:white;
            border:1px solid #3a404c;
            border-radius:7px;
        }

        </style>

        </head>

        <body>

        <p>

            <a href="/">
                ← Dashboard
            </a>

        </p>


        <h1>
            Network
        </h1>


        <div class="card">

            <h2>
                WAN
            </h2>

            <p>
                Interface:
                {{ wan.interface }}
            </p>

            <p>
                IP:
                {{ wan.ip or "N/A" }}
            </p>

            <p>
                State:
                {{ wan.state }}
            </p>

        </div>


        <div class="card">

            <h2>
                LAN
            </h2>

            <p>
                Interface:
                {{ lan.interface }}
            </p>

            <p>
                IP:
                {{ lan.ip or "N/A" }}
            </p>

            <p>
                State:
                {{ lan.state }}
            </p>

        </div>


        <div class="card">

            <h2>
                NAT
            </h2>

            <p>

                Status:

                {% if nat.enabled %}
                    Enabled
                {% else %}
                    Disabled
                {% endif %}

            </p>


            <form method="post">

                {% if nat.enabled %}

                    <button
                        name="nat_action"
                        value="disable"
                    >
                        Disable NAT
                    </button>

                {% else %}

                    <button
                        name="nat_action"
                        value="enable"
                    >
                        Enable NAT
                    </button>

                {% endif %}

            </form>

        </div>

        </body>

        </html>
        """,

        wan=wan,
        lan=lan,
        nat=nat,
    )


# ============================================================
# DHCP
# ============================================================

@app.route("/dhcp")
def dhcp_page():

    return simple_page(
        "DHCP",
        "DHCP configuration and lease management."
    )


# ============================================================
# DNS / Ad Blocking Page
# ============================================================

@app.route(
    "/dns",
    methods=["GET", "POST"],
)
def dns_page():

    message = None
    message_type = None


    if request.method == "POST":

        action = request.form.get(
            "adblock_action"
        )


        custom_action = request.form.get(
            "custom_action"
        )


        try:

            # ------------------------------------------------
            # Custom blocklist actions
            # ------------------------------------------------

            if custom_action == "add":

                domain = request.form.get(
                    "domain",
                    "",
                )


                result = (
                    add_custom_blocked_domain(
                        domain
                    )
                )


                message = result.get(
                    "message",
                    "Custom domain operation completed.",
                )


                message_type = (
                    "success"
                    if result.get("success")
                    else "error"
                )


            elif custom_action == "remove":

                domain = request.form.get(
                    "domain",
                    "",
                )


                result = (
                    remove_custom_blocked_domain(
                        domain
                    )
                )


                message = result.get(
                    "message",
                    "Custom domain operation completed.",
                )


                message_type = (
                    "success"
                    if result.get("success")
                    else "error"
                )


            # ------------------------------------------------
            # Built-in blocklist actions
            # ------------------------------------------------

            elif action == "update":

                result = update_adblock()


                message = result.get(
                    "message",
                    "Blocklist update completed.",
                )


                message_type = (
                    "success"
                    if result.get("success")
                    else "error"
                )


            elif action == "enable":

                success = enable_adblock()


                message = (

                    "Ad blocking enabled."

                    if success

                    else

                    "Failed to enable ad blocking."

                )


                message_type = (
                    "success"
                    if success
                    else "error"
                )


            elif action == "disable":

                success = disable_adblock()


                message = (

                    "Ad blocking disabled."

                    if success

                    else

                    "Failed to disable ad blocking."

                )


                message_type = (
                    "success"
                    if success
                    else "error"
                )


        except Exception as exc:

            message = (
                f"Ad blocking operation failed: {exc}"
            )

            message_type = "error"


    status = get_adblock_status()


    custom_domains = (
        get_custom_blocked_domains()
    )


    dns_health = None


    if dns_backend is not None:

        try:

            dns_health = (
                dns_backend.get_dns_health()
            )

        except Exception:

            dns_health = None


    return render_template_string(
        """
        <!DOCTYPE html>

        <html>

        <head>

        <meta
            name="viewport"
            content="width=device-width"
        >

        <title>
            DNS - PiHarbor
        </title>

        <style>

        body {
            background:#0f1115;
            color:#f1f1f1;
            font-family:Arial,sans-serif;
            padding:30px;
        }

        .card {
            background:#171a21;
            border:1px solid #282c35;
            border-radius:12px;
            padding:20px;
            max-width:900px;
            margin-bottom:20px;
        }

        a {
            color:white;
        }

        .status {
            font-size:24px;
            font-weight:bold;
        }

        .active {
            color:#65d985;
        }

        .inactive {
            color:#d96868;
        }

        .button {
            padding:9px 14px;
            background:#252a34;
            color:white;
            border:1px solid #3a404c;
            border-radius:7px;
            cursor:pointer;
            margin-right:8px;
        }

        .button:hover {
            background:#303642;
        }

        .message {
            padding:12px;
            border-radius:8px;
            margin-bottom:20px;
            background:#252a34;
        }

        .message.success {
            border:1px solid #3b7650;
        }

        .message.error {
            border:1px solid #7a4141;
        }

        .row {
            padding:12px 0;
            border-bottom:1px solid #282c35;
        }

        .row:last-child {
            border-bottom:none;
        }

        .value {
            float:right;
            font-weight:600;
        }

        .custom-domain-form {
            display:flex;
            gap:10px;
            margin-bottom:20px;
        }

        .domain-input {
            flex:1;
            padding:10px;
            background:#0f1115;
            color:white;
            border:1px solid #3a404c;
            border-radius:7px;
            min-width:0;
        }

        .custom-domain {
            display:flex;
            justify-content:space-between;
            align-items:center;
            gap:10px;
            padding:12px 0;
            border-bottom:1px solid #282c35;
        }

        .custom-domain:last-child {
            border-bottom:none;
        }

        .domain-name {
            word-break:break-all;
        }

        .remove-form {
            margin:0;
        }

        @media (max-width:600px) {

            .custom-domain-form {
                flex-direction:column;
            }

        }

        </style>

        </head>

        <body>

        <p>

            <a href="/">
                ← Dashboard
            </a>

        </p>


        <h1>
            DNS
        </h1>


        {% if message %}

            <div class="message {{ message_type }}">
                {{ message }}
            </div>

        {% endif %}


        <!-- DNS STATUS -->

        <div class="card">

            <h2>
                DNS Service
            </h2>


            {% if dns_health %}

                <div class="row">

                    Status

                    <span class="value">
                        {{ dns_health.status }}
                    </span>

                </div>


                <div class="row">

                    Connectivity

                    <span class="value">
                        {{ dns_health.connectivity }}
                    </span>

                </div>


                <div class="row">

                    Upstream Servers

                    <span class="value">

                        {% for server in dns_health.upstream_servers %}

                            {{ server }}{% if not loop.last %}, {% endif %}

                        {% endfor %}

                    </span>

                </div>


                <div class="row">

                    DNS Latency

                    <span class="value">

                        {% if dns_health.latency_ms is not none %}

                            {{ dns_health.latency_ms }} ms

                        {% else %}

                            N/A

                        {% endif %}

                    </span>

                </div>


            {% else %}

                <p>
                    DNS health information unavailable.
                </p>

            {% endif %}

        </div>


        <!-- AD BLOCKING -->

        <div class="card">

            <h2>
                Ad Blocking
            </h2>


            <div class="row">

                Status

                {% if status.enabled %}

                    <span class="value active">
                        Enabled
                    </span>

                {% else %}

                    <span class="value inactive">
                        Disabled
                    </span>

                {% endif %}

            </div>


            <div class="row">

                Blocked Domains

                <span class="value">
                    {{ status.blocked_domains }}
                </span>

            </div>


            <div class="row">

                Last Updated

                <span class="value">

                    {% if status.last_update %}

                        {{ status.last_update }}

                    {% else %}

                        Never

                    {% endif %}

                </span>

            </div>


            <br>


            <form method="post">

                {% if status.enabled %}

                    <button
                        class="button"
                        name="adblock_action"
                        value="disable"
                    >
                        Disable Ad Blocking
                    </button>

                {% else %}

                    <button
                        class="button"
                        name="adblock_action"
                        value="enable"
                    >
                        Enable Ad Blocking
                    </button>

                {% endif %}


                <button
                    class="button"
                    name="adblock_action"
                    value="update"
                >
                    Update Blocklist
                </button>

            </form>

        </div>


        <!-- CUSTOM BLOCKLIST -->

        <div class="card">

            <h2>
                Custom Blocklist
            </h2>


            <p style="color:#888;">

                Add your own domains to block.
                You can enter a domain or paste a URL.

            </p>


            <form method="post">

                <div class="custom-domain-form">

                    <input
                        class="domain-input"
                        type="text"
                        name="domain"
                        placeholder="example.com"
                        required
                    >


                    <button
                        class="button"
                        type="submit"
                        name="custom_action"
                        value="add"
                    >
                        Block Domain
                    </button>

                </div>

            </form>


            <h3>
                Custom Blocked Domains
            </h3>


            {% if custom_domains %}

                {% for domain in custom_domains %}

                    <div class="custom-domain">

                        <span class="domain-name">
                            {{ domain }}
                        </span>


                        <form
                            method="post"
                            class="remove-form"
                        >

                            <input
                                type="hidden"
                                name="domain"
                                value="{{ domain }}"
                            >


                            <button
                                class="button"
                                type="submit"
                                name="custom_action"
                                value="remove"
                            >
                                Remove
                            </button>

                        </form>

                    </div>

                {% endfor %}


            {% else %}

                <p style="color:#777;">
                    No custom domains are blocked.
                </p>

            {% endif %}

        </div>


        </body>

        </html>
        """,

        status=status,
        dns_health=dns_health,
        message=message,
        message_type=message_type,
        custom_domains=custom_domains,
    )


# ============================================================
# Firewall
# ============================================================

@app.route("/firewall")
def firewall_page():

    return simple_page(
        "Firewall",
        "PiHarbor nftables firewall controls."
    )


# ============================================================
# VPN
# ============================================================

@app.route("/vpn")
def vpn_page():

    return simple_page(
        "VPN",
        "WireGuard VPN configuration and status."
    )


# ============================================================
# Monitoring
# ============================================================

@app.route("/monitoring")
def monitoring_page():

    data = monitoring.get_dashboard_metrics()


    return render_template_string(
        """
        <!DOCTYPE html>

        <html>

        <head>

        <meta
            name="viewport"
            content="width=device-width"
        >

        <title>
            Monitoring - PiHarbor
        </title>

        <style>

        body {
            background:#0f1115;
            color:#f1f1f1;
            font-family:Arial,sans-serif;
            padding:30px;
        }

        .card {
            background:#171a21;
            border:1px solid #282c35;
            border-radius:12px;
            padding:20px;
            margin-bottom:20px;
        }

        a {
            color:white;
        }

        </style>

        </head>

        <body>

        <p>

            <a href="/">
                ← Dashboard
            </a>

        </p>


        <h1>
            Monitoring
        </h1>


        <div class="card">

            <h2>
                System
            </h2>


            <p>
                CPU:
                {{ data.system.cpu_usage }}%
            </p>


            <p>
                Memory:
                {{ data.system.memory_usage }}%
            </p>


            <p>
                Temperature:
                {{ data.system.temperature }}°C
            </p>


            <p>
                Storage:
                {{ data.system.storage_usage }}%
            </p>


            <p>
                Uptime:
                {{ data.system.uptime_text }}
            </p>

        </div>


        <div class="card">

            <h2>
                Network
            </h2>


            <p>
                Internet:
                {{ data.network.internet }}
            </p>


            <p>
                TCP connections:
                {{ data.network.connections }}
            </p>


            <p>
                Default route:
                {{ data.network.default_route }}
            </p>

        </div>


        </body>

        </html>
        """,

        data=data,
    )


# ============================================================
# Logs
# ============================================================

@app.route("/logs")
def logs_page():

    logs = []


    if gateway_logging is not None:

        try:

            if hasattr(
                gateway_logging,
                "get_recent_logs",
            ):

                logs = (
                    gateway_logging
                    .get_recent_logs()
                )

        except Exception:

            logs = []


    return render_template_string(
        """
        <!DOCTYPE html>

        <html>

        <head>

        <meta
            name="viewport"
            content="width=device-width"
        >

        <title>
            Logs - PiHarbor
        </title>

        <style>

        body {
            background:#0f1115;
            color:#f1f1f1;
            font-family:Arial,sans-serif;
            padding:30px;
        }

        .card {
            background:#171a21;
            border:1px solid #282c35;
            border-radius:12px;
            padding:20px;
        }

        pre {
            white-space:pre-wrap;
            word-break:break-word;
        }

        a {
            color:white;
        }

        </style>

        </head>

        <body>

        <p>

            <a href="/">
                ← Dashboard
            </a>

        </p>


        <h1>
            Logs
        </h1>


        <div class="card">

            {% if logs %}

                <pre>{{ logs }}</pre>

            {% else %}

                <p>
                    No recent logs available.
                </p>

            {% endif %}

        </div>


        </body>

        </html>
        """,

        logs=logs,
    )


# ============================================================
# Shared Simple Page
# ============================================================

def simple_page(title, description):
    """
    Render a simple module page.
    """

    return render_template_string(
        """
        <!DOCTYPE html>

        <html>

        <head>

        <meta
            name="viewport"
            content="width=device-width"
        >

        <title>
            {{ title }} - PiHarbor
        </title>

        <style>

        body {
            background:#0f1115;
            color:#f1f1f1;
            font-family:Arial,sans-serif;
            padding:30px;
        }

        .card {
            background:#171a21;
            border:1px solid #282c35;
            border-radius:12px;
            padding:20px;
            max-width:900px;
        }

        a {
            color:white;
        }

        </style>

        </head>

        <body>

        <p>

            <a href="/">
                ← Dashboard
            </a>

        </p>


        <div class="card">

            <h1>
                {{ title }}
            </h1>


            <p>
                {{ description }}
            </p>

        </div>


        </body>

        </html>
        """,

        title=title,
        description=description,
    )
