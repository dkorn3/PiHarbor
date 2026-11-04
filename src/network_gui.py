from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    url_for,
)
from datetime import datetime
import ipaddress
import os
import subprocess
import threading
import time

import config as gateway_config
import metrics_history
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
# Logo
# ============================================================

SRC_DIR = os.path.dirname(os.path.abspath(__file__))

# The logo lives in the piharbor directory, one level above src/.
PROJECT_DIR = os.path.abspath(
    os.path.join(SRC_DIR, "..")
)


def find_logo_path():
    """
    Find the PiHarbor logo PNG in the project directory
    (falls back to src/).
    """

    for folder in (PROJECT_DIR, SRC_DIR):

        try:
            names = sorted(os.listdir(folder))
        except OSError:
            continue

        matches = [
            name
            for name in names
            if name.lower().endswith(".png")
            and (
                "logo" in name.lower()
                or "piharbor" in name.lower()
            )
        ]

        # Prefer files that mention both piharbor and logo.
        matches.sort(
            key=lambda name: (
                "piharbor" not in name.lower(),
                "logo" not in name.lower(),
            )
        )

        if matches:
            return os.path.join(folder, matches[0])

    return None


@app.route("/logo.png")
def logo():

    path = find_logo_path()

    if path is None:
        abort(404)

    return send_file(
        path,
        mimetype="image/png",
        max_age=3600,
    )


# ============================================================
# 24-Hour History (throughput + packet loss)
# ============================================================

def _history_settings():
    """
    WAN interface and ping target for the history sampler.

    Add "ping_target" to the "network" section of the config
    to change the packet-loss target (default 1.1.1.1).
    """

    network = get_network_config()

    return (
        network.get("wan_interface", "eth0"),
        network.get("ping_target", "1.1.1.1"),
    )


metrics_history.start(_history_settings)


@app.route("/api/history")
def history_api():

    return jsonify(
        {
            "interface": _history_settings()[0],
            "interval": metrics_history.SAMPLE_INTERVAL,
            "points": metrics_history.get_history(hours=24),
        }
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
# Device Health / Interface Link Metrics
# ============================================================

def read_int_file(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return int(file.read().strip())
    except (OSError, ValueError):
        return None


def get_interface_link_metrics(interface):
    """Return negotiated link details and interface error counters."""
    base = os.path.join("/sys/class/net", interface)
    if not os.path.exists(base):
        return {
            "interface": interface,
            "state": "Unavailable",
            "speed_mbps": None,
            "duplex": "N/A",
            "tx_bitrate": None,
            "rx_bitrate": None,
            "clients": 0,
            "rx_errors": None,
            "tx_errors": None,
            "rx_dropped": None,
            "tx_dropped": None,
        }

    state_path = os.path.join(base, "operstate")
    try:
        with open(state_path, "r", encoding="utf-8") as file:
            state = file.read().strip().capitalize()
    except OSError:
        state = "Unknown"

    speed = read_int_file(os.path.join(base, "speed"))
    if speed is not None and speed < 0:
        speed = None

    try:
        with open(os.path.join(base, "duplex"), "r", encoding="utf-8") as file:
            duplex = file.read().strip().capitalize()
    except OSError:
        duplex = "N/A"

    # Wi-Fi interfaces in AP mode have per-client PHY rates, not one
    # meaningful negotiated rate for the entire interface.
    tx_rates = []
    rx_rates = []
    client_count = 0
    if command_exists("iw"):
        result = run_command(["iw", "dev", interface, "station", "dump"], timeout=4)
        if result is not None:
            current = {}
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("Station "):
                    if current:
                        tx_rates.append(current.get("tx"))
                        rx_rates.append(current.get("rx"))
                    current = {}
                    client_count += 1
                elif stripped.lower().startswith("tx bitrate:"):
                    current["tx"] = stripped.split(":", 1)[1].strip()
                elif stripped.lower().startswith("rx bitrate:"):
                    current["rx"] = stripped.split(":", 1)[1].strip()
            if current:
                tx_rates.append(current.get("tx"))
                rx_rates.append(current.get("rx"))

    stats = {}
    for key in ("rx_errors", "tx_errors", "rx_dropped", "tx_dropped"):
        stats[key] = read_int_file(os.path.join(base, "statistics", key))

    return {
        "interface": interface,
        "state": state,
        "speed_mbps": speed,
        "duplex": duplex,
        "tx_bitrate": [rate for rate in tx_rates if rate],
        "rx_bitrate": [rate for rate in rx_rates if rate],
        "clients": client_count,
        **stats,
    }


def get_device_health_details():
    """Collect lightweight Raspberry Pi diagnostics without extra packages."""
    network = get_network_config()
    wan = network.get("wan_interface", "eth0")
    lan = network.get("lan_interface", "wlan0")

    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as file:
            load = file.read().split()
            load_average = load[:3]
    except (OSError, IndexError):
        load_average = []

    cpu_frequency = read_int_file(
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"
    )
    if cpu_frequency is not None:
        cpu_frequency = round(cpu_frequency / 1000)

    meminfo = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as file:
            for line in file:
                key, value = line.split(":", 1)
                meminfo[key] = int(value.strip().split()[0])
    except (OSError, ValueError, IndexError):
        pass

    swap_total = meminfo.get("SwapTotal", 0)
    swap_free = meminfo.get("SwapFree", 0)
    swap_used_pct = (
        round((swap_total - swap_free) / swap_total * 100, 1)
        if swap_total else 0
    )

    throttling = "Unavailable"
    throttling_raw = None
    if command_exists("vcgencmd"):
        result = run_command(["vcgencmd", "get_throttled"], timeout=3)
        if result is not None:
            throttling_raw = result.stdout.strip()
            match = re.search(r"0x([0-9a-fA-F]+)", throttling_raw)
            if match:
                flags = int(match.group(1), 16)
                throttling = "No flags" if flags == 0 else "Warning flags present"

    failed_services = None
    if command_exists("systemctl"):
        result = run_command(
            ["systemctl", "--failed", "--no-legend", "--plain"], timeout=5
        )
        if result is not None:
            failed_services = len([
                line for line in result.stdout.splitlines() if line.strip()
            ])

    return {
        "cpu_frequency_mhz": cpu_frequency,
        "load_average": load_average,
        "swap_used_percent": swap_used_pct,
        "swap_total_kb": swap_total,
        "throttling": throttling,
        "throttling_raw": throttling_raw,
        "failed_services": failed_services,
        "wan_link": get_interface_link_metrics(wan),
        "lan_link": get_interface_link_metrics(lan),
    }


@app.route("/api/health-details")
def health_details_api():
    return jsonify(get_device_health_details())


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

<link rel="icon" type="image/png" href="/logo.png">

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
    margin-bottom: 30px;
}

.logo img {
    display: block;
    width: 150px;
    height: 150px;
    object-fit: cover;
    border-radius: 50%;
    margin: 0 auto 8px;
}

.logo-text {
    display: none;
    font-size: 24px;
    font-weight: 700;
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
        repeat(3, minmax(180px, 1fr));
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

.chart-grid {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 14px;
    margin-bottom: 14px;
}

.chart-legend {
    display: flex;
    gap: 16px;
    margin-bottom: 8px;
    color: #8f98a5;
    font-size: 12px;
}

.swatch {
    display: inline-block;
    width: 10px;
    height: 10px;
    margin-right: 6px;
    border-radius: 2px;
}

.chart-readout {
    min-height: 18px;
    margin-bottom: 6px;
    color: #8f98a5;
    font-family: monospace;
    font-size: 12px;
}

.chart-canvas {
    display: block;
    width: 100%;
    height: 220px;
    touch-action: pan-y;
}

@media (max-width: 1050px) {

    .chart-grid {
        grid-template-columns: 1fr;
    }
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

/* Network address overview */
.address-section {
    margin: 0 0 18px;
    padding: 20px;
    background: linear-gradient(135deg, #141b24 0%, #10151c 100%);
    border: 1px solid #293342;
    border-radius: 16px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, .16);
}

.address-section-heading {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    margin-bottom: 16px;
}

.address-section-heading h2 {
    margin: 0;
    font-size: 17px;
    font-weight: 650;
    letter-spacing: -.02em;
}

.address-section-heading p {
    margin: 5px 0 0;
    color: #8793a3;
    font-size: 12px;
}

.address-live {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 6px 10px;
    border: 1px solid #2b473c;
    border-radius: 999px;
    color: #9ddbb5;
    background: rgba(43, 112, 75, .12);
    font-size: 11px;
    white-space: nowrap;
}

.live-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #5ed58b;
    box-shadow: 0 0 8px rgba(94, 213, 139, .5);
}

.ip-strip {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
}

.ip-item {
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 18px;
    border: 1px solid #2b3543;
    border-radius: 12px;
    background: rgba(8, 12, 18, .56);
}

.ip-icon {
    display: grid;
    place-items: center;
    flex: 0 0 44px;
    width: 44px;
    height: 44px;
    border-radius: 12px;
    font-size: 24px;
    font-weight: 600;
}

.wan-address .ip-icon {
    color: #8fc7ff;
    background: rgba(73, 145, 220, .15);
    border: 1px solid rgba(105, 174, 245, .2);
}

.lan-address .ip-icon {
    color: #b8a0ff;
    background: rgba(137, 102, 220, .15);
    border: 1px solid rgba(163, 132, 245, .2);
}

.ip-details {
    display: flex;
    flex-direction: column;
    min-width: 0;
    gap: 4px;
}

.ip-label {
    color: #e3e9f1;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: .06em;
}

.ip-label-sub {
    color: #8793a3;
    font-weight: 400;
    letter-spacing: 0;
}

.ip-value {
    color: #f7f9fc;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: clamp(17px, 2vw, 23px);
    font-weight: 650;
    letter-spacing: -.04em;
    overflow-wrap: anywhere;
    line-height: 1.35;
}

.ip-interface {
    color: #8793a3;
    font-size: 11px;
}

.ip-kind {
    margin-left: auto;
    align-self: flex-start;
    padding: 5px 7px;
    border-radius: 5px;
    color: #8fa0b4;
    background: #202936;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: .08em;
    white-space: nowrap;
}

@media (max-width: 800px) {
    .ip-strip { grid-template-columns: 1fr; }
    .address-section { padding: 15px; }
    .ip-item { padding: 15px; }
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
        <img
            src="/logo.png"
            alt="PiHarbor"
            onerror="this.style.display='none'; this.nextElementSibling.style.display='block';"
        >
        <div class="logo-text">PiHarbor</div>
     
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
        
        <a href="/dns">
            DNS
        </a>

    </div>

</div>

<div class="main">

    <div class="header">

        <div>

            <h1>Dashboard</h1>


        </div>
    </div>

    <!-- WAN / LAN ADDRESSES -->
    <section class="address-section" aria-label="Network addresses">
        <div class="address-section-heading">
            <div>
                <h2>Network Addresses</h2>
                <p>Your gateway's external and local network addresses</p>
            </div>
            <span class="address-live"><span class="live-dot"></span> Gateway info</span>
        </div>
        <div class="ip-strip">
            <div class="ip-item wan-address">
                <div class="ip-icon" aria-hidden="true">↗</div>
                <div class="ip-details">
                    <span class="ip-label">WAN <span class="ip-label-sub">· Internet</span></span>
                    <span class="ip-value" id="wan-ip">--</span>
                    <span class="ip-interface" id="wan-interface">External interface</span>
                </div>
                <span class="ip-kind">EXTERNAL</span>
            </div>
            <div class="ip-item lan-address">
                <div class="ip-icon" aria-hidden="true">⌂</div>
                <div class="ip-details">
                    <span class="ip-label">LAN <span class="ip-label-sub">· Local network</span></span>
                    <span class="ip-value" id="lan-ip">--</span>
                    <span class="ip-interface" id="lan-interface">Local interface</span>
                </div>
                <span class="ip-kind">LOCAL</span>
            </div>
        </div>
    </section>

    <!-- LAST 24 HOURS: COMBINED THROUGHPUT + PACKET LOSS -->

    <div class="card" style="margin-bottom:14px;">

        <div class="section-title">
            <h2>Network Performance - Last 24 Hours</h2>
            <span id="throughput-summary">Collecting data...</span>
        </div>

        <div class="chart-legend">
            <span><i class="swatch" style="background:#8fc7ff"></i>Download</span>
            <span><i class="swatch" style="background:#d0a7ff"></i>Upload</span>
            <span><i class="swatch" style="background:#ffb86b"></i>Packet loss</span>
        </div>

        <div class="chart-readout" id="throughput-readout">Hover over the chart for details</div>

        <canvas id="throughput-chart" class="chart-canvas"></canvas>

        <div class="sub">Left axis: throughput · Right axis: packet loss (%)</div>

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
            "lan-ip"
        ).textContent =
            lan.ip || "N/A";


        document.getElementById(
            "lan-interface"
        ).textContent =
            lan.interface || "LAN";

        renderDevices(
            data.devices || []
        );


        document.getElementById(
            "device-updated"
        ).textContent =
            "Updated " +
            new Date().toLocaleTimeString();
} catch (error) {

        console.error(
            "Dashboard refresh failed:",
            error
        );
}

}


function formatRate(bytesPerSecond) {

    const bits = bytesPerSecond * 8;

    if (bits >= 1e9) {
        return (bits / 1e9).toFixed(2) + " Gbps";
    }

    if (bits >= 1e6) {
        return (bits / 1e6).toFixed(1) + " Mbps";
    }

    if (bits >= 1e3) {
        return (bits / 1e3).toFixed(0) + " Kbps";
    }

    return bits.toFixed(0) + " bps";
}


function formatPercent(value) {
    return value.toFixed(value < 10 ? 1 : 0) + "%";
}


function formatClock(timestamp) {

    return new Date(timestamp * 1000).toLocaleString(
        [],
        {
            weekday: "short",
            hour: "2-digit",
            minute: "2-digit"
        }
    );
}


function createChart(canvasId, readoutId, seriesDefs, options) {

    const canvas = document.getElementById(canvasId);
    const readout = document.getElementById(readoutId);

    const PAD = {left: 66, right: 66, top: 12, bottom: 26};
    const DAY = 86400;
    const GAP = 180;

    let points = [];
    let hoverX = null;


    function geometry() {

        const rect = canvas.getBoundingClientRect();
        const end = Date.now() / 1000;

        return {
            rect: rect,
            start: end - DAY,
            plotW: rect.width - PAD.left - PAD.right
        };
    }


    function nearest(g) {

        const hoverT =
            g.start + (hoverX - PAD.left) / g.plotW * DAY;

        let best = null;

        points.forEach(function(p) {

            if (
                best === null ||
                Math.abs(p.t - hoverT) < Math.abs(best.t - hoverT)
            ) {
                best = p;
            }
        });

        if (best && Math.abs(best.t - hoverT) <= GAP * 2) {
            return best;
        }

        return null;
    }


    function render() {

        const g = geometry();

        if (!g.rect.width) {
            return;
        }

        const dpr = window.devicePixelRatio || 1;

        canvas.width = Math.round(g.rect.width * dpr);
        canvas.height = Math.round(g.rect.height * dpr);

        const ctx = canvas.getContext("2d");

        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        const w = g.rect.width;
        const h = g.rect.height;
        const plotH = h - PAD.top - PAD.bottom;

        let maxY = options.minMax;

        points.forEach(function(p) {
            seriesDefs.forEach(function(s) {
                if (s.axis !== "right" && p[s.key] != null && p[s.key] > maxY) {
                    maxY = p[s.key];
                }
            });
        });

        maxY = maxY * 1.15;

        const x = function(t) {
            return PAD.left + (t - g.start) / DAY * g.plotW;
        };

        const y = function(v, series) {
            if (series && series.axis === "right") {
                return PAD.top + (1 - v / options.rightMax) * plotH;
            }
            return PAD.top + (1 - v / maxY) * plotH;
        };

        ctx.font =
            "11px -apple-system, BlinkMacSystemFont, sans-serif";

        ctx.lineWidth = 1;

        // Horizontal grid + value labels
        ctx.textAlign = "right";
        ctx.textBaseline = "middle";

        for (let i = 0; i <= 4; i++) {

            const value = maxY * i / 4;
            const gy = Math.round(y(value)) + 0.5;

            ctx.strokeStyle = "#252b34";
            ctx.beginPath();
            ctx.moveTo(PAD.left, gy);
            ctx.lineTo(w - PAD.right, gy);
            ctx.stroke();

            ctx.fillStyle = "#737c89";
            ctx.fillText(options.format(value), PAD.left - 8, gy);
        }

        if (options.rightMax != null) {
            ctx.textAlign = "left";
            for (let i = 0; i <= 4; i++) {
                const value = options.rightMax * i / 4;
                const gy = Math.round(PAD.top + (1 - value / options.rightMax) * plotH) + 0.5;
                ctx.fillStyle = "#737c89";
                ctx.fillText(formatPercent(value), w - PAD.right + 8, gy);
            }
        }

        // Time labels every 4 hours
        ctx.textBaseline = "top";

        for (let i = 0; i <= 6; i++) {

            const t = g.start + i * 4 * 3600;

            ctx.fillStyle = "#737c89";

            ctx.textAlign =
                i === 0 ? "left" : (i === 6 ? "right" : "center");

            ctx.fillText(
                new Date(t * 1000).toLocaleTimeString(
                    [],
                    {hour: "2-digit", minute: "2-digit"}
                ),
                x(t),
                h - PAD.bottom + 8
            );
        }

        // Data lines (broken where samples are missing)
        seriesDefs.forEach(function(s) {

            ctx.strokeStyle = s.color;
            ctx.lineWidth = 1.6;
            ctx.lineJoin = "round";
            ctx.beginPath();

            let prevT = null;

            points.forEach(function(p) {

                const v = p[s.key];

                if (v == null) {
                    prevT = null;
                    return;
                }

                if (prevT === null || p.t - prevT > GAP) {
                    ctx.moveTo(x(p.t), y(v, s));
                } else {
                    ctx.lineTo(x(p.t), y(v, s));
                }

                prevT = p.t;
            });

            ctx.stroke();
        });

        // Hover crosshair
        const point = hoverX === null ? null : nearest(g);

        if (point) {

            const px = x(point.t);

            ctx.strokeStyle = "#4a5668";
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(px, PAD.top);
            ctx.lineTo(px, PAD.top + plotH);
            ctx.stroke();

            seriesDefs.forEach(function(s) {

                if (point[s.key] != null) {

                    ctx.fillStyle = s.color;
                    ctx.beginPath();
                    ctx.arc(px, y(point[s.key], s), 3.5, 0, Math.PI * 2);
                    ctx.fill();
                }
            });

            readout.textContent = options.readout(point);

        } else {

            readout.textContent = options.idle;
        }
    }


    canvas.addEventListener("pointermove", function(event) {

        hoverX = event.clientX - canvas.getBoundingClientRect().left;
        render();
    });

    canvas.addEventListener("pointerleave", function() {

        hoverX = null;
        render();
    });

    window.addEventListener("resize", render);

    return {
        setData: function(newPoints) {
            points = newPoints;
            render();
        }
    };
}


const throughputChart = createChart(
    "throughput-chart",
    "throughput-readout",
    [
        {key: "rx", color: "#8fc7ff"},
        {key: "tx", color: "#d0a7ff"},
        {key: "loss", color: "#ffb86b", axis: "right"}
    ],
    {
        minMax: 125000,
        rightMax: 100,
        format: formatRate,
        idle: "Hover over the chart for download, upload, and packet loss",
        readout: function(p) {
            return formatClock(p.t) +
                "  |  Down " + (p.rx != null ? formatRate(p.rx) : "n/a") +
                "  |  Up " + (p.tx != null ? formatRate(p.tx) : "n/a") +
                "  |  Loss " + (p.loss != null ? formatPercent(p.loss) : "n/a");
        }
    }
);

async function refreshHistory() {

    try {

        const response = await fetch(
            "/api/history",
            {cache: "no-store"}
        );

        if (!response.ok) {
            throw new Error("History request failed");
        }

        const data = await response.json();
        const points = data.points || [];

        throughputChart.setData(points);

        let peakRx = 0;
        let peakTx = 0;
        let lossSum = 0;
        let lossCount = 0;
        let lossMax = 0;

        points.forEach(function(p) {

            if (p.rx != null && p.rx > peakRx) {
                peakRx = p.rx;
            }

            if (p.tx != null && p.tx > peakTx) {
                peakTx = p.tx;
            }

            if (p.loss != null) {
                lossSum += p.loss;
                lossCount += 1;

                if (p.loss > lossMax) {
                    lossMax = p.loss;
                }
            }
        });

        document.getElementById("throughput-summary").textContent =
            points.length > 1
                ? "Peak down " + formatRate(peakRx) +
                  " / up " + formatRate(peakTx) +
                  (lossCount ? " · Avg loss " + formatPercent(lossSum / lossCount) +
                  " / max " + formatPercent(lossMax) : "")
                : "Collecting data...";

    } catch (error) {

        console.error("History refresh failed:", error);
    }
}


refreshDashboard();

setInterval(
    refreshDashboard,
    3000
);

refreshHistory();

setInterval(
    refreshHistory,
    60000
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
            <title>Network Topology - PiHarbor</title>

            <style>
                * {
                    box-sizing: border-box;
                }

                body {
                    margin: 0;
                    padding: 0;
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
                    z-index: 10;
                }

                .logo {
                    margin-bottom: 30px;
                    text-align: center;
                }

                .logo img {
                    display: block;
                    width: 150px;
                    height: 150px;
                    object-fit: cover;
                    border-radius: 50%;
                    margin: 0 auto 8px;
                }

                .logo-text {
                    display: none;
                    font-size: 24px;
                    font-weight: 700;
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
                    min-width: 0;
                }

                .page {
                    max-width: 1600px;
                    margin: auto;
                    padding: 28px;
                }

                .back {
                    display: inline-block;
                    margin-bottom: 22px;
                    color: #aeb5bf;
                    text-decoration: none;
                    font-size: 13px;
                }

                .back:hover {
                    color: white;
                }

                .header {
                    margin-bottom: 24px;
                }

                .header h1 {
                    margin: 0;
                    font-size: 28px;
                    letter-spacing: -0.5px;
                }

                .header-sub {
                    margin-top: 7px;
                    color: #7f8793;
                    font-size: 13px;
                }

                .summary {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 10px;
                    margin-bottom: 22px;
                }

                .summary-item {
                    padding: 11px 15px;
                    background: #12161c;
                    border: 1px solid #252b34;
                    border-radius: 11px;
                    color: #8f98a5;
                    font-size: 12px;
                }

                .summary-item strong {
                    color: #f3f4f6;
                    margin-left: 4px;
                }

                .topology-panel {
                    background:
                        radial-gradient(
                            circle,
                            rgba(122, 162, 247, 0.07) 1px,
                            transparent 1px
                        );
                    background-size: 24px 24px;
                    background-color: #10141a;
                    border: 1px solid #252b34;
                    border-radius: 16px;
                    overflow: auto;
                    min-height: 380px;
                    padding: 42px 24px 55px;
                }

                .topology-canvas {
                    width: max-content;
                    min-width: 100%;
                    display: flex;
                    justify-content: center;
                }

                /* Each level forms a horizontal tier. */


                /* Tree layout */
                .tree,
                .tree ul {
                    list-style: none;
                    margin: 0;
                    padding: 0;
                }
                
                .tree {
                    display: flex;
                    justify-content: center;
                    width: max-content;
                    min-width: 100%;
                }
                
                .tree ul {
                    position: relative;
                    display: flex;
                    justify-content: center;
                    align-items: flex-start;
                    padding-top: 38px;
                }
                
                /* Each node and its children */
                .tree-node {
                    position: relative;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    flex: 0 0 auto;
                    list-style: none;
                    text-align: center;
                    padding: 38px 13px 0;
                }
                
                /* Root node has no incoming connector */
                .tree > .tree-node {
                    padding-top: 0;
                }
                
                /* Horizontal connectors between siblings */
                .tree-node::before,
                .tree-node::after {
                    content: "";
                    position: absolute;
                    top: 0;
                    width: 50%;
                    height: 38px;
                    border-top: 1px solid #3c4655;
                }
                
                .tree-node::before {
                    right: 50%;
                }
                
                .tree-node::after {
                    left: 50%;
                    border-left: 1px solid #3c4655;
                }
                
                /* First and last children terminate the horizontal line */
                .tree-node:first-child::before {
                    border-top: 0;
                }
                
                .tree-node:last-child::after {
                    border-top: 0;
                }
                
                /* A single child needs only a vertical connector */
                .tree-node:only-child::before {
                    display: none;
                }
                
                .tree-node:only-child::after {
                    border-top: 0;
                }
                
                /* Hide connectors above the root */
                .tree > .tree-node::before,
                .tree > .tree-node::after {
                    display: none;
                }
                
                /* Vertical connector from a parent to its child row */
                .tree ul::before {
                    content: "";
                    position: absolute;
                    top: 0;
                    left: 50%;
                    height: 38px;
                    border-left: 1px solid #3c4655;
                }


                /* Device bubbles. */

                .node-bubble {
                    position: relative;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    width: 224px;
                    min-height: 88px;
                    padding: 15px;
                    text-align: left;
                    background: linear-gradient(
                        145deg,
                        #1b222c,
                        #131820
                    );
                    border: 1px solid #343e4d;
                    border-radius: 16px;
                    box-shadow:
                        0 8px 22px rgba(0, 0, 0, 0.22);
                    transition:
                        transform 0.2s ease,
                        border-color 0.2s ease,
                        box-shadow 0.2s ease;
                }

                .node-bubble:hover {
                    transform: translateY(-3px);
                    border-color: #7aa2f7;
                    box-shadow:
                        0 10px 28px rgba(0, 0, 0, 0.35);
                }

                .node-symbol {
                    flex: 0 0 42px;
                    width: 42px;
                    height: 42px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 21px;
                    border-radius: 13px;
                    background: #252f40;
                    border: 1px solid #37465e;
                }

                .node-symbol.node-logo {
                    flex: 0 0 56px;
                    width: 56px;
                    height: 56px;
                    background: transparent;
                    border-color: transparent;
                }

                .node-symbol img {
                    width: 100%;
                    height: 100%;
                    object-fit: contain;
                }

                .node-bubble.is-pi {
                    border-color: #7aa2f7;
                }

                .node-main {
                    min-width: 0;
                    flex: 1;
                }

                .node-label {
                    color: #f3f4f6;
                    font-size: 13px;
                    line-height: 1.4;
                    font-weight: 650;
                    overflow-wrap: anywhere;
                }

                .node-details {
                    margin-top: 5px;
                    color: #8e99a9;
                    font-family: monospace;
                    font-size: 11px;
                    line-height: 1.5;
                    overflow-wrap: anywhere;
                }

                .node-status {
                    display: flex;
                    align-items: center;
                    gap: 6px;
                    margin-top: 9px;
                    color: #65d985;
                    font-size: 10px;
                    font-weight: 600;
                }

                .node-status.status-down {
                    color: #e77979;
                }

                .status-dot {
                    width: 6px;
                    height: 6px;
                    background: currentColor;
                    border-radius: 50%;
                    box-shadow: 0 0 8px currentColor;
                }

                .legend {
                    display: flex;
                    align-items: center;
                    flex-wrap: wrap;
                    gap: 18px;
                    margin-top: 20px;
                    color: #858f9d;
                    font-size: 11px;
                }

                .legend-item {
                    display: flex;
                    align-items: center;
                    gap: 7px;
                }

                .legend-line {
                    width: 20px;
                    height: 1px;
                    background: #3c4655;
                }

                .empty {
                    margin-top: 20px;
                    color: #7f8793;
                    font-size: 13px;
                }

                @media (max-width: 800px) {
                    .sidebar {
                        position: static;
                        width: 100%;
                        height: auto;
                    }

                    .main {
                        margin-left: 0;
                    }

                    .page {
                        padding: 16px;
                    }

                    .header h1 {
                        font-size: 24px;
                    }

                    .topology-panel {
                        padding: 32px 15px 40px;
                    }

                    .topology-canvas {
                        justify-content: flex-start;
                    }

                    .node-bubble {
                        width: 200px;
                    }
                }

            </style>
        </head>

        <body>
            <div class="sidebar">
                <div class="logo">
                    <img src="/logo.png" alt="PiHarbor"
                         onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
                    <div class="logo-text">PiHarbor</div>
                </div>
                <div class="nav">
                    <a href="/">Dashboard</a>
                    <a href="/health">Device Health</a>
                    <a href="/topology" class="active">Topology</a>
                    <a href="/dns">DNS</a>
                </div>
            </div>
            <div class="main">
              <div class="page">

                <div class="header">
                    <h1>Network Topology</h1>
                    <div class="header-sub">
                        Explore how PiHarbor connects your network.
                        Each bubble represents a discovered node.
                    </div>
                </div>

                                 {% if topology.metadata.wireguard_present %}
                <div class="summary">
                    <div class="summary-item">
                        WireGuard
                        <strong>
                            {{ "Active" if topology.metadata.wireguard_active else "Inactive" }}
                        </strong>
                    </div>
                </div>
                {% endif %}

                <div class="topology-panel">
                    <div class="topology-canvas">

                        {% macro render_node(node, root=false) %}

                            {% set name = (node.label or "")|lower %}
                            {% set status = node.status or "Unknown" %}
                            {% set is_pi = (
                                "piharbor" in name
                                or "raspberry" in name
                                or name|trim == "pi"
                                or ("gateway" in name and "router" not in name)
                            ) %}

                            <li class="tree-node">

                                <div class="node-bubble {% if is_pi %}is-pi{% endif %}">

                                    <div class="node-symbol {% if is_pi %}node-logo{% endif %}">
                                        {% if is_pi %}
                                            <img
                                                src="/logo.png"
                                                alt="PiHarbor"
                                                onerror="this.replaceWith('🛡️')"
                                            >
                                        {% elif "internet" in name %}
                                            🌐
                                        {% elif "router" in name %}
                                            📡
                                        {% elif "wireguard" in name or "wg0" in name %}
                                            🔐
                                        {% elif "wifi" in name or "wi-fi" in name or "wlan" in name %}
                                            📶
                                        {% elif "eth" in name or "wan" in name or "lan" in name %}
                                            🔌
                                        {% elif "phone" in name or "mobile" in name %}
                                            📱
                                        {% elif "laptop" in name or "computer" in name or "pc" in name %}
                                            💻
                                        {% elif "pi" in name or "gateway" in name or "piharbor" in name %}
                                            🛡️
                                        {% else %}
                                            🖥️
                                        {% endif %}
                                    </div>

                                    <div class="node-main">

                                        <div class="node-label">
                                            {{ node.label }}
                                        </div>

                                        {% if node.details %}
                                        <div class="node-details">
                                            {{ node.details }}
                                        </div>
                                        {% endif %}

                                        <div class="node-status
                                            {% if status|lower in ['offline', 'inactive', 'down', 'failed'] %}
                                                status-down
                                            {% endif %}
                                        ">
                                            <span class="status-dot"></span>
                                            {{ status }}
                                        </div>

                                    </div>

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

                    </div>
                </div>

                <div class="legend">
                    <div class="legend-item">
                        <span class="legend-line"></span>
                        Parent / child connection
                    </div>
                    <div class="legend-item">
                        <span class="status-dot" style="color:#65d985"></span>
                        Active
                    </div>
                    <div class="legend-item">
                        <span class="status-dot" style="color:#e77979"></span>
                        Offline / inactive
                    </div>
                </div>

                {% if topology.metadata.client_count == 0 %}
                <div class="empty">
                    No LAN clients are currently visible.
                    Connect a device to the PiHarbor network to see it here.
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
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Device Health - PiHarbor</title>
            <style>
                * { box-sizing: border-box; }
                :root {
                    color-scheme: dark;
                    --bg: #0b0e12; --panel: #121821; --panel2: #151d28;
                    --border: #263241; --muted: #8793a3; --text: #eef3f8;
                    --blue: #78b7ff; --green: #62d995; --amber: #f4bd70;
                    --red: #ef7777; --purple: #b9a1ff;
                }
                body {
                    margin: 0; background: var(--bg); color: var(--text);
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                }
                .sidebar {
                    position: fixed; inset: 0 auto 0 0; width: 220px;
                    padding: 22px 16px; background: #111720;
                    border-right: 1px solid var(--border);
                }
                .logo { margin-bottom: 28px; text-align: center; }
                .logo img {
                    display: block; width: 138px; height: 138px;
                    object-fit: cover; border-radius: 50%; margin: 0 auto 8px;
                }
                .logo-text { display: none; font-size: 23px; font-weight: 750; }
                .nav a {
                    display: block; padding: 11px 13px; margin: 4px 0;
                    border-radius: 9px; color: #aeb9c7; text-decoration: none;
                    font-size: 14px; transition: .15s ease;
                }
                .nav a:hover, .nav a.active { background: #202b39; color: #fff; }
                .main { margin-left: 220px; padding: 32px; max-width: 1650px; }
                .page-header {
                    display: flex; justify-content: space-between; align-items: flex-start;
                    gap: 20px; margin-bottom: 25px;
                }
                h1 { margin: 0; font-size: 29px; letter-spacing: -.7px; }
                .subtitle { color: var(--muted); margin-top: 7px; font-size: 13px; }
                .refresh-pill {
                    padding: 8px 12px; border: 1px solid var(--border);
                    border-radius: 999px; background: #121821; color: #aab6c5;
                    font-size: 12px; white-space: nowrap;
                }
                .live-dot {
                    display: inline-block; width: 7px; height: 7px; border-radius: 50%;
                    background: var(--green); margin-right: 7px;
                    box-shadow: 0 0 9px #62d99588;
                }
                .section { margin-top: 25px; }
                .section-heading {
                    display: flex; align-items: baseline; justify-content: space-between;
                    gap: 12px; margin: 0 0 12px;
                }
                .section-heading h2 { margin: 0; font-size: 16px; letter-spacing: -.2px; }
                .section-heading span { color: var(--muted); font-size: 11px; }
                .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 13px; }
                .grid.three { grid-template-columns: repeat(3, minmax(0, 1fr)); }
                .card {
                    min-width: 0; padding: 17px; border-radius: 13px;
                    background: linear-gradient(145deg, var(--panel2), var(--panel));
                    border: 1px solid var(--border);
                }
                .card-label {
                    color: #9aa7b7; font-size: 11px; font-weight: 650;
                    letter-spacing: .075em; text-transform: uppercase;
                }
                .metric {
                    margin-top: 9px; font-size: 29px; font-weight: 720;
                    letter-spacing: -.8px; line-height: 1.1; overflow-wrap: anywhere;
                }
                .metric.small { font-size: 22px; }
                .card-note { margin-top: 7px; color: var(--muted); font-size: 11px; }
                .progress {
                    height: 6px; margin-top: 13px; background: #26313e;
                    border-radius: 99px; overflow: hidden;
                }
                .progress > div { height: 100%; width: 0; border-radius: inherit; background: var(--blue); transition: width .25s; }
                .blue { color: var(--blue); } .green { color: var(--green); }
                .amber { color: var(--amber); } .purple { color: var(--purple); }
                .detail-list { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 10px; }
                .detail {
                    display: flex; justify-content: space-between; gap: 12px;
                    padding: 11px 0; border-bottom: 1px solid #26313d; font-size: 12px;
                }
                .detail:last-child, .detail:nth-last-child(2) { border-bottom: 0; }
                .detail span:first-child { color: var(--muted); }
                .detail strong { text-align: right; overflow-wrap: anywhere; }
                .interface-grid { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 13px; }
                .interface-card { padding: 19px; }
                .interface-head { display:flex; justify-content:space-between; gap:12px; align-items:center; }
                .interface-title { font-weight: 700; font-size: 15px; }
                .interface-name { color: var(--muted); font: 11px ui-monospace, monospace; margin-top: 4px; }
                .chip {
                    padding: 5px 9px; border: 1px solid #2c4b3b; border-radius: 999px;
                    color: #8cddb0; background: #14271f; font-size: 10px; white-space: nowrap;
                }
                .link-speed { margin: 19px 0 4px; font-size: 28px; font-weight: 730; letter-spacing: -.6px; }
                .link-caption { color: var(--muted); font-size: 11px; }
                .rate-list { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 8px; margin-top: 15px; }
                .rate {
                    padding: 10px; border-radius: 9px; background: #0e141c;
                    border: 1px solid #26313d;
                }
                .rate span { display:block; color:var(--muted); font-size:10px; margin-bottom:5px; }
                .rate strong { font-size:13px; overflow-wrap:anywhere; }
                .footer-line {
                    display:flex; justify-content:space-between; flex-wrap:wrap; gap:10px;
                    padding: 14px 16px; margin-top: 16px; background:#111821;
                    border:1px solid var(--border); border-radius:11px;
                    color:var(--muted); font-size:11px;
                }
                @media (max-width: 1150px) {
                    .grid { grid-template-columns: repeat(2,minmax(0,1fr)); }
                    .grid.three { grid-template-columns: repeat(2,minmax(0,1fr)); }
                }
                @media (max-width: 800px) {
                    .sidebar { position: static; width: 100%; height:auto; }
                    .logo img { width:90px; height:90px; }
                    .main { margin-left:0; padding:19px; }
                    .page-header { flex-direction:column; }
                    .interface-grid { grid-template-columns:1fr; }
                }
                @media (max-width: 520px) {
                    .grid, .grid.three, .detail-list { grid-template-columns:1fr; }
                    .detail:last-child, .detail:nth-last-child(2) { border-bottom:1px solid #26313d; }
                    .detail:last-child { border-bottom:0; }
                    h1 { font-size:25px; }
                }
            </style>
        </head>
        <body>
            <aside class="sidebar">
                <div class="logo">
                    <img src="/logo.png" alt="PiHarbor"
                         onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
                    <div class="logo-text">PiHarbor</div>
                </div>
                <nav class="nav">
                    <a href="/">Dashboard</a>
                    <a href="/health" class="active">Device Health</a>
                    <a href="/topology">Topology</a>
                    <a href="/dns">DNS</a>
                </nav>
            </aside>

            <main class="main">
                <header class="page-header">
                    <div>
                        <h1>Device Health</h1>
                        <div class="subtitle">Live Raspberry Pi diagnostics, hardware status and network interface capacity</div>
                    </div>
                    <div class="refresh-pill"><span class="live-dot"></span><span id="health-state">Connecting</span></div>
                </header>

                <section class="section">
                    <div class="section-heading"><h2>System overview</h2><span>Live resource utilization</span></div>
                    <div class="grid">
                        <div class="card">
                            <div class="card-label">CPU utilization</div>
                            <div class="metric blue" id="cpu">--</div>
                            <div class="progress"><div id="cpu-bar"></div></div>
                            <div class="card-note">Processor usage</div>
                        </div>
                        <div class="card">
                            <div class="card-label">Memory</div>
                            <div class="metric purple" id="memory">--</div>
                            <div class="progress"><div id="memory-bar"></div></div>
                            <div class="card-note" id="memory-note">RAM utilization</div>
                        </div>
                        <div class="card">
                            <div class="card-label">CPU temperature</div>
                            <div class="metric amber" id="temperature">--</div>
                            <div class="card-note">SoC temperature</div>
                        </div>
                        <div class="card">
                            <div class="card-label">Root storage</div>
                            <div class="metric green" id="storage">--</div>
                            <div class="progress"><div id="storage-bar"></div></div>
                            <div class="card-note">Filesystem utilization</div>
                        </div>
                    </div>
                </section>

                <section class="section">
                    <div class="section-heading"><h2>Network link capacity</h2><span>Negotiated link details, not internet speed-test results</span></div>
                    <div class="interface-grid">
                        <div class="card interface-card">
                            <div class="interface-head">
                                <div><div class="interface-title">WAN · Ethernet</div><div class="interface-name" id="wan-name">eth0</div></div>
                                <span class="chip" id="wan-state">Checking</span>
                            </div>
                            <div class="link-speed blue" id="wan-speed">--</div>
                            <div class="link-caption" id="wan-duplex">Negotiated Ethernet capacity</div>
                            <div class="rate-list">
                                <div class="rate"><span>RX errors / drops</span><strong id="wan-rx">--</strong></div>
                                <div class="rate"><span>TX errors / drops</span><strong id="wan-tx">--</strong></div>
                            </div>
                        </div>
                        <div class="card interface-card">
                            <div class="interface-head">
                                <div><div class="interface-title">LAN · Wi-Fi access point</div><div class="interface-name" id="lan-name">wlan0</div></div>
                                <span class="chip" id="lan-state">Checking</span>
                            </div>
                            <div class="link-speed purple" id="lan-speed">--</div>
                            <div class="link-caption" id="lan-duplex">Per-client wireless PHY rates</div>
                            <div class="rate-list">
                                <div class="rate"><span>Connected stations</span><strong id="lan-clients">--</strong></div>
                                <div class="rate"><span>Example TX / RX rate</span><strong id="lan-rates">--</strong></div>
                                <div class="rate"><span>RX errors / drops</span><strong id="lan-rx">--</strong></div>
                                <div class="rate"><span>TX errors / drops</span><strong id="lan-tx">--</strong></div>
                            </div>
                        </div>
                    </div>
                </section>

                <section class="section">
                    <div class="section-heading"><h2>System diagnostics</h2><span>Additional operating conditions</span></div>
                    <div class="grid three">
                        <div class="card">
                            <div class="card-label">CPU frequency</div>
                            <div class="metric small" id="frequency">--</div>
                            <div class="card-note">Current CPU clock</div>
                        </div>
                        <div class="card">
                            <div class="card-label">Load average</div>
                            <div class="metric small" id="load">--</div>
                            <div class="card-note">1 / 5 / 15 minute averages</div>
                        </div>
                        <div class="card">
                            <div class="card-label">Swap utilization</div>
                            <div class="metric small" id="swap">--</div>
                            <div class="progress"><div id="swap-bar"></div></div>
                            <div class="card-note">Swap space in use</div>
                        </div>
                        <div class="card">
                            <div class="card-label">Power / throttling</div>
                            <div class="metric small" id="throttling">--</div>
                            <div class="card-note" id="throttling-note">Firmware throttling flags</div>
                        </div>
                        <div class="card">
                            <div class="card-label">Failed services</div>
                            <div class="metric small" id="failed-services">--</div>
                            <div class="card-note">systemd failed-unit count</div>
                        </div>
                        <div class="card">
                            <div class="card-label">System uptime</div>
                            <div class="metric small" id="uptime">--</div>
                            <div class="card-note">Time since last boot</div>
                        </div>
                    </div>
                </section>

                <div class="footer-line">
                    <span>Metrics refresh automatically every 5 seconds</span>
                    <span>Last updated: <strong id="updated">--</strong></span>
                </div>
            </main>

            <script>
                const byId = id => document.getElementById(id);
                function valueText(value, suffix = "") {
                    return value === null || value === undefined || value === "" ? "N/A" : `${value}${suffix}`;
                }
                function setProgress(id, value) {
                    const n = Number(value);
                    byId(id).style.width = Number.isFinite(n) ? `${Math.max(0, Math.min(100, n))}%` : "0%";
                }
                function setText(id, value) { byId(id).textContent = value; }
                function renderInterface(prefix, link, isWifi) {
                    if (!link) return;
                    setText(`${prefix}-name`, link.interface || "Unknown interface");
                    setText(`${prefix}-state`, link.state || "Unknown");
                    const speed = link.speed_mbps;
                    if (isWifi) {
                        setText(`${prefix}-speed`, link.clients ? `${link.clients} station${link.clients === 1 ? "" : "s"}` : "AP link");
                        setText(`${prefix}-duplex`, "Wireless capacity varies by connected client");
                        setText("lan-clients", valueText(link.clients));
                        const tx = (link.tx_bitrate || [])[0] || "N/A";
                        const rx = (link.rx_bitrate || [])[0] || "N/A";
                        setText("lan-rates", `${tx} / ${rx}`);
                    } else {
                        setText(`${prefix}-speed`, speed ? `${speed} Mbps` : "N/A");
                        setText(`${prefix}-duplex`, speed ? `${link.duplex || "Unknown"} duplex · negotiated Ethernet link` : "Link speed unavailable");
                    }
                    setText(`${prefix}-rx`, `${valueText(link.rx_errors)} / ${valueText(link.rx_dropped)}`);
                    setText(`${prefix}-tx`, `${valueText(link.tx_errors)} / ${valueText(link.tx_dropped)}`);
                }
                async function refreshHealth() {
                    try {
                        const [dashboardResponse, detailsResponse] = await Promise.all([
                            fetch("/api/dashboard", {cache:"no-store"}),
                            fetch("/api/health-details", {cache:"no-store"})
                        ]);
                        if (!dashboardResponse.ok || !detailsResponse.ok) throw new Error("Health API unavailable");
                        const dashboard = await dashboardResponse.json();
                        const details = await detailsResponse.json();
                        const system = dashboard.system || {};
                        for (const [key, val] of [["cpu",system.cpu_usage],["memory",system.memory_usage],["storage",system.storage_usage]]) {
                            setText(key, valueText(val, "%"));
                            setProgress(`${key}-bar`, val);
                        }
                        setText("temperature", valueText(system.temperature, "°C"));
                        setText("uptime", system.uptime_text || "Unknown");
                        setText("frequency", valueText(details.cpu_frequency_mhz, " MHz"));
                        setText("load", (details.load_average || []).join(" / ") || "N/A");
                        setText("swap", valueText(details.swap_used_percent, "%"));
                        setProgress("swap-bar", details.swap_used_percent);
                        setText("throttling", details.throttling || "Unknown");
                        setText("throttling-note", details.throttling_raw || "Firmware status");
                        setText("failed-services", valueText(details.failed_services));
                        renderInterface("wan", details.wan_link, false);
                        renderInterface("lan", details.lan_link, true);
                        setText("health-state", "Live diagnostics");
                        setText("updated", new Date().toLocaleTimeString());
                    } catch (error) {
                        console.error("Device health refresh failed:", error);
                        setText("health-state", "Refresh error");
                    }
                }
                refreshHealth();
                setInterval(refreshHealth, 5000);
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
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>DNS - PiHarbor</title>
            <style>
                * { box-sizing: border-box; }
                :root {
                    color-scheme: dark; --bg:#0b0e12; --panel:#121821;
                    --panel2:#151d28; --border:#263241; --muted:#8793a3;
                    --text:#eef3f8; --green:#62d995; --red:#ef7777; --blue:#78b7ff;
                }
                body { margin:0; background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
                .sidebar { position:fixed; inset:0 auto 0 0; width:220px; padding:22px 16px; background:#111720; border-right:1px solid var(--border); }
                .logo { margin-bottom:28px; text-align:center; }
                .logo img { display:block; width:138px; height:138px; object-fit:cover; border-radius:50%; margin:0 auto 8px; }
                .logo-text { display:none; font-size:23px; font-weight:750; }
                .nav a { display:block; padding:11px 13px; margin:4px 0; border-radius:9px; color:#aeb9c7; text-decoration:none; font-size:14px; }
                .nav a:hover,.nav a.active { background:#202b39; color:#fff; }
                .main { margin-left:220px; padding:32px; max-width:1500px; }
                .page-header { display:flex; justify-content:space-between; align-items:flex-start; gap:20px; margin-bottom:24px; }
                h1 { margin:0; font-size:29px; letter-spacing:-.7px; }
                h2 { margin:0; font-size:16px; letter-spacing:-.2px; }
                h3 { margin:20px 0 12px; font-size:13px; }
                .subtitle { margin-top:7px; color:var(--muted); font-size:13px; }
                .status-pill { padding:7px 11px; border-radius:999px; font-size:11px; font-weight:650; white-space:nowrap; }
                .status-pill.on { color:#8cddb0; background:#14271f; border:1px solid #2c4b3b; }
                .status-pill.off { color:#f09a9a; background:#2b191c; border:1px solid #583238; }
                .card { min-width:0; padding:20px; margin-bottom:15px; border:1px solid var(--border); border-radius:13px; background:linear-gradient(145deg,var(--panel2),var(--panel)); }
                .card-heading { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:16px; }
                .card-description { color:var(--muted); font-size:12px; line-height:1.6; margin:7px 0 0; }
                .overview { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:13px; margin-bottom:15px; }
                .stat { padding:17px; border:1px solid var(--border); border-radius:12px; background:#111821; }
                .stat-label { color:#9aa7b7; font-size:10px; font-weight:650; letter-spacing:.08em; text-transform:uppercase; }
                .stat-value { margin-top:8px; font-size:25px; font-weight:730; letter-spacing:-.5px; overflow-wrap:anywhere; }
                .stat-note { margin-top:5px; color:var(--muted); font-size:11px; }
                .green { color:var(--green); } .blue { color:var(--blue); }
                .notice { padding:12px 14px; margin-bottom:15px; border:1px solid var(--border); border-radius:10px; background:#151d28; color:#c5d0dc; font-size:12px; }
                .notice.success { border-color:#315d45; color:#a1e3b9; }
                .notice.error { border-color:#63363b; color:#f0a1a1; }
                .actions { display:flex; flex-wrap:wrap; gap:9px; margin-top:17px; }
                .button { padding:10px 14px; border:1px solid #39495b; border-radius:8px; background:#202c3a; color:#edf4fb; font-size:12px; font-weight:650; cursor:pointer; transition:.15s; }
                .button:hover { background:#2a3a4d; border-color:#52708e; }
                .button.primary { background:#1b4262; border-color:#2d638f; }
                .button.danger { background:#321e23; border-color:#63363b; color:#f0b0b0; }
                .custom-form { display:flex; gap:10px; margin-top:16px; }
                .domain-input { flex:1; min-width:0; padding:11px 12px; border:1px solid #344253; border-radius:8px; background:#0d131b; color:#f2f6fa; font:13px ui-monospace,monospace; outline:none; }
                .domain-input:focus { border-color:#6099cb; box-shadow:0 0 0 3px #6099cb22; }
                .domain-list { margin-top:12px; border-top:1px solid var(--border); }
                .domain-row { display:flex; justify-content:space-between; align-items:center; gap:14px; padding:12px 0; border-bottom:1px solid #26313d; }
                .domain-row:last-child { border-bottom:0; }
                .domain-name { min-width:0; overflow-wrap:anywhere; font:12px ui-monospace,monospace; color:#d9e4ef; }
                .empty { padding:17px 0 4px; color:var(--muted); font-size:12px; }
                .health-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:0 24px; }
                .health-row { display:flex; justify-content:space-between; gap:12px; padding:11px 0; border-bottom:1px solid #26313d; font-size:12px; }
                .health-row span:first-child { color:var(--muted); }
                .health-row strong { text-align:right; overflow-wrap:anywhere; }
                @media(max-width:950px) { .overview { grid-template-columns:repeat(2,minmax(0,1fr)); } }
                @media(max-width:800px) {
                    .sidebar { position:static; width:100%; height:auto; }
                    .logo img { width:90px; height:90px; }
                    .main { margin-left:0; padding:19px; }
                    .page-header { flex-direction:column; }
                }
                @media(max-width:560px) {
                    .overview,.health-grid { grid-template-columns:1fr; }
                    .custom-form { flex-direction:column; }
                    .domain-row { align-items:flex-start; }
                    h1 { font-size:25px; }
                }
            </style>
        </head>
        <body>
            <aside class="sidebar">
                <div class="logo">
                    <img src="/logo.png" alt="PiHarbor"
                         onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
                    <div class="logo-text">PiHarbor</div>
                </div>
                <nav class="nav">
                    <a href="/">Dashboard</a>
                    <a href="/health">Device Health</a>
                    <a href="/topology">Topology</a>
                    <a href="/dns" class="active">DNS</a>
                </nav>
            </aside>

            <main class="main">
                <header class="page-header">
                    <div>
                        <h1>DNS & Ad Blocking</h1>
                        <div class="subtitle">Manage domain filtering, custom rules and DNS resolver health</div>
                    </div>
                    <span class="status-pill {{ 'on' if status.enabled else 'off' }}">
                        {{ 'Protection enabled' if status.enabled else 'Protection disabled' }}
                    </span>
                </header>

                {% if message %}
                    <div class="notice {{ message_type }}">{{ message }}</div>
                {% endif %}

                <section class="overview">
                    <div class="stat">
                        <div class="stat-label">Ad blocking</div>
                        <div class="stat-value {{ 'green' if status.enabled else '' }}">{{ 'Enabled' if status.enabled else 'Disabled' }}</div>
                        <div class="stat-note">PiHarbor domain filtering</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Blocked domains</div>
                        <div class="stat-value blue">{{ "{:,}".format(status.blocked_domains or 0) }}</div>
                        <div class="stat-note">Domains in the active blocklist</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Blocklist size</div>
                        <div class="stat-value">{{ (status.size_bytes / 1048576)|round(1) if status.size_bytes else 0 }} MB</div>
                        <div class="stat-note">Last update: {{ status.last_update or "Never" }}</div>
                    </div>
                </section>

                <section class="card">
                    <div class="card-heading">
                        <div>
                            <h2>Protection controls</h2>
                            <p class="card-description">Enable or disable filtering, or refresh the domain blocklist.</p>
                        </div>
                    </div>
                    <form method="post" class="actions">
                        {% if status.enabled %}
                            <button class="button danger" name="adblock_action" value="disable">Disable protection</button>
                        {% else %}
                            <button class="button primary" name="adblock_action" value="enable">Enable protection</button>
                        {% endif %}
                        <button class="button" name="adblock_action" value="update">Update blocklist</button>
                    </form>
                </section>

                {% if dns_health %}
                <section class="card">
                    <div class="card-heading">
                        <div>
                            <h2>DNS resolver health</h2>
                            <p class="card-description">Live status reported by the DNS monitoring backend.</p>
                        </div>
                    </div>
                    <div class="health-grid">
                        {% for key, value in dns_health.items() %}
                            <div class="health-row">
                                <span>{{ key|replace('_',' ')|title }}</span>
                                <strong>{{ value if value is not none else "N/A" }}</strong>
                            </div>
                        {% endfor %}
                    </div>
                </section>
                {% else %}
                <section class="card">
                    <h2>DNS resolver health</h2>
                    <p class="card-description">DNS health details are currently unavailable from the monitoring backend.</p>
                </section>
                {% endif %}

                <section class="card">
                    <div class="card-heading">
                        <div>
                            <h2>Custom blocklist</h2>
                            <p class="card-description">Add a domain to block it on your network. You can enter a hostname or paste a URL.</p>
                        </div>
                    </div>
                    <form method="post" class="custom-form">
                        <input class="domain-input" type="text" name="domain" placeholder="example.com" required>
                        <button class="button primary" type="submit" name="custom_action" value="add">Block domain</button>
                    </form>

                    <h3>Custom blocked domains <span style="color:var(--muted);font-weight:400;">({{ custom_domains|length }})</span></h3>
                    <div class="domain-list">
                        {% if custom_domains %}
                            {% for domain in custom_domains %}
                                <div class="domain-row">
                                    <span class="domain-name">{{ domain }}</span>
                                    <form method="post" class="remove-form">
                                        <input type="hidden" name="domain" value="{{ domain }}">
                                        <button class="button danger" type="submit" name="custom_action" value="remove">Remove</button>
                                    </form>
                                </div>
                            {% endfor %}
                        {% else %}
                            <div class="empty">No custom domains have been added.</div>
                        {% endif %}
                    </div>
                </section>
            </main>
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
