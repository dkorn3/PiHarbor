

import os
import subprocess
import time

try:
    import psutil
except ImportError:
    psutil = None


# ============================================================
# Utility
# ============================================================

def _run_command(command, timeout=5):
    """
    Run a system command and return the CompletedProcess.

    Returns None if the command cannot be executed.
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


def format_bytes(value):
    """
    Convert bytes into a human-readable string.
    """

    if value is None:
        return "N/A"

    value = float(value)

    if value < 1024:
        return f"{value:.0f} B"

    if value < 1024 ** 2:
        return f"{value / 1024:.1f} KB"

    if value < 1024 ** 3:
        return f"{value / 1024 ** 2:.1f} MB"

    if value < 1024 ** 4:
        return f"{value / 1024 ** 3:.2f} GB"

    return f"{value / 1024 ** 4:.2f} TB"


def format_uptime(seconds):
    """
    Convert uptime in seconds into a readable string.
    """

    if seconds is None:
        return "Unknown"

    seconds = int(seconds)

    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60

    if days:
        return f"{days}d {hours}h {minutes}m"

    if hours:
        return f"{hours}h {minutes}m"

    return f"{minutes}m"


# ============================================================
# System Monitoring
# ============================================================

def get_system_status():
    """
    Return a snapshot of overall system health.
    """

    uptime = get_uptime()

    return {
        "cpu_usage": get_cpu_usage(),
        "memory_usage": get_memory_usage(),
        "storage_usage": get_storage_usage(),
        "temperature": get_temperature(),
        "uptime": uptime,
        "uptime_text": format_uptime(uptime),
        "load_average": get_load_average(),
    }


def get_cpu_usage():
    """
    Return CPU utilization as a percentage.
    """

    if psutil is not None:

        try:
            return round(
                psutil.cpu_percent(
                    interval=0.2
                ),
                1,
            )

        except (
            OSError,
            ValueError,
        ):
            pass

    return None


def get_memory_usage():
    """
    Return memory utilization as a percentage.
    """

    if psutil is None:
        return None

    try:

        return round(
            psutil.virtual_memory().percent,
            1,
        )

    except OSError:
        return None


def get_memory_details():
    """
    Return detailed memory statistics.
    """

    if psutil is None:
        return {}

    try:

        memory = psutil.virtual_memory()

        return {
            "total": memory.total,
            "available": memory.available,
            "used": memory.used,
            "percent": memory.percent,
            "total_human": format_bytes(
                memory.total
            ),
            "used_human": format_bytes(
                memory.used
            ),
            "available_human": format_bytes(
                memory.available
            ),
        }

    except OSError:
        return {}


def get_storage_usage():
    """
    Return root filesystem storage utilization.
    """

    if psutil is None:
        return None

    try:

        return round(
            psutil.disk_usage("/").percent,
            1,
        )

    except OSError:
        return None


def get_storage_details():
    """
    Return detailed root filesystem storage.
    """

    if psutil is None:
        return {}

    try:

        disk = psutil.disk_usage("/")

        return {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent,
            "total_human": format_bytes(
                disk.total
            ),
            "used_human": format_bytes(
                disk.used
            ),
            "free_human": format_bytes(
                disk.free
            ),
        }

    except OSError:
        return {}


def get_temperature():
    """
    Return CPU/system temperature in Celsius.
    """

    temperature_file = (
        "/sys/class/thermal/"
        "thermal_zone0/temp"
    )

    try:

        with open(
            temperature_file,
            "r",
            encoding="utf-8",
        ) as file:

            temperature = int(
                file.read().strip()
            )

        return round(
            temperature / 1000.0,
            1,
        )

    except (
        FileNotFoundError,
        ValueError,
        OSError,
    ):
        return None


def get_uptime():
    """
    Return system uptime in seconds.
    """

    if psutil is not None:

        try:

            return time.time() - (
                psutil.boot_time()
            )

        except OSError:
            pass

    try:

        with open(
            "/proc/uptime",
            "r",
            encoding="utf-8",
        ) as file:

            return float(
                file.read().split()[0]
            )

    except (
        FileNotFoundError,
        ValueError,
        OSError,
    ):
        return None


def get_load_average():
    """
    Return Linux load averages.
    """

    try:

        load1, load5, load15 = (
            os.getloadavg()
        )

        return {
            "1m": round(load1, 2),
            "5m": round(load5, 2),
            "15m": round(load15, 2),
        }

    except OSError:
        return {}


# ============================================================
# Network Monitoring
# ============================================================

def get_interface_stats(interface):
    """
    Return traffic and error statistics for
    a specific network interface.
    """

    if psutil is None:
        return None

    try:

        stats = psutil.net_io_counters(
            pernic=True
        )

        if interface not in stats:
            return None

        data = stats[interface]

        return {
            "bytes_sent": data.bytes_sent,
            "bytes_received": data.bytes_recv,
            "packets_sent": data.packets_sent,
            "packets_received": data.packets_recv,
            "errors_sent": data.errout,
            "errors_received": data.errin,
            "drops_sent": data.dropout,
            "drops_received": data.dropin,

            "bytes_sent_human": format_bytes(
                data.bytes_sent
            ),

            "bytes_received_human": format_bytes(
                data.bytes_recv
            ),
        }

    except OSError:
        return None


def get_network_stats():
    """
    Return statistics for all network interfaces.
    """

    if psutil is None:
        return {}

    try:

        stats = psutil.net_io_counters(
            pernic=True
        )

        return {
            interface: {
                "bytes_sent": data.bytes_sent,
                "bytes_received": data.bytes_recv,
                "packets_sent": data.packets_sent,
                "packets_received": data.packets_recv,
                "errors_sent": data.errout,
                "errors_received": data.errin,
                "drops_sent": data.dropout,
                "drops_received": data.dropin,
                "bytes_sent_human": format_bytes(
                    data.bytes_sent
                ),
                "bytes_received_human": format_bytes(
                    data.bytes_recv
                ),
            }

            for interface, data
            in stats.items()
        }

    except OSError:
        return {}


def get_interface_state(interface):
    """
    Return whether an interface is operational.
    """

    path = (
        f"/sys/class/net/"
        f"{interface}/operstate"
    )

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:

            return file.read().strip()

    except (
        FileNotFoundError,
        OSError,
    ):
        return "unknown"


def get_interface_ip(interface):
    """
    Return the first IPv4 address assigned to
    an interface.
    """

    result = _run_command(
        [
            "ip",
            "-4",
            "-o",
            "addr",
            "show",
            "dev",
            interface,
        ]
    )

    if result is None:
        return None

    for line in result.stdout.splitlines():

        parts = line.split()

        if "inet" not in parts:
            continue

        index = parts.index("inet")

        if index + 1 < len(parts):

            return (
                parts[index + 1]
                .split("/")[0]
            )

    return None


def get_interface_health(interface):
    """
    Return a complete status snapshot for
    one network interface.
    """

    stats = get_interface_stats(
        interface
    )

    return {
        "interface": interface,
        "state": get_interface_state(
            interface
        ),
        "ip": get_interface_ip(
            interface
        ),
        "stats": stats,
    }


def get_connection_count():
    """
    Return the number of active TCP connections.
    """

    if psutil is None:
        return None

    try:

        connections = psutil.net_connections(
            kind="tcp"
        )

        return len(connections)

    except (
        psutil.AccessDenied,
        OSError,
    ):
        return None


def get_default_route():
    """
    Return the Linux default route.
    """

    result = _run_command(
        [
            "ip",
            "route",
            "show",
            "default",
        ]
    )

    if result is None:
        return None

    lines = result.stdout.splitlines()

    if not lines:
        return None

    return lines[0]


def check_internet():
    """
    Test basic Internet connectivity.

    This is intentionally a simple ICMP test.
    """

    result = _run_command(
        [
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "1.1.1.1",
        ],
        timeout=4,
    )

    if result is None:
        return False

    return result.returncode == 0


# ============================================================
# Service Monitoring
# ============================================================

def get_service_status(service):
    """
    Return the systemd state of a service.
    """

    result = _run_command(
        [
            "systemctl",
            "is-active",
            service,
        ]
    )

    if result is None:
        return None

    return result.stdout.strip()


def get_gateway_services_status():
    """
    Return PiHarbor service states.
    """

    services = {
        "pi_gateway": "pi-gateway.service",
        "piharbor_lan": "piharbor-lan.service",
        "hostapd": "hostapd.service",
        "dnsmasq": "dnsmasq.service",
        "nftables": "nftables.service",
        "ssh": "ssh.service",
    }

    return {
        name: get_service_status(
            service
        )

        for name, service
        in services.items()
    }


# ============================================================
# NAT Monitoring
# ============================================================

def get_nat_status():
    """
    Return the current PiHarbor NAT state.
    """

    try:

        import nat

        return nat.get_nat_status()

    except (
        ImportError,
        AttributeError,
        OSError,
    ):

        return {
            "enabled": False,
            "rules": "",
            "error": (
                "NAT monitoring unavailable"
            ),
        }


# ============================================================
# VPN Monitoring
# ============================================================

def get_vpn_status():
    """
    Return the operational state of WireGuard.
    """

    result = _run_command(
        [
            "wg",
            "show",
            "wg0",
        ]
    )

    if result is None:
        return "unknown"

    if result.returncode != 0:
        return "inactive"

    return "active"


def get_vpn_handshake():
    """
    Return WireGuard peer handshake information.
    """

    result = _run_command(
        [
            "wg",
            "show",
            "wg0",
            "latest-handshakes",
        ]
    )

    if result is None:
        return {}

    if result.returncode != 0:
        return {}

    handshakes = {}

    for line in result.stdout.splitlines():

        parts = line.split()

        if len(parts) != 2:
            continue

        public_key = parts[0]

        try:
            timestamp = int(parts[1])

        except ValueError:
            timestamp = None

        handshakes[
            public_key
        ] = timestamp

    return handshakes


def get_vpn_statistics():
    """
    Return WireGuard transfer statistics.
    """

    result = _run_command(
        [
            "wg",
            "show",
            "wg0",
            "transfer",
        ]
    )

    if result is None:
        return {}

    if result.returncode != 0:
        return {}

    statistics = {}

    for line in result.stdout.splitlines():

        parts = line.split()

        if len(parts) != 3:
            continue

        public_key = parts[0]

        try:

            received = int(
                parts[1]
            )

            sent = int(
                parts[2]
            )

        except ValueError:
            continue

        statistics[
            public_key
        ] = {
            "bytes_received": received,
            "bytes_sent": sent,
            "bytes_received_human":
                format_bytes(
                    received
                ),
            "bytes_sent_human":
                format_bytes(
                    sent
                ),
        }

    return statistics


# ============================================================
# DNS Monitoring
# ============================================================

def get_dns_health():
    """
    Return DNS health information.
    """

    try:

        import dns

        return dns.get_dns_health()

    except (
        ImportError,
        AttributeError,
    ):

        return {
            "status": "unknown",
            "reason": (
                "DNS monitoring not implemented"
            ),
        }


# ============================================================
# DHCP Monitoring
# ============================================================

def get_dhcp_health():
    """
    Return DHCP health information.
    """

    try:

        import dhcp

        return dhcp.get_dhcp_health()

    except (
        ImportError,
        AttributeError,
    ):

        return {
            "status": "unknown",
            "reason": (
                "DHCP monitoring not implemented"
            ),
        }


# ============================================================
# Firewall Monitoring
# ============================================================

def get_firewall_health():
    """
    Return firewall health information.
    """

    try:

        import firewall

        status = (
            firewall.get_firewall_status()
        )

        return {
            "status": status
        }

    except (
        ImportError,
        AttributeError,
    ):

        return {
            "status": "unknown",
            "reason": (
                "Firewall monitoring not implemented"
            ),
        }


# ============================================================
# Dashboard Metrics
# ============================================================

def get_dashboard_metrics(
    wan_interface="eth0",
    lan_interface="wlan0",
):
    """
    Return the information required by
    the PiHarbor dashboard.
    """

    wan = get_interface_health(
        wan_interface
    )

    lan = get_interface_health(
        lan_interface
    )

    services = (
        get_gateway_services_status()
    )

    nat = get_nat_status()

    return {
        "system": get_system_status(),

        "network": {
            "wan": wan,
            "lan": lan,
            "default_route":
                get_default_route(),
            "internet":
                check_internet(),
            "connections":
                get_connection_count(),
        },

        "services": services,

        "nat": nat,

        "vpn": {
            "status":
                get_vpn_status(),
            "handshakes":
                get_vpn_handshake(),
            "statistics":
                get_vpn_statistics(),
        },

        "dns":
            get_dns_health(),

        "dhcp":
            get_dhcp_health(),

        "firewall":
            get_firewall_health(),

        "timestamp":
            time.time(),
    }


# ============================================================
# Gateway Health
# ============================================================

def get_gateway_health():
    """
    Return a combined health snapshot of
    the PiHarbor gateway.

    This preserves the original interface
    used by the existing GUI.
    """

    return {
        "system":
            get_system_status(),

        "network":
            get_network_stats(),

        "connections":
            get_connection_count(),

        "services":
            get_gateway_services_status(),

        "nat":
            get_nat_status(),

        "vpn": {
            "status":
                get_vpn_status(),
            "handshakes":
                get_vpn_handshake(),
            "statistics":
                get_vpn_statistics(),
        },

        "dns":
            get_dns_health(),

        "dhcp":
            get_dhcp_health(),

        "firewall":
            get_firewall_health(),
    }


# ============================================================
# Network health convenience wrapper
# ============================================================

def get_network_health():

    try:

        import network

        return network.get_network_status()

    except (
        ImportError,
        AttributeError,
    ):

        return {
            "status": "unknown"
        }


# ============================================================
# Standalone test
# ============================================================

if __name__ == "__main__":

    print(
        "==================================="
    )

    print(
        "PiHarbor Monitoring"
    )

    print(
        "==================================="
    )

    print()

    print(
        "System:"
    )

    system = get_system_status()

    for key, value in system.items():

        print(
            f"  {key}: {value}"
        )

    print()

    print(
        "Network:"
    )

    dashboard = get_dashboard_metrics()

    print(
        f"  WAN: "
        f"{dashboard['network']['wan']}"
    )

    print(
        f"  LAN: "
        f"{dashboard['network']['lan']}"
    )

    print(
        f"  Internet: "
        f"{dashboard['network']['internet']}"
    )

    print(
        f"  Connections: "
        f"{dashboard['network']['connections']}"
    )

    print()

    print(
        "Services:"
    )

    for name, status in (
        dashboard["services"].items()
    ):

        print(
            f"  {name}: {status}"
        )

    print()

    print(
        "NAT:"
    )

    print(
        f"  Enabled: "
        f"{dashboard['nat'].get('enabled')}"
    )

    print()

    print(
        "PiHarbor monitoring test complete."
    )

