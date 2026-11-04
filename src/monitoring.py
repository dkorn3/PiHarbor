
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
    """Run a system command safely."""

    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def format_bytes(value):
    """Convert bytes into a human-readable string."""

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
    """Convert uptime into a readable string."""

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
    """Return an overall system health snapshot."""

    uptime = get_uptime()

    return {
        "cpu_usage": get_cpu_usage(),
        "cpu_frequency": get_cpu_frequency(),
        "memory_usage": get_memory_usage(),
        "storage_usage": get_storage_usage(),
        "temperature": get_temperature(),
        "uptime": uptime,
        "uptime_text": format_uptime(uptime),
        "load_average": get_load_average(),
    }


def get_cpu_usage():
    """Return CPU utilization percentage."""

    if psutil is not None:
        try:
            return round(psutil.cpu_percent(interval=0.2), 1)
        except (OSError, ValueError):
            pass

    return None


def get_cpu_frequency():
    """Return current CPU frequency in MHz and GHz."""

    if psutil is not None:
        try:
            frequency = psutil.cpu_freq()

            if frequency and frequency.current:
                mhz = round(frequency.current, 1)

                return {
                    "mhz": mhz,
                    "ghz": round(mhz / 1000, 2),
                }

        except (OSError, ValueError):
            pass

    paths = [
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq",
    ]

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as file:
                mhz = int(file.read().strip()) / 1000

            return {
                "mhz": round(mhz, 1),
                "ghz": round(mhz / 1000, 2),
            }

        except (FileNotFoundError, ValueError, OSError):
            continue

    return {
        "mhz": None,
        "ghz": None,
    }


def get_memory_usage():
    """Return memory utilization percentage."""

    if psutil is None:
        return None

    try:
        return round(psutil.virtual_memory().percent, 1)
    except OSError:
        return None


def get_memory_details():
    """Return detailed memory statistics."""

    if psutil is None:
        return {}

    try:
        memory = psutil.virtual_memory()

        return {
            "total": memory.total,
            "available": memory.available,
            "used": memory.used,
            "percent": memory.percent,
            "total_human": format_bytes(memory.total),
            "used_human": format_bytes(memory.used),
            "available_human": format_bytes(memory.available),
        }

    except OSError:
        return {}


def get_storage_usage():
    """Return root filesystem utilization."""

    if psutil is None:
        return None

    try:
        return round(psutil.disk_usage("/").percent, 1)
    except OSError:
        return None


def get_storage_details():
    """Return detailed root filesystem storage."""

    if psutil is None:
        return {}

    try:
        disk = psutil.disk_usage("/")

        return {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent,
            "total_human": format_bytes(disk.total),
            "used_human": format_bytes(disk.used),
            "free_human": format_bytes(disk.free),
        }

    except OSError:
        return {}


def get_temperature():
    """Return CPU/system temperature in Celsius."""

    temperature_file = (
        "/sys/class/thermal/thermal_zone0/temp"
    )

    try:
        with open(temperature_file, "r", encoding="utf-8") as file:
            temperature = int(file.read().strip())

        return round(temperature / 1000.0, 1)

    except (FileNotFoundError, ValueError, OSError):
        return None


def get_uptime():
    """Return system uptime in seconds."""

    if psutil is not None:
        try:
            return time.time() - psutil.boot_time()
        except OSError:
            pass

    try:
        with open("/proc/uptime", "r", encoding="utf-8") as file:
            return float(file.read().split()[0])

    except (FileNotFoundError, ValueError, OSError):
        return None


def get_load_average():
    """Return Linux load averages."""

    try:
        load1, load5, load15 = os.getloadavg()

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

# Previous interface counters for throughput calculations.
_interface_previous = {}


def get_interface_stats(interface):
    """Return traffic and error statistics for an interface."""

    if psutil is None:
        return None

    try:
        stats = psutil.net_io_counters(pernic=True)

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
            "bytes_sent_human": format_bytes(data.bytes_sent),
            "bytes_received_human": format_bytes(data.bytes_recv),
        }

    except OSError:
        return None


def get_network_stats():
    """Return statistics for all network interfaces."""

    if psutil is None:
        return {}

    try:
        stats = psutil.net_io_counters(pernic=True)

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
                "bytes_sent_human": format_bytes(data.bytes_sent),
                "bytes_received_human": format_bytes(data.bytes_recv),
            }
            for interface, data in stats.items()
        }

    except OSError:
        return {}


def get_interface_state(interface):
    """Return whether an interface is operational."""

    path = f"/sys/class/net/{interface}/operstate"

    try:
        with open(path, "r", encoding="utf-8") as file:
            return file.read().strip()

    except (FileNotFoundError, OSError):
        return "unknown"


def get_interface_ip(interface):
    """Return the first IPv4 address assigned to an interface."""

    result = _run_command([
        "ip", "-4", "-o", "addr", "show", "dev", interface
    ])

    if result is None:
        return None

    for line in result.stdout.splitlines():
        parts = line.split()

        if "inet" not in parts:
            continue

        index = parts.index("inet")

        if index + 1 < len(parts):
            return parts[index + 1].split("/")[0]

    return None


# ============================================================
# Ethernet Link Capacity
# ============================================================

def get_ethernet_link_capacity(interface):
    """Detect negotiated Ethernet speed in Mbps."""

    path = f"/sys/class/net/{interface}/speed"

    try:
        with open(path, "r", encoding="utf-8") as file:
            speed = int(file.read().strip())

        if speed > 0:
            return {
                "mbps": speed,
                "gbps": round(speed / 1000, 2),
                "source": "sysfs",
            }

    except (FileNotFoundError, ValueError, OSError):
        pass

    result = _run_command(["ethtool", interface])

    if result is not None:
        for line in result.stdout.splitlines():

            if "Speed:" not in line:
                continue

            value = line.split("Speed:")[-1].strip()

            if value.lower().endswith("mb/s"):
                try:
                    speed = int(value[:-4].strip())

                    if speed > 0:
                        return {
                            "mbps": speed,
                            "gbps": round(speed / 1000, 2),
                            "source": "ethtool",
                        }

                except ValueError:
                    pass

    return {
        "mbps": None,
        "gbps": None,
        "source": "unavailable",
    }


# ============================================================
# Wi-Fi Link Capacity
# ============================================================

def get_wifi_clients(interface):
    """
    Return connected Wi-Fi client information.

    Uses iw station dump.
    TX/RX bitrate represents negotiated PHY rates
    for individual clients, not aggregate AP capacity.
    """

    result = _run_command([
        "iw", "dev", interface, "station", "dump"
    ])

    if result is None or result.returncode != 0:
        return []

    clients = []
    current = None

    for line in result.stdout.splitlines():

        line = line.strip()

        if line.startswith("Station "):

            if current:
                clients.append(current)

            parts = line.split()

            current = {
                "mac": parts[1] if len(parts) > 1 else "unknown",
                "tx_bitrate_mbps": None,
                "rx_bitrate_mbps": None,
            }

        elif current and "tx bitrate:" in line:

            try:
                value = line.split("tx bitrate:")[-1].strip()
                current["tx_bitrate_mbps"] = float(value.split()[0])

            except (ValueError, IndexError):
                pass

        elif current and "rx bitrate:" in line:

            try:
                value = line.split("rx bitrate:")[-1].strip()
                current["rx_bitrate_mbps"] = float(value.split()[0])

            except (ValueError, IndexError):
                pass

    if current:
        clients.append(current)

    return clients


def get_wifi_link_capacity(interface):
    """
    Return indicative Wi-Fi client bitrate information.

    Highest observed client bitrate is NOT the total
    wireless AP capacity.
    """

    clients = get_wifi_clients(interface)

    rates = []

    for client in clients:

        tx = client["tx_bitrate_mbps"]
        rx = client["rx_bitrate_mbps"]

        if tx is not None:
            rates.append(tx)

        if rx is not None:
            rates.append(rx)

    highest_rate = max(rates) if rates else None

    return {
        "mbps": round(highest_rate, 1) if highest_rate else None,
        "gbps": (
            round(highest_rate / 1000, 2)
            if highest_rate else None
        ),
        "source": "iw_station_clients" if highest_rate else "unavailable",
        "clients_connected": len(clients),
        "clients": clients,
        "capacity_type": "highest_observed_client_bitrate",
    }


def get_interface_link_capacity(interface):
    """
    Detect interface link capacity.

    Wi-Fi interfaces use client bitrate detection.
    Other interfaces use Ethernet negotiation.
    """

    try:
        wireless_path = f"/sys/class/net/{interface}/wireless"

        if os.path.exists(wireless_path):
            return get_wifi_link_capacity(interface)

        return get_ethernet_link_capacity(interface)

    except OSError:
        return {
            "mbps": None,
            "gbps": None,
            "source": "unavailable",
        }


# ============================================================
# Network Throughput
# ============================================================

def get_interface_throughput(interface):
    """
    Calculate real-time RX/TX throughput.

    Uses interface counters and elapsed time.
    Utilization is calculated only when a reliable
    link capacity is available.
    """

    empty_result = {
        "rx_mbps": None,
        "tx_mbps": None,
        "rx_usage_percent": None,
        "tx_usage_percent": None,
    }

    if psutil is None:
        return empty_result

    try:
        counters = psutil.net_io_counters(pernic=True)

        if interface not in counters:
            return empty_result

        current = counters[interface]
        now = time.monotonic()

        previous = _interface_previous.get(interface)

        _interface_previous[interface] = {
            "rx": current.bytes_recv,
            "tx": current.bytes_sent,
            "time": now,
        }

        if previous is None:
            return empty_result

        elapsed = now - previous["time"]

        if elapsed <= 0:
            return empty_result

        rx_bytes = max(
            0,
            current.bytes_recv - previous["rx"]
        )

        tx_bytes = max(
            0,
            current.bytes_sent - previous["tx"]
        )

        rx_mbps = rx_bytes * 8 / elapsed / 1_000_000
        tx_mbps = tx_bytes * 8 / elapsed / 1_000_000

        capacity = get_interface_link_capacity(interface)
        link_speed = capacity.get("mbps")

        if link_speed:

            rx_usage = min(
                100.0,
                (rx_mbps / link_speed) * 100
            )

            tx_usage = min(
                100.0,
                (tx_mbps / link_speed) * 100
            )

        else:
            rx_usage = None
            tx_usage = None

        return {
            "rx_mbps": round(rx_mbps, 2),
            "tx_mbps": round(tx_mbps, 2),
            "rx_usage_percent": (
                round(rx_usage, 1)
                if rx_usage is not None else None
            ),
            "tx_usage_percent": (
                round(tx_usage, 1)
                if tx_usage is not None else None
            ),
        }

    except (OSError, ValueError, KeyError):
        return empty_result


# ============================================================
# Complete Interface Health
# ============================================================

def get_interface_health(interface):
    """Return complete status for one network interface."""

    return {
        "interface": interface,
        "state": get_interface_state(interface),
        "ip": get_interface_ip(interface),
        "stats": get_interface_stats(interface),
        "link_capacity": get_interface_link_capacity(interface),
        "throughput": get_interface_throughput(interface),
    }


def get_connection_count():
    """Return active TCP connection count."""

    if psutil is None:
        return None

    try:
        connections = psutil.net_connections(kind="tcp")
        return len(connections)

    except (psutil.AccessDenied, OSError):
        return None


def get_default_route():
    """Return Linux default route."""

    result = _run_command([
        "ip", "route", "show", "default"
    ])

    if result is None:
        return None

    lines = result.stdout.splitlines()

    return lines[0] if lines else None


def check_internet():
    """Test basic Internet connectivity."""

    result = _run_command(
        ["ping", "-c", "1", "-W", "2", "1.1.1.1"],
        timeout=4,
    )

    if result is None:
        return False

    return result.returncode == 0


# ============================================================
# Service Monitoring
# ============================================================

def get_service_status(service):
    """Return systemd service state."""

    result = _run_command([
        "systemctl", "is-active", service
    ])

    if result is None:
        return None

    return result.stdout.strip()


def get_gateway_services_status():
    """Return PiHarbor service states."""

    services = {
        "pi_gateway": "pi-gateway.service",
        "piharbor_lan": "piharbor-lan.service",
        "hostapd": "hostapd.service",
        "dnsmasq": "dnsmasq.service",
        "nftables": "nftables.service",
        "ssh": "ssh.service",
    }

    return {
        name: get_service_status(service)
        for name, service in services.items()
    }


# ============================================================
# NAT Monitoring
# ============================================================

def get_nat_status():
    """Return current PiHarbor NAT state."""

    try:
        import nat
        return nat.get_nat_status()

    except (ImportError, AttributeError, OSError):
        return {
            "enabled": False,
            "rules": "",
            "error": "NAT monitoring unavailable",
        }


# ============================================================
# DNS Monitoring
# ============================================================

def get_dns_health():
    """Return DNS health information."""

    try:
        import dns
        return dns.get_dns_health()

    except (ImportError, AttributeError):
        return {
            "status": "unknown",
            "reason": "DNS monitoring not implemented",
        }


# ============================================================
# DHCP Monitoring
# ============================================================

def get_dhcp_health():
    """Return DHCP health information."""

    try:
        import dhcp
        return dhcp.get_dhcp_health()

    except (ImportError, AttributeError):
        return {
            "status": "unknown",
            "reason": "DHCP monitoring not implemented",
        }


# ============================================================
# Firewall Monitoring
# ============================================================

def get_firewall_health():
    """Return firewall health information."""

    try:
        import firewall

        status = firewall.get_firewall_status()

        return {
            "status": status
        }

    except (ImportError, AttributeError):
        return {
            "status": "unknown",
            "reason": "Firewall monitoring not implemented",
        }


# ============================================================
# Dashboard Metrics
# ============================================================

def get_dashboard_metrics(
    wan_interface="eth0",
    lan_interface="wlan0",
):
    """
    Return information required by the PiHarbor dashboard.

    WAN: eth0
    LAN: wlan0
    """

    wan = get_interface_health(wan_interface)
    lan = get_interface_health(lan_interface)

    return {
        "system": get_system_status(),

        "network": {
            "wan": wan,
            "lan": lan,
            "default_route": get_default_route(),
            "internet": check_internet(),
            "connections": get_connection_count(),
        },

        "services": get_gateway_services_status(),
        "nat": get_nat_status(),
        "dns": get_dns_health(),
        "dhcp": get_dhcp_health(),
        "firewall": get_firewall_health(),
        "timestamp": time.time(),
    }


# ============================================================
# Gateway Health
# ============================================================

def get_gateway_health():
    """
    Return combined PiHarbor gateway health.

    Preserves the original interface used by the GUI.
    """

    return {
        "system": get_system_status(),
        "network": get_network_stats(),
        "connections": get_connection_count(),
        "services": get_gateway_services_status(),
        "nat": get_nat_status(),
        "dns": get_dns_health(),
        "dhcp": get_dhcp_health(),
        "firewall": get_firewall_health(),
    }


# ============================================================
# Network Health Convenience Wrapper
# ============================================================

def get_network_health():

    try:
        import network
        return network.get_network_status()

    except (ImportError, AttributeError):
        return {
            "status": "unknown"
        }


# ============================================================
# Standalone Test
# ============================================================

if __name__ == "__main__":

    print("===================================")
    print("PiHarbor Monitoring")
    print("===================================")

    print("\nSystem:")

    system = get_system_status()

    for key, value in system.items():
        print(f"  {key}: {value}")

    print("\nNetwork:")

    dashboard = get_dashboard_metrics()

    for name in ("wan", "lan"):

        interface = dashboard["network"][name]

        print(f"\n  {name.upper()}:")
        print(f"    Interface: {interface['interface']}")
        print(f"    State: {interface['state']}")
        print(f"    IP: {interface['ip']}")
        print(f"    Link capacity: {interface['link_capacity']}")
        print(f"    Throughput: {interface['throughput']}")

        if name == "lan":
            print(
                f"    Wi-Fi clients: "
                f"{interface['link_capacity'].get('clients', [])}"
            )

    print("\nServices:")

    for name, status in dashboard["services"].items():
        print(f"  {name}: {status}")

    print("\nNAT:")
    print(f"  Enabled: {dashboard['nat'].get('enabled')}")

    print("\nPiHarbor monitoring test complete.")
