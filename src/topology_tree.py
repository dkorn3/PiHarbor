"""
PiHarbor Network Topology Tree

Builds a simple, JSON-serializable representation of the gateway's
current network topology.  network_gui.py can call get_topology()
and render the returned tree.
"""

import ipaddress
import os
import subprocess

try:
    import config as gateway_config
except ImportError:
    gateway_config = None


DEFAULT_WAN = "eth0"
DEFAULT_LAN = "wlan0"
DEFAULT_LAN_IP = "192.168.50.1"


def run_command(command, timeout=3):
    """Run a system command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None


def get_network_config():
    """Load network configuration with safe defaults."""
    if gateway_config is None:
        return {
            "wan_interface": DEFAULT_WAN,
            "lan_interface": DEFAULT_LAN,
        }

    try:
        config = gateway_config.load_config()
        network = config.get("network", {})
        return network if isinstance(network, dict) else {}
    except Exception:
        return {}


def get_interface_ip(interface):
    """Return the first IPv4 address assigned to an interface."""
    output = run_command(
        ["ip", "-4", "addr", "show", "dev", interface]
    )

    if not output:
        return None

    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("inet "):
            continue

        address = line.split()[1].split("/")[0]

        try:
            if ipaddress.ip_address(address).version == 4:
                return address
        except ValueError:
            continue

    return None


def get_interface_state(interface):
    """Return a simple up/down state for an interface."""
    output = run_command(
        ["cat", f"/sys/class/net/{interface}/operstate"]
    )

    if output:
        return output.lower()

    return "unknown"


def get_default_gateway():
    """Return the current IPv4 default gateway address."""
    output = run_command(["ip", "-4", "route", "show", "default"])

    if not output:
        return None

    for line in output.splitlines():
        parts = line.split()

        if "via" not in parts:
            continue

        index = parts.index("via")

        if index + 1 >= len(parts):
            continue

        gateway = parts[index + 1]

        try:
            if ipaddress.ip_address(gateway).version == 4:
                return gateway
        except ValueError:
            continue

    return None


def get_dhcp_leases():
    """Read dnsmasq DHCP leases."""
    lease_files = (
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/dnsmasq/dnsmasq.leases",
    )

    lease_file = next(
        (path for path in lease_files if os.path.exists(path)),
        None,
    )

    if lease_file is None:
        return {}

    leases = {}

    try:
        with open(lease_file, "r", encoding="utf-8") as file:
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
                        hostname if hostname != "*" else "Unknown"
                    ),
                    "ip": ip,
                    "mac": mac,
                }
    except (OSError, ValueError):
        return {}

    return leases


def get_arp_devices(interface):
    """Return IPv4 neighbors currently visible on an interface."""
    output = run_command(
        ["ip", "neigh", "show", "dev", interface]
    )

    if not output:
        return {}

    devices = {}

    for line in output.splitlines():
        parts = line.split()

        if not parts:
            continue

        ip = parts[0]

        try:
            if ipaddress.ip_address(ip).version != 4:
                continue
        except ValueError:
            continue

        mac = None
        state = "unknown"

        for index, value in enumerate(parts):
            if value == "lladdr" and index + 1 < len(parts):
                mac = parts[index + 1]

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
            "connected": state not in ("failed", "incomplete"),
        }

    return devices


def get_clients(lan_interface):
    """Combine DHCP leases and ARP neighbors into topology clients."""
    leases = get_dhcp_leases()
    arp = get_arp_devices(lan_interface)

    clients = {}

    for ip, lease in leases.items():
        client = dict(lease)

        if ip in arp:
            neighbor = arp[ip]
            client["mac"] = neighbor.get("mac") or client.get("mac")
            client["state"] = neighbor.get("state", "unknown")
            client["connected"] = neighbor.get("connected", True)
        else:
            client["state"] = "unknown"
            client["connected"] = True

        clients[ip] = client

    for ip, neighbor in arp.items():
        if ip in clients:
            continue

        clients[ip] = {
            "hostname": "Unknown",
            "ip": ip,
            "mac": neighbor.get("mac"),
            "state": neighbor.get("state", "unknown"),
            "connected": neighbor.get("connected", False),
        }

    return sorted(
        clients.values(),
        key=lambda client: tuple(
            int(part) for part in client["ip"].split(".")
        ),
    )


def get_wireguard_status():
    """Return basic wg0 state when WireGuard is available."""
    output = run_command(["ip", "link", "show", "wg0"])

    if output is None:
        return {
            "present": False,
            "active": False,
        }

    return {
        "present": True,
        "active": "state UP" in output or "UP" in output,
    }


def get_topology():
    """Build and return the current network topology tree."""
    network = get_network_config()

    wan_interface = network.get("wan_interface", DEFAULT_WAN)
    lan_interface = network.get("lan_interface", DEFAULT_LAN)

    wan_ip = get_interface_ip(wan_interface)
    lan_ip = get_interface_ip(lan_interface) or DEFAULT_LAN_IP
    wan_state = get_interface_state(wan_interface)
    lan_state = get_interface_state(lan_interface)
    upstream_gateway = get_default_gateway()
    clients = get_clients(lan_interface)
    wireguard = get_wireguard_status()

    client_nodes = []

    for client in clients:
        label = client.get("hostname") or "Unknown"
        details = client.get("ip") or "Unknown IP"

        client_nodes.append(
            {
                "type": "device",
                "label": label,
                "details": details,
                "status": (
                    "Online"
                    if client.get("connected", False)
                    else "Offline"
                ),
                "children": [],
            }
        )

    lan_children = []

    if wireguard.get("present"):
        lan_children.append(
            {
                "type": "vpn",
                "label": "WireGuard wg0",
                "details": (
                    "Active"
                    if wireguard.get("active")
                    else "Inactive"
                ),
                "status": (
                    "Online"
                    if wireguard.get("active")
                    else "Offline"
                ),
                "children": [],
            }
        )

    lan_children.extend(client_nodes)

    pi_node = {
        "type": "gateway",
        "label": "PiHarbor",
        "details": "Network Gateway",
        "status": "Online",
        "children": [
            {
                "type": "interface",
                "label": f"{wan_interface} (WAN)",
                "details": wan_ip or "No IPv4 address",
                "status": wan_state.capitalize(),
                "children": [],
            },
            {
                "type": "interface",
                "label": f"{lan_interface} (LAN)",
                "details": f"{lan_ip}/24",
                "status": lan_state.capitalize(),
                "children": lan_children,
            },
        ],
    }

    return {
        "label": "Internet",
        "details": "Upstream network",
        "status": "Detected" if upstream_gateway else "Unknown",
        "children": [
            {
                "type": "router",
                "label": "Home Router",
                "details": upstream_gateway or "Unknown gateway",
                "status": "Detected" if upstream_gateway else "Unknown",
                "children": [pi_node],
            }
        ],
        "metadata": {
            "wan_interface": wan_interface,
            "wan_ip": wan_ip,
            "lan_interface": lan_interface,
            "lan_ip": lan_ip,
            "upstream_gateway": upstream_gateway,
            "client_count": len(clients),
            "wireguard_present": wireguard.get("present", False),
            "wireguard_active": wireguard.get("active", False),
        },
    }
