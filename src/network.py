
import os
import socket
import subprocess


# ============================================================
# PiHarbor Network Configuration
# ============================================================

WAN_INTERFACE = "eth0"
LAN_INTERFACE = "wlan0"
LAN_ADDRESS = "192.168.50.1/24"


# ============================================================
# Helpers
# ============================================================

def run_command(command, check=False):
    """
    Run a system command and return the CompletedProcess object.
    """
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=check
    )


# ============================================================
# Interface Discovery
# ============================================================

def get_interfaces():
    """
    Return all network interface names.
    """
    return [name for _, name in socket.if_nameindex()]


def get_interface_status(interface):
    """
    Return Linux operational state for an interface.
    """
    try:
        with open(f"/sys/class/net/{interface}/operstate", "r") as file:
            return file.read().strip()

    except FileNotFoundError:
        return None


def get_interface_type(interface):
    """
    Return a human-readable interface type.
    """
    interface_path = f"/sys/class/net/{interface}"

    try:
        if os.path.isdir(f"{interface_path}/wireless"):
            return "wifi"

        with open(f"{interface_path}/type", "r") as file:
            interface_type = int(file.read().strip())

        if interface_type == 772:
            return "loopback"

        if interface_type == 1:
            return "ethernet"

        return f"unknown ({interface_type})"

    except FileNotFoundError:
        return None


# ============================================================
# Address Information
# ============================================================

def get_ip_addresses(interface):
    """
    Return IPv4 and IPv6 addresses assigned to an interface.
    """
    result = run_command(
        ["ip", "addr", "show", interface]
    )

    if result.returncode != 0:
        return []

    addresses = []

    for line in result.stdout.splitlines():
        parts = line.split()

        if parts and parts[0] in ("inet", "inet6"):
            addresses.append(parts[1])

    return addresses


def get_mac_address(interface):
    """
    Return the MAC address of an interface.
    """
    try:
        with open(f"/sys/class/net/{interface}/address", "r") as file:
            return file.read().strip()

    except FileNotFoundError:
        return None


# ============================================================
# Routing
# ============================================================

def get_routes():
    """
    Return the kernel routing table.
    """
    result = run_command(["ip", "route"])

    if result.returncode != 0:
        return []

    return [
        line
        for line in result.stdout.splitlines()
        if line.strip()
    ]


def get_default_route():
    """
    Return the current default IPv4 route.
    """
    for route in get_routes():
        if route.startswith("default"):
            return route

    return None


# ============================================================
# IPv4 Forwarding
# ============================================================

def get_ipv4_forwarding():
    """
    Return whether Linux IPv4 forwarding is enabled.
    """
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as file:
            return file.read().strip() == "1"

    except (FileNotFoundError, OSError):
        return None


def set_ipv4_forwarding(enabled):
    """
    Enable or disable IPv4 forwarding.

    Requires root privileges.
    """
    value = "1" if enabled else "0"

    result = run_command(
        ["sysctl", "-w", f"net.ipv4.ip_forward={value}"]
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or
            "Failed to change IPv4 forwarding"
        )

    return get_ipv4_forwarding()


# ============================================================
# LAN Configuration
# ============================================================

def configure_lan(interface, address=LAN_ADDRESS):
    """
    Configure the protected LAN interface with a static IPv4 address.

    This function:
    - verifies that the interface exists
    - brings it up
    - assigns the configured address

    It does not configure DHCP, NAT, or firewall rules.
    """
    if interface not in get_interfaces():
        raise RuntimeError(
            f"LAN interface '{interface}' does not exist"
        )

    result = run_command(
        ["ip", "link", "set", "dev", interface, "up"]
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or
            f"Failed to bring {interface} up"
        )

    result = run_command(
        ["ip", "addr", "replace", address, "dev", interface]
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or
            f"Failed to assign {address} to {interface}"
        )

    return {
        "interface": interface,
        "address": address,
        "status": get_interface_status(interface),
        "addresses": get_ip_addresses(interface),
    }


# ============================================================
# Router Configuration
# ============================================================

def configure_router():
    """
    Configure PiHarbor as a basic IPv4 router.

    WAN:
        eth0 → upstream router / Internet

    LAN:
        wlan0 → PiHarbor Wi-Fi clients

    This function:
    - verifies both interfaces exist
    - brings both interfaces up
    - configures the LAN address
    - enables IPv4 forwarding

    NAT, DHCP, DNS, and firewall rules are handled
    by their respective PiHarbor modules.
    """

    if WAN_INTERFACE not in get_interfaces():
        raise RuntimeError(
            f"WAN interface '{WAN_INTERFACE}' does not exist"
        )

    if LAN_INTERFACE not in get_interfaces():
        raise RuntimeError(
            f"LAN interface '{LAN_INTERFACE}' does not exist"
        )

    # Bring both interfaces up
    for interface in (WAN_INTERFACE, LAN_INTERFACE):
        result = run_command(
            ["ip", "link", "set", "dev", interface, "up"]
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip() or
                f"Failed to bring {interface} up"
            )

    # Configure LAN
    configure_lan(
        LAN_INTERFACE,
        LAN_ADDRESS
    )

    # Enable IPv4 forwarding
    set_ipv4_forwarding(True)

    return get_network_status()


# ============================================================
# Network Status
# ============================================================

def get_network_status():
    """
    Return a complete snapshot of network state.
    """
    interfaces = {}

    for interface in get_interfaces():
        interfaces[interface] = {
            "name": interface,
            "status": get_interface_status(interface),
            "type": get_interface_type(interface),
            "mac": get_mac_address(interface),
            "addresses": get_ip_addresses(interface),
        }

    return {
        "interfaces": interfaces,
        "default_route": get_default_route(),
        "ipv4_forwarding": get_ipv4_forwarding(),
        "routes": get_routes(),
        "wan_interface": WAN_INTERFACE,
        "lan_interface": LAN_INTERFACE,
        "lan_address": LAN_ADDRESS,
    }


# ============================================================
# Test
# ============================================================

if __name__ == "__main__":
    print("=== PIHARBOR NETWORK CONFIGURATION ===")
    print(f"WAN interface: {WAN_INTERFACE}")
    print(f"LAN interface: {LAN_INTERFACE}")
    print(f"LAN address:   {LAN_ADDRESS}")

    print()
    print("=== INTERFACES ===")

    for interface in get_interfaces():
        print(
            interface,
            "|",
            get_interface_type(interface),
            "|",
            get_interface_status(interface),
            "|",
            get_ip_addresses(interface)
        )

    print()
    print("=== DEFAULT ROUTE ===")
    print(get_default_route())

    print()
    print("=== IPV4 FORWARDING ===")
    print(get_ipv4_forwarding())

    print()
    print("=== ROUTES ===")

    for route in get_routes():
        print(route)

