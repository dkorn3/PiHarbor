from copy import deepcopy
import ipaddress
import os
import tempfile

try:
    import yaml
except ImportError as exc:
    raise RuntimeError(
        "PyYAML is required. Install it with: sudo apt install python3-yaml"
    ) from exc


CONFIG_FILE = "config/gateway.yaml"


DEFAULT_CONFIG = {
    "network": {
        "wan_interface": "eth0",
        "wan_dhcp": True,
        "lan_interface": "wlan0",
        "lan_address": "192.168.50.1/24",
        "lan_network": "192.168.50.0/24",
        "ipv4_forwarding": True,
        "nat_enabled": False,
    },
    "firewall": {
        "enabled": False,
        "table": "inet pi_gateway",
        "default_policy": "drop",
        "allow_established": True,
        "allow_related": True,
        "allow_lan_to_wan": True,
        "allow_dhcp": True,
        "allow_dns": True,
        "allow_ssh": True,
        "allow_management_from_wan": False,
        "rules": [],
    },
    "dns": {
        "enabled": False,
        "listen_address": "192.168.50.1",
        "listen_port": 53,
        "upstream_servers": ["1.1.1.1", "9.9.9.9"],
        "block_direct_dns": True,
        "logging": True,
        "allowlist": [],
        "blocklist": [],
    },
    "dhcp": {
        "enabled": True,
        "interface": "wlan0",
        "range_start": "192.168.50.100",
        "range_end": "192.168.50.200",
        "subnet_mask": "255.255.255.0",
        "gateway": "192.168.50.1",
        "dns_server": "192.168.50.1",
        "lease_time": 86400,
        "reservations": [],
    },
}


# ============================================================
# Internal helpers
# ============================================================


def _config_path():
    """Return the absolute path to the gateway configuration file."""
    return os.path.abspath(CONFIG_FILE)


def _deep_merge(base, override):
    """Recursively merge override into base without modifying either input."""
    result = deepcopy(base)

    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)

    return result


def _require_dict(config, name="config"):
    if not isinstance(config, dict):
        raise ValueError(f"{name} must be a mapping/object")


def _validate_ip(value, field):
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid IP address: {value}") from exc


def _validate_network(value, field):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid network: {value}") from exc


def _validate_interface(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty interface name")


def _validate_bool(value, field):
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be true or false")


def _validate_list(value, field):
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")


# ============================================================
# Configuration
# ============================================================


def load_config():
    """
    Load gateway configuration from YAML.

    If the configuration file does not exist, a validated default
    configuration is created and returned.
    """
    path = _config_path()

    if not os.path.exists(path):
        config = deepcopy(DEFAULT_CONFIG)
        save_config(config)
        return config

    with open(path, "r", encoding="utf-8") as file:
        loaded = yaml.safe_load(file) or {}

    _require_dict(loaded)
    config = _deep_merge(DEFAULT_CONFIG, loaded)
    validate_config(config)
    return config


def save_config(config):
    """
    Validate and atomically save gateway configuration as YAML.

    Returns the absolute path written.
    """
    validate_config(config)

    path = _config_path()
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)

    fd, temp_path = tempfile.mkstemp(
        prefix="gateway-",
        suffix=".yaml",
        dir=directory,
        text=True,
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            yaml.safe_dump(
                config,
                file,
                default_flow_style=False,
                sort_keys=False,
            )
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, path)

    except Exception:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        raise

    return path


def validate_config(config):
    """
    Validate the complete gateway configuration.

    Returns True when valid. Raises ValueError for invalid data.
    """
    _require_dict(config)

    required_sections = {"network", "firewall", "dns", "dhcp"}
    missing = required_sections - config.keys()
    if missing:
        raise ValueError(
            "Missing configuration sections: " + ", ".join(sorted(missing))
        )

    # ---------------- Network ----------------
    network = config["network"]
    _require_dict(network, "network")
    _validate_interface(network.get("wan_interface"), "network.wan_interface")
    _validate_interface(network.get("lan_interface"), "network.lan_interface")
    _validate_bool(network.get("wan_dhcp"), "network.wan_dhcp")
    _validate_bool(network.get("ipv4_forwarding"), "network.ipv4_forwarding")
    _validate_bool(network.get("nat_enabled"), "network.nat_enabled")

    lan_address = network.get("lan_address")
    lan_network = network.get("lan_network")

    try:
        lan_interface = ipaddress.ip_interface(lan_address)
    except ValueError as exc:
        raise ValueError(
            f"network.lan_address must be a valid CIDR address: {lan_address}"
        ) from exc

    lan_net = _validate_network(lan_network, "network.lan_network")

    if lan_interface.network != lan_net:
        raise ValueError(
            "network.lan_address and network.lan_network do not describe "
            "the same network"
        )

    # ---------------- Firewall ----------------
    firewall = config["firewall"]
    _require_dict(firewall, "firewall")
    _validate_bool(firewall.get("enabled"), "firewall.enabled")
    _validate_bool(
        firewall.get("allow_established"),
        "firewall.allow_established",
    )
    _validate_bool(
        firewall.get("allow_related"),
        "firewall.allow_related",
    )
    _validate_bool(
        firewall.get("allow_lan_to_wan"),
        "firewall.allow_lan_to_wan",
    )
    _validate_bool(firewall.get("allow_dhcp"), "firewall.allow_dhcp")
    _validate_bool(firewall.get("allow_dns"), "firewall.allow_dns")
    _validate_bool(firewall.get("allow_ssh"), "firewall.allow_ssh")
    _validate_bool(
        firewall.get("allow_management_from_wan"),
        "firewall.allow_management_from_wan",
    )

    if firewall.get("default_policy") not in {"drop", "accept"}:
        raise ValueError("firewall.default_policy must be 'drop' or 'accept'")

    _validate_list(firewall.get("rules"), "firewall.rules")

    # ---------------- DNS ----------------
    dns = config["dns"]
    _require_dict(dns, "dns")
    _validate_bool(dns.get("enabled"), "dns.enabled")
    _validate_ip(dns.get("listen_address"), "dns.listen_address")
    _validate_list(dns.get("upstream_servers"), "dns.upstream_servers")
    _validate_list(dns.get("allowlist"), "dns.allowlist")
    _validate_list(dns.get("blocklist"), "dns.blocklist")
    _validate_bool(
        dns.get("block_direct_dns"),
        "dns.block_direct_dns",
    )
    _validate_bool(dns.get("logging"), "dns.logging")

    if not 1 <= int(dns.get("listen_port")) <= 65535:
        raise ValueError("dns.listen_port must be between 1 and 65535")

    for server in dns["upstream_servers"]:
        _validate_ip(server, "dns.upstream_servers")

    # ---------------- DHCP ----------------
    dhcp = config["dhcp"]
    _require_dict(dhcp, "dhcp")
    _validate_bool(dhcp.get("enabled"), "dhcp.enabled")
    _validate_interface(dhcp.get("interface"), "dhcp.interface")
    _validate_ip(dhcp.get("range_start"), "dhcp.range_start")
    _validate_ip(dhcp.get("range_end"), "dhcp.range_end")
    _validate_ip(dhcp.get("gateway"), "dhcp.gateway")
    _validate_ip(dhcp.get("dns_server"), "dhcp.dns_server")
    _validate_list(dhcp.get("reservations"), "dhcp.reservations")

    start = ipaddress.ip_address(dhcp["range_start"])
    end = ipaddress.ip_address(dhcp["range_end"])
    gateway = ipaddress.ip_address(dhcp["gateway"])

    if int(start) > int(end):
        raise ValueError("dhcp.range_start must not be greater than range_end")

    if gateway not in lan_net:
        raise ValueError("dhcp.gateway must belong to network.lan_network")

    if start not in lan_net or end not in lan_net:
        raise ValueError("DHCP range must belong to network.lan_network")


# ============================================================
# Network Configuration
# ============================================================


def get_network_config(config):
    _require_dict(config)
    return deepcopy(config.get("network", {}))


# ============================================================
# Firewall Configuration
# ============================================================


def get_firewall_config(config):
    _require_dict(config)
    return deepcopy(config.get("firewall", {}))


# ============================================================
# DNS Configuration
# ============================================================


def get_dns_config(config):
    _require_dict(config)
    return deepcopy(config.get("dns", {}))


# ============================================================
# DHCP Configuration
# ============================================================


def get_dhcp_config(config):
    _require_dict(config)
    return deepcopy(config.get("dhcp", {}))


if __name__ == "__main__":
    try:
        config = load_config()
        validate_config(config)
        print("Configuration: valid")
        print(f"Configuration file: {_config_path()}")
        print("Network:", get_network_config(config))
        print("DHCP:", get_dhcp_config(config))
        print("DNS:", get_dns_config(config))
        print("Firewall:", get_firewall_config(config))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"Configuration error: {exc}")
        raise SystemExit(1)
