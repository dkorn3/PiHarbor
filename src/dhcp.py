
import os
import subprocess

from config import load_config


CONFIG_PATH = "/etc/dnsmasq.d/pi-gateway.conf"
LEASE_FILE = "/var/lib/misc/dnsmasq.leases"


def _run(command):
    """Run a system command and return the completed process."""
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )


def _get_dhcp_settings():
    """Load DHCP settings from the PiHarbor configuration."""
    config = load_config()
    dhcp = config["dhcp"]

    return {
        "interface": dhcp["interface"],
        "address": dhcp["gateway"],
        "range_start": dhcp["range_start"],
        "range_end": dhcp["range_end"],
        "lease_time": dhcp["lease_time"],
    }


def get_dhcp_status():
    """Return the current dnsmasq service status."""
    result = _run(["systemctl", "is-active", "dnsmasq"])

    return result.stdout.strip() or "inactive"


def get_dhcp_config():
    """Read the currently installed dnsmasq DHCP configuration."""
    if not os.path.exists(CONFIG_PATH):
        settings = _get_dhcp_settings()

        return {
            "interface": settings["interface"],
            "address": settings["address"],
            "range_start": settings["range_start"],
            "range_end": settings["range_end"],
            "lease_time": settings["lease_time"],
        }

    config = _get_dhcp_settings()

    with open(
        CONFIG_PATH,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)

            if key == "interface":
                config["interface"] = value

            elif key == "dhcp-range":
                parts = value.split(",")

                if len(parts) >= 3:
                    config["range_start"] = parts[0]
                    config["range_end"] = parts[1]
                    config["lease_time"] = parts[2]

            elif key == "dhcp-option":
                if value.startswith("3,"):
                    config["address"] = value.split(",", 1)[1]

    return config


def get_leases():
    """Return DHCP leases currently recorded by dnsmasq."""
    leases = []

    if not os.path.exists(LEASE_FILE):
        return leases

    with open(
        LEASE_FILE,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as file:
        for line in file:
            parts = line.split()

            if len(parts) < 4:
                continue

            expiry, mac, address, hostname = parts[:4]

            leases.append(
                {
                    "expiry": int(expiry) if expiry.isdigit() else None,
                    "mac": mac,
                    "ip": address,
                    "hostname": (
                        hostname
                        if hostname != "*"
                        else None
                    ),
                }
            )

    return leases


def get_client_lease(client):
    """Find a DHCP lease by MAC address, IP address, or hostname."""
    client = str(client).lower()

    for lease in get_leases():
        if client in {
            lease["mac"].lower(),
            lease["ip"].lower(),
            (lease["hostname"] or "").lower(),
        }:
            return lease

    return None


def get_connected_clients():
    """Return clients with active DHCP leases."""
    return get_leases()


def get_dhcp_health():
    """Return a summary of DHCP service health."""
    status = get_dhcp_status()
    config = get_dhcp_config()
    leases = get_leases()

    return {
        "status": status,
        "interface": config["interface"],
        "range": (
            f'{config["range_start"]}-'
            f'{config["range_end"]}'
        ),
        "lease_count": len(leases),
    }


def _write_dnsmasq_config(config):
    """Write the PiHarbor DHCP configuration for dnsmasq."""
    content = f"""# PiHarbor DHCP configuration
interface={config["interface"]}
bind-interfaces
dhcp-authoritative
dhcp-range={config["range_start"]},{config["range_end"]},{config["lease_time"]}
dhcp-option=3,{config["address"]}
dhcp-option=6,{config["address"]}
"""

    directory = os.path.dirname(CONFIG_PATH)
    os.makedirs(directory, exist_ok=True)

    with open(
        CONFIG_PATH,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(content)


def configure_dhcp(config=None):
    """
    Generate and apply the PiHarbor DHCP configuration.

    The supplied configuration overrides values loaded
    from config.py.
    """
    settings = _get_dhcp_settings()

    if config:
        settings.update(config)

    _write_dnsmasq_config(settings)

    test = _run(["dnsmasq", "--test"])

    if test.returncode != 0:
        return False

    result = _run(
        ["systemctl", "restart", "dnsmasq"]
    )

    return result.returncode == 0


def disable_dhcp():
    """Stop dnsmasq and remove the PiHarbor DHCP configuration."""
    result = _run(
        ["systemctl", "stop", "dnsmasq"]
    )

    if result.returncode != 0:
        return False

    return True


if __name__ == "__main__":
    print("=== PiHarbor DHCP ===")

    try:
        print(
            f"Service: {get_dhcp_status()}"
        )

        print(
            f"Configuration: {get_dhcp_config()}"
        )

        print(
            f"Leases: {get_leases()}"
        )

    except (OSError, RuntimeError, ValueError) as exc:
        print(f"DHCP check failed: {exc}")
        raise SystemExit(1)
