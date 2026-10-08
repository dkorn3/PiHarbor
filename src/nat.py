
"""
PiHarbor NAT management.

Provides IPv4 masquerading for traffic leaving the
PiHarbor LAN through the WAN interface.
"""

import subprocess

from config import load_config


# ============================================================
# Command Helper
# ============================================================

def _run(command):
    """
    Run a system command and return the completed process.
    """

    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )


# ============================================================
# Configuration
# ============================================================

def _get_network_settings():
    """
    Load WAN/LAN settings from PiHarbor configuration.
    """

    config = load_config()
    network = config["network"]

    return {
        "wan_interface": network["wan_interface"],
        "lan_interface": network["lan_interface"],
        "lan_network": network["lan_network"],
    }


# ============================================================
# NAT Configuration
# ============================================================

def configure_nat():
    """
    Configure IPv4 masquerading for PiHarbor LAN traffic.

    LAN traffic from the configured subnet is masqueraded
    when leaving through the WAN interface.

    The configuration is idempotent, meaning calling this
    function multiple times will not create duplicate rules.
    """

    settings = _get_network_settings()

    wan_interface = settings["wan_interface"]
    lan_network = settings["lan_network"]

    # --------------------------------------------------------
    # Create NAT table if it does not already exist
    # --------------------------------------------------------

    result = _run(
        [
            "nft",
            "add",
            "table",
            "ip",
            "piharbor_nat",
        ]
    )

    if result.returncode != 0:
        if "exists" not in result.stderr.lower():
            raise RuntimeError(
                result.stderr.strip()
                or "Failed to create NAT table"
            )

    # --------------------------------------------------------
    # Create postrouting chain if it does not exist
    # --------------------------------------------------------

    result = _run(
        [
            "nft",
            "add",
            "chain",
            "ip",
            "piharbor_nat",
            "postrouting",
            "{",
            "type",
            "nat",
            "hook",
            "postrouting",
            "priority",
            "100",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ]
    )

    if result.returncode != 0:
        if "exists" not in result.stderr.lower():
            raise RuntimeError(
                result.stderr.strip()
                or "Failed to create NAT postrouting chain"
            )

    # --------------------------------------------------------
    # Check whether masquerade rule already exists
    # --------------------------------------------------------

    rules = _run(
        [
            "nft",
            "list",
            "chain",
            "ip",
            "piharbor_nat",
            "postrouting",
        ]
    )

    expected_rule = (
        f'oifname "{wan_interface}" '
        f'ip saddr {lan_network} masquerade'
    )

    if expected_rule not in rules.stdout:

        result = _run(
            [
                "nft",
                "add",
                "rule",
                "ip",
                "piharbor_nat",
                "postrouting",
                "oifname",
                wan_interface,
                "ip",
                "saddr",
                lan_network,
                "masquerade",
            ]
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip()
                or "Failed to create NAT masquerade rule"
            )

    return get_nat_status()


# ============================================================
# NAT Status
# ============================================================

def get_nat_status():
    """
    Return the current PiHarbor NAT configuration.
    """

    result = _run(
        [
            "nft",
            "list",
            "table",
            "ip",
            "piharbor_nat",
        ]
    )

    return {
        "enabled": result.returncode == 0,
        "rules": result.stdout.strip(),
        "error": (
            result.stderr.strip()
            if result.returncode != 0
            else None
        ),
    }


# ============================================================
# NAT Disable
# ============================================================

def disable_nat():
    """
    Remove the PiHarbor NAT table.

    Deleting the table removes the NAT chain and all
    masquerade rules belonging to PiHarbor.
    """

    result = _run(
        [
            "nft",
            "delete",
            "table",
            "ip",
            "piharbor_nat",
        ]
    )

    if result.returncode != 0:

        if (
            "does not exist"
            in result.stderr.lower()
        ):
            return True

        raise RuntimeError(
            result.stderr.strip()
            or "Failed to disable NAT"
        )

    return True


# ============================================================
# Standalone Test
# ============================================================

if __name__ == "__main__":

    print("PiHarbor NAT status:")

    status = get_nat_status()

    print(
        f"Enabled: {status['enabled']}"
    )

    if status["rules"]:
        print()
        print(status["rules"])

    if status["error"]:
        print()
        print(
            f"Error: {status['error']}"
        )

