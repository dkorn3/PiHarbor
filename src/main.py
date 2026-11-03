

"""
PiHarbor main coordinator.

This file is the main entry point for PiHarbor.

Responsibilities:
    1. Load and validate configuration
    2. Configure the LAN interface
    3. Enable IPv4 forwarding
    4. Configure NAT when enabled
    5. Configure firewall when enabled
    6. Configure DHCP when enabled
    7. Configure DNS
    9. Start the PiHarbor web GUI
   10. Shut down services cleanly
"""
import logging
import config
import network
import dns
import dhcp
import firewall
import monitoring
import nat

from network_gui import app


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger("PiHarbor")
_running = False

_gateway_config = None


# ============================================================
# Configuration
# ============================================================

def load_gateway_config():
    """
    Load and validate the PiHarbor configuration.
    """

    global _gateway_config

    _gateway_config = config.load_config()

    config.validate_config(
        _gateway_config
    )

    return _gateway_config


# ============================================================
# Network Initialization
# ============================================================

def initialize_network():
    """
    Initialize the PiHarbor network
 configuration.

    The network module owns the actual interface configuration.
    main.py coordinates the operation.
    """

    gateway_config = _gateway_config

    lan = gateway_config["network"]["lan_interface"]
    wan = gateway_config["network"]["wan_interface"]

    logger.info(
        f"Configuring network: WAN={wan}, LAN={lan}"
    )

    network.configure_router()

    logger.info(
        "Network configuration completed."
    )

    return True


# ============================================================
# NAT
# ============================================================

def initialize_nat():
    """
    Configure or disable NAT based on configuration.
    """

    enabled = _gateway_config[
        "network"
    ].get(
        "nat_enabled",
        False,
    )

    if enabled:

        logger.info(
            "Enabling NAT."
        )

        nat.configure_nat()

    else:

        logger.info(
            "NAT is disabled."
        )


# ============================================================
# Firewall
# ============================================================

def initialize_firewall():
    """
    Configure the PiHarbor firewall.
    """

    enabled = _gateway_config[
        "firewall"
    ].get(
        "enabled",
        False,
    )

    if not enabled:

        logger.info(
            "Firewall is disabled."
        )

        return

    lan = _gateway_config[
        "network"
    ][
        "lan_interface"
    ]

    wan = _gateway_config[
        "network"
    ][
        "wan_interface"
    ]

    logger.info(
        "Initializing firewall."
    )

    firewall.save_ruleset(
        lan,
        wan,
    )

    firewall.apply_firewall_rules(
        lan,
        wan,
    )


# ============================================================
# DHCP
# ============================================================

def initialize_dhcp():
    """
    Configure DHCP for the PiHarbor LAN.
    """

    enabled = _gateway_config[
        "dhcp"
    ].get(
        "enabled",
        False,
    )

    if not enabled:

        logger.info(
            "DHCP is disabled."
        )

        return

    dhcp_config = dict(
        _gateway_config[
            "dhcp"
        ]
    )

    dhcp_config[
        "interface"
    ] = _gateway_config[
        "network"
    ][
        "lan_interface"
    ]

    dhcp_config[
        "address"
    ] = _gateway_config[
        "network"
    ][
        "lan_address"
    ].split(
        "/"
    )[0]

    logger.info(
        "Initializing DHCP."
    )

    dhcp.configure_dhcp(
        dhcp_config
    )


# ============================================================
# DNS
# ============================================================

def initialize_dns():
    """
    Configure PiHarbor DNS upstream servers.
    """

    dns_config = _gateway_config[
        "dns"
    ]

    upstream_servers = dns_config.get(
        "upstream_servers",
        [],
    )

    logger.info(
        "Configuring DNS upstream servers."
    )

    dns.set_upstream_servers(
        upstream_servers
    )


# ============================================================
# Gateway Initialization
# ============================================================

def initialize_gateway():
    """
    Initialize all PiHarbor gateway components.
    """

    global _running

    logger.info(
        "================================="
    )

    logger.info(
        "PiHarbor gateway initialization"
    )

    logger.info(
        "================================="
    )

    load_gateway_config()

    initialize_network()
    initialize_nat()
    initialize_firewall()
    initialize_dhcp()
    initialize_dns()
    
    _running = True

    logger.info(
        "PiHarbor gateway initialization completed."
    )

    return True


# ============================================================
# Gateway Status
# ============================================================

def get_gateway_status():
    """
    Return the current PiHarbor gateway status.
    """

    return {
        "running": _running,
        "config": _gateway_config,
        "health":
            monitoring.get_gateway_health(),
    }


# ============================================================
# Shutdown
# ============================================================

def shutdown_gateway():
    """
    Stop gateway services cleanly.
    """

    global _running

    logger.info("PiHarbor gateway shutdown started.")

    _running = False

    logger.info("PiHarbor gateway shutdown completed.")

    return True


# ============================================================
# Web GUI
# ============================================================

def start_gui():
    """
    Start the PiHarbor web GUI.

    The GUI is intentionally started by main.py
    so main.py remains the application entry point.
    """

    if app is None:

        raise RuntimeError(
            "PiHarbor GUI could not be imported."
        )

    logger.info(
        "Starting PiHarbor web GUI."
    )

    app.run(
        host="0.0.0.0",
        port=80,
        debug=False,
        threaded=True,
    )


# ============================================================
# Main
# ============================================================

def main():
    """
    Main PiHarbor application entry point.
    """

    try:

        initialize_gateway()

        print(
            "PiHarbor gateway initialized."
        )

        print(
            "PiHarbor GUI available on port 80."
        )

        start_gui()

    except KeyboardInterrupt:

        print(
            "\nPiHarbor shutting down..."
        )

  except Exception:

    logger.exception("PiHarbor startup failed.")

    raise

    finally:

        shutdown_gateway()


if __name__ == "__main__":
    main()

