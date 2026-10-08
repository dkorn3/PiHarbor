"""
PiHarbor per-device traffic accounting.

Uses nftables counters to track upload and download traffic
for devices on the LAN interface.
"""

import ipaddress
import re
import subprocess
import threading
import time


TRAFFIC_TABLE = "piharbor_traffic"
TRAFFIC_CHAIN = "forward"

_counter_lock = threading.Lock()


def run_command(command):
    """Run a system command and return stdout, or an empty string on failure."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            return ""

        return result.stdout

    except (OSError, subprocess.SubprocessError):
        return ""


def nft_available():
    """Return True if nftables is installed."""
    try:
        result = subprocess.run(
            ["nft", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0

    except OSError:
        return False


def valid_ipv4(ip):
    """Return True if the supplied address is a valid IPv4 address."""
    try:
        address = ipaddress.ip_address(ip)
        return address.version == 4

    except ValueError:
        return False


def counter_name(ip, direction):
    """
    Generate a safe nftables counter name.

    Example:
        upload_192_168_50_10
        download_192_168_50_10
    """
    safe_ip = ip.replace(".", "_")
    return f"{direction}_{safe_ip}"


def ensure_traffic_table():
    """
    Create the PiHarbor nftables traffic accounting table and chain.

    The chain uses a low priority so the accounting rules run
    alongside the existing firewall/NAT configuration.
    """
    if not nft_available():
        return False

    with _counter_lock:
        existing = run_command(
            [
                "nft",
                "list",
                "table",
                "inet",
                TRAFFIC_TABLE,
            ]
        )

        if existing:
            return True

        commands = [
            [
                "nft",
                "add",
                "table",
                "inet",
                TRAFFIC_TABLE,
            ],
            [
                "nft",
                "add",
                "chain",
                "inet",
                TRAFFIC_TABLE,
                TRAFFIC_CHAIN,
                "{",
                "type",
                "filter",
                "hook",
                "forward",
                "priority",
                "-10",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
        ]

        for command in commands:
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                )

                if result.returncode != 0:
                    return False

            except OSError:
                return False

        return True


def get_traffic_rules():
    """Return the current PiHarbor traffic accounting rules."""
    if not nft_available():
        return ""

    return run_command(
        [
            "nft",
            "-a",
            "list",
            "chain",
            "inet",
            TRAFFIC_TABLE,
            TRAFFIC_CHAIN,
        ]
    )


def counter_exists(ip, direction):
    """Check whether a traffic counter rule already exists."""
    rules = get_traffic_rules()

    if not rules:
        return False

    name = counter_name(ip, direction)

    return f'counter name "{name}"' in rules


def add_device_counters(ip):
    """
    Add upload/download counters for a LAN device.

    Upload:
        LAN device -> Internet

    Download:
        Internet -> LAN device
    """
    if not valid_ipv4(ip):
        return False

    if not ensure_traffic_table():
        return False

    upload_name = counter_name(ip, "upload")
    download_name = counter_name(ip, "download")

    with _counter_lock:
        if not counter_exists(ip, "upload"):
            try:
                result = subprocess.run(
                    [
                        "nft",
                        "add",
                        "rule",
                        "inet",
                        TRAFFIC_TABLE,
                        TRAFFIC_CHAIN,
                        "ip",
                        "saddr",
                        ip,
                        "counter",
                        "name",
                        upload_name,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )

                if result.returncode != 0:
                    return False

            except OSError:
                return False

        if not counter_exists(ip, "download"):
            try:
                result = subprocess.run(
                    [
                        "nft",
                        "add",
                        "rule",
                        "inet",
                        TRAFFIC_TABLE,
                        TRAFFIC_CHAIN,
                        "ip",
                        "daddr",
                        ip,
                        "counter",
                        "name",
                        download_name,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )

                if result.returncode != 0:
                    return False

            except OSError:
                return False

    return True


def remove_device_counters(ip):
    """
    Remove traffic accounting rules for a device.

    This is optional and should generally only be used when
    cleaning up old/stale devices.
    """
    if not valid_ipv4(ip):
        return False

    rules = get_traffic_rules()

    if not rules:
        return False

    upload_name = counter_name(ip, "upload")
    download_name = counter_name(ip, "download")

    success = True

    for name in (upload_name, download_name):
        handle = find_counter_handle(rules, name)

        if handle is None:
            continue

        try:
            result = subprocess.run(
                [
                    "nft",
                    "delete",
                    "rule",
                    "inet",
                    TRAFFIC_TABLE,
                    TRAFFIC_CHAIN,
                    "handle",
                    str(handle),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode != 0:
                success = False

        except OSError:
            success = False

    return success


def find_counter_handle(rules, name):
    """Find the nftables rule handle associated with a counter."""
    pattern = re.compile(
        rf'counter name "{re.escape(name)}".*?# handle (\d+)'
    )

    match = pattern.search(rules)

    if not match:
        return None

    return int(match.group(1))


def parse_counter(rules, name):
    """
    Parse packet/byte values for a named nftables counter.

    Returns:
        {
            "packets": int,
            "bytes": int
        }

    or None if the counter cannot be found.
    """
    if not rules:
        return None

    pattern = re.compile(
        rf'counter packets (\d+) bytes (\d+) name "{re.escape(name)}"'
    )

    match = pattern.search(rules)

    if not match:
        return None

    return {
        "packets": int(match.group(1)),
        "bytes": int(match.group(2)),
    }


def get_device_traffic(ip):
    """
    Return traffic statistics for one LAN device.
    """
    if not valid_ipv4(ip):
        return None

    if not ensure_traffic_table():
        return None

    add_device_counters(ip)

    rules = get_traffic_rules()

    upload = parse_counter(
        rules,
        counter_name(ip, "upload"),
    )

    download = parse_counter(
        rules,
        counter_name(ip, "download"),
    )

    if upload is None or download is None:
        return None

    return {
        "download_bytes": download["bytes"],
        "upload_bytes": upload["bytes"],
        "download_packets": download["packets"],
        "upload_packets": upload["packets"],
    }


def get_all_device_traffic(ips):
    """
    Return traffic statistics for multiple LAN devices.

    Args:
        ips: iterable of IPv4 addresses

    Returns:
        {
            "192.168.50.10": {
                "download_bytes": ...,
                "upload_bytes": ...,
                ...
            }
        }
    """
    if not ensure_traffic_table():
        return {}

    for ip in ips:
        add_device_counters(ip)

    rules = get_traffic_rules()

    traffic = {}

    for ip in ips:
        if not valid_ipv4(ip):
            continue

        upload = parse_counter(
            rules,
            counter_name(ip, "upload"),
        )

        download = parse_counter(
            rules,
            counter_name(ip, "download"),
        )

        if upload is None or download is None:
            continue

        traffic[ip] = {
            "download_bytes": download["bytes"],
            "upload_bytes": upload["bytes"],
            "download_packets": download["packets"],
            "upload_packets": upload["packets"],
        }

    return traffic


def reset_device_counters(ip):
    """
    Reset a device's counters to zero.

    This deletes and recreates the device's accounting rules.
    """
    if not valid_ipv4(ip):
        return False

    remove_device_counters(ip)

    return add_device_counters(ip)
