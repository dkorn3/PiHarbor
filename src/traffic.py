"""
PiHarbor per-device traffic accounting.

Uses nftables counters to track upload and download traffic
for devices on the LAN interface.
"""

import ipaddress
import re
import subprocess
import threading


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

    Examples:
        upload_192_168_50_10
        download_192_168_50_10
    """
    safe_ip = ip.replace(".", "_")
    return f"{direction}_{safe_ip}"


def ensure_traffic_table():
    """
    Create the PiHarbor nftables traffic accounting table and chain.

    The chain runs on the forward hook so traffic routed through
    PiHarbor can be counted without modifying the existing firewall.
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

        try:
            result = subprocess.run(
                [
                    "nft",
                    "add",
                    "table",
                    "inet",
                    TRAFFIC_TABLE,
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode != 0:
                return False

            result = subprocess.run(
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
    """Return the current PiHarbor traffic accounting chain."""
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


def get_traffic_table():
    """Return the complete PiHarbor traffic accounting table."""
    if not nft_available():
        return ""

    return run_command(
        [
            "nft",
            "-a",
            "list",
            "table",
            "inet",
            TRAFFIC_TABLE,
        ]
    )


def counter_object_exists(name):
    """Return True if a named nftables counter object exists."""
    table = get_traffic_table()

    if not table:
        return False

    # nftables lists named counters like:
    #
    # counter upload_192_168_50_188 {
    #     packets 0 bytes 0
    # }
    #
    pattern = re.compile(
        rf"\bcounter\s+{re.escape(name)}\s*\{{"
    )

    return pattern.search(table) is not None


def counter_rule_exists(ip, direction):
    """Return True if a counter rule exists for the device."""
    rules = get_traffic_rules()

    if not rules:
        return False

    name = counter_name(ip, direction)

    return f'counter name "{name}"' in rules


def create_counter_object(name):
    """Create a named nftables counter object."""
    if counter_object_exists(name):
        return True

    try:
        result = subprocess.run(
            [
                "nft",
                "add",
                "counter",
                "inet",
                TRAFFIC_TABLE,
                name,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        return result.returncode == 0

    except OSError:
        return False


def add_counter_rule(ip, direction):
    """
    Add an nftables rule using an existing named counter.

    Upload:
        ip saddr <device>

    Download:
        ip daddr <device>
    """
    if not valid_ipv4(ip):
        return False

    name = counter_name(ip, direction)

    if counter_rule_exists(ip, direction):
        return True

    if direction == "upload":
        address_expression = [
            "ip",
            "saddr",
            ip,
        ]

    elif direction == "download":
        address_expression = [
            "ip",
            "daddr",
            ip,
        ]

    else:
        return False

    try:
        result = subprocess.run(
            [
                "nft",
                "add",
                "rule",
                "inet",
                TRAFFIC_TABLE,
                TRAFFIC_CHAIN,
                *address_expression,
                "counter",
                "name",
                name,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        return result.returncode == 0

    except OSError:
        return False


def add_device_counters(ip):
    """
    Create upload and download accounting for a LAN device.

    Upload:
        LAN device -> Internet

    Download:
        Internet -> LAN device
    """
    if not valid_ipv4(ip):
        return False

    with _counter_lock:
        if not ensure_traffic_table():
            return False

        upload_name = counter_name(ip, "upload")
        download_name = counter_name(ip, "download")

        # Named counters must exist before rules can reference them.
        if not create_counter_object(upload_name):
            return False

        if not create_counter_object(download_name):
            return False

        # Add the rules that use those counters.
        if not add_counter_rule(ip, "upload"):
            return False

        if not add_counter_rule(ip, "download"):
            return False

    return True


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
    Parse packet and byte values for a named nftables counter.

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

    Returns None if traffic accounting is unavailable.
    """
    if not valid_ipv4(ip):
        return None

    if not add_device_counters(ip):
        return None

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
                "download_bytes": 123456,
                "upload_bytes": 7890,
                "download_packets": 100,
                "upload_packets": 20,
            }
        }
    """
    valid_ips = [
        ip for ip in ips
        if valid_ipv4(ip)
    ]

    if not valid_ips:
        return {}

    if not ensure_traffic_table():
        return {}

    traffic = {}

    for ip in valid_ips:
        if add_device_counters(ip):
            traffic[ip] = get_device_traffic(ip)

    return {
        ip: data
        for ip, data in traffic.items()
        if data is not None
    }


def remove_device_counters(ip):
    """
    Remove upload/download rules and counter objects for a device.

    This is useful for cleaning up devices that are no longer
    being tracked.
    """
    if not valid_ipv4(ip):
        return False

    rules = get_traffic_rules()

    if not rules:
        return False

    upload_name = counter_name(ip, "upload")
    download_name = counter_name(ip, "download")

    success = True

    # Remove rules first.
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

    # Remove named counter objects.
    for name in (upload_name, download_name):
        if not counter_object_exists(name):
            continue

        try:
            result = subprocess.run(
                [
                    "nft",
                    "delete",
                    "counter",
                    "inet",
                    TRAFFIC_TABLE,
                    name,
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


def reset_device_counters(ip):
    """
    Reset a device's traffic counters.

    The device's rules and counter objects are removed and
    recreated with zeroed counters.
    """
    if not valid_ipv4(ip):
        return False

    remove_device_counters(ip)

    return add_device_counters(ip)
