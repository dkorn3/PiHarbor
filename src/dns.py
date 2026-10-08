import os
import socket
import subprocess
import time

DNSMASQ_DNS_CONFIG = "/etc/dnsmasq.d/pi-gateway-dns.conf"

UPSTREAM_SERVERS = ["1.1.1.1", "9.9.9.9"]
ALLOWLIST = set()
BLOCKLIST = set()

_QUERY_STATS = {
    "queries": 0,
    "successful": 0,
    "failed": 0,
    "blocked": 0,
}


def _run(command):
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )


def get_dns_status():
    result = _run(["systemctl", "is-active", "dnsmasq"])
    status = result.stdout.strip()

    if status == "active":
        return "active"

    return "inactive"


def get_upstream_servers():
    return list(UPSTREAM_SERVERS)


def resolve(domain):
    domain = str(domain).strip().rstrip(".").lower()

    if not domain:
        raise ValueError("Domain must not be empty.")

    if not is_domain_allowed(domain):
        _QUERY_STATS["blocked"] += 1
        raise PermissionError(f"Domain blocked by DNS policy: {domain}")

    _QUERY_STATS["queries"] += 1

    try:
        result = socket.getaddrinfo(
            domain,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )

        addresses = sorted({entry[4][0] for entry in result})

        _QUERY_STATS["successful"] += 1
        return addresses

    except socket.gaierror:
        _QUERY_STATS["failed"] += 1
        return []


def test_dns_connectivity():
    for server in UPSTREAM_SERVERS:
        try:
            start = time.monotonic()
            socket.create_connection(
                (server, 53),
                timeout=2
            ).close()

            elapsed_ms = (time.monotonic() - start) * 1000

            return {
                "status": "healthy",
                "server": server,
                "latency_ms": round(elapsed_ms, 2),
            }
        except OSError:
            continue

    return {
        "status": "failed",
        "server": None,
        "latency_ms": None,
    }


def _write_upstream_config():
    os.makedirs(os.path.dirname(DNSMASQ_DNS_CONFIG), exist_ok=True)

    lines = [
        "# PiHarbor DNS configuration",
        "no-resolv",
    ]

    lines.extend(
        f"server={server}"
        for server in UPSTREAM_SERVERS
    )

    with open(DNSMASQ_DNS_CONFIG, "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")


def set_upstream_servers(servers):
    global UPSTREAM_SERVERS

    if not isinstance(servers, (list, tuple)) or not servers:
        raise ValueError("At least one upstream DNS server is required.")

    for server in servers:
        socket.inet_pton(socket.AF_INET, server)

    UPSTREAM_SERVERS = list(servers)

    try:
        _write_upstream_config()
        result = _run(["systemctl", "restart", "dnsmasq"])

        if result.returncode != 0:
            return False

    except OSError:
        return False

    return True


def is_domain_allowed(domain):
    domain = str(domain).strip().rstrip(".").lower()

    for blocked in BLOCKLIST:
        if domain == blocked or domain.endswith("." + blocked):
            return False

    if not ALLOWLIST:
        return True

    return any(
        domain == allowed or domain.endswith("." + allowed)
        for allowed in ALLOWLIST
    )


def get_query_stats():
    return dict(_QUERY_STATS)


def get_dns_health():
    connectivity = test_dns_connectivity()

    return {
        "status": get_dns_status(),
        "connectivity": connectivity["status"],
        "upstream_servers": get_upstream_servers(),
        "queries": _QUERY_STATS["queries"],
        "successful_queries": _QUERY_STATS["successful"],
        "failed_queries": _QUERY_STATS["failed"],
        "blocked_queries": _QUERY_STATS["blocked"],
        "latency_ms": connectivity["latency_ms"],
    }
