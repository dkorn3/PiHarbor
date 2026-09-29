
"""
PiServer ad blocking.

Downloads and manages the Hagezi Multi NORMAL blocklist for dnsmasq.
The downloaded list is installed as a dnsmasq configuration file.

This module does not modify the firewall or DNS upstream configuration.
"""

import os
import subprocess
import tempfile
import time
import urllib.request


BLOCKLIST_URL = (
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/"
    "dnsmasq/pro.txt"
)

BLOCKLIST_PATH = "/etc/dnsmasq.d/pi-gateway-adblock.conf"
TEMP_BLOCKLIST_PATH = "/tmp/pi-gateway-adblock.conf"

DNSMASQ_SERVICE = "dnsmasq"


def _run(command):
    """Run a system command and return the completed process."""
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )


def is_enabled():
    """Return True if the PiServer adblock configuration exists."""
    return os.path.exists(BLOCKLIST_PATH)


def get_blocklist_path():
    """Return the installed blocklist path."""
    return BLOCKLIST_PATH


def get_blocked_domain_count():
    """Return the number of domains currently in the blocklist."""
    if not os.path.exists(BLOCKLIST_PATH):
        return 0

    count = 0

    try:
        with open(BLOCKLIST_PATH, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                if line.startswith("address=/"):
                    count += 1

    except OSError:
        return 0

    return count


def get_blocklist_size():
    """Return the installed blocklist size in bytes."""
    try:
        return os.path.getsize(BLOCKLIST_PATH)
    except OSError:
        return 0


def get_last_update():
    """Return the installed blocklist modification time."""
    try:
        return os.path.getmtime(BLOCKLIST_PATH)
    except OSError:
        return None


def get_status():
    """Return current adblock status."""
    enabled = is_enabled()

    last_update = get_last_update()

    return {
        "enabled": enabled,
        "path": BLOCKLIST_PATH,
        "blocked_domains": get_blocked_domain_count(),
        "size_bytes": get_blocklist_size(),
        "last_update": last_update,
    }


def download_blocklist(destination=TEMP_BLOCKLIST_PATH):
    """
    Download the Hagezi Multi NORMAL dnsmasq blocklist.

    Returns True on success and False on failure.
    """
    try:
        request = urllib.request.Request(
            BLOCKLIST_URL,
            headers={
                "User-Agent": "PiServer-AdBlock/1.0",
            },
        )

        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read()

        if not data:
            return False

        with open(destination, "wb") as file:
            file.write(data)

        return True

    except (OSError, urllib.error.URLError):
        return False


def validate_blocklist(path=TEMP_BLOCKLIST_PATH):
    """
    Validate the downloaded dnsmasq configuration.

    Returns True only if dnsmasq accepts the configuration.
    """
    if not os.path.exists(path):
        return False

    result = _run([
        "dnsmasq",
        "--test",
        "--conf-file=" + path,
    ])

    return result.returncode == 0


def _validate_content(path):
    """
    Perform basic validation before installing the list.

    This prevents accidentally replacing the working list with
    an empty or obviously invalid download.
    """
    try:
        size = os.path.getsize(path)

        # Prevent replacing a valid list with an unexpectedly tiny file.
        if size < 1000:
            return False

        domain_count = 0

        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()

                if line.startswith("address=/"):
                    domain_count += 1

        # Hagezi NORMAL should contain many entries.
        if domain_count < 100:
            return False

        return True

    except OSError:
        return False


def install_blocklist(source=TEMP_BLOCKLIST_PATH):
    """
    Install a validated blocklist.

    The existing blocklist is kept until the new file is ready.
    """
    if not os.path.exists(source):
        return False

    try:
        os.makedirs(os.path.dirname(BLOCKLIST_PATH), exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=os.path.dirname(BLOCKLIST_PATH),
            prefix=".pi-gateway-adblock-",
            suffix=".conf",
            delete=False,
        ) as file:
            temporary_install_path = file.name

        with open(source, "rb") as source_file:
            data = source_file.read()

        with open(temporary_install_path, "wb") as destination:
            destination.write(data)

        os.replace(temporary_install_path, BLOCKLIST_PATH)

        return True

    except OSError:
        try:
            if os.path.exists(temporary_install_path):
                os.remove(temporary_install_path)
        except OSError:
            pass

        return False


def reload_dnsmasq():
    """Reload dnsmasq after installing a new blocklist."""
    result = _run([
        "systemctl",
        "reload",
        DNSMASQ_SERVICE,
    ])

    if result.returncode == 0:
        return True

    # Some systems/services may not support reload.
    result = _run([
        "systemctl",
        "restart",
        DNSMASQ_SERVICE,
    ])

    return result.returncode == 0


def update_blocklist():
    """
    Download, validate, install, and reload the Hagezi blocklist.

    The existing working list is preserved if any step fails.

    Returns a status dictionary suitable for the GUI.
    """
    start_time = time.monotonic()

    if not download_blocklist():
        return {
            "success": False,
            "stage": "download",
            "message": "Failed to download the Hagezi blocklist.",
        }

    if not _validate_content():
        return {
            "success": False,
            "stage": "content_validation",
            "message": "Downloaded blocklist failed content validation.",
        }

    if not validate_blocklist():
        return {
            "success": False,
            "stage": "dnsmasq_validation",
            "message": "dnsmasq rejected the downloaded blocklist.",
        }

    if not install_blocklist():
        return {
            "success": False,
            "stage": "installation",
            "message": "Failed to install the blocklist.",
        }

    if not reload_dnsmasq():
        return {
            "success": False,
            "stage": "reload",
            "message": "Blocklist installed, but dnsmasq failed to reload.",
        }

    elapsed = round(time.monotonic() - start_time, 2)

    return {
        "success": True,
        "stage": "complete",
        "message": "Hagezi Multi NORMAL blocklist updated successfully.",
        "blocked_domains": get_blocked_domain_count(),
        "elapsed_seconds": elapsed,
        "last_update": get_last_update(),
    }


def disable():
    """
    Disable PiServer ad blocking.

    The blocklist is removed and dnsmasq is reloaded.
    """
    if not os.path.exists(BLOCKLIST_PATH):
        return True

    try:
        os.remove(BLOCKLIST_PATH)
    except OSError:
        return False

    return reload_dnsmasq()


def enable():
    """
    Enable ad blocking.

    If no blocklist exists, download it first.
    """
    if not os.path.exists(BLOCKLIST_PATH):
        result = update_blocklist()
        return result["success"]

    return reload_dnsmasq()


def test():
    """
    Test the installed blocklist without changing anything.

    Returns a status dictionary.
    """
    if not os.path.exists(BLOCKLIST_PATH):
        return {
            "success": False,
            "message": "Adblock list is not installed.",
        }

    valid = validate_blocklist(BLOCKLIST_PATH)

    return {
        "success": valid,
        "blocked_domains": get_blocked_domain_count(),
        "message": (
            "Adblock configuration is valid."
            if valid
            else "Adblock configuration is invalid."
        ),
    }


if __name__ == "__main__":
    result = update_blocklist()
    print(result)

