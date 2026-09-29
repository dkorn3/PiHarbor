"""
PiServer ad blocking.

Downloads and manages the HaGeZi Multi PRO DNS blocklist
for dnsmasq.

The downloaded blocklist is installed as a dnsmasq
configuration fragment.

This module does not modify firewall rules or DNS
upstream configuration.
"""

import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


# ============================================================
# Configuration
# ============================================================

# Current Hagezi dnsmasq blocklist.
#
# This URL currently returns HaGeZi Multi PRO.
BLOCKLIST_URL = (
    "https://cdn.jsdelivr.net/gh/hagezi/"
    "dns-blocklists@latest/dnsmasq/pro.txt"
)

# Installed dnsmasq configuration.
BLOCKLIST_PATH = (
    "/etc/dnsmasq.d/pi-gateway-adblock.conf"
)

# Temporary downloaded file.
TEMP_BLOCKLIST_PATH = (
    "/tmp/pi-gateway-adblock.conf"
)

# Temporary backup used during installation.
BACKUP_BLOCKLIST_PATH = (
    "/tmp/pi-gateway-adblock.conf.backup"
)

DNSMASQ_SERVICE = "dnsmasq"

DOWNLOAD_TIMEOUT = 60

MIN_FILE_SIZE = 1000

MIN_DOMAIN_ENTRIES = 100


# ============================================================
# Command Helper
# ============================================================

def _run(command, timeout=30):
    """
    Run a system command.

    Returns:
        subprocess.CompletedProcess
    """

    try:

        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )

    except (
        OSError,
        subprocess.TimeoutExpired,
    ):

        return None


# ============================================================
# Status
# ============================================================

def is_enabled():
    """
    Return True when the blocklist is installed.
    """

    return os.path.exists(
        BLOCKLIST_PATH
    )


def get_blocklist_path():
    """
    Return the installed blocklist path.
    """

    return BLOCKLIST_PATH


def _count_blocklist_entries(path):
    """
    Count dnsmasq blocklist entries.

    Hagezi may use either:

        local=/example.com/

    or:

        address=/example.com/

    Both are supported.
    """

    if not os.path.exists(path):
        return 0

    count = 0

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            for line in file:

                line = line.strip()

                if (
                    line.startswith("local=/")
                    or line.startswith("address=/")
                ):
                    count += 1

    except OSError:

        return 0

    return count


def get_blocked_domain_count():
    """
    Return the number of domains in the installed
    blocklist.
    """

    return _count_blocklist_entries(
        BLOCKLIST_PATH
    )


def get_blocklist_size():
    """
    Return installed blocklist size in bytes.
    """

    try:

        return os.path.getsize(
            BLOCKLIST_PATH
        )

    except OSError:

        return 0


def get_last_update():
    """
    Return the installed blocklist modification
    timestamp.
    """

    try:

        return os.path.getmtime(
            BLOCKLIST_PATH
        )

    except OSError:

        return None


def get_status():
    """
    Return complete ad-blocking status.
    """

    enabled = is_enabled()

    return {
        "enabled": enabled,
        "path": BLOCKLIST_PATH,
        "blocked_domains":
            get_blocked_domain_count(),
        "size_bytes":
            get_blocklist_size(),
        "last_update":
            get_last_update(),
    }


# ============================================================
# Download
# ============================================================

def download_blocklist(
    destination=TEMP_BLOCKLIST_PATH,
):
    """
    Download the Hagezi blocklist.

    Returns:
        True on success
        False on failure
    """

    try:

        request = urllib.request.Request(
            BLOCKLIST_URL,
            headers={
                "User-Agent":
                    "PiServer-AdBlock/1.0"
            },
        )

        with urllib.request.urlopen(
            request,
            timeout=DOWNLOAD_TIMEOUT,
        ) as response:

            data = response.read()

        if not data:
            return False

        with open(
            destination,
            "wb",
        ) as file:

            file.write(data)

        return True

    except (
        OSError,
        urllib.error.URLError,
        urllib.error.HTTPError,
    ):

        return False


# ============================================================
# Content Validation
# ============================================================

def _validate_content(
    path=TEMP_BLOCKLIST_PATH,
):
    """
    Validate that the downloaded file appears
    to be a real dnsmasq blocklist.
    """

    try:

        size = os.path.getsize(path)

        if size < MIN_FILE_SIZE:
            return False

        domain_count = 0

        has_hagezi_header = False

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                if (
                    "HaGeZi" in line
                    or "Hagezi" in line
                ):
                    has_hagezi_header = True

                if (
                    line.startswith("local=/")
                    or line.startswith("address=/")
                ):
                    domain_count += 1

        if domain_count < MIN_DOMAIN_ENTRIES:
            return False

        if not has_hagezi_header:
            return False

        return True

    except OSError:

        return False


# ============================================================
# dnsmasq Validation
# ============================================================

def validate_blocklist(
    path=TEMP_BLOCKLIST_PATH,
):
    """
    Ask dnsmasq to validate the blocklist file.

    Returns:
        True when dnsmasq accepts the file.
    """

    if not os.path.exists(path):
        return False

    result = _run(
        [
            "dnsmasq",
            "--test",
            "--conf-file=" + path,
        ],
        timeout=30,
    )

    if result is None:
        return False

    return result.returncode == 0


def validate_full_dnsmasq_config():
    """
    Validate the complete dnsmasq configuration.

    This is performed after the blocklist has been
    installed.
    """

    result = _run(
        [
            "dnsmasq",
            "--test",
        ],
        timeout=30,
    )

    if result is None:
        return False

    return result.returncode == 0


# ============================================================
# Installation
# ============================================================

def _backup_existing_blocklist():
    """
    Backup the currently installed blocklist.

    Returns:
        True if there is no existing file or backup
        succeeds.
    """

    if not os.path.exists(
        BLOCKLIST_PATH
    ):
        return True

    try:

        shutil.copy2(
            BLOCKLIST_PATH,
            BACKUP_BLOCKLIST_PATH,
        )

        return True

    except OSError:

        return False


def _restore_backup():
    """
    Restore the previous blocklist.
    """

    if not os.path.exists(
        BACKUP_BLOCKLIST_PATH
    ):
        return False

    try:

        shutil.copy2(
            BACKUP_BLOCKLIST_PATH,
            BLOCKLIST_PATH,
        )

        return True

    except OSError:

        return False


def _remove_backup():
    """
    Remove the temporary backup.
    """

    try:

        if os.path.exists(
            BACKUP_BLOCKLIST_PATH
        ):
            os.remove(
                BACKUP_BLOCKLIST_PATH
            )

    except OSError:
        pass


def install_blocklist(
    source=TEMP_BLOCKLIST_PATH,
):
    """
    Atomically install the downloaded blocklist.

    Returns:
        True on success.
        False on failure.
    """

    if not os.path.exists(source):
        return False

    temporary_install_path = None

    try:

        os.makedirs(
            os.path.dirname(
                BLOCKLIST_PATH
            ),
            exist_ok=True,
        )

        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=os.path.dirname(
                BLOCKLIST_PATH
            ),
            prefix=".pi-gateway-adblock-",
            suffix=".conf",
            delete=False,
        ) as file:

            temporary_install_path = (
                file.name
            )

            with open(
                source,
                "rb",
            ) as source_file:

                shutil.copyfileobj(
                    source_file,
                    file,
                )

        os.replace(
            temporary_install_path,
            BLOCKLIST_PATH,
        )

        temporary_install_path = None

        return True

    except OSError:

        return False

    finally:

        if (
            temporary_install_path
            and os.path.exists(
                temporary_install_path
            )
        ):

            try:
                os.remove(
                    temporary_install_path
                )
            except OSError:
                pass


# ============================================================
# dnsmasq Reload
# ============================================================

def reload_dnsmasq():
    """
    Reload dnsmasq.

    Reload is attempted first. If reload fails,
    restart is attempted.

    Returns:
        True if dnsmasq successfully reloads/restarts.
    """

    result = _run(
        [
            "systemctl",
            "reload",
            DNSMASQ_SERVICE,
        ],
        timeout=30,
    )

    if (
        result is not None
        and result.returncode == 0
    ):

        return True

    result = _run(
        [
            "systemctl",
            "restart",
            DNSMASQ_SERVICE,
        ],
        timeout=30,
    )

    if (
        result is not None
        and result.returncode == 0
    ):

        return True

    return False


# ============================================================
# Update
# ============================================================

def update_blocklist():
    """
    Download, validate, install, and activate
    the latest Hagezi blocklist.

    The previous blocklist is restored if the
    new configuration causes dnsmasq to fail.
    """

    start_time = time.monotonic()

    # --------------------------------------------------------
    # Download
    # --------------------------------------------------------

    if not download_blocklist():

        return {
            "success": False,
            "stage": "download",
            "message":
                "Failed to download the Hagezi blocklist.",
        }

    # --------------------------------------------------------
    # Content validation
    # --------------------------------------------------------

    if not _validate_content():

        return {
            "success": False,
            "stage": "content_validation",
            "message":
                "Downloaded blocklist failed content validation.",
        }

    # --------------------------------------------------------
    # Validate downloaded blocklist with dnsmasq
    # --------------------------------------------------------

    if not validate_blocklist():

        return {
            "success": False,
            "stage": "dnsmasq_validation",
            "message":
                "dnsmasq rejected the downloaded blocklist.",
        }

    # --------------------------------------------------------
    # Backup existing list
    # --------------------------------------------------------

    if not _backup_existing_blocklist():

        return {
            "success": False,
            "stage": "backup",
            "message":
                "Failed to back up the existing blocklist.",
        }

    # --------------------------------------------------------
    # Install new list
    # --------------------------------------------------------

    if not install_blocklist():

        _remove_backup()

        return {
            "success": False,
            "stage": "installation",
            "message":
                "Failed to install the blocklist.",
        }

    # --------------------------------------------------------
    # Validate complete dnsmasq configuration
    # --------------------------------------------------------

    if not validate_full_dnsmasq_config():

        _restore_backup()
        _remove_backup()

        return {
            "success": False,
            "stage": "full_dnsmasq_validation",
            "message":
                "Complete dnsmasq configuration failed validation. "
                "Previous blocklist restored.",
        }

    # --------------------------------------------------------
    # Reload dnsmasq
    # --------------------------------------------------------

    if not reload_dnsmasq():

        _restore_backup()

        # Try to restore the known-good configuration.
        validate_full_dnsmasq_config()
        reload_dnsmasq()

        _remove_backup()

        return {
            "success": False,
            "stage": "reload",
            "message":
                "dnsmasq failed to reload with the new blocklist. "
                "Previous blocklist restored.",
        }

    # --------------------------------------------------------
    # Success
    # --------------------------------------------------------

    _remove_backup()

    try:

        if os.path.exists(
            TEMP_BLOCKLIST_PATH
        ):
            os.remove(
                TEMP_BLOCKLIST_PATH
            )

    except OSError:
        pass

    elapsed = round(
        time.monotonic() - start_time,
        2,
    )

    return {
        "success": True,
        "stage": "complete",
        "message":
            "Hagezi Multi PRO blocklist "
            "updated successfully.",
        "blocked_domains":
            get_blocked_domain_count(),
        "size_bytes":
            get_blocklist_size(),
        "elapsed_seconds":
            elapsed,
        "last_update":
            get_last_update(),
    }


# ============================================================
# Enable / Disable
# ============================================================

def disable():
    """
    Disable ad blocking by removing the installed
    blocklist and reloading dnsmasq.

    If dnsmasq fails to reload, the blocklist
    is restored.
    """

    if not os.path.exists(
        BLOCKLIST_PATH
    ):

        return True

    backup_created = False

    try:

        shutil.copy2(
            BLOCKLIST_PATH,
            BACKUP_BLOCKLIST_PATH,
        )

        backup_created = True

        os.remove(
            BLOCKLIST_PATH
        )

    except OSError:

        return False

    if validate_full_dnsmasq_config():

        if reload_dnsmasq():

            _remove_backup()

            return True

    # Something went wrong.
    if backup_created:

        _restore_backup()

        validate_full_dnsmasq_config()
        reload_dnsmasq()

        _remove_backup()

    return False


def enable():
    """
    Enable ad blocking.

    If a blocklist already exists, simply reload
    dnsmasq.

    If no blocklist exists, download the latest
    blocklist.
    """

    if not os.path.exists(
        BLOCKLIST_PATH
    ):

        result = update_blocklist()

        return bool(
            result.get(
                "success",
                False,
            )
        )

    if not validate_full_dnsmasq_config():

        return False

    return reload_dnsmasq()


# ============================================================
# Testing
# ============================================================

def test():
    """
    Test the installed ad-blocking configuration.
    """

    if not os.path.exists(
        BLOCKLIST_PATH
    ):

        return {
            "success": False,
            "message":
                "Adblock list is not installed.",
            "blocked_domains": 0,
        }

    content_valid = _validate_content(
        BLOCKLIST_PATH
    )

    dnsmasq_valid = (
        validate_full_dnsmasq_config()
    )

    success = (
        content_valid
        and dnsmasq_valid
    )

    return {
        "success": success,
        "blocked_domains":
            get_blocked_domain_count(),
        "message": (
            "Adblock configuration is valid."
            if success
            else
            "Adblock configuration is invalid."
        ),
    }


# ============================================================
# Command Line
# ============================================================

if __name__ == "__main__":

    result = update_blocklist()

    print(result)
