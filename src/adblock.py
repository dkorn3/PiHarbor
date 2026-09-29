
"""
PiServer ad blocking.

Downloads and manages the HaGeZi Multi PRO DNS blocklist
for dnsmasq.

Also manages a separate custom blocklist that can be
controlled from the PiServer GUI.

The downloaded HaGeZi blocklist and custom blocklist
are kept separate.
"""

import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


# ============================================================
# Configuration
# ============================================================

BLOCKLIST_URL = (
    "https://cdn.jsdelivr.net/gh/hagezi/"
    "dns-blocklists@latest/dnsmasq/pro.txt"
)

BLOCKLIST_PATH = (
    "/etc/dnsmasq.d/pi-gateway-adblock.conf"
)

TEMP_BLOCKLIST_PATH = (
    "/tmp/pi-gateway-adblock.conf"
)

BACKUP_BLOCKLIST_PATH = (
    "/tmp/pi-gateway-adblock.conf.backup"
)

CUSTOM_BLOCKLIST_PATH = (
    "/etc/dnsmasq.d/pi-gateway-custom.conf"
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
# HageZi Status
# ============================================================

def is_enabled():
    """
    Return True when the HaGeZi blocklist is installed.
    """

    return os.path.exists(
        BLOCKLIST_PATH
    )


def get_blocklist_path():
    """
    Return the installed HaGeZi blocklist path.
    """

    return BLOCKLIST_PATH


def _count_blocklist_entries(path):
    """
    Count dnsmasq blocklist entries.

    Supports both:

        local=/example.com/

    and:

        address=/example.com/0.0.0.0
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
    Return number of domains in the installed
    HaGeZi blocklist.
    """

    return _count_blocklist_entries(
        BLOCKLIST_PATH
    )


def get_blocklist_size():
    """
    Return installed HaGeZi blocklist size.
    """

    try:
        return os.path.getsize(
            BLOCKLIST_PATH
        )

    except OSError:
        return 0


def get_last_update():
    """
    Return installed HaGeZi blocklist modification
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
# Download HaGeZi
# ============================================================

def download_blocklist(
    destination=TEMP_BLOCKLIST_PATH,
):
    """
    Download the current HaGeZi blocklist.
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
    Validate that a blocklist file appears to be
    a real HaGeZi dnsmasq blocklist.
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
    Validate a downloaded blocklist with dnsmasq.
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
    Backup the current HaGeZi blocklist.
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
    Restore the previous HaGeZi blocklist.
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
    Remove temporary backup.
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
    Atomically install the downloaded HaGeZi list.
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

            temporary_install_path = file.name

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

    If reload fails, restart is attempted.
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
# Update HaGeZi
# ============================================================

def update_blocklist():
    """
    Download, validate, install, and activate
    the latest HaGeZi blocklist.
    """

    start_time = time.monotonic()

    if not download_blocklist():

        return {
            "success": False,
            "stage": "download",
            "message":
                "Failed to download the HaGeZi blocklist.",
        }

    if not _validate_content():

        return {
            "success": False,
            "stage": "content_validation",
            "message":
                "Downloaded blocklist failed content validation.",
        }

    if not validate_blocklist():

        return {
            "success": False,
            "stage": "dnsmasq_validation",
            "message":
                "dnsmasq rejected the downloaded blocklist.",
        }

    if not _backup_existing_blocklist():

        return {
            "success": False,
            "stage": "backup",
            "message":
                "Failed to back up the existing blocklist.",
        }

    if not install_blocklist():

        _remove_backup()

        return {
            "success": False,
            "stage": "installation",
            "message":
                "Failed to install the blocklist.",
        }

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

    if not reload_dnsmasq():

        _restore_backup()

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
            "HaGeZi Multi PRO blocklist "
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
    Disable HaGeZi ad blocking.

    The custom blocklist remains installed.
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

    if backup_created:

        _restore_backup()

        validate_full_dnsmasq_config()
        reload_dnsmasq()

        _remove_backup()

    return False


def enable():
    """
    Enable HaGeZi ad blocking.
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
# Custom Blocklist
# ============================================================

def _normalize_domain(domain):
    """
    Normalize and validate a domain.

    Users may enter either:

        example.com

    or:

        https://example.com/something
    """

    domain = str(domain).strip().lower()

    if "://" in domain:

        parsed = urlparse(domain)

        domain = parsed.hostname or ""

    else:

        # Remove accidental path/query data.
        domain = domain.split("/")[0]

    domain = domain.rstrip(".")

    if not domain:
        raise ValueError(
            "Domain cannot be empty."
        )

    if len(domain) > 253:
        raise ValueError(
            "Domain is too long."
        )

    labels = domain.split(".")

    if len(labels) < 2:
        raise ValueError(
            "Please enter a domain such as example.com."
        )

    for label in labels:

        if not label:
            raise ValueError(
                "Invalid domain."
            )

        if len(label) > 63:
            raise ValueError(
                "Invalid domain."
            )

        if (
            label.startswith("-")
            or label.endswith("-")
        ):
            raise ValueError(
                "Invalid domain."
            )

        if not all(
            character.isalnum()
            or character == "-"
            for character in label
        ):
            raise ValueError(
                "Invalid domain."
            )

    return domain


def get_custom_domains():
    """
    Return all custom blocked domains.

    Supports:

        address=/example.com/0.0.0.0

    and also the older:

        local=/example.com/
    """

    if not os.path.exists(
        CUSTOM_BLOCKLIST_PATH
    ):
        return []

    domains = []

    try:

        with open(
            CUSTOM_BLOCKLIST_PATH,
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                # New format:
                # address=/example.com/0.0.0.0
                if line.startswith("address=/"):

                    value = line[
                        len("address=/"):
                    ]

                    suffix = "/0.0.0.0"

                    if value.endswith(suffix):

                        domain = value[
                            : -len(suffix)
                        ]

                        if domain:
                            domains.append(
                                domain
                            )

                        continue

                # Older format:
                # local=/example.com/
                if line.startswith("local=/"):

                    domain = line[
                        len("local=/"):
                    ]

                    if domain.endswith("/"):
                        domain = domain[:-1]

                    if domain:
                        domains.append(
                            domain
                        )

    except OSError:

        return []

    return sorted(
        set(domains)
    )


def _write_custom_domains(domains):
    """
    Write custom domains to the dnsmasq config.

    Each custom domain is blocked by returning
    0.0.0.0.
    """

    try:

        os.makedirs(
            os.path.dirname(
                CUSTOM_BLOCKLIST_PATH
            ),
            exist_ok=True,
        )

        with open(
            CUSTOM_BLOCKLIST_PATH,
            "w",
            encoding="utf-8",
        ) as file:

            file.write(
                "# PiServer custom blocklist\n"
            )

            file.write(
                "# Managed through the PiServer GUI\n\n"
            )

            for domain in domains:

                file.write(
                    f"address=/{domain}/0.0.0.0\n"
                )

        return True

    except OSError:

        return False


def add_custom_domain(domain):
    """
    Add a domain to the custom blocklist.

    The GUI only needs to provide the domain name.
    For example:

        espn.com

    The resulting dnsmasq entry is:

        address=/espn.com/0.0.0.0
    """

    try:

        domain = _normalize_domain(
            domain
        )

    except ValueError as exc:

        return {
            "success": False,
            "message": str(exc),
        }

    domains = get_custom_domains()

    if domain in domains:

        return {
            "success": False,
            "message":
                f"{domain} is already blocked.",
        }

    domains.append(domain)
    domains.sort()

    if not _write_custom_domains(
        domains
    ):

        return {
            "success": False,
            "message":
                "Failed to save custom blocklist.",
        }

    if not validate_full_dnsmasq_config():

        # Restore previous configuration.
        domains.remove(domain)

        _write_custom_domains(
            domains
        )

        return {
            "success": False,
            "message":
                "dnsmasq rejected the custom domain.",
        }

    if not reload_dnsmasq():

        # Restore previous configuration.
        domains.remove(domain)

        _write_custom_domains(
            domains
        )

        validate_full_dnsmasq_config()
        reload_dnsmasq()

        return {
            "success": False,
            "message":
                "dnsmasq failed to reload.",
        }

    return {
        "success": True,
        "message":
            f"{domain} is now blocked.",
        "domain": domain,
    }


def remove_custom_domain(domain):
    """
    Remove a domain from the custom blocklist.
    """

    try:

        domain = _normalize_domain(
            domain
        )

    except ValueError as exc:

        return {
            "success": False,
            "message": str(exc),
        }

    domains = get_custom_domains()

    if domain not in domains:

        return {
            "success": False,
            "message":
                f"{domain} is not in the custom blocklist.",
        }

    old_domains = list(domains)

    domains.remove(domain)

    if not _write_custom_domains(
        domains
    ):

        return {
            "success": False,
            "message":
                "Failed to update custom blocklist.",
        }

    if not validate_full_dnsmasq_config():

        _write_custom_domains(
            old_domains
        )

        return {
            "success": False,
            "message":
                "dnsmasq rejected the updated blocklist.",
        }

    if not reload_dnsmasq():

        _write_custom_domains(
            old_domains
        )

        validate_full_dnsmasq_config()
        reload_dnsmasq()

        return {
            "success": False,
            "message":
                "dnsmasq failed to reload.",
        }

    return {
        "success": True,
        "message":
            f"{domain} was removed from the blocklist.",
    }


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
                "HaGeZi blocklist is not installed.",
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
        "custom_domains":
            len(get_custom_domains()),
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

