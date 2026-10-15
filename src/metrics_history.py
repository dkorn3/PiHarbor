"""
PiHarbor metrics history.

Samples WAN throughput and packet loss once a minute and keeps the last
24 hours in a small SQLite database next to this file, so the graphs
survive Flask / Pi restarts.

Usage (from the Flask app):

    import metrics_history
    metrics_history.start(lambda: ("eth0", "1.1.1.1"))
    metrics_history.get_history()
"""

import os
import re
import sqlite3
import subprocess
import threading
import time


DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "metrics_history.db",
)

SAMPLE_INTERVAL = 60
RETENTION_SECONDS = 24 * 60 * 60
PING_COUNT = 5

_started = False
_start_lock = threading.Lock()
_write_lock = threading.Lock()

_LOSS_PATTERN = re.compile(r"([\d.]+)% packet loss")


def _connect():
    connection = sqlite3.connect(DB_PATH, timeout=10)

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS samples (
            ts INTEGER PRIMARY KEY,
            rx_bytes_per_sec REAL,
            tx_bytes_per_sec REAL,
            loss_percent REAL
        )
        """
    )

    return connection


def _read_counters(interface):
    """
    Return (rx_bytes, tx_bytes) for an interface, or None.
    """

    base = f"/sys/class/net/{interface}/statistics"

    try:

        with open(f"{base}/rx_bytes", "r") as file:
            rx_bytes = int(file.read().strip())

        with open(f"{base}/tx_bytes", "r") as file:
            tx_bytes = int(file.read().strip())

        return rx_bytes, tx_bytes

    except (OSError, ValueError):

        return None


def measure_packet_loss(target, count=PING_COUNT):
    """
    Ping a target and return packet loss as a percentage.

    Returns None if ping itself cannot be run.
    """

    try:

        result = subprocess.run(
            [
                "ping",
                "-c", str(count),
                "-W", "1",
                "-q",
                target,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=count + 10,
        )

    except (OSError, subprocess.TimeoutExpired):

        return None

    match = _LOSS_PATTERN.search(result.stdout)

    if match:

        return float(match.group(1))

    # ping ran but produced no summary (e.g. network unreachable).
    return 100.0


def _store(timestamp, rx_rate, tx_rate, loss):

    with _write_lock:

        connection = _connect()

        try:

            connection.execute(
                """
                INSERT OR REPLACE INTO samples
                    (ts, rx_bytes_per_sec, tx_bytes_per_sec, loss_percent)
                VALUES (?, ?, ?, ?)
                """,
                (timestamp, rx_rate, tx_rate, loss),
            )

            connection.execute(
                "DELETE FROM samples WHERE ts < ?",
                (timestamp - RETENTION_SECONDS,),
            )

            connection.commit()

        finally:

            connection.close()


def _sampler_loop(get_settings):

    previous = None

    while True:

        loop_started = time.time()

        try:

            interface, target = get_settings()

            counters = _read_counters(interface)
            now = time.time()

            rx_rate = None
            tx_rate = None

            if counters is not None:

                if (
                    previous is not None
                    and previous["interface"] == interface
                ):

                    elapsed = now - previous["time"]

                    rx_delta = counters[0] - previous["rx"]
                    tx_delta = counters[1] - previous["tx"]

                    # Negative delta means the counters reset.
                    if elapsed > 0 and rx_delta >= 0 and tx_delta >= 0:

                        rx_rate = rx_delta / elapsed
                        tx_rate = tx_delta / elapsed

                previous = {
                    "interface": interface,
                    "time": now,
                    "rx": counters[0],
                    "tx": counters[1],
                }

            else:

                previous = None

            loss = measure_packet_loss(target)

            _store(int(now), rx_rate, tx_rate, loss)

        except Exception:

            # Never let the sampler thread die.
            pass

        elapsed_loop = time.time() - loop_started

        time.sleep(max(1, SAMPLE_INTERVAL - elapsed_loop))


def start(get_settings):
    """
    Start the background sampler once.

    get_settings must return (wan_interface, ping_target).
    """

    global _started

    with _start_lock:

        if _started:
            return

        _started = True

    thread = threading.Thread(
        target=_sampler_loop,
        args=(get_settings,),
        name="piharbor-metrics-history",
        daemon=True,
    )

    thread.start()


def get_history(hours=24):
    """
    Return samples for the last N hours, oldest first.
    """

    cutoff = int(time.time() - hours * 3600)

    try:

        connection = _connect()

        try:

            rows = connection.execute(
                """
                SELECT ts, rx_bytes_per_sec, tx_bytes_per_sec, loss_percent
                FROM samples
                WHERE ts >= ?
                ORDER BY ts ASC
                """,
                (cutoff,),
            ).fetchall()

        finally:

            connection.close()

    except sqlite3.Error:

        return []

    return [
        {
            "t": ts,
            "rx": rx,
            "tx": tx,
            "loss": loss,
        }
        for ts, rx, tx, loss in rows
    ]
