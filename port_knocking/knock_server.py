#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import time
import subprocess
import threading

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def open_protected_port(protected_port, protected_ip):
    """Open the protected port using firewall rules."""
    # TODO: Use iptables/nftables to allow access to protected_port.
    subprocess.run(
        ["iptables", "-D", "OUTPUT", "-p", "tcp", "-d", protected_ip, "--dport", str(protected_port), "-j", "REJECT"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    logging.info("Opened %s:%s (OUTPUT unblocked)", protected_ip, protected_port)


def close_protected_port(protected_port, protected_ip):
    """Close the protected port using firewall rules."""
    # TODO: Remove firewall rules for protected_port.
    subprocess.run(
        ["iptables", "-C", "OUTPUT", "-p", "tcp", "-d", protected_ip, "--dport", str(protected_port), "-j", "REJECT"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if subprocess.run(
        ["iptables", "-C", "OUTPUT", "-p", "tcp", "-d", protected_ip, "--dport", str(protected_port), "-j", "REJECT"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode != 0:
        subprocess.run(
            ["iptables", "-I", "OUTPUT", "1", "-p", "tcp", "-d", protected_ip, "--dport", str(protected_port), "-j", "REJECT"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    logging.info("Closed %s:%s (OUTPUT blocked)", protected_ip, protected_port)


def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)

    # TODO: Create UDP or TCP listeners for each knock port.
    # TODO: Track each source IP and its progress through the sequence.
    # TODO: Enforce timing window per sequence.
    # TODO: On correct sequence, call open_protected_port().
    # TODO: On incorrect sequence, reset progress.

    protected_ip = "172.20.0.20"
    close_protected_port(protected_port, protected_ip)

    listeners = []
    for p in sequence:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", p))
        s.listen(50)
        listeners.append((p, s))
        logger.info("Listening on knock port %s", p)

    progress = {}
    events = []
    def accept_loop(port, sock):
        while True:
            conn, addr = sock.accept()
            client_ip = addr[0]
            conn.close()
            events.append((time.time(), client_ip, port))

    for p, s in listeners:
        t = threading.Thread(target=accept_loop, args=(p, s), daemon=True)
        t.start()

    open_seconds = 20.0

    while True:
        if not events:
            time.sleep(0.05)
            continue

        ts, client_ip, port = events.pop(0)
        idx, start_ts = progress.get(client_ip, (0, ts))
        if ts - start_ts > window_seconds:
            idx, start_ts = 0, ts

        expected = sequence[idx]
        if port == expected:
            idx += 1
            progress[client_ip] = (idx, start_ts)
            logger.info("Knock %s/%s from %s on %s", idx, len(sequence), client_ip, port)

            if idx == len(sequence):
                logger.info("Sequence complete for %s — opening port %s", client_ip, protected_port)
                progress[client_ip] = (0, ts)
                open_protected_port(protected_port, protected_ip)

                def close_later():
                    time.sleep(open_seconds)
                    close_protected_port(protected_port, protected_ip)

                threading.Thread(target=close_later, daemon=True).start()
        else:
            progress[client_ip] = (0, ts)

def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()
