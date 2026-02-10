#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import logging
import os
import time
import socket
import threading
import json
from datetime import datetime, timezone

LOG_DIR = "/app/logs"
LOG_PATH = os.path.join(LOG_DIR, "honeypot.log")
JSONL_PATH = os.path.join(LOG_DIR, "connections.jsonl")

BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13\r\n"

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

def setup_logging():
    os.makedirs("/app/logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
    )

def log_json(event: dict):
    event.setdefault("timestamp", utc_now_iso())
    with open(JSONL_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def recv_line(conn: socket.socket, timeout=10.0, max_bytes=256) -> str:
    conn.settimeout(timeout)
    data = b""
    while len(data) < max_bytes:
        bch = conn.recv(1)
        if not bch:
            break
        data += bch
        if bch in (b"\n",):
            break
    return data.decode(errors="replace").strip()


def handle_client(conn: socket.socket, addr):
    logger = logging.getLogger("Honeypot")
    client_ip, client_port = addr[0], addr[1]
    start = time.time()

    logger.info("Connection from %s:%s", client_ip, client_port)
    log_json({"event": "connection", "client_ip": client_ip, "client_port": client_port})

    try:
        conn.sendall(BANNER.encode())
        conn.sendall(b"login: ")
        username = recv_line(conn)
        conn.sendall(b"Password: ")
        password = recv_line(conn)
        logger.info("Auth attempt from %s:%s username=%r password=%r", client_ip, client_port, username, password)
        log_json(
            {
                "event": "auth_attempt",
                "client_ip": client_ip,
                "client_port": client_port,
                "username": username,
                "password": password,
            }
        )
        conn.sendall(b"Permission denied, please try again.\r\n")
        time.sleep(0.5)

    except Exception as e:
        logger.info("Error with %s:%s (%s)", client_ip, client_port, str(e))
        log_json({"event": "error", "client_ip": client_ip, "client_port": client_port, "message": str(e)})

    finally:
        duration = round(time.time() - start, 3)
        logger.info("Disconnected %s:%s duration=%.3fs", client_ip, client_port, duration)
        log_json({"event": "disconnect", "client_ip": client_ip, "client_port": client_port, "duration_s": duration})
        try:
            conn.close()
        except Exception:
            pass

def run_honeypot(listen_host="0.0.0.0", listen_port=22):
    logger = logging.getLogger("Honeypot")
    logger.info("Honeypot starter template running.")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((listen_host, listen_port))
    s.listen(50)

    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    setup_logging()
    run_honeypot()
