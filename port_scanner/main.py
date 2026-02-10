#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

import socket
import sys


def scan_port(target, port, timeout=1.0):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        # TODO: Create a socket
        # TODO: Set timeout
        # TODO: Try to connect to target:port
        # TODO: Close the socket
        # TODO: Return True if connection successful

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        s.close()
        return True

    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_range(target, start_port, end_port):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number

    Returns:
        list: List of open ports
    """
    open_ports = []

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] This may take a while...")

    # TODO: Implement the scanning logic
    # Hint: Loop through port range and call scan_port()
    # Hint: Consider using threading for better performance

    for port in range(start_port, end_port + 1):
        # TODO: Scan this port
        # TODO: If open, add to open_ports list
        # TODO: Print progress (optional)
        if scan_port(target, port):
            if port not in open_ports:
                open_ports.append(port)

                banner = grab_banner(target, port, timeout=1.0)
                service = guess_service(port, banner)

                first_line = banner.splitlines()[0] if banner else ""
                if first_line:
                    print(f"[+] Port {port}: open | {service} | {first_line}")
                else:
                    print(f"[+] Port {port}: open | {service}")

    return open_ports

def grab_banner(target, port, timeout=1.0):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))

        try:
            data = s.recv(1024)
            if data:
                return data.decode(errors="replace").strip()
        except socket.timeout:
            pass

        http_probe = f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()
        try:
            s.sendall(http_probe)
            data = s.recv(2048)
            if data:
                return data.decode(errors="replace").strip()
        except Exception:
            pass

        try:
            s.sendall(b"PING\r\n")
            data = s.recv(1024)
            if data:
                return data.decode(errors="replace").strip()
        except Exception:
            pass

        return ""

    except Exception:
        return ""
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def guess_service(port, banner):
   
    b = (banner or "").lower()

    if "ssh" in b:
        return "SSH"
    if "http/" in b or "server:" in b:
        return "HTTP"
    if "mysql" in b:
        return "MySQL"
    if "redis" in b or "+pong" in b:
        return "Redis"
    if port in (80, 443, 5000, 5001, 8888):
        return "HTTP."
    if port in (22, 2222):
        return "SSH."
    if port == 3306:
        return "MySQL."
    if port == 6379:
        return "Redis."

    return "Unknown"
    
def main():
    """Main function"""
    # TODO: Parse command-line arguments
    # TODO: Validate inputs
    # TODO: Call scan_range()
    # TODO: Display results

    # Example usage (you should improve this):
    if len(sys.argv) < 2:
        print("Usage: python3 port_scanner_template.py <target>")
        print("Example: python3 port_scanner_template.py 172.20.0.10")
        sys.exit(1)

    target = sys.argv[1]
    # start_port = 1
    # end_port = 1024  # Scan first 1024 ports by default
    try:
        start_port = int(sys.argv[2])
        end_port = int(sys.argv[3])
    except ValueError:
        print("Error: start_port and end_port need to be integers")
        sys.exit(1)

    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
        print("Error: ports need to be between 1 and 65535, and start_port <= end_port.")
        sys.exit(1)

    print(f"[*] Starting port scan on {target}")

    open_ports = scan_range(target, start_port, end_port)

    print(f"\n[+] Scan complete!")
    print(f"[+] Found {len(open_ports)} open ports:")
    for port in open_ports:
        print(f"    Port {port}: open")


if __name__ == "__main__":
    main()
