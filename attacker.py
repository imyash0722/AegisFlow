#!/usr/bin/env python3
"""
attacker.py — Simple Attack Generator (Port Scanning & Connection Flooding)
Generates controlled TCP test traffic to trigger the intrusion detection system.
"""

import socket
import time
import sys

TARGET_IP = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.3"
MODE = sys.argv[1] if len(sys.argv) > 1 else "scan"  # 'scan' or 'flood'


def port_scan():
    """Scans multiple destination ports on the victim."""
    ports = [21, 22, 23, 25, 80, 110, 443, 8080, 9000]
    print(f"[*] Starting Port Scan against {TARGET_IP} on ports {ports}...")

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        res = s.connect_ex((TARGET_IP, port))
        if res == 0:
            print(f"  [+] Port {port:<5} OPEN")
        else:
            print(f"  [-] Port {port:<5} CLOSED or FILTERED / BLOCKED (code: {res})")
        s.close()
        time.sleep(0.1)


def connection_flood():
    """Rapidly floods connections to port 8080."""
    print(f"[*] Starting Connection Flood against {TARGET_IP}:8080 (30 rapid connections)...")

    for i in range(30):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((TARGET_IP, 8080))
            s.sendall(b"FLOOD_TEST\n")
            print(f"  [+] Connection #{i+1:02d} established")
            s.close()
        except Exception as e:
            print(f"  [X] Connection #{i+1:02d} BLOCKED / DROPPED: {e}")
        time.sleep(0.05)


def main():
    if MODE == "scan":
        port_scan()
    elif MODE == "flood":
        connection_flood()
    else:
        print("Usage: python3 attacker.py [scan|flood] [TARGET_IP]")


if __name__ == "__main__":
    main()
