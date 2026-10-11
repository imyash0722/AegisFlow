#!/usr/bin/env python3
"""
client.py — Simple Legitimate TCP Client
Connects to the protected server, sends a request, and measures response time.
"""

import socket
import time
import sys

TARGET_IP = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.3"
TARGET_PORT = 8080


def send_request():
    start_time = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((TARGET_IP, TARGET_PORT))
        s.sendall(b"GET /data HTTP/1.1\r\nHost: server\r\n\r\n")
        response = s.recv(1024)
        latency_ms = (time.time() - start_time) * 1000

        print(f"[✓] Success: Received {len(response)} bytes in {latency_ms:.2f} ms")
        s.close()
    except Exception as e:
        print(f"[X] Request failed: {e}")


def main():
    print(f"[*] Starting legitimate client -> Target {TARGET_IP}:{TARGET_PORT}")
    for i in range(5):
        print(f"--- Request {i+1} ---")
        send_request()
        time.sleep(1.0)  # Paced normal traffic


if __name__ == "__main__":
    main()
