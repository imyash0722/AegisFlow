#!/usr/bin/env python3
"""
tcp_client.py — Legitimate TCP Service Client
Project 25: Network Intrusion Detection and Response System

Generates controlled, legitimate TCP socket traffic against the protected server.
Communicates using standard request-response protocols, measures round-trip
latency (RTT), logs transaction success/failure rates, and exports client-side
telemetry for baseline versus active mitigation comparison.
"""

import socket
import time
import json
import argparse
import sys
import signal
from typing import Dict, Any, List
from protocol import DEFAULT_SERVER_PORT, DEFAULT_TARGET_IP


class TCPClient:
    """Legitimate TCP client connecting to the protected service server."""

    def __init__(self, target_ip: str = DEFAULT_TARGET_IP, target_port: int = DEFAULT_SERVER_PORT,
                 rate: float = 2.0, duration: int = 15, count: int = 0):
        self.target_ip = target_ip
        self.target_port = target_port
        self.rate = rate  # requests per second
        self.duration = duration  # seconds to run
        self.count = count  # max requests (0 = use duration)
        self.running = False

        self.stats = {
            "target_ip": target_ip,
            "target_port": target_port,
            "start_time": 0.0,
            "end_time": 0.0,
            "total_sent": 0,
            "total_success": 0,
            "total_failed": 0,
            "latencies_ms": [],
            "avg_latency_ms": 0.0,
            "min_latency_ms": 0.0,
            "max_latency_ms": 0.0,
        }

    def start(self):
        """Execute the paced request loop."""
        self.running = True
        self.stats["start_time"] = time.time()
        interval = 1.0 / max(0.1, self.rate)
        req_num = 0

        print(f"[*] TCPClient started -> Target: {self.target_ip}:{self.target_port} | Rate: {self.rate} req/s")

        try:
            while self.running:
                now = time.time()
                elapsed = now - self.stats["start_time"]

                if self.count > 0 and req_num >= self.count:
                    break
                if self.duration > 0 and elapsed >= self.duration:
                    break

                req_num += 1
                self._send_transaction(req_num)
                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n[*] Client interrupted by user (Ctrl+C)...")
        finally:
            self.stop()

    def _send_transaction(self, seq: int):
        """Open a low-level TCP connection, send request, receive response, and measure latency."""
        self.stats["total_sent"] += 1
        t_start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.5)

        try:
            sock.connect((self.target_ip, self.target_port))

            # Application request payload
            payload = f"GET /api/data?seq={seq}&client_time={t_start} HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"
            sock.sendall(payload.encode("utf-8"))

            response = sock.recv(4096)
            t_end = time.time()
            latency_ms = (t_end - t_start) * 1000.0

            if response:
                self.stats["total_success"] += 1
                self.stats["latencies_ms"].append(latency_ms)
                print(f"[REQ #{seq:03d}] Status: 200 OK | Latency: {latency_ms:.2f} ms | Size: {len(response)} B")
            else:
                self.stats["total_failed"] += 1
                print(f"[REQ #{seq:03d}] Status: EMPTY RESPONSE")

        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            self.stats["total_failed"] += 1
            t_end = time.time()
            latency_ms = (t_end - t_start) * 1000.0
            print(f"[REQ #{seq:03d}] Failed: {exc} | Latency: {latency_ms:.2f} ms")
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def stop(self):
        """Finalize client session and record summary metrics."""
        if not self.running:
            return
        self.running = False
        self.stats["end_time"] = time.time()

        latencies = self.stats["latencies_ms"]
        if latencies:
            self.stats["avg_latency_ms"] = sum(latencies) / len(latencies)
            self.stats["min_latency_ms"] = min(latencies)
            self.stats["max_latency_ms"] = max(latencies)

        duration = max(0.1, self.stats["end_time"] - self.stats["start_time"])
        success_rate = (self.stats["total_success"] / max(1, self.stats["total_sent"])) * 100.0

        print("\n" + "=" * 55)
        print("          TCP CLIENT EXECUTION SUMMARY")
        print("=" * 55)
        print(f" Target Server       : {self.target_ip}:{self.target_port}")
        print(f" Session Duration    : {duration:.2f} s")
        print(f" Requests Sent       : {self.stats['total_sent']}")
        print(f" Requests Succeeded  : {self.stats['total_success']} ({success_rate:.1f}%)")
        print(f" Requests Failed     : {self.stats['total_failed']}")
        print(f" Average Latency     : {self.stats['avg_latency_ms']:.2f} ms")
        print(f" Min / Max Latency   : {self.stats['min_latency_ms']:.2f} ms / {self.stats['max_latency_ms']:.2f} ms")
        print("=" * 55)

        self.export_stats("client_stats.json")

    def export_stats(self, filepath: str = "client_stats.json"):
        """Save client metrics to JSON file for performance comparison."""
        try:
            with open(filepath, "w") as f:
                json.dump(self.stats, f, indent=2)
            print(f"[+] Saved client metrics to {filepath}")
        except Exception as exc:
            print(f"[-] Failed to export {filepath}: {exc}")


def main():
    parser = argparse.ArgumentParser(description="Legitimate TCP Service Client")
    parser.add_argument("--server-ip", default=DEFAULT_TARGET_IP, help=f"Target server IP (default: {DEFAULT_TARGET_IP})")
    parser.add_argument("--server-port", type=int, default=DEFAULT_SERVER_PORT, help=f"Target port (default: {DEFAULT_SERVER_PORT})")
    parser.add_argument("--rate", type=float, default=2.0, help="Requests per second (default: 2.0)")
    parser.add_argument("--duration", type=int, default=15, help="Test duration in seconds (default: 15)")
    parser.add_argument("--count", type=int, default=0, help="Max requests to send (0 = infinite up to duration)")
    args = parser.parse_args()

    client = TCPClient(
        target_ip=args.server_ip,
        target_port=args.server_port,
        rate=args.rate,
        duration=args.duration,
        count=args.count,
    )

    def sig_handler(sig, frame):
        client.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    client.start()


if __name__ == "__main__":
    main()
