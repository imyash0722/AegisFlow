#!/usr/bin/env python3
"""
attack_generator.py — Controlled TCP Security-Test Traffic Generator
Project 25: Network Intrusion Detection and Response System

Generates controlled adversarial traffic to evaluate the Intrusion Detection System
and SDN dynamic response engine. Implements multiple attack vectors:
  1. Horizontal/Vertical Port Scanning (multi-port reconnaissance)
  2. TCP Connection Flooding (high-rate DoS bursts)
  3. Rapid SYN-connect exhaustion
  4. Brute-Force authentication probing
Tracks attack initiation, delivery success, and the exact moment traffic is blocked.
"""

import socket
import time
import json
import argparse
import sys
import signal
from typing import List, Dict, Any
from protocol import (
    DEFAULT_TARGET_IP,
    DEFAULT_SERVER_PORT,
    PROTECTED_PORTS,
    ATTACK_PORT_SCAN,
    ATTACK_CONN_FLOOD,
    ATTACK_SYN_FLOOD,
    ATTACK_BRUTE_FORCE,
    VALID_TRAFFIC_MODES,
)


class AttackGenerator:
    """Adversarial traffic generator for IDS and SDN defense evaluation."""

    def __init__(self, target_ip: str = DEFAULT_TARGET_IP, target_port: int = DEFAULT_SERVER_PORT,
                 mode: str = ATTACK_PORT_SCAN, duration: int = 10, rate: float = 25.0,
                 ports: Optional[List[int]] = None, total_attempts: int = 50):
        self.target_ip = target_ip
        self.target_port = target_port
        self.mode = mode
        self.duration = duration
        self.rate = rate
        self.ports = ports or PROTECTED_PORTS
        self.total_attempts = total_attempts
        self.running = False

        self.stats = {
            "mode": mode,
            "target_ip": target_ip,
            "start_time": 0.0,
            "end_time": 0.0,
            "total_attempts": 0,
            "successful_attempts": 0,
            "blocked_or_timed_out": 0,
            "first_block_time": None,
            "durations_per_attempt_ms": [],
        }

    def start(self):
        """Dispatch the selected attack simulation mode."""
        self.running = True
        self.stats["start_time"] = time.time()
        print(f"[!] ATTACK GENERATOR STARTED -> Mode: {self.mode.upper()} on {self.target_ip}")

        try:
            if self.mode == ATTACK_PORT_SCAN:
                self._run_port_scan()
            elif self.mode == ATTACK_CONN_FLOOD:
                self._run_conn_flood()
            elif self.mode == ATTACK_SYN_FLOOD:
                self._run_syn_flood()
            elif self.mode == ATTACK_BRUTE_FORCE:
                self._run_brute_force()
            else:
                print(f"[-] Unknown attack mode: {self.mode}")
        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user (Ctrl+C)...")
        finally:
            self.stop()

    def _run_port_scan(self):
        """Simulate vertical port reconnaissance across multiple destination ports."""
        print(f"[*] Commencing Port Scan across ports: {self.ports}")
        interval = 1.0 / max(1.0, self.rate)

        while self.running:
            for p in self.ports:
                if not self.running:
                    break
                elapsed = time.time() - self.stats["start_time"]
                if self.duration > 0 and elapsed >= self.duration:
                    return

                self._probe_port(p)
                time.sleep(interval)

    def _probe_port(self, port: int):
        """Probe an individual TCP destination port."""
        self.stats["total_attempts"] += 1
        t_start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)  # Fast timeout for rapid reconnaissance

        try:
            res = sock.connect_ex((self.target_ip, port))
            t_ms = (time.time() - t_start) * 1000.0
            self.stats["durations_per_attempt_ms"].append(t_ms)

            if res == 0:
                self.stats["successful_attempts"] += 1
                print(f"  [+] Port {port:<5} OPEN  ({t_ms:.1f}ms)")
            else:
                # Port closed or filtered
                self.stats["blocked_or_timed_out"] += 1
                if self.stats["first_block_time"] is None:
                    self.stats["first_block_time"] = time.time()
                print(f"  [-] Port {port:<5} CLOSED/FILTERED (code: {res})")
        except (socket.timeout, OSError) as exc:
            self.stats["blocked_or_timed_out"] += 1
            if self.stats["first_block_time"] is None:
                self.stats["first_block_time"] = time.time()
            print(f"  [X] Port {port:<5} DROPPED/TIMED OUT: {exc}")
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _run_conn_flood(self):
        """Simulate connection flooding (DoS) by bursting TCP connections."""
        print(f"[*] Commencing TCP Connection Flood at {self.rate} connections/sec")
        interval = 1.0 / max(1.0, self.rate)
        attempt = 0

        while self.running:
            attempt += 1
            elapsed = time.time() - self.stats["start_time"]
            if (self.duration > 0 and elapsed >= self.duration) or (
                self.total_attempts > 0 and attempt > self.total_attempts
            ):
                break

            self.stats["total_attempts"] += 1
            t_start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            try:
                sock.connect((self.target_ip, self.target_port))
                sock.sendall(b"FLOOD_PAYLOAD_TEST_ABNORMAL_BURST\n")
                self.stats["successful_attempts"] += 1
                t_ms = (time.time() - t_start) * 1000.0
                print(f"  [CONN #{attempt:04d}] ESTABLISHED ({t_ms:.1f}ms)")
            except (socket.timeout, ConnectionRefusedError, OSError) as exc:
                self.stats["blocked_or_timed_out"] += 1
                if self.stats["first_block_time"] is None:
                    self.stats["first_block_time"] = time.time()
                print(f"  [CONN #{attempt:04d}] BLOCKED / DROPPED: {exc}")
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

            time.sleep(interval)

    def _run_syn_flood(self):
        """Simulate rapid TCP connect aborts (abnormal connection setup/teardown)."""
        print(f"[*] Simulating Rapid TCP Connection Burst (SYN Flood proxy)")
        interval = 1.0 / max(1.0, self.rate)
        attempt = 0

        while self.running:
            attempt += 1
            elapsed = time.time() - self.stats["start_time"]
            if (self.duration > 0 and elapsed >= self.duration) or (
                self.total_attempts > 0 and attempt > self.total_attempts
            ):
                break

            self.stats["total_attempts"] += 1
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Enable SO_LINGER with timeout 0 to force TCP RST upon close
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
            sock.settimeout(0.3)

            try:
                sock.connect((self.target_ip, self.target_port))
                self.stats["successful_attempts"] += 1
                print(f"  [SYN-BURST #{attempt:04d}] Connected -> sending instant RST")
            except Exception as exc:
                self.stats["blocked_or_timed_out"] += 1
                if self.stats["first_block_time"] is None:
                    self.stats["first_block_time"] = time.time()
                print(f"  [SYN-BURST #{attempt:04d}] FAILED / BLOCKED: {exc}")
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

            time.sleep(interval)

    def _run_brute_force(self):
        """Simulate brute-force password guessing on the authentication gateway."""
        print(f"[*] Simulating Brute-Force Auth attack against {self.target_ip}:{self.target_port}")
        interval = 1.0 / max(1.0, self.rate)
        attempt = 0

        passwords = [f"password_{i}" for i in range(100)]
        for pwd in passwords:
            if not self.running:
                break
            attempt += 1
            elapsed = time.time() - self.stats["start_time"]
            if self.duration > 0 and elapsed >= self.duration:
                break

            self.stats["total_attempts"] += 1
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            try:
                sock.connect((self.target_ip, self.target_port))
                req = f"POST /api/auth HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\nuser=admin&pass={pwd}"
                sock.sendall(req.encode("utf-8"))
                resp = sock.recv(1024)
                self.stats["successful_attempts"] += 1
                print(f"  [AUTH #{attempt:03d}] Sent attempt with pass='{pwd}' -> {resp[:20]!r}")
            except Exception as exc:
                self.stats["blocked_or_timed_out"] += 1
                if self.stats["first_block_time"] is None:
                    self.stats["first_block_time"] = time.time()
                print(f"  [AUTH #{attempt:03d}] BLOCKED: {exc}")
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

            time.sleep(interval)

    def stop(self):
        """Finalize and export attack summary statistics."""
        if not self.running:
            return
        self.running = False
        self.stats["end_time"] = time.time()

        elapsed = max(0.1, self.stats["end_time"] - self.stats["start_time"])
        block_rate = (self.stats["blocked_or_timed_out"] / max(1, self.stats["total_attempts"])) * 100.0

        print("\n" + "=" * 55)
        print("          ATTACK EXECUTION SUMMARY")
        print("=" * 55)
        print(f" Mode               : {self.mode.upper()}")
        print(f" Target             : {self.target_ip}")
        print(f" Duration           : {elapsed:.2f} s")
        print(f" Total Attempts     : {self.stats['total_attempts']}")
        print(f" Successful         : {self.stats['successful_attempts']}")
        print(f" Blocked/Timed Out  : {self.stats['blocked_or_timed_out']} ({block_rate:.1f}%)")
        if self.stats["first_block_time"]:
            time_to_block = self.stats["first_block_time"] - self.stats["start_time"]
            print(f" Time to First Block: {time_to_block:.3f} s")
        print("=" * 55)

        self.export_stats("attack_stats.json")

    def export_stats(self, filepath: str = "attack_stats.json"):
        """Write attack statistics to JSON file for analysis."""
        try:
            with open(filepath, "w") as f:
                json.dump(self.stats, f, indent=2)
            print(f"[+] Saved attack telemetry to {filepath}")
        except Exception as exc:
            print(f"[-] Failed to export {filepath}: {exc}")


def main():
    parser = argparse.ArgumentParser(description="Controlled TCP Security-Test Traffic Generator")
    parser.add_argument("--target-ip", default=DEFAULT_TARGET_IP, help=f"Target IP (default: {DEFAULT_TARGET_IP})")
    parser.add_argument("--target-port", type=int, default=DEFAULT_SERVER_PORT, help=f"Target port (default: {DEFAULT_SERVER_PORT})")
    parser.add_argument("--mode", choices=VALID_TRAFFIC_MODES, default=ATTACK_PORT_SCAN, help=f"Attack mode (default: {ATTACK_PORT_SCAN})")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds (default: 10)")
    parser.add_argument("--rate", type=float, default=25.0, help="Attempt rate per second (default: 25.0)")
    parser.add_argument("--ports", default=",".join(map(str, PROTECTED_PORTS)), help="Comma-separated ports for port scan")
    parser.add_argument("--attempts", type=int, default=50, help="Total attempts (default: 50)")
    args = parser.parse_args()

    port_list = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]

    generator = AttackGenerator(
        target_ip=args.target_ip,
        target_port=args.target_port,
        mode=args.mode,
        duration=args.duration,
        rate=args.rate,
        ports=port_list,
        total_attempts=args.attempts,
    )

    def sig_handler(sig, frame):
        generator.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    generator.start()


if __name__ == "__main__":
    main()
