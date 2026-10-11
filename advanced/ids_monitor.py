#!/usr/bin/env python3
"""
ids_monitor.py — Real-Time Intrusion Detection System Engine
Project 25: Network Intrusion Detection and Response System

Analyzes TCP traffic telemetry, detects predefined abnormal behaviors
(Port Scanning, DoS Connection Floods, SYN Bursts), computes precise detection
and response latencies, and dynamically commands the SDN Controller to install
flow-level drop rules.
"""

import socket
import threading
import time
import json
import argparse
import sys
import signal
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
from protocol import (
    DEFAULT_HOST,
    DEFAULT_MONITOR_PORT,
    DEFAULT_SDN_CMD_PORT,
    TH_CONN_RATE,
    TH_PORT_SCAN_PORTS,
    TH_PORT_SCAN_WINDOW,
    TH_FAILED_CONN,
    TH_SYN_BURST,
    TH_BURST_WINDOW,
    DEFAULT_BLOCK_DURATION,
    ATTACK_PORT_SCAN,
    ATTACK_CONN_FLOOD,
    ATTACK_SYN_FLOOD,
    CMD_BLOCK,
    CMD_UNBLOCK,
    SecurityAlert,
    format_alert_log,
    serialize_ipc_message,
    parse_ipc_message,
)


class HostTracker:
    """Maintains sliding-window activity records for an individual source IP."""

    def __init__(self, ip: str):
        self.ip = ip
        self.connection_history: deque = deque()  # (timestamp, dst_ip, dst_port, status)
        self.ports_accessed: Dict[int, float] = {}  # dst_port -> last_timestamp
        self.first_activity: float = time.time()
        self.last_activity: float = time.time()
        self.is_blocked: bool = False
        self.block_timestamp: float = 0.0
        self.alerts_count: int = 0

    def record_connection(self, dst_ip: str, dst_port: int, status: str = "SYN") -> Tuple[Optional[str], float, float]:
        """
        Record a connection event and evaluate intrusion rules.
        Returns: (alert_type, metric_value, threshold_value) if abnormal, else (None, 0.0, 0.0).
        """
        now = time.time()
        self.last_activity = now
        self.connection_history.append((now, dst_ip, dst_port, status))
        self.ports_accessed[dst_port] = now

        if self.is_blocked:
            return None, 0.0, 0.0  # Already blocked

        # Prune records older than the maximum sliding window (10.0 seconds)
        cutoff_window = now - TH_PORT_SCAN_WINDOW
        while self.connection_history and self.connection_history[0][0] < cutoff_window:
            self.connection_history.popleft()

        # Prune old ports
        self.ports_accessed = {p: t for p, t in self.ports_accessed.items() if t >= cutoff_window}

        # --- RULE 1: Port Scanning Reconnaissance ---
        # Triggered if >= TH_PORT_SCAN_PORTS distinct destination ports accessed in sliding window
        distinct_ports_count = len(self.ports_accessed)
        if distinct_ports_count >= TH_PORT_SCAN_PORTS:
            return ATTACK_PORT_SCAN, float(distinct_ports_count), float(TH_PORT_SCAN_PORTS)

        # --- RULE 2: Connection Flooding / High Connection Rate ---
        # Count connections in the last 1.0 second
        one_sec_cutoff = now - 1.0
        conns_last_sec = sum(1 for (t, _, _, _) in self.connection_history if t >= one_sec_cutoff)
        if conns_last_sec >= TH_CONN_RATE:
            return ATTACK_CONN_FLOOD, float(conns_last_sec), float(TH_CONN_RATE)

        # --- RULE 3: SYN / Connection Burst ---
        # Count connections in the 2.0-second burst window
        burst_cutoff = now - TH_BURST_WINDOW
        conns_burst = sum(1 for (t, _, _, _) in self.connection_history if t >= burst_cutoff)
        if conns_burst >= TH_SYN_BURST:
            return ATTACK_SYN_FLOOD, float(conns_burst), float(TH_SYN_BURST)

        return None, 0.0, 0.0


class IDSMonitor:
    """Central Intrusion Detection and Response Controller."""

    def __init__(self, listen_port: int = DEFAULT_MONITOR_PORT,
                 sdn_host: str = "127.0.0.1", sdn_port: int = DEFAULT_SDN_CMD_PORT,
                 block_duration: int = DEFAULT_BLOCK_DURATION):
        self.listen_port = listen_port
        self.sdn_host = sdn_host
        self.sdn_port = sdn_port
        self.block_duration = block_duration
        self.running = False
        self.lock = threading.Lock()

        self.trackers: Dict[str, HostTracker] = {}
        self.alerts: List[SecurityAlert] = []
        self.blocked_ips: Set[str] = set()
        self.server_sock: Optional[socket.socket] = None

    def start(self):
        """Start IDS listener and monitoring loops."""
        self.running = True
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((DEFAULT_HOST, self.listen_port))
        self.server_sock.listen(64)
        self.server_sock.settimeout(1.0)

        print(f"[*] IDSMonitor listening for telemetry on port {self.listen_port}")
        print(f"[*] SDN Controller target: {self.sdn_host}:{self.sdn_port}")

        # Start background unblock expiration checker
        unblock_thread = threading.Thread(target=self._unblock_expiration_loop, daemon=True)
        unblock_thread.start()

        # Listen loop
        try:
            while self.running:
                try:
                    conn, addr = self.server_sock.accept()
                    worker = threading.Thread(target=self._handle_telemetry_conn, args=(conn, addr), daemon=True)
                    worker.start()
                except socket.timeout:
                    continue
                except OSError:
                    break
        except KeyboardInterrupt:
            print("\n[*] IDSMonitor interrupted by user (Ctrl+C)...")
        finally:
            self.stop()

    def process_event(self, src_ip: str, dst_ip: str, dst_port: int, status: str = "SYN") -> Optional[SecurityAlert]:
        """Direct API for processing connection events (used in both live sockets and unit tests)."""
        with self.lock:
            if src_ip not in self.trackers:
                self.trackers[src_ip] = HostTracker(src_ip)
            tracker = self.trackers[src_ip]

            alert_type, metric_val, threshold_val = tracker.record_connection(dst_ip, dst_port, status)

            if alert_type and not tracker.is_blocked:
                # Mark as blocked
                tracker.is_blocked = True
                tracker.block_timestamp = time.time()
                tracker.alerts_count += 1
                self.blocked_ips.add(src_ip)

                # Measure Detection Latency (from first observed abnormal activity to alert decision)
                detection_time_ms = (time.time() - tracker.connection_history[0][0]) * 1000.0

                # Formulate SecurityAlert
                alert = SecurityAlert(
                    alert_id=f"ALT-{len(self.alerts)+1:04d}",
                    timestamp=time.time(),
                    iso_time=datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    attack_type=alert_type,
                    description=f"Exceeded threshold for {alert_type}: {metric_val:.1f} >= {threshold_val:.1f}",
                    metric_value=metric_val,
                    threshold_value=threshold_val,
                    action_taken="DISPATCH_SDN_BLOCK",
                    detection_time_ms=max(0.1, detection_time_ms),
                )

                # Dispatch block action to SDN Controller and measure response latency
                resp_ms = self._dispatch_sdn_block(src_ip, alert_type)
                alert.response_time_ms = resp_ms
                self.alerts.append(alert)

                print(format_alert_log(alert))
                return alert

        return None

    def _handle_telemetry_conn(self, sock: socket.socket, addr: Tuple[str, int]):
        """Ingest newline-delimited JSON telemetry stream from network agents/switches."""
        sock.settimeout(5.0)
        buffer = ""

        try:
            while self.running:
                data = sock.recv(4096)
                if not data:
                    break
                buffer += data.decode("utf-8", errors="ignore")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        src_ip = record.get("src_ip", "")
                        dst_ip = record.get("dst_ip", "")
                        dst_port = int(record.get("dst_port", 80))
                        status = record.get("status", "SYN")
                        if src_ip and dst_ip:
                            self.process_event(src_ip, dst_ip, dst_port, status)
                    except Exception as err:
                        print(f"[-] Telemetry parse error: {err}")
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _dispatch_sdn_block(self, offender_ip: str, reason: str) -> float:
        """Send dynamic BLOCK command to SDN controller over IPC socket and measure latency."""
        t_start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            sock.connect((self.sdn_host, self.sdn_port))

            msg = serialize_ipc_message(CMD_BLOCK, {
                "ip": offender_ip,
                "duration": self.block_duration,
                "reason": reason,
                "priority": 200,
            })
            sock.sendall(msg)

            # Receive confirmation acknowledgment
            resp_bytes = sock.recv(1024)
            sock.close()
            t_end = time.time()
            return (t_end - t_start) * 1000.0
        except Exception as exc:
            t_end = time.time()
            print(f"[-] Could not communicate with SDN Controller at {self.sdn_host}:{self.sdn_port}: {exc}")
            return (t_end - t_start) * 1000.0

    def _dispatch_sdn_unblock(self, offender_ip: str):
        """Send UNBLOCK command to SDN controller when penalty time expires."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            sock.connect((self.sdn_host, self.sdn_port))
            msg = serialize_ipc_message(CMD_UNBLOCK, {"ip": offender_ip})
            sock.sendall(msg)
            sock.close()
            print(f"[+] Dispatched SDN unblock for {offender_ip}")
        except Exception as exc:
            print(f"[-] Failed to unblock {offender_ip} on SDN controller: {exc}")

    def _unblock_expiration_loop(self):
        """Periodically audit blocked hosts and unblock those whose punishment expired."""
        while self.running:
            time.sleep(2.0)
            now = time.time()
            with self.lock:
                expired = []
                for ip in list(self.blocked_ips):
                    tracker = self.trackers.get(ip)
                    if tracker and (now - tracker.block_timestamp) >= self.block_duration:
                        expired.append(ip)

                for ip in expired:
                    self.blocked_ips.remove(ip)
                    if ip in self.trackers:
                        self.trackers[ip].is_blocked = False
                    self._dispatch_sdn_unblock(ip)

    def stop(self):
        """Shutdown IDS monitor and write alerts to disk."""
        if not self.running:
            return
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        self.export_alerts("alerts.json")

    def export_alerts(self, filepath: str = "alerts.json"):
        """Save captured security alerts to JSON file."""
        with self.lock:
            data = [a.to_dict() for a in self.alerts]
            try:
                with open(filepath, "w") as f:
                    json.dump(data, f, indent=2)
                print(f"[+] Saved {len(data)} security alerts to {filepath}")
            except Exception as exc:
                print(f"[-] Failed to export {filepath}: {exc}")


def main():
    parser = argparse.ArgumentParser(description="Real-Time Intrusion Detection System Engine")
    parser.add_argument("--port", type=int, default=DEFAULT_MONITOR_PORT, help=f"Telemetry listen port (default: {DEFAULT_MONITOR_PORT})")
    parser.add_argument("--sdn-host", default="127.0.0.1", help="SDN controller host (default: 127.0.0.1)")
    parser.add_argument("--sdn-port", type=int, default=DEFAULT_SDN_CMD_PORT, help=f"SDN controller command port (default: {DEFAULT_SDN_CMD_PORT})")
    parser.add_argument("--block-duration", type=int, default=DEFAULT_BLOCK_DURATION, help=f"Block duration in seconds (default: {DEFAULT_BLOCK_DURATION})")
    args = parser.parse_args()

    ids = IDSMonitor(
        listen_port=args.port,
        sdn_host=args.sdn_host,
        sdn_port=args.sdn_port,
        block_duration=args.block_duration,
    )

    def sig_handler(sig, frame):
        ids.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    ids.start()


if __name__ == "__main__":
    main()
