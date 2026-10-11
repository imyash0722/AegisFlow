#!/usr/bin/env python3
"""
tcp_server.py — Multi-Client Protected TCP Service Server
Project 25: Network Intrusion Detection and Response System

Implements a robust multi-threaded TCP socket server running protected services
(e.g., HTTP Web API, Authentication Gateway, Health Monitoring).
Logs connection telemetry, tracks connection rates, handles concurrent requests,
and exports comprehensive session metrics for performance evaluation.
"""

import socket
import threading
import time
import json
import argparse
import sys
import signal
from datetime import datetime
from typing import Dict, Tuple, List, Optional
from protocol import (
    DEFAULT_HOST,
    DEFAULT_SERVER_PORT,
    PROTECTED_PORTS,
)


class TCPServer:
    """Multi-threaded TCP server supporting concurrent client connections."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_SERVER_PORT, enable_multi_port: bool = False):
        self.host = host
        self.port = port
        self.enable_multi_port = enable_multi_port
        self.running = False
        self.sockets: List[socket.socket] = []
        self.lock = threading.Lock()

        # Telemetry and Performance Metrics
        self.stats = {
            "start_time": 0.0,
            "end_time": 0.0,
            "total_connections": 0,
            "active_connections": 0,
            "total_requests": 0,
            "bytes_received": 0,
            "bytes_sent": 0,
            "errors": 0,
            "connections_per_client": {},  # ip -> count
            "requests_per_client": {},     # ip -> count
            "connection_timestamps": [],   # list of epoch timestamps
        }

        self.client_threads: Dict[int, threading.Thread] = {}

    def start(self):
        """Bind sockets and start listening loops."""
        self.running = True
        self.stats["start_time"] = time.time()

        # Primary listening socket
        primary_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        primary_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        primary_sock.bind((self.host, self.port))
        primary_sock.listen(128)
        primary_sock.settimeout(1.0)
        self.sockets.append(primary_sock)

        print(f"[*] TCPServer started on {self.host}:{self.port} (PID: {threading.get_native_id()})")

        # Spawn accept thread for primary socket
        primary_thread = threading.Thread(
            target=self._accept_loop, args=(primary_sock, self.port), daemon=True
        )
        primary_thread.start()

        # Start periodic telemetry stats display thread
        stats_thread = threading.Thread(target=self._stats_reporter_loop, daemon=True)
        stats_thread.start()

        # Keep main thread alive until stopped
        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[*] Server shutdown initiated by user (Ctrl+C)...")
        finally:
            self.stop()

    def _accept_loop(self, s: socket.socket, listen_port: int):
        """Worker loop accepting incoming connections on a specific socket."""
        while self.running:
            try:
                client_sock, client_addr = s.accept()
                client_ip, client_port = client_addr

                with self.lock:
                    self.stats["total_connections"] += 1
                    self.stats["active_connections"] += 1
                    self.stats["connection_timestamps"].append(time.time())
                    self.stats["connections_per_client"][client_ip] = (
                        self.stats["connections_per_client"].get(client_ip, 0) + 1
                    )

                client_id = id(client_sock)
                worker = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr, client_id, listen_port),
                    daemon=True,
                )
                with self.lock:
                    self.client_threads[client_id] = worker
                worker.start()

            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as exc:
                if self.running:
                    print(f"[-] Accept error on port {listen_port}: {exc}")

    def _handle_client(self, sock: socket.socket, addr: Tuple[str, int], client_id: int, listen_port: int):
        """Handle communication with a connected client."""
        client_ip, client_port = addr
        sock.settimeout(4.0)

        try:
            while self.running:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break  # Client closed connection

                    with self.lock:
                        self.stats["total_requests"] += 1
                        self.stats["bytes_received"] += len(data)
                        self.stats["requests_per_client"][client_ip] = (
                            self.stats["requests_per_client"].get(client_ip, 0) + 1
                        )

                    # Process application request and prepare response
                    response = self._process_request(data, addr, listen_port)
                    sock.sendall(response)

                    with self.lock:
                        self.stats["bytes_sent"] += len(response)

                except socket.timeout:
                    # Timeout on idle connection, gracefully close
                    break
                except (ConnectionResetError, BrokenPipeError):
                    with self.lock:
                        self.stats["errors"] += 1
                    break
                except Exception as exc:
                    with self.lock:
                        self.stats["errors"] += 1
                    break
        finally:
            try:
                sock.close()
            except Exception:
                pass
            with self.lock:
                self.stats["active_connections"] = max(0, self.stats["active_connections"] - 1)
                self.client_threads.pop(client_id, None)

    def _process_request(self, data: bytes, addr: Tuple[str, int], port: int) -> bytes:
        """Parse client request and generate realistic HTTP/service response."""
        req_text = data.decode("utf-8", errors="ignore").strip()

        # Simulated HTTP GET /api/data endpoint
        if req_text.startswith("GET /api/data") or req_text.startswith("GET /"):
            body = json.dumps({
                "status": "success",
                "message": "Authorized service payload delivery",
                "timestamp": datetime.now().isoformat(),
                "server_port": port,
                "client": f"{addr[0]}:{addr[1]}",
            })
            resp = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: keep-alive\r\n\r\n{body}"
            )
            return resp.encode("utf-8")

        # Simulated Auth Gateway POST /api/auth
        elif req_text.startswith("POST /api/auth"):
            if "admin_token_valid" in req_text:
                resp_payload = json.dumps({"auth": "granted", "role": "operator"})
                code = "200 OK"
            else:
                resp_payload = json.dumps({"auth": "failed", "error": "Invalid credentials"})
                code = "401 Unauthorized"

            resp = (
                f"HTTP/1.1 {code}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(resp_payload)}\r\n\r\n{resp_payload}"
            )
            return resp.encode("utf-8")

        # Generic Echo / Probe response
        else:
            resp_body = f"ACK: Received {len(data)} bytes on port {port}"
            return resp_body.encode("utf-8")

    def _stats_reporter_loop(self):
        """Periodically prints active server statistics every 5 seconds."""
        while self.running:
            time.sleep(5.0)
            with self.lock:
                elapsed = max(0.1, time.time() - self.stats["start_time"])
                req_rate = self.stats["total_requests"] / elapsed
                conn_rate = self.stats["total_connections"] / elapsed
                print(
                    f"[STATS] Uptime: {elapsed:.1f}s | "
                    f"Active Conns: {self.stats['active_connections']} | "
                    f"Total Conns: {self.stats['total_connections']} ({conn_rate:.1f}/s) | "
                    f"Requests: {self.stats['total_requests']} ({req_rate:.1f}/s) | "
                    f"Rx: {self.stats['bytes_received']/1024:.1f} KB | "
                    f"Tx: {self.stats['bytes_sent']/1024:.1f} KB | "
                    f"Errors: {self.stats['errors']}"
                )

    def stop(self):
        """Gracefully stop server and export final telemetry."""
        if not self.running:
            return
        self.running = False
        self.stats["end_time"] = time.time()

        for s in self.sockets:
            try:
                s.close()
            except Exception:
                pass

        print("[*] TCPServer stopped. Exporting session metrics to server_stats.json...")
        self.export_stats("server_stats.json")

    def export_stats(self, filepath: str = "server_stats.json"):
        """Save telemetry statistics to a JSON file for analysis."""
        with self.lock:
            stats_copy = dict(self.stats)
            # Remove raw timestamp array or summarize it
            timestamps = stats_copy.pop("connection_timestamps", [])
            stats_copy["duration_seconds"] = stats_copy["end_time"] - stats_copy["start_time"]
            stats_copy["peak_connections_recorded"] = len(timestamps)

            try:
                with open(filepath, "w") as f:
                    json.dump(stats_copy, f, indent=2)
                print(f"[+] Saved server telemetry to {filepath}")
            except Exception as e:
                print(f"[-] Failed to write {filepath}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Multi-Client Protected TCP Service Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Host address to bind (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_SERVER_PORT, help=f"Service port (default: {DEFAULT_SERVER_PORT})")
    parser.add_argument("--multi-port", action="store_true", help="Also listen on secondary protected ports")
    args = parser.parse_args()

    server = TCPServer(host=args.host, port=args.port, enable_multi_port=args.multi_port)

    def sig_handler(sig, frame):
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    server.start()


if __name__ == "__main__":
    main()
