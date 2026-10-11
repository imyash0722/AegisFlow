#!/usr/bin/env python3
"""
test_suite.py — Automated Unit & Integration Test Suite
Project 25: Network Intrusion Detection and Response System

Provides comprehensive verification of low-level TCP socket communications,
attack traffic simulation, intrusion detection thresholds, and dynamic SDN
flow rule modifications. Can be run standalone in any test environment.
"""

import sys
import os
import time
import json
import socket
import unittest
import threading
from typing import List

# Import project modules
from protocol import (
    DEFAULT_SERVER_PORT,
    DEFAULT_MONITOR_PORT,
    DEFAULT_SDN_CMD_PORT,
    TH_CONN_RATE,
    TH_PORT_SCAN_PORTS,
    TH_PORT_SCAN_WINDOW,
    ATTACK_PORT_SCAN,
    ATTACK_CONN_FLOOD,
    ATTACK_SYN_FLOOD,
    CMD_BLOCK,
    CMD_UNBLOCK,
    CMD_STATUS,
    SecurityAlert,
    serialize_ipc_message,
    parse_ipc_message,
)
from tcp_server import TCPServer
from tcp_client import TCPClient
from attack_generator import AttackGenerator
from ids_monitor import IDSMonitor, HostTracker
from sdn_controller import BaseControllerLogic, StandaloneMockController


class TestIntrusionDetectionSystem(unittest.TestCase):
    """End-to-end integration and component tests."""

    @classmethod
    def setUpClass(cls):
        """Prepare ephemeral test ports dynamically to avoid collisions."""
        def get_free_port():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', 0))
                return s.getsockname()[1]

        cls.test_server_port = get_free_port()
        cls.test_sdn_port = get_free_port()
        cls.test_monitor_port = get_free_port()

        # Start background mock SDN controller
        cls.sdn = StandaloneMockController(cmd_port=cls.test_sdn_port)
        cls.sdn_thread = threading.Thread(target=cls.sdn.start_ipc_server, daemon=True)
        cls.sdn_thread.start()

        # Start background TCP Server
        cls.server = TCPServer(host="127.0.0.1", port=cls.test_server_port)
        cls.server_thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.server_thread.start()

        # Allow servers to bind
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        """Clean up running instances."""
        cls.server.stop()
        cls.sdn.running = False

    def test_01_protocol_serialization(self):
        """Verify protocol IPC message serialization and deserialization."""
        msg = serialize_ipc_message(CMD_BLOCK, {"ip": "10.0.0.99", "priority": 200})
        self.assertTrue(msg.endswith(b"\n"))

        parsed = parse_ipc_message(msg.decode("utf-8"))
        self.assertEqual(parsed.get("command"), CMD_BLOCK)
        self.assertEqual(parsed.get("params", {}).get("ip"), "10.0.0.99")
        self.assertEqual(parsed.get("params", {}).get("priority"), 200)

    def test_02_tcp_client_server_communication(self):
        """Verify low-level TCP socket request-response transaction and latency measurement."""
        client = TCPClient(target_ip="127.0.0.1", target_port=self.test_server_port, rate=5.0, count=3)
        client.start()

        self.assertEqual(client.stats["total_sent"], 3)
        self.assertEqual(client.stats["total_success"], 3)
        self.assertEqual(client.stats["total_failed"], 0)
        self.assertGreater(len(client.stats["latencies_ms"]), 0)
        self.assertGreater(client.stats["avg_latency_ms"], 0.0)

    def test_03_port_scan_detection_rule(self):
        """Verify that accessing >= TH_PORT_SCAN_PORTS distinct ports triggers detection."""
        tracker = HostTracker("10.0.0.50")

        # Access 4 distinct ports (below threshold)
        for port in [21, 22, 23, 80]:
            alert_type, metric, th = tracker.record_connection("10.0.0.3", port)
            self.assertIsNone(alert_type)

        # Access 5th distinct port (meets threshold)
        alert_type, metric, th = tracker.record_connection("10.0.0.3", 443)
        self.assertEqual(alert_type, ATTACK_PORT_SCAN)
        self.assertEqual(metric, 5.0)
        self.assertEqual(th, float(TH_PORT_SCAN_PORTS))

    def test_04_connection_flood_detection_rule(self):
        """Verify that exceeding TH_CONN_RATE within 1 second triggers flood detection."""
        tracker = HostTracker("10.0.0.60")

        # Send connections rapidly to same destination port
        alert_triggered = False
        for i in range(15):
            alert_type, metric, th = tracker.record_connection("10.0.0.3", 8080)
            if alert_type == ATTACK_CONN_FLOOD:
                alert_triggered = True
                self.assertGreaterEqual(metric, TH_CONN_RATE)
                break

        self.assertTrue(alert_triggered, "Connection flood rule failed to fire.")

    def test_05_sdn_controller_dynamic_flow_modification(self):
        """Verify dynamic block and unblock commands via IPC socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", self.test_sdn_port))

        # Send BLOCK command
        block_msg = serialize_ipc_message(CMD_BLOCK, {
            "ip": "10.0.0.77",
            "duration": 30,
            "priority": 200,
            "reason": "Test Suite Attack Simulation"
        })
        sock.sendall(block_msg)
        resp = json.loads(sock.recv(1024).decode("utf-8"))
        sock.close()

        self.assertEqual(resp.get("status"), "SUCCESS")
        self.assertEqual(resp.get("action"), "DROP_INSTALLED")
        self.assertIn("10.0.0.77", self.sdn.blocked_ips)

        # Send UNBLOCK command
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect(("127.0.0.1", self.test_sdn_port))
        unblock_msg = serialize_ipc_message(CMD_UNBLOCK, {"ip": "10.0.0.77"})
        sock2.sendall(unblock_msg)
        resp2 = json.loads(sock2.recv(1024).decode("utf-8"))
        sock2.close()

        self.assertEqual(resp2.get("status"), "SUCCESS")
        self.assertNotIn("10.0.0.77", self.sdn.blocked_ips)

    def test_06_ids_monitor_end_to_end_mitigation(self):
        """Verify IDSMonitor event pipeline, latency measurement, and SDN dispatch."""
        monitor = IDSMonitor(
            listen_port=self.test_monitor_port,
            sdn_host="127.0.0.1",
            sdn_port=self.test_sdn_port,
            block_duration=2,
        )

        # Feed port scan sequence
        scan_ports = [21, 22, 25, 80, 110, 443]
        alert_fired = None
        for p in scan_ports:
            res = monitor.process_event("10.0.0.88", "10.0.0.3", p)
            if res:
                alert_fired = res
                break

        self.assertIsNotNone(alert_fired)
        self.assertEqual(alert_fired.attack_type, ATTACK_PORT_SCAN)
        self.assertEqual(alert_fired.src_ip, "10.0.0.88")
        self.assertGreater(alert_fired.detection_time_ms, 0.0)
        self.assertGreater(alert_fired.response_time_ms, 0.0)
        self.assertIn("10.0.0.88", self.sdn.blocked_ips)


def run_tests():
    """Execute test suite and print results."""
    print("=" * 70)
    print("  RUNNING AUTOMATED TEST SUITE FOR PROJECT 25 (IDS + SDN)")
    print("=" * 70)
    suite = unittest.TestLoader().loadTestsFromTestCase(TestIntrusionDetectionSystem)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\n[+] ALL TEST CASES PASSED SUCCESSFULLY (6/6)!")
        return 0
    else:
        print("\n[-] TEST FAILURES DETECTED!")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
