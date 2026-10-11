#!/usr/bin/env python3
"""
protocol.py — Shared Protocol Constants, Security Rules, and IPC Definitions
Project 25: Network Intrusion Detection and Response System

Defines standard network ports, intrusion detection thresholds, attack signatures,
inter-process communication (IPC) formats, and structured alert schemas used
across the client, server, IDS monitor, and SDN controller.
"""

import json
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

# ============================================================================
# Network Addressing and Port Configurations
# ============================================================================
DEFAULT_HOST = "0.0.0.0"
DEFAULT_TARGET_IP = "10.0.0.3"
DEFAULT_SERVER_PORT = 8080
DEFAULT_MONITOR_PORT = 9999
DEFAULT_SDN_CMD_PORT = 8081
DEFAULT_OFP_PORT = 6633

# Simulated protected service ports on the victim server
PROTECTED_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080, 9000]

# ============================================================================
# Intrusion Detection Rule Thresholds
# ============================================================================
# Rule 1: High Connection Rate (DoS / Connection Flooding)
# Threshold: Exceeding 10 new connection attempts per second from a single source IP
TH_CONN_RATE = 10.0  # connections per second

# Rule 2: Port Scanning (Reconnaissance)
# Threshold: Accessing 5 or more distinct destination ports within 10 seconds
TH_PORT_SCAN_PORTS = 5      # distinct destination ports
TH_PORT_SCAN_WINDOW = 10.0  # sliding window duration in seconds

# Rule 3: Abnormal Failed Connections (TCP Reset / Incomplete Handshakes)
# Threshold: 5 or more failed/reset connections within a sliding window
TH_FAILED_CONN = 5

# Rule 4: SYN Burst / Aggressive Connection Bursts
# Threshold: More than 15 connection attempts within a 2-second sub-window
TH_SYN_BURST = 15
TH_BURST_WINDOW = 2.0  # seconds

# Rule 5: Mitigation Parameters
DEFAULT_BLOCK_DURATION = 60  # seconds to block offender via OpenFlow rule
FLOW_HARD_TIMEOUT = 60       # seconds for switch flow rule hard timeout
FLOW_IDLE_TIMEOUT = 30       # seconds for switch flow rule idle timeout
OFP_DROP_PRIORITY = 200      # High priority for DROP flow rule
OFP_FORWARD_PRIORITY = 1     # Normal priority for standard forwarding flow

# ============================================================================
# Attack and Traffic Mode Identifiers
# ============================================================================
TRAFFIC_NORMAL = "normal"
ATTACK_PORT_SCAN = "portscan"
ATTACK_CONN_FLOOD = "flood"
ATTACK_SYN_FLOOD = "synflood"
ATTACK_BRUTE_FORCE = "bruteforce"

VALID_TRAFFIC_MODES = [
    TRAFFIC_NORMAL,
    ATTACK_PORT_SCAN,
    ATTACK_CONN_FLOOD,
    ATTACK_SYN_FLOOD,
    ATTACK_BRUTE_FORCE,
]

# ============================================================================
# Inter-Process Communication (IPC) Commands for SDN Controller
# ============================================================================
CMD_BLOCK = "BLOCK"
CMD_UNBLOCK = "UNBLOCK"
CMD_STATS_REQ = "STATS_REQ"
CMD_STATUS = "STATUS"
CMD_CLEAR = "CLEAR"


@dataclass
class SecurityAlert:
    """Represents a structured intrusion alert emitted by the IDS engine."""
    alert_id: str
    timestamp: float
    iso_time: str
    src_ip: str
    dst_ip: str
    attack_type: str
    description: str
    metric_value: float
    threshold_value: float
    action_taken: str
    detection_time_ms: float = 0.0
    response_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize alert to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityAlert":
        """Reconstruct alert from dictionary."""
        return cls(**data)


def format_alert_log(alert: SecurityAlert) -> str:
    """Format an alert into a human-readable high-visibility console log string."""
    return (
        f"🚨 [SECURITY ALERT] [{alert.iso_time}] "
        f"Type: {alert.attack_type.upper()} | "
        f"Source: {alert.src_ip} -> Target: {alert.dst_ip} | "
        f"Observed: {alert.metric_value:.2f} (Threshold: {alert.threshold_value:.2f}) | "
        f"Action: {alert.action_taken} | "
        f"Detection Latency: {alert.detection_time_ms:.2f}ms | "
        f"Response Latency: {alert.response_time_ms:.2f}ms"
    )


def serialize_ipc_message(command: str, params: Optional[Dict[str, Any]] = None) -> bytes:
    """Serialize command and payload parameters into a newline-terminated JSON byte buffer."""
    payload = {"command": command, "params": params or {}}
    return (json.dumps(payload) + "\n").encode("utf-8")


def parse_ipc_message(raw_data: str) -> Dict[str, Any]:
    """Parse newline-delimited JSON message received from IPC socket."""
    try:
        return json.loads(raw_data.strip())
    except Exception as exc:
        return {"command": "ERROR", "error": str(exc)}
