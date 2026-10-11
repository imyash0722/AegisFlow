#!/usr/bin/env python3
"""
sdn_controller.py — OpenFlow 1.3 Ryu SDN Controller with Dynamic Intrusion Response
Project 25: Network Intrusion Detection and Response System

Implements an intelligent Software-Defined Networking (SDN) controller using Ryu
and OpenFlow 1.3:
  1. Installs table-miss flow entries for proactive controller discovery
  2. Implements MAC learning and L2/L3 forwarding (Priority 1)
  3. Periodically collects switch flow statistics via OFPFlowStatsRequest
  4. Hosts an IPC command server to receive real-time mitigation instructions
  5. Dynamically modifies switch flow tables by installing high-priority (Priority 200)
     DROP rules to isolate malicious sources
  6. Supports unblocking and automatic flow expiration via idle/hard timeouts
  7. Includes a standalone mock mode for evaluation without an active Ryu/Mininet daemon
"""

import sys
import os
import time
import json
import socket
import threading
from typing import Dict, Any, List, Optional

# Attempt Ryu imports; if Ryu is not installed, provide mock datapath structures
try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ipv4, tcp
    from ryu.lib.packet import ether_types
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False
    app_manager = object
    set_ev_cls = lambda *args, **kwargs: (lambda fn: fn)
    CONFIG_DISPATCHER = None
    MAIN_DISPATCHER = None

from protocol import (
    DEFAULT_SDN_CMD_PORT,
    OFP_DROP_PRIORITY,
    OFP_FORWARD_PRIORITY,
    FLOW_HARD_TIMEOUT,
    FLOW_IDLE_TIMEOUT,
    CMD_BLOCK,
    CMD_UNBLOCK,
    CMD_STATS_REQ,
    CMD_STATUS,
    serialize_ipc_message,
    parse_ipc_message,
)


class BaseControllerLogic:
    """Core controller tracking and flow manipulation state."""

    def __init__(self, cmd_port: int = DEFAULT_SDN_CMD_PORT):
        self.cmd_port = cmd_port
        self.switches: Dict[int, Any] = {}          # dpid -> datapath
        self.mac_to_port: Dict[int, Dict[str, int]] = {}  # dpid -> {mac: port}
        self.blocked_ips: Dict[str, Dict[str, Any]] = {} # ip -> {time, duration, priority, flows_installed}
        self.flow_statistics: Dict[str, Any] = {}
        self.lock = threading.Lock()
        self.running = True

    def block_ip(self, ip: str, duration: int = 60, priority: int = OFP_DROP_PRIORITY, reason: str = "Anomaly") -> Dict[str, Any]:
        """Apply dynamic flow-mod rule to drop all traffic from suspicious IP."""
        with self.lock:
            t_now = time.time()
            self.blocked_ips[ip] = {
                "blocked_at": t_now,
                "duration": duration,
                "priority": priority,
                "reason": reason,
                "switches_updated": len(self.switches),
            }

            print(f"\n[SDN CONTROLLER] 🛡️ DYNAMIC RULE MODIFICATION:")
            print(f"  Action   : DROP (Priority {priority})")
            print(f"  Match    : IPv4 Source = {ip}, Protocol = TCP")
            print(f"  Timeouts : Hard={FLOW_HARD_TIMEOUT}s, Idle={FLOW_IDLE_TIMEOUT}s")
            print(f"  Switches : {list(self.switches.keys()) if self.switches else 'All active datapaths'}")

            # Install OpenFlow drop rule on all connected datapaths
            for dpid, datapath in self.switches.items():
                self._install_drop_flow(datapath, ip, priority)

            return {
                "status": "SUCCESS",
                "ip": ip,
                "priority": priority,
                "action": "DROP_INSTALLED",
                "datapaths": list(self.switches.keys()),
            }

    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """Remove drop rule and restore normal forwarding for IP."""
        with self.lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                print(f"[SDN CONTROLLER] 🔓 Dynamic Rule Expiration: Unblocked {ip}")
                for dpid, datapath in self.switches.items():
                    self._remove_drop_flow(datapath, ip)
                return {"status": "SUCCESS", "ip": ip, "action": "DROP_REMOVED"}
            return {"status": "NOT_FOUND", "ip": ip}

    def _install_drop_flow(self, datapath, ip: str, priority: int):
        """Install OpenFlow drop flow on datapath."""
        if not RYU_AVAILABLE or datapath is None:
            return
        parser = datapath.ofproto_parser
        # Match TCP traffic from offender IP
        match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,
            ipv4_src=ip,
        )
        # Empty action list designates packet drop in OpenFlow 1.3
        self._add_flow_entry(datapath, priority, match, actions=[],
                             hard_timeout=FLOW_HARD_TIMEOUT, idle_timeout=FLOW_IDLE_TIMEOUT)

    def _remove_drop_flow(self, datapath, ip: str):
        """Delete specific drop flow from datapath."""
        if not RYU_AVAILABLE or datapath is None:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=OFP_DROP_PRIORITY,
            match=match,
        )
        datapath.send_msg(mod)

    def _add_flow_entry(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """Send OFPFlowMod to datapath."""
        if not RYU_AVAILABLE or datapath is None:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id, priority=priority,
                match=match, instructions=inst, idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match,
                instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout
            )
        datapath.send_msg(mod)

    def start_ipc_server(self):
        """Start socket server listening for IDS monitor commands."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", self.cmd_port))
        server_sock.listen(16)
        print(f"[SDN CONTROLLER] IPC Command Server listening on port {self.cmd_port}")

        while self.running:
            try:
                conn, _ = server_sock.accept()
                threading.Thread(target=self._handle_ipc_client, args=(conn,), daemon=True).start()
            except Exception:
                break

    def _handle_ipc_client(self, conn: socket.socket):
        """Handle individual IPC command client."""
        try:
            conn.settimeout(3.0)
            data = conn.recv(4096)
            if not data:
                return
            msg = parse_ipc_message(data.decode("utf-8"))
            cmd = msg.get("command")
            params = msg.get("params", {})

            if cmd == CMD_BLOCK:
                ip = params.get("ip")
                duration = params.get("duration", 60)
                reason = params.get("reason", "IDS Trigger")
                priority = params.get("priority", OFP_DROP_PRIORITY)
                resp = self.block_ip(ip, duration, priority, reason)
            elif cmd == CMD_UNBLOCK:
                ip = params.get("ip")
                resp = self.unblock_ip(ip)
            elif cmd == CMD_STATUS:
                resp = {
                    "active_switches": list(self.switches.keys()),
                    "blocked_ips": self.blocked_ips,
                    "flow_stats_count": len(self.flow_statistics),
                }
            else:
                resp = {"status": "UNKNOWN_COMMAND", "command": cmd}

            conn.sendall(json.dumps(resp).encode("utf-8"))
        except Exception as exc:
            print(f"[-] IPC handling error: {exc}")
        finally:
            try:
                conn.close()
            except Exception:
                pass


if RYU_AVAILABLE:
    class SDNControllerApp(app_manager.RyuApp, BaseControllerLogic):
        """Full OpenFlow 1.3 Ryu Application for Intrusion Response."""
        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

        def __init__(self, *args, **kwargs):
            app_manager.RyuApp.__init__(self, *args, **kwargs)
            BaseControllerLogic.__init__(self, cmd_port=DEFAULT_SDN_CMD_PORT)

            # Start IPC thread
            self.ipc_thread = threading.Thread(target=self.start_ipc_server, daemon=True)
            self.ipc_thread.start()

            # Start periodic flow statistics collection thread
            self.stats_thread = threading.Thread(target=self._stats_poll_loop, daemon=True)
            self.stats_thread.start()

            self.logger.info("SDN Intrusion Detection & Response Controller initialized")

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features_handler(self, ev):
            """Install table-miss flow entry when switch connects."""
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Priority 0 catch-all rule: Send unhandled packets to controller
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self._add_flow_entry(datapath, 0, match, actions)

            self.switches[datapath.id] = datapath
            self.mac_to_port[datapath.id] = {}
            self.logger.info(f"[OFP] Switch connected: DPID={datapath.id}")

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in_handler(self, ev):
            """Handle reactive packet-in messages and implement L2 learning."""
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            if eth.eth_type == ether_types.ETH_TYPE_LLDP:
                return

            dst = eth.dst
            src = eth.src
            dpid = datapath.id
            self.mac_to_port[dpid][src] = in_port

            # Check if source IP is actively blocked
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt and ip_pkt.src in self.blocked_ips:
                # Silently drop packet from blocked source
                return

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # Install forwarding flow rule (Priority 1) if destination known
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self._add_flow_entry(datapath, OFP_FORWARD_PRIORITY, match, actions, msg.buffer_id)
                    return
                else:
                    self._add_flow_entry(datapath, OFP_FORWARD_PRIORITY, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

        def _stats_poll_loop(self):
            """Periodically send OFPFlowStatsRequest every 5 seconds to all switches."""
            while self.running:
                time.sleep(5.0)
                for dpid, datapath in list(self.switches.items()):
                    parser = datapath.ofproto_parser
                    req = parser.OFPFlowStatsRequest(datapath)
                    datapath.send_msg(req)

        @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
        def flow_stats_reply_handler(self, ev):
            """Parse flow statistics replies from switches."""
            body = ev.msg.body
            dpid = ev.msg.datapath.id
            stats = []
            for stat in body:
                stats.append({
                    "priority": stat.priority,
                    "packets": stat.packet_count,
                    "bytes": stat.byte_count,
                    "duration_sec": stat.duration_sec,
                })
            self.flow_statistics[f"switch_{dpid}"] = stats


class StandaloneMockController(BaseControllerLogic):
    """Standalone controller mode when Ryu is not present or for quick mock verification."""

    def __init__(self, cmd_port: int = DEFAULT_SDN_CMD_PORT):
        super().__init__(cmd_port=cmd_port)
        # Register simulated switches
        self.switches[1] = "mock_switch_1"
        self.switches[2] = "mock_switch_2"

    def run(self):
        print(f"[*] Starting Standalone Mock SDN Controller on port {self.cmd_port}...")
        self.start_ipc_server()


def main():
    """CLI Entry point: Allows running mock controller directly or instructions for Ryu."""
    if len(sys.argv) > 1 and sys.argv[1] == "--mock":
        controller = StandaloneMockController()
        controller.run()
    else:
        print("=" * 60)
        print("SDN Controller — Project 25: Intrusion Detection & Response")
        print("=" * 60)
        print("To run in Mininet with Ryu OpenFlow 1.3:")
        print("  ryu-manager sdn_controller.py --verbose")
        print("\nTo run in standalone mock/simulation mode (no Ryu needed):")
        print("  python3 sdn_controller.py --mock")
        print("=" * 60)
        if not RYU_AVAILABLE:
            print("[*] Ryu library not detected in environment. Starting standalone mock mode...")
            controller = StandaloneMockController()
            controller.run()


if __name__ == "__main__":
    main()
