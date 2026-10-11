#!/usr/bin/env python3
"""
controller.py — Simple Ryu SDN Controller with Intrusion Detection & Response
Tracks connection rates and port scans. Dynamically installs DROP flow rules.
"""

import time
from collections import defaultdict

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False
    app_manager = object
    set_ev_cls = lambda *a, **k: (lambda f: f)


# Intrusion Detection Thresholds
PORT_SCAN_THRESHOLD = 5    # Max distinct ports allowed
CONN_RATE_THRESHOLD = 10   # Max connections allowed per second


class SimpleIDSController(app_manager.RyuApp):
    """Ryu OpenFlow 1.3 controller with dynamic intrusion response."""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] if RYU_AVAILABLE else []

    def __init__(self, *args, **kwargs):
        if RYU_AVAILABLE:
            super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ports_accessed = defaultdict(set)      # ip -> set of dst_ports
        self.connection_times = defaultdict(list)   # ip -> list of timestamps
        self.blocked_ips = set()
        self.start_times = {}                       # ip -> first suspicious activity time
        print("[*] Simple IDS Controller initialized.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install Priority 0 Table-Miss rule: send unknown packets to controller."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        print(f"[*] Switch {datapath.id} connected. Table-miss installed.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0):
        """Helper to install a flow entry."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, buffer_id=buffer_id or ofproto.OFP_NO_BUFFER,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    def block_attacker(self, datapath, attacker_ip, reason):
        """Dynamically install Priority 200 DROP flow rule for attacker."""
        t_detect = time.time()
        det_latency = (t_detect - self.start_times.get(attacker_ip, t_detect)) * 1000

        print("\n" + "=" * 60)
        print(f"🚨 [ALERT] INTRUSION DETECTED from {attacker_ip}!")
        print(f"   Reason            : {reason}")
        print(f"   Detection Latency : {det_latency:.2f} ms")

        # Install DROP rule on the switch (Priority 200, empty actions = DROP)
        t_mod_start = time.time()
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=attacker_ip)
        self.add_flow(datapath, priority=200, match=match, actions=[], hard_timeout=60)
        resp_latency = (time.time() - t_mod_start) * 1000

        print(f"   SDN Response Time : {resp_latency:.2f} ms")
        print(f"   Action            : INSTALLED PRIORITY 200 DROP FLOW (Hard timeout: 60s)")
        print("=" * 60 + "\n")
        self.blocked_ips.add(attacker_ip)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Inspect packets, check thresholds, and forward or drop."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.eth_type == ether_types.ETH_TYPE_LLDP:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # Intrusion Detection Analysis for TCP
        if ip_pkt and tcp_pkt:
            src_ip = ip_pkt.src
            dst_port = tcp_pkt.dst_port

            if src_ip in self.blocked_ips:
                return  # Silently drop packet

            if src_ip not in self.start_times:
                self.start_times[src_ip] = time.time()

            now = time.time()
            self.ports_accessed[src_ip].add(dst_port)
            self.connection_times[src_ip].append(now)

            # Keep only timestamps within last 1 second
            self.connection_times[src_ip] = [t for t in self.connection_times[src_ip] if t >= now - 1.0]

            # Rule 1: Port Scanning Check
            if len(self.ports_accessed[src_ip]) >= PORT_SCAN_THRESHOLD:
                self.block_attacker(datapath, src_ip, f"Port Scan (>={PORT_SCAN_THRESHOLD} ports)")
                return

            # Rule 2: Connection Rate Check
            if len(self.connection_times[src_ip]) >= CONN_RATE_THRESHOLD:
                self.block_attacker(datapath, src_ip, f"High Connection Rate (>={CONN_RATE_THRESHOLD}/s)")
                return

        # Normal L2 Forwarding (Learning Switch)
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)


if __name__ == "__main__":
    print("Run this controller with Ryu:")
    print("  ryu-manager controller.py --verbose")
