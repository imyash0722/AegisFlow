#!/usr/bin/env python3
"""
topology.py — Simple Mininet Topology for Project 25
3 Hosts (h1 client, h2 attacker, h3 server) connected to 1 OpenFlow 1.3 Switch.
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def run():
    setLogLevel("info")
    info("*** Building Mininet Topology ***\n")

    net = Mininet(controller=RemoteController, switch=OVSSwitch, autoSetMacs=True)

    c0 = net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    h1 = net.addHost("h1", ip="10.0.0.1/24")  # Client
    h2 = net.addHost("h2", ip="10.0.0.2/24")  # Attacker
    h3 = net.addHost("h3", ip="10.0.0.3/24")  # Server

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    info("*** Starting Network ***\n")
    net.start()

    info("*** Testing Initial Connectivity ***\n")
    net.pingAll()

    info("\n*** Instructions to Test in Mininet CLI: ***\n")
    info("  1. Start server on h3   : h3 python3 server.py &\n")
    info("  2. Test client from h1 : h1 python3 client.py 10.0.0.3\n")
    info("  3. Run scan from h2    : h2 python3 attacker.py scan 10.0.0.3\n")
    info("  4. Check switch flows  : sh ovs-ofctl dump-flows s1 -O OpenFlow13\n\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    run()
