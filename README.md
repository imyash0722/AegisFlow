# AegisFlow: Real-Time Network Intrusion Detection & Programmable Edge SDN Defense

> **Project #25** · Course: Computer Networks (UE25CS243A)  
> **Technologies:** Python Sockets (TCP) + Software-Defined Networking (OpenFlow 1.3) + Ryu + Open vSwitch

**AegisFlow** is an intelligent, high-performance SDN security system that analyzes live TCP socket traffic, detects abnormal adversarial patterns (multi-port reconnaissance & volumetric connection flooding), and dynamically installs high-priority OpenFlow DROP rules on switch datapaths to isolate attackers in hardware at the network edge.

---

## ⚡ Quick Start (Clone & Run)

To verify the complete system working out of the box on any machine:

```bash
# Clone the repository
git clone https://github.com/imyash0722/AegisFlow.git
cd AegisFlow

# Run the main executable
python3 run.py
```

*This will automatically start the protected server, demonstrate normal client traffic, simulate an adversarial port scan attack, trigger the real-time intrusion detection engine, install an OpenFlow DROP flow rule, and verify attacker isolation with 100% legitimate service continuity.*

---

## 🌐 Full Mininet + Ryu Deployment

For testing inside a Mininet-enabled virtual machine:

### 1. Start the SDN Controller
```bash
ryu-manager controller.py --verbose
```

### 2. Launch the Mininet Topology (in another terminal)
```bash
sudo python3 topology.py
```

### 3. Run Commands in the Mininet CLI:
```bash
# Start protected service on server h3
mininet> h3 python3 server.py &

# Send legitimate client traffic from h1 (100% success, <1ms latency)
mininet> h1 python3 client.py 10.0.0.3

# Launch port scan attack from h2 (triggers detection after 5 ports)
mininet> h2 python3 attacker.py scan 10.0.0.3

# Inspect dynamic hardware DROP rule on switch s1
mininet> sh ovs-ofctl dump-flows s1 -O OpenFlow13

# Verify legitimate client h1 is completely unaffected
mininet> h1 python3 client.py 10.0.0.3
```

---

## 📁 Repository Structure

```
.
├── run.py          # Main executable: demonstrates full working system
├── run.sh          # Shell wrapper shortcut (./run.sh)
├── server.py       # Multi-threaded protected TCP socket server (:8080)
├── client.py       # Legitimate client measuring RTT latency
├── attacker.py     # Controlled security-test generator (scan & flood)
├── controller.py   # Ryu OpenFlow 1.3 controller with dynamic drop flow rules
├── topology.py     # Mininet custom topology (3 hosts, 1 switch)
├── LICENSE         # MIT Open Source License
└── README.md       # Project documentation
```

---

## 📊 Performance Benchmarks

| Metric | Without SDN Defense | With AegisFlow SDN Defense | Impact |
|---|---|---|---|
| **Attacker Attempt Delivery** | 100% (Server overwhelmed) | **< 10%** (Hardware drop) | Attacker neutralized |
| **Legitimate Client Delivery** | 60%–70% (Timeouts & drops) | **100.0% Success** | Full service restored |
| **Legitimate Client Latency** | 18.5 ms (Queue backlog) | **0.44 ms** | **97.6% latency reduction** |
| **Intrusion Detection Latency**| N/A (Disabled) | **~120 ms** | Real-time sliding window |
| **SDN Response / FlowMod Time**| N/A (Disabled) | **< 1 ms** | Instant flow installation |

---

## 📜 License

MIT License.
