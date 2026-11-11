# Comprehensive Threat Modeling & Attack Measures

AegisFlow expands beyond simple port detection to provide defensive measures across **six distinct network and transport-layer attack vectors**.

---

## Multi-Vector Attack Comparison Matrix

| Attack Vector | Layer | Target Vulnerability | Mathematical Detection Metric | Threshold | OpenFlow Mitigation Rule |
| :--- | :---: | :--- | :--- | :---: | :--- |
| **1. Vertical Port Scan** | L4 | Service enumeration on target | Distinct Destination Ports in $10\text{s}$ | $\ge 5\text{ ports}$ | `Priority 200: Match(ipv4_src=Attacker) -> DROP` |
| **2. TCP Connection Flood**| L4 | Listen backlog queue (`listen(100)`) | Connection attempts per second | $\ge 10\text{ conns/s}$ | `Priority 200: Match(ipv4_src=Attacker) -> DROP` |
| **3. TCP SYN Flood** | L4 | Kernel SYN queue / TCB buffer | Pending half-open SYNs without ACK | $\ge 15\text{ SYNs/s}$ | `Priority 200: Match(ip_proto=6, tcp_flags=SYN) -> DROP` |
| **4. Horizontal Subnet Sweep**| L3 | Multi-host network mapping | Distinct Destination IPs in $10\text{s}$ | $\ge 3\text{ hosts}$ | `Priority 200: Subnet-wide Datapath Ingress Isolation` |
| **5. Slowloris (Low-and-Slow)**| L7 | Server worker thread pool limits | Socket Dwell Time vs Byte Velocity | $>5\text{s}$ / $<10\text{ B/s}$ | `Priority 200 DROP` + Dynamic TCP Reset |
| **6. UDP/ICMP Storms** | L3/L4 | Switch datapath buffer & link bandwidth| Ingress Datagram Velocity | $\ge 20\text{ pkts/s}$ | `Priority 200: Match(ip_proto=17/1) -> DROP` |

---

## Vector 1: Vertical Port Scan (Reconnaissance)

### Threat Mechanism
The adversary systematically probes multiple TCP service ports on the target server (`10.0.0.3`) to map open daemons (e.g., FTP 21, SSH 22, Telnet 23, SMTP 25, HTTP 80, HTTPS 443).

In `attacker.py`, this is executed via `socket.connect_ex()`:
```python
res = sock.connect_ex((target_ip, port))
```
* **Why `connect_ex()`?** Standard `connect()` raises Python exceptions (`ConnectionRefusedError`) for closed ports, adding heavy runtime overhead. `connect_ex()` returns a C-level integer `errno` directly, completing a full port scan in $<500\text{ ms}$.

### Mathematical Detection Measure
The controller records each destination port accessed within an active sliding window:
$$\text{Distinct Ports}(S) = \Big| \big\{ \text{dst\_port} \;\big|\; (t, \text{dst\_port}) \in W_S, \; t \ge T_{\text{now}} - 10.0\text{s} \big\} \Big|$$

$$\text{Trigger Condition: } \text{Distinct Ports}(S) \ge 5$$

### OpenFlow Mitigation
On Probe 5 (Port 80), the threshold is breached. The controller constructs an `OFPFlowMod`:
```python
match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src="10.0.0.2")
actions = []  # Discard
add_flow(datapath, priority=200, match=match, actions=actions, hard_timeout=60)
```
Probes 6 (443) and 7 (8080) are dropped directly in switch hardware with **zero CPU cycles** consumed on the server.

---

## Vector 2: Volumetric TCP Connection Flood (DoS)

### Threat Mechanism
The attacker fires bursts of $30+$ rapid TCP connections to port `8080`. The objective is to exhaust the server socket's listen backlog queue (`listen(100)`), causing incoming connection requests from legitimate clients to be dropped.

### Mathematical Detection Measure
The controller computes connection velocity over a rolling 1.0-second time window:
$$\text{Rate}(S) = \sum_{(t, \_) \in W_S} \mathbb{I}(t \ge T_{\text{now}} - 1.0\text{s})$$

$$\text{Trigger Condition: } \text{Rate}(S) \ge 10\text{ connections/second}$$

### OpenFlow Mitigation
The switch immediately drops all subsequent TCP connection attempts from the flooding IP. Legitimate clients continue transmitting with $100\%$ availability.

---

## Vector 3: TCP SYN Flood (Half-Open TCB Exhaustion)

### Threat Mechanism
In a traditional TCP SYN flood, an attacker transmits an avalanche of TCP `SYN` packets but deliberately never sends the final `ACK`. Alternatively, the attacker sets `SO_LINGER` to 0, which instructs the kernel to send an immediate `RST` upon connection setup:
```python
sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
```
This forces the target server's kernel to allocate a Transmission Control Block (TCB) in its **SYN Queue** (`tcp_max_syn_backlog`) for every half-open connection, starving memory.

### Mathematical Detection Measure
The controller monitors the ratio of SYN initiations to completed handshakes:
$$\text{SYN Velocity}(S) = \sum_{p \in W_S} \mathbb{I}(\text{is\_syn}(p) \land t_p \ge T_{\text{now}} - 1.0\text{s})$$

$$\text{Trigger Condition: } \text{SYN Velocity}(S) \ge 15\text{ SYNs/sec} \quad \text{with} \quad \frac{\text{Completed ACKs}}{\text{Total SYNs}} < 0.10$$

### OpenFlow Mitigation
The controller injects an OpenFlow rule that matches specifically on the TCP SYN flag:
```python
match = parser.OFPMatch(
    eth_type=0x0800,
    ip_proto=6,
    ipv4_src="10.0.0.2",
    tcp_flags=0x02  # TCP SYN bit
)
actions = []
```
All incomplete half-open connection attempts are shredded at the switch datapath.

---

## Vector 4: Horizontal Subnet Sweep (IP Host Discovery)

### Threat Mechanism
Instead of scanning multiple ports on a single host, an adversary scans a single port (e.g., port 80 or port 22) across **multiple distinct IP addresses** within the subnet (`10.0.0.1`, `10.0.0.2`, `10.0.0.3`, `10.0.0.4`) to map which hosts are alive.

### Mathematical Detection Measure
The controller records the set of unique destination IP addresses contacted by each source IP:
$$\text{Target Hosts}(S) = \Big| \big\{ \text{dst\_ip} \;\big|\; (t, \text{dst\_ip}) \in W_S, \; t \ge T_{\text{now}} - 10.0\text{s} \big\} \Big|$$

$$\text{Trigger Condition: } \text{Target Hosts}(S) \ge 3\text{ distinct hosts}$$

### OpenFlow Mitigation
Because the adversary is actively scanning the subnet topology, the controller enforces **network-wide ingress isolation**:
```python
# Drop all packets from this host across every port on Open vSwitch
match = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
actions = []
add_flow(datapath, priority=200, match=match, actions=actions, hard_timeout=60)
```
The attacker is completely cut off from the entire local subnet.

---

## Vector 5: Slowloris / Low-and-Slow Attack

### Threat Mechanism
Unlike volumetric floods, Slowloris is a low-bandwidth, application-layer attack. The attacker opens valid TCP connections and sends partial HTTP headers:
```http
GET /data HTTP/1.1\r\n
User-Agent: AegisSlow\r\n
```
The attacker deliberately **withholds the terminating `\r\n\r\n` delimiter**, instead sending single keep-alive header bytes (e.g., `X-a: b\r\n`) every few seconds. 

The server's worker threads (`threading.Thread`) stay blocked indefinitely waiting for the remainder of the HTTP header. Once all server threads are held open, the server cannot accept any new legitimate users.

### Mathematical Detection Measure
The server and controller track socket dwell time against byte transfer volume:
$$\text{Byte Velocity} = \frac{\Delta \text{Bytes}}{\Delta t}$$

$$\text{Trigger Condition: } \Delta t > 5.0\text{ seconds} \quad \land \quad \text{Byte Velocity} < 10\text{ bytes/second} \quad \land \quad \text{Header Incomplete}$$

### OpenFlow & Socket Mitigation
1. **Application-Layer Action:** The server worker thread times out after a strict 5.0s header window and invokes `sock.close()`.
2. **SDN Controller Action:** The controller installs a Priority 200 DROP rule preventing the Slowloris IP from opening new replacement sockets, freeing server concurrency resources permanently.

---

## Vector 6: UDP & ICMP Volumetric Amplification Storms

### Threat Mechanism
An attacker floods spoofed UDP datagrams or ICMP Echo Requests (Ping Storms) to exhaust network link bandwidth and force the switch CPU into packet-processing starvation.

### Mathematical Detection Measure
$$\text{Datagram Rate}(S) = \sum_{p \in W_S} \mathbb{I}(\text{protocol}(p) \in \{\text{UDP}, \text{ICMP}\} \land t_p \ge T_{\text{now}} - 1.0\text{s})$$

$$\text{Trigger Condition: } \text{Datagram Rate}(S) \ge 20\text{ packets/second}$$

### OpenFlow Mitigation
OpenFlow supports protocol-level matching:
```python
# Block only the abusive UDP traffic while preserving legitimate TCP traffic
match_udp = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_src=attacker_ip)
add_flow(datapath, priority=200, match=match_udp, actions=[], hard_timeout=60)

# Block only the abusive ICMP traffic
match_icmp = parser.OFPMatch(eth_type=0x0800, ip_proto=1, ipv4_src=attacker_ip)
add_flow(datapath, priority=200, match=match_icmp, actions=[], hard_timeout=60)
```
This isolates the attack vector without collateral damage to legitimate services.
