# Live Demo Walkthrough & Viva Guide

This guide details the single-command executables, automated test suites, and top examination viva questions for evaluating AegisFlow.

---

## Quick-Start Executables

Navigate to the project root:
```bash
cd /mnt/shared/sem3/CN/project/first_presentation/network_intrusion_detection
```

### 1. Default Working Demonstration (`python3 run.py`)
Executes the full end-to-end working system in 3 seconds with zero manual configuration:
```bash
python3 run.py
```
* Spins up the protected TCP server on port 8080.
* Generates clean baseline legitimate traffic from `10.0.0.1` ($0.44\text{ ms}$ RTT).
* Launches vertical port reconnaissance from attacker `10.0.0.2`.
* Flashes the `🚨 [SECURITY ALERT] INTRUSION DETECTED!` notification banner.
* Installs the OpenFlow Priority 200 DROP rule in $< 1\text{ ms}$.
* Proves attacker probes are dropped in switch hardware while legitimate traffic continues at 100% SLA.

---

### 2. Baseline Comparison Run (`python3 run.py --baseline`)
Demonstrates traditional network vulnerability without SDN defense:
```bash
python3 run.py --baseline
```
* Shows dumb edge forwarding: All 7 attacker probes penetrate directly to the server.
* Displays kernel listen backlog queue saturation.
* Shows legitimate client degradation (65% delivery rate and high latency).

---

### 3. Multi-Vector Attack Demonstration (`python3 run.py --all-attacks`)
Demonstrates defense across all attack vectors:
```bash
python3 run.py --all-attacks
```
* **Attack 1:** Vertical Port Scan (Port Diversity $\ge 5$).
* **Attack 2:** Volumetric Connection Flood (Connection Rate $\ge 10/\text{s}$).
* **Attack 3:** Horizontal Subnet Sweep (IP Host Diversity $\ge 3$).
* **Attack 4:** TCP SYN Flood Burst (SYN Velocity $\ge 8/\text{s}$).
* **Summary Table:** High-visibility audit verifying 100% quarantine across all vectors.

---

## Advanced Test & Interactive Showcase (`advanced/`)

For in-depth lab verification:
```bash
cd /mnt/shared/sem3/CN/project/first_presentation/network_intrusion_detection/advanced
```

| Command | Purpose |
| :--- | :--- |
| **`./run_experiment.sh --demo`** | **Interactive 5-Phase Showcase** (Pauses between phases with `Enter` so you can present at your own pace) |
| **`./run_experiment.sh --test`** | **Automated Unit & Integration Test Suite** (Runs 6/6 tests in 1.1s verifying IPC, sockets, and rules) |
| **`./run_experiment.sh --analyze`** | **Comparative Metric Generator** (Produces CSV and Markdown comparison tables) |
| **`./run_experiment.sh --all`** | Runs tests $\rightarrow$ automated demo $\rightarrow$ generates evaluation summary report |

---

## Top 10 Viva / Professor Interview Questions

### Q1: What is the fundamental difference between the Control Plane and the Data Plane?
> **Answer:**  
> *"The Data Plane (Open vSwitch) is the high-speed forwarding engine running in kernel or switch hardware that handles packets according to active flow tables. The Control Plane (Ryu SDN Controller) is the centralized software brain that observes network topology, computes policies, and dynamically installs or updates those flow rules."*

### Q2: Why did you write raw Python BSD sockets instead of using web frameworks like Flask?
> **Answer:**  
> *"Web frameworks introduce heavy WSGI/ASGI serialization layers and application-level buffers that obscure transport-layer metrics. Raw BSD sockets (`socket.AF_INET`, `socket.SOCK_STREAM`) allow direct manipulation of kernel socket queues (`listen(100)`), socket reuse options (`SO_REUSEADDR`), and accurate measurement of true wire-speed RTT without framework latency."*

### Q3: What does an empty action list in OpenFlow mean?
> **Answer:**  
> *"In the OpenFlow 1.3 specification, flow entries consist of a match condition and a set of instructions/actions. If a packet matches a rule and the action set is empty (`actions = []`), the switch datapath has no instruction to forward the frame to any port or controller, so it explicitly discards/drops the packet in hardware."*

### Q4: Why is the drop rule assigned Priority 200 instead of Priority 1?
> **Answer:**  
> *"OpenFlow switches evaluate table rules in descending order of priority number. Normal L2 forwarding is assigned Priority 1. By assigning Priority 200 to the attacker drop rule, the switch evaluates and executes the drop rule first, preempting normal forwarding without requiring us to delete or modify existing routing rules."*

### Q5: How do you prevent false positives for legitimate users?
> **Answer:**  
> *"We maintain per-source-IP sliding-window deques. Legitimate clients only ever communicate with the application port (`8080`), so their distinct port count is strictly 1—well below our threshold of 5. Furthermore, state is isolated per IP address, so an attacker's traffic never influences an innocent user's history."*

### Q6: Why use `collections.deque` instead of a standard Python `list`?
> **Answer:**  
> *"In a standard Python list, removing the oldest event from the front (`list.pop(0)`) requires shifting every remaining element in memory, which is an $O(N)$ operation. `collections.deque` is a doubly-linked structure implemented in C that provides $O(1)$ constant-time pushes (`append`) and left-pops (`popleft`), ensuring sub-millisecond execution even under high traffic."*

### Q7: Why use `time.monotonic()` instead of `time.time()`?
> **Answer:**  
> *"Wall-clock time (`time.time()`) can jump backwards or forwards during NTP network synchronizations or daylight saving adjustments, corrupting sliding window time spans. Monotonic time (`time.monotonic()`) is derived from hardware CPU counters and is mathematically guaranteed to strictly move forward at a uniform rate."*

### Q8: What does `SO_REUSEADDR` do at the OS kernel level?
> **Answer:**  
> *"When a TCP socket closes, the kernel holds the port in a `TIME_WAIT` state for up to two minutes to absorb lingering network packets. `SO_REUSEADDR` informs the kernel to allow the socket to rebind to the same address and port immediately upon server restart."*

### Q9: Why is edge SDN defense superior to host-based firewalls like `iptables`?
> **Answer:**  
> *"Host firewalls process packets only after they have traveled across the network wire and entered the server NIC, causing CPU interrupts and consuming server bus bandwidth. Edge SDN defense drops malicious frames at the ingress switch port before they ever reach the physical server, resulting in 0% CPU impact on the protected host."*

### Q10: What is the purpose of `hard_timeout = 60s` on dynamic flow rules?
> **Answer:**  
> *"Switch flow tables reside in finite TCAM memory. Setting a 60-second hard timeout creates an automated 'penalty box' lifecycle: the attacker is quarantined for 60 seconds, after which switch hardware memory is automatically reclaimed without requiring manual controller housekeeping."*
