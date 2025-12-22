# NetGuard-IPS

**NetGuard-IPS** is a lightweight, Host-based Intrusion Prevention System (HIPS) built in Python. It provides real-time network traffic monitoring, anomaly detection, and active defense mechanisms by integrating directly with the Windows Firewall.

This project demonstrates the practical application of core Data Structures and Algorithms (BST, Graphs, Stacks, Queues, Sorting) to solve real-world cybersecurity challenges.

## Key Features

- **Real-Time Packet Sniffing**  
  Captures and analyzes network packets on the fly using raw sockets.

- **Threat Detection Engine**
  - **ARP Spoofing Detection**: Identifies malicious ARP cache poisoning attempts.
  - **SYN Flood Protection**: Detects DoS attempts based on high-frequency SYN packets.
  - **Port Scanning Detection**: Flags IPs attempting to scan multiple ports.
  - **Signature Matching**: Deep Packet Inspection (DPI) to find suspicious keywords such as `admin`, `password`, and common SQL injection patterns.

- **Active Response**  
  Automatically blocks malicious IPs using the Windows Firewall (`netsh`).

- **Interactive Dashboard**
  - **Live Traffic Table**: Displays source IP, destination IP, protocol, and packet size.
  - **Network Topology Graph**: Visualizes connections between the host and external IPs.
  - **Alert Log**: Stack-based history of detected security incidents.

## Data Structures & Algorithms Implemented

This project relies on custom implementations of fundamental data structures for performance and clarity.

| Component | Data Structure / Algorithm | Use Case |
|---------|----------------------------|----------|
| Blacklist Manager | Binary Search Tree (BST) | Efficient storage and lookup of blocked IP addresses (O(log n)) |
| Search Engine | Binary Search | Quickly checks whether an IP exists in the blacklist |
| Alert System | Stack (Linked List) | Maintains recent security alerts using LIFO order |
| Network Map | Graph (Adjacency List) | Represents relationships between the host and connected IPs |
| Packet Buffer | Queue (FIFO) | Safely transfers packets from sniffer thread to detection engine |
| Traffic Analysis | Bubble Sort | Sorts captured packets by size for dashboard analysis |

## Tech Stack

- **Programming Language**: Python 3.8+
- **GUI Framework**: Tkinter (Standard Library)
- **Network Library**: Scapy
- **System Integration**: `subprocess` (Windows Firewall control)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/mohsin-rasul/netguard-ips.git
cd netguard-ips
```
### 2. Install Dependencies

Scapy requires Npcap on Windows.
```bash
pip install scapy
```

Ensure Npcap is installed with WinPcap API-compatible mode enabled.

### 3. Run the Application

Administrator privileges are required for packet sniffing and firewall rule management.
```bash
python main.py
```
### Project Structure
```bash
NetGuard-IPS/
│
├── main.py               # Entry point (GUI, threading, initialization)
├── core_modules.py       # Detection engine, sniffer, firewall manager, logger
├── data_structures.py    # Custom data structures (BST, Stack, Graph, Queue)
├── hips_alerts.log       # Persistent security alert logs
├── LICENSE               # MIT License
└── README.md             # Project documentation
```
### Usage Guide
```bash
Click Start System to begin packet sniffing and intrusion detection.

Monitor real-time traffic in the Live Traffic table.

View active connections in the Network Map.

Detected attacks are automatically blocked and logged in Security Alerts.

Use Simulate Attack to test the alert system with a sample SQL injection payload.

Click Sort Traffic to organize packets by size using Bubble Sort.

Select a blocked IP and click Unblock IP to remove the firewall rule.
```
### Disclaimer

This project is intended strictly for educational and defensive purposes.
Do not use this tool on networks you do not own or have explicit permission to test.
The author is not responsible for misuse.

### License

This project is licensed under the MIT License.
See the LICENSE file for details.

Author: Mohsin Rasul
Copyright: © 2025
