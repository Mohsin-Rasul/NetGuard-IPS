# NetGuard-IPS: Host-Based Intrusion Prevention System

**NetGuard-IPS** is a lightweight, Python-based Intrusion Prevention System (IPS) designed for Windows. It provides real-time network traffic monitoring, detects malicious anomalies (such as DoS attacks, ARP spoofing, and malicious domains), and automatically blocks threats using the Windows Firewall.

This project demonstrates the practical application of fundamental **Data Structures and Algorithms** in cybersecurity.

---

## 🚀 Key Features

* **Live Traffic Monitoring:** Captures and displays incoming/outgoing packets in real time with protocol color-coding.
* **Advanced Threat Detection:**
    * **DoS/DDoS Detection:** Flags IPs sending an abnormal volume of packets.
    * **SYN Flood Detection:** Identifies rapid TCP connection attempts.
    * **ARP Spoofing:** Detects inconsistent MAC addresses for a specific IP to prevent Man-in-the-Middle attacks.
    * **Malicious Domain Blocking:** Inspects DNS queries and TLS SNI (Server Name Indication) against a list of known malicious domains.
    * **Threat Intelligence:** Fetches malicious IP feeds (e.g., Emerging Threats) to proactively block known attackers.
    * **Payload Inspection:** Scans for suspicious keywords (e.g., "admin", "password") in unencrypted traffic.
* **Active Defense:**
    * **Automatic Blocking:** Uses Windows `netsh` to create firewall rules instantly upon threat detection.
    * **Persistence:** Blocked IPs are saved securely and re-applied on system startup.
* **GUI & Usability:**
    * **Dark Mode:** Modern UI with toggleable themes.
    * **Process Identification:** Maps network connections to specific running applications (PIDs).
    * **Async Hostname Resolution:** Resolves IP hostnames in the background without freezing the interface.
    * **Export Data:** Save traffic logs to CSV for further analysis.
    * **IPv6 Support:** Full support for analyzing and blocking IPv6 traffic.

---

## 🧠 Data Structures & Algorithms Used

This project implements specific data structures from scratch to ensure efficiency:

1.  **Queue (FIFO):**
    *   **Usage:** Buffers packets between the *Packet Sniffer* thread and the *Detection Engine*.
    *   **Benefit:** Decouples capture from analysis, preventing packet loss during high-traffic spikes.

2.  **Binary Search Tree (BST):**
    *   **Usage:** Manages the database of Blacklisted IPs.
    *   **Benefit:** Provides $O(\log n)$ lookup time for checking if an incoming IP is blocked.

3.  **Stack (LIFO):**
    *   **Usage:** Manages the "Security Alerts" log.
    *   **Benefit:** Ensures the most recent security warnings are always displayed at the top of the dashboard.

4.  **Bubble Sort:**
    *   **Usage:** Sorting the live traffic table by packet size.
    *   **Benefit:** Allows the user to quickly identify large data transfers via the GUI.

5.  **Hash Maps (Dictionaries):**
    *   **Usage:** Tracks connection states, ARP tables, and DNS caches.
    *   **Benefit:** Provides $O(1)$ access for state tracking and anomaly detection.

---

## 🛠️ Prerequisites

* **OS:** Windows 10 or 11 (Required for Firewall integration).
* **Python:** Version 3.8 or higher.
* **Npcap:** Required for Scapy to sniff packets on Windows. [Download Npcap here](https://npcap.com/#download) (Select "Install Npcap in WinPcap API-compatible Mode").

---

## 📦 Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/yourusername/netguard-ips.git
    cd netguard-ips
    ```

2.  **Install Python Dependencies:**
    ```bash
    pip install scapy psutil
    ```

---

## ▶️ How to Run

⚠️ **Important:** This application requires **Administrator Privileges** to sniff network packets and modify Firewall rules.

1.  Open Command Prompt or PowerShell as **Administrator** (Right-click -> Run as Administrator).
2.  Navigate to the project folder.
3.  Run the main script:
    ```bash
    python main.py
    ```
4.  Click **"Start Monitoring"** on the dashboard.

---

## 📂 Project Structure

* **`main.py`**: The entry point. Handles the GUI (Tkinter), Process ID mapping, and thread management.
* **`core_modules.py`**: Contains the logic for the Packet Sniffer, Detection Engine, Logger, and Firewall Manager.
* **`hostname_resolver.py`**: Handles asynchronous DNS reverse lookups to prevent UI blocking.
* **`data_structures.py`**: Custom implementations of the BST, Stack, and Graph classes.

---

## 🛡️ Privacy & Safety

* **Local Analysis:** All packet analysis is performed locally on your machine. No data is sent to the cloud.
* **Firewall Rules:** When an IP is blocked, a rule is added to your Windows Defender Firewall. To remove these rules manually, open Windows Firewall > Advanced Settings > Inbound Rules, and delete rules starting with "HIPS_BLOCK_".

---

## 📝 License

This project is for educational purposes. Use responsible network monitoring practices.