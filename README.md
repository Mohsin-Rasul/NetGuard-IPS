# NetGuard-IPS: Host-Based Intrusion Prevention System

**NetGuard-IPS** is a lightweight, Python-based Intrusion Prevention System (IPS) designed for Windows. It provides real-time network traffic monitoring, detects malicious anomalies (such as DoS attacks and ARP spoofing), and automatically blocks threats using the Windows Firewall.

This project was developed to demonstrate the practical application of fundamental **Data Structures and Algorithms** in cybersecurity.

---

## 🚀 Key Features

* **Live Traffic Monitoring:** Captures and displays incoming/outgoing packets in real time.
* **Process Identification:** Maps network connections to specific running applications (PIDs) using `psutil`.
* **Attack Detection:**
    * **DoS/DDoS Detection:** Flags IPs sending an abnormal volume of packets.
    * **SYN Flood Detection:** Identifies rapid TCP connection attempts.
    * **ARP Spoofing:** Detects inconsistent MAC addresses for a specific IP.
    * **Payload Inspection:** Scans for suspicious keywords (e.g., "admin", "password") in unencrypted traffic.
* **Automatic Blocking:** Uses Windows `netsh` commands to create firewall rules instantly when a threat is detected.
* **IPv6 Support:** Full support for analyzing and blocking IPv6 traffic.

---

## 🧠 Data Structures & Algorithms Used

This project implements specific data structures from scratch to ensure efficiency:

1.  **Queue (FIFO):**
    * **Usage:** Acts as a buffer between the *Packet Sniffer* thread and the *Detection Engine*.
    * **Benefit:** Prevents packet loss during high-traffic spikes by decoupling capture from analysis.

2.  **Binary Search Tree (BST):**
    * **Usage:** Stores the database of Blacklisted IPs.
    * **Benefit:** Provides $O(\log n)$ time complexity for searching if an incoming IP is blocked, which is much faster than linear lists.

3.  **Stack (LIFO):**
    * **Usage:** Manages the "Security Alerts" log.
    * **Benefit:** Ensures the most recent security warnings are always displayed at the top of the dashboard.

4.  **Graph (Adjacency List):**
    * **Usage:** Models the internal network topology (Source IP $\rightarrow$ Destination IP).
    * **Benefit:** Tracks connection relationships in the backend logic.

5.  **Bubble Sort:**
    * **Usage:** Sorting the live traffic table by packet size.
    * **Benefit:** Allows the user to quickly identify large data transfers.

---

## 🛠️ Prerequisites

* **OS:** Windows 10 or 11 (Required for Firewall integration).
* **Python:** Version 3.8 or higher.
* **Npcap:** Required for Scapy to sniff packets on Windows. [Download Npcap here](https://npcap.com/#download) (Select "Install Npcap in WinPcap API-compatible Mode").

---

## 📦 Installation

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/yourusername/netguard-ips.git](https://github.com/yourusername/netguard-ips.git)
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
4.  Click **"Start System"** on the dashboard.

---

## 📂 Project Structure

* **`main.py`**: The entry point. Handles the GUI (Tkinter), Process ID mapping, and thread management.
* **`core_modules.py`**: Contains the logic for the Packet Sniffer, Detection Engine, and Firewall Manager.
* **`data_structures.py`**: Custom implementations of the BST, Stack, and Graph classes.

---

## 🛡️ Privacy & Safety

* **Local Analysis:** All packet analysis is performed locally on your machine. No data is sent to the cloud.
* **Firewall Rules:** When an IP is blocked, a rule is added to your Windows Defender Firewall. To remove these rules manually, open Windows Firewall > Advanced Settings > Inbound Rules, and delete rules starting with "Block...".

---

## 📝 License

This project is for educational purposes. Use responsible network monitoring practices.