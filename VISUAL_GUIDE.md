# 🎨 NetGuard-IPS - Visual Reference Guide

## Dashboard Overview

```
┌────────────────────────────────────────────────────────────────────┐
│ 🛡️ NetGuard-IPS                              ● ONLINE  Packets: 1050 │
│ Network Intrusion Prevention System          Alerts: 3  Blocked: 2   │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  [▶ Start] [⏹ Stop] [⚡ Simulate] [📥 Export] [🔄 Sort] [ℹ Info]   │
│                                                                     │
│  ┌─────────────────┬──────────────┬───────────────┬─────────────┐  │
│  │ Packets: 1050   │ Alerts: 3    │ Blocked: 2    │ Uptime: 5m  │  │
│  │                 │              │               │ 23s         │  │
│  └─────────────────┴──────────────┴───────────────┴─────────────┘  │
│                                                                     │
│  System Status:                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ [14:32:15] System initialized and monitoring...              │  │
│  │ [14:32:18] Packet captured: 192.168.1.50:52348 → 8.8.8.8:53 │  │
│  │ [14:32:25] IDS ALERT: Suspicious pattern detected            │  │
│  │ [14:32:26] Firewall blocked: 203.0.113.45                    │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘
```

---

## Traffic Monitor Tab

```
┌─────────────────────────────────────────────────────────────────┐
│ [📡 Traffic Monitor]                                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ☑ Analyze Local Traffic    [🗑 Clear]    [📊 Sort by IP]     │
│                                                                  │
│  ┌──────────┬──────────────────┬──────────────────┬──────────┐  │
│  │ Time     │ Source IP        │ Dest IP          │ Status   │  │
│  ├──────────┼──────────────────┼──────────────────┼──────────┤  │
│  │ 14:32:18 │ 192.168.1.50     │ 8.8.8.8          │ Normal   │  │
│  │ 14:32:19 │ 192.168.1.100    │ 203.0.113.45     │ BLOCKED  │  │
│  │ 14:32:20 │ 10.0.0.15        │ 142.251.32.4     │ Normal   │  │
│  │ 14:32:21 │ 192.168.1.50     │ 172.217.164.14   │ Normal   │  │
│  │ 14:32:22 │ 203.0.113.100    │ 192.168.1.1      │ BLOCKED  │  │
│  │ ...      │ ...              │ ...              │ ...      │  │
│  └──────────┴──────────────────┴──────────────────┴──────────┘  │
│                                                                  │
│  Status: 2,156 packets analyzed, 5 suspicious detected         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Alerts Tab

```
┌─────────────────────────────────────────────────────────────────┐
│ [🚨 Security Alerts]                                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 🔴 [14:32:26] BLOCKED: 203.0.113.45 (Malicious IP)      │  │
│  │ 🔴 [14:32:19] BLOCKED: 192.168.1.100 (Port Scan)        │  │
│  │ 🟠 [14:32:15] ALERT: Unusual DNS activity detected      │  │
│  │ 🟡 [14:32:10] INFO: System started monitoring            │  │
│  │                                                          │  │
│  │ (More alerts...)                                         │  │
│  │                                                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  [🔄 Clear]    [💾 Save Alerts]    [🔓 Unblock IP]             │
│                                                                  │
│  Status: 3 alerts today, 0 false positives blocked             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Blocked IPs Tab

```
┌─────────────────────────────────────────────────────────────────┐
│ [🔒 Blocked IPs]                                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┬──────────────┬──────────────────────────┐ │
│  │ IP Address       │ Reason       │ Date Blocked             │ │
│  ├──────────────────┼──────────────┼──────────────────────────┤ │
│  │ 203.0.113.45     │ Malicious IP │ 2024-01-15 14:32:26     │ │
│  │ 198.51.100.89    │ Port Scan    │ 2024-01-15 10:45:12     │ │
│  │ 192.0.2.56       │ Brute Force  │ 2024-01-14 23:18:55     │ │
│  │ 203.0.113.100    │ Malware C&C  │ 2024-01-14 15:30:42     │ │
│  │ ...              │ ...          │ ...                      │ │
│  └──────────────────┴──────────────┴──────────────────────────┘ │
│                                                                  │
│  [🔓 Unblock Selected]    [🗑 Clear All Blocks]                 │
│                                                                  │
│  Status: 4 active blocks, 23 total blocked (session)            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Settings Tab

```
┌─────────────────────────────────────────────────────────────────┐
│ [⚙️ Settings]                                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Configuration Settings:                                        │
│                                                                  │
│  ☑ Enable IPv6 Detection                                       │
│  ☑ Auto-Update Threat Feeds                                    │
│  ☑ Notification on Block                                       │
│  ☐ Analyze Local Traffic                                       │
│                                                                  │
│  Detection Sensitivity:                                         │
│  ┌────────────────────────────┐                                │
│  │ Medium ▼                   │  (Low / Medium / High)          │
│  └────────────────────────────┘                                │
│                                                                  │
│  Log Rotation: 10 MB max, 5 backups retained                    │
│  Threat Feed: Last updated 2024-01-15 10:30 UTC                │
│                                                                  │
│  [💾 Save Settings]    [🔄 Reset to Defaults]                  │
│                                                                  │
│  ────────────────────────────────────────────────────────────  │
│                                                                  │
│  About:                                                         │
│  NetGuard-IPS v2.0 - Network Intrusion Prevention System       │
│  Features: Real-time detection, Auto-blocking, IPv6 support   │
│  Requirements: Windows, Admin privileges, Python 3.7+         │
│                                                                  │
│  For help, see USER_GUIDE.md                                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Color Legend

```
Status Indicators:
● GREEN  (#4caf50)  - System Online / Protected
● RED    (#f44336)  - System Offline / Critical Alert
● BLUE   (#2196F3)  - Information / Normal Activity
● ORANGE (#ff9800)  - Warning / Suspicious Activity
● YELLOW (#ffc107)  - Test / Simulation

Severity Levels:
🔴 RED    - Critical threat, action taken
🟠 ORANGE - Warning, review recommended
🟡 YELLOW - Information, for reference
🟢 GREEN  - Normal operation
⚪ GRAY   - Historical/archived
```

---

## Quick Reference: Controls

```
Top Left Controls (always available):
┌─────────────────────────────────────────┐
│ [▶ Start]        - Begin monitoring     │
│ [⏹ Stop]         - Pause monitoring     │
│ [⚡ Simulate]    - Test alert system    │
│ [📥 Export]      - Save statistics      │
│ [📊 Sort]        - Organize traffic     │
└─────────────────────────────────────────┘

Top Right Status (always visible):
┌─────────────────────────────────────────┐
│ ● STATUS (ONLINE/OFFLINE)               │
│ Packets: XXX  Alerts: XX  Blocked: X   │
└─────────────────────────────────────────┘

Tab Navigation (click to switch):
┌─────────────────────────────────────────┐
│ [📊 Dashboard] [📡 Traffic] [🚨 Alerts] │
│ [🔒 Blocks]    [⚙️ Settings]              │
└─────────────────────────────────────────┘
```

---

## Workflow: Common Scenarios

### Scenario 1: Start & Monitor
```
1. Launch: python launcher.py
2. Choose: 🚀 Modern GUI
3. Click: [▶ Start System]
4. View: 📡 Traffic Monitor tab
5. Check: 🚨 Security Alerts tab
6. End: [⏹ Stop System]
```

### Scenario 2: Test System
```
1. Ensure: System is started
2. Click: [⚡ Simulate Attack]
3. Check: 🚨 Alerts tab (new alert appears)
4. Review: 🔒 Blocked IPs tab
5. Optional: [🔓 Unblock] the test IP
```

### Scenario 3: Respond to Alert
```
1. See: Alert in 🚨 Security Alerts tab
2. Go: to 🔒 Blocked IPs tab
3. Review: IP and reason
4. Decide: Keep block or unblock
5. Action: [🔓 Unblock Selected] if needed
6. Save: [💾 Save Alerts] for records
```

### Scenario 4: Export Data
```
1. Click: [📥 Export Stats]
2. Choose: .json or .csv format
3. Select: Save location
4. Wait: File creation completes
5. Use: Open with Excel/text editor
6. Analyze: Trends and patterns
```

---

## Keyboard Shortcuts (when available)

```
Ctrl+Q   - Quit application
Ctrl+S   - Save current data
Ctrl+E   - Export statistics
Ctrl+C   - Clear selected data
Ctrl+R   - Refresh display
Ctrl+L   - Clear logs
```

---

## Data Display Formats

### Time Format
```
Display: HH:MM:SS (24-hour)
Example: 14:32:26 = 2:32:26 PM
```

### IP Address Format
```
IPv4: 192.168.1.50
IPv6: 2001:db8::1
CIDR: 192.168.0.0/24
```

### File Sizes
```
Bytes:     1024 B
Kilobytes: 1.2 KB
Megabytes: 2.5 MB
Gigabytes: 1.0 GB
```

### Packet Details
```
Protocol: TCP, UDP, ICMP, Other
Port:     0-65535
TTL:      0-255 (Time To Live)
Flags:    SYN, ACK, FIN, RST, etc.
```

---

## Troubleshooting Visual Guide

```
Problem: No traffic showing
┌────────────────────────────────────┐
│ ☑ Analyze Local Traffic Enabled?   │ YES → Next
│ ☑ System Started?                  │ YES → Next
│ ☑ Network activity happening?      │ NO → Generate traffic
│ Solution: Enable checkbox + start system
└────────────────────────────────────┘

Problem: Too many alerts
┌────────────────────────────────────┐
│ Settings → Detection Sensitivity    │
│ Current: HIGH                       │
│ Change to: MEDIUM                   │
│ Click: [💾 Save Settings]           │
│ Solution: Lower sensitivity level
└────────────────────────────────────┘

Problem: Can't block IPs
┌────────────────────────────────────┐
│ ☑ Running as Administrator?        │ NO → Run as Admin
│ ☑ Windows Firewall enabled?        │ NO → Enable it
│ ☑ Permissions correct?             │ Check Settings
│ Solution: Run as Administrator
└────────────────────────────────────┘
```

---

## Performance Indicators

```
Good Performance:
✅ Green status indicator
✅ Smooth scrolling in tables
✅ Real-time updates visible
✅ Alerts appear within 1 second
✅ No lag when clicking buttons

Poor Performance Signs:
❌ Sluggish table scrolling
❌ Delayed button responses
❌ Memory usage > 500 MB
❌ CPU usage constantly > 50%
❌ Slow startup (> 5 seconds)

Solutions:
1. Clear old traffic data
2. Reduce detection sensitivity
3. Clear old alerts
4. Restart application
5. Check system resources
```

---

## Export & Backup

### What to Export
```
📊 Daily:   Statistics snapshot (JSON)
📋 Weekly:  Alert logs (TXT)
📁 Monthly: Configuration backup (JSON)
🗂️ Yearly:  Full data archive (ZIP)
```

### File Locations
```
Current Directory:
├── config.json        (Settings)
├── blocked_ips.json   (IP list)
├── hips_stats.json    (Statistics)
└── hips_alerts.log    (Alert history)

Exported Files:
├── stats_2024-01-15.json
├── alerts_2024-01-15.txt
└── backup_2024-01-15.zip
```

---

## Success Checklist

```
✅ Installation
   ☑ Python 3.7+ installed
   ☑ Scapy installed (pip install scapy)
   ☑ psutil installed (pip install psutil)

✅ First Launch
   ☑ Running as Administrator
   ☑ launcher.py opens without errors
   ☑ Modern GUI appears

✅ Basic Operations
   ☑ Can click "Start System"
   ☑ Traffic appears in monitor
   ☑ Can view alerts
   ☑ Can export stats

✅ Full Functionality
   ☑ Simulate attack works
   ☑ IPs can be blocked
   ☑ IPs can be unblocked
   ☑ Settings can be saved
   ☑ Multiple tabs work smoothly
```

---

**NetGuard-IPS v2.0 - Visual Quick Reference**

Print this page for handy reference while using the system!
