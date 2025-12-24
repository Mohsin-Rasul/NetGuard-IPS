# 🛡️ NetGuard-IPS - User Guide

## Quick Start

### Installation
1. **Install Python dependencies:**
   ```bash
   pip install scapy psutil
   ```

2. **Run the launcher:**
   ```bash
   python launcher.py
   ```
   
   OR run directly:
   ```bash
   # Modern GUI (Recommended)
   python gui_modern.py
   
   # Classic GUI
   python main.py
   ```

⚠️ **Important:** Run as Administrator for full functionality

---

## 🚀 Modern GUI - Features & How to Use

### 1. Dashboard Tab 📊
**Overview of your system in one place**

- **Start/Stop System**: Control when IPS is actively monitoring
- **Simulate Attack**: Test the system's alert capabilities
- **Export Stats**: Save statistics to JSON or CSV
- **Live Statistics**: Real-time display of:
  - Packets Processed
  - Security Alerts
  - IPs Blocked
  - System Uptime

**Quick Tips:**
- Start the system first before monitoring traffic
- Use Simulate Attack to test alert functionality
- Check system status for real-time updates

---

### 2. Traffic Monitor Tab 📡
**Real-time network traffic viewing**

**Features:**
- **Live Traffic Table**: Displays all captured packets
- **Columns:**
  - Time: When packet was captured
  - Source IP: Where traffic originated
  - Dest IP: Destination address
  - Port: Communication port
  - Protocol: TCP/UDP/Other
  - Size: Packet size in bytes
  - Status: Normal/Suspicious/Blocked

**Controls:**
- **Analyze Local Traffic**: Checkbox to include local machine traffic
- **Clear Traffic**: Remove all entries from monitor
- **Sort Traffic**: Organize traffic by source IP

**Quick Tips:**
- Local analysis helps diagnose issues with your own applications
- Sort by source IP to group related connections
- Table updates in real-time when system is running

---

### 3. Security Alerts Tab 🚨
**Track detected threats and suspicious activity**

**Features:**
- **Alert List**: Chronological list of security events
- **Alert Details:**
  - Timestamp
  - Threat type
  - Source IP
  - Action taken

**Controls:**
- **Clear Alerts**: Remove all alerts (after reviewing)
- **Save Alerts**: Export alerts to text file for records

**Understanding Alerts:**
- 🔴 Red background = Active/Critical alert
- Alerts are added to top of list (newest first)
- Each alert includes source IP and reason for blocking

**Quick Tips:**
- Review alerts regularly for security awareness
- Save alerts weekly for compliance/auditing
- High alert frequency may indicate attack attempts

---

### 4. Blocked IPs Tab 🔒
**Manage and review blocked IP addresses**

**Table Columns:**
- **IP Address**: The blocked IP in CIDR format
- **Reason**: Why this IP was blocked
- **Date Blocked**: When blocking was applied
- **Status**: Active/Inactive

**Controls:**
- **Unblock Selected**: Remove block on chosen IP
- **Clear All Blocks**: Remove all firewall rules (⚠️ Use with caution)

**Understanding Blocks:**
- Blocks are applied to Windows Firewall
- Incoming traffic from blocked IPs is rejected
- Can unblock if false positive occurs

**Quick Tips:**
- Always verify before unblocking IPs
- Keep records of why IPs were blocked
- Clear old blocks periodically (with caution)

---

### 5. Settings Tab ⚙️
**Configure system behavior and preferences**

**Available Settings:**

| Setting | Purpose | Default |
|---------|---------|---------|
| **Enable IPv6 Detection** | Monitor IPv6 traffic alongside IPv4 | ON |
| **Auto-Update Threat Feeds** | Automatically fetch latest threat lists | ON |
| **Notification on Block** | Show alerts when IP is blocked | ON |
| **Analyze Local Traffic** | Include local machine's own traffic | OFF |
| **Detection Sensitivity** | Threat detection aggressiveness | Medium |

**Detection Sensitivity Levels:**
- **Low**: Fewer alerts, misses some threats
- **Medium**: Balanced approach (Recommended)
- **High**: More alerts, may have false positives

**Managing Settings:**
1. Enable/disable checkboxes as needed
2. Adjust detection sensitivity
3. Click **Save Settings** to apply
4. Click **Reset to Defaults** to restore

**Quick Tips:**
- Keep most settings on for best protection
- Lower sensitivity if receiving too many alerts
- Save settings immediately after changes

---

## 📊 Understanding Statistics

### Real-Time Metrics

**Packets Processed**
- Total number of network packets analyzed
- Increases as traffic flows through system
- Helps gauge traffic volume

**Security Alerts**
- Number of suspicious activities detected
- Click to see details in Alerts tab
- High count may indicate attack

**IPs Blocked**
- Total unique IP addresses currently blocked
- Managed in Blocked IPs tab
- Can be increased/decreased manually

**System Uptime**
- How long the system has been running
- Format: HH:MM:SS
- Resets when you stop/start system

---

## 🔧 Common Tasks

### Start Monitoring
1. Open Modern GUI (launcher.py)
2. Click "Start System" on Dashboard
3. Header will show "● ONLINE"
4. Traffic Monitor will begin updating

### Respond to Alert
1. Check Security Alerts tab for details
2. Review the IP address and reason
3. Go to Blocked IPs tab to verify block
4. Unblock if false positive, or leave blocked

### Export Data
1. Dashboard → Click "Export Stats"
2. Choose JSON or CSV format
3. Select save location
4. File contains all captured metrics

### Change Detection Sensitivity
1. Go to Settings tab
2. Find "Detection Sensitivity" dropdown
3. Select Low/Medium/High
4. Click "Save Settings"
5. Changes apply immediately

### Clear Old Data
1. **Clear Traffic**: Traffic Monitor → Click "Clear Traffic"
2. **Clear Alerts**: Security Alerts → Click "Clear Alerts"
3. **Clear Blocks**: Blocked IPs → Click "Clear All Blocks"

---

## ⚠️ Troubleshooting

### "Administrator privileges required"
- **Problem:** System cannot apply firewall blocks
- **Solution:** Run as Administrator (right-click → Run as Administrator)

### No traffic showing
- **Problem:** Traffic Monitor is empty
- **Solution:** 
  - Ensure system is started (Dashboard tab)
  - Enable "Analyze Local Traffic" checkbox
  - Generate traffic with browser or ping

### High number of alerts
- **Problem:** Too many security alerts
- **Solution:**
  - Reduce Detection Sensitivity to "Low"
  - Check if legitimate traffic is being flagged
  - Save and review alerts for patterns

### IPs won't unblock
- **Problem:** Cannot remove firewall block
- **Solution:**
  - Run as Administrator
  - Try "Clear All Blocks" instead
  - Restart system if issue persists

### Settings not saving
- **Problem:** Configuration changes lost after restart
- **Solution:**
  - Ensure you click "Save Settings" button
  - Check file permissions on config.json
  - Try resetting to defaults first

---

## 🎯 Best Practices

### Daily Use
✅ Start system at beginning of workday
✅ Monitor alerts periodically
✅ Save alerts at end of week
✅ Review blocked IPs monthly

### Security
✅ Always run as Administrator
✅ Keep threat feeds updated
✅ Review alerts for trends
✅ Maintain backup of configurations

### Performance
✅ Clear old traffic data regularly
✅ Clear old alerts to save memory
✅ Use "Medium" detection sensitivity
✅ Monitor system uptime

### Compliance
✅ Export and archive alerts weekly
✅ Document all IP blocks
✅ Keep settings backed up
✅ Review logs regularly

---

## 📁 Key Files

| File | Purpose |
|------|---------|
| **gui_modern.py** | Modern user-friendly interface |
| **main.py** | Classic advanced interface |
| **launcher.py** | Choose between GUI versions |
| **core_modules.py** | Detection engine and firewall |
| **data_structures.py** | Data organization (BST, Stack) |
| **config.json** | Saved settings |
| **blocked_ips.json** | Blocked IP list |
| **hips_stats.json** | Exported statistics |
| **hips_alerts.log** | Alert history log |

---

## 🎓 Tips for New Users

1. **Start Simple**: Begin with Dashboard → Start System
2. **Explore Safely**: Use "Simulate Attack" to learn the interface
3. **Review Regularly**: Check Security Alerts tab daily
4. **Export Data**: Practice exporting stats to understand format
5. **Adjust Settings**: Find sensitivity level that works for you
6. **Read Alerts**: Understand why IPs are being blocked

---

## 📞 Need Help?

- Check **Status Bar** at bottom for real-time info
- Review **System Status** box in Dashboard for logs
- Consult **README.md** for technical details
- Check **hips_alerts.log** for alert history
- Run as Administrator if features don't work

---

## 🔄 Updates & Maintenance

### Regular Tasks
- **Daily**: Check alerts, review blocks
- **Weekly**: Export stats, clear old alerts
- **Monthly**: Review all settings, update threat feeds
- **Quarterly**: Full system health check

### Backup Important Data
```bash
# Save configuration
copy config.json config.json.backup

# Export statistics
# Use "Export Stats" button in GUI

# Archive alerts
# Use "Save Alerts" button in Alerts tab
```

---

**NetGuard-IPS v2.0 - Network Intrusion Prevention System**
Your complete network security solution.
