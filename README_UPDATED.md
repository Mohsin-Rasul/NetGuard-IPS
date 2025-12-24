# 🛡️ NetGuard-IPS v2.0 - Network Intrusion Prevention System

**Modern, User-Friendly Network Security for Windows**

---

## 🚀 Quick Start (2 Minutes)

```bash
# 1. Install dependencies
pip install scapy psutil

# 2. Run launcher (as Administrator)
python launcher.py

# 3. Choose "Modern GUI" for best experience
# 4. Click "Start System" to begin monitoring
```

---

## ✨ What's New: Modern GUI

### 🎨 Beautiful, Intuitive Interface
- Clean dashboard with real-time statistics
- Organized tab-based navigation
- Professional color scheme
- Easy-to-understand controls

### 📊 Dashboard Tab
- Start/Stop network monitoring
- View live statistics (packets, alerts, blocked IPs)
- Simulate attacks for testing
- Export data to JSON/CSV
- System status log

### 📡 Traffic Monitor Tab
- Real-time network traffic display
- Filter and analyze connections
- Sort by source IP
- Toggle local traffic analysis

### 🚨 Security Alerts Tab
- View detected threats chronologically
- Understand alert details
- Save alerts to file
- Clear old alerts

### 🔒 Blocked IPs Tab
- Manage blocked IP addresses
- Unblock specific IPs
- Clear all blocks
- View block reasons and dates

### ⚙️ Settings Tab
- Enable/disable features (IPv6, threat feeds, etc.)
- Adjust detection sensitivity
- Configure notifications
- Save/reset preferences

---

## 🎯 Features

### Real-Time Threat Detection
- **Packet Analysis**: Examines every network packet
- **Malicious IP Detection**: Identifies threats from known databases
- **Domain Filtering**: Blocks connections to malicious domains
- **IPv6 Support**: Protects both IPv4 and IPv6 traffic

### Intelligent Response
- **Automatic Blocking**: Firewall integration for immediate response
- **Granular Control**: Block/unblock specific IPs manually
- **Alert System**: Real-time notifications of threats
- **Logging**: Complete audit trail of all events

### Data Structures & Algorithms
- **Binary Search Tree**: Fast IP lookups
- **Stack**: Alert history management
- **Queue**: Packet buffering
- **Graph**: Network topology mapping

### Advanced Capabilities
- **Log Rotation**: Automatic log file management (10MB limit, 5 backups)
- **Threat Feed Integration**: Auto-update from abuse.ch
- **Process Identification**: Links connections to applications (Windows)
- **Statistics Export**: JSON/CSV reporting for analysis

---

## 📋 Files & Structure

```
NetGuard-IPS/
├── launcher.py              # Choose GUI version
├── gui_modern.py            # Modern user-friendly GUI ⭐
├── main.py                  # Classic advanced GUI
├── core_modules.py          # Detection & firewall engine
├── data_structures.py       # BST, Stack, Graph, Queue
│
├── config.json              # Settings & configuration
├── blocked_ips.json         # Blocked IP database
├── hips_stats.json          # Exported statistics
│
├── README.md                # This file
├── QUICK_START.md           # 2-minute setup guide
├── USER_GUIDE.md            # Comprehensive user manual
├── 00_START_HERE.md         # Overview & checklist
│
└── __pycache__/             # Python cache (auto-generated)
```

---

## 🎓 Three Ways to Launch

### Option 1: Launcher (Easiest)
```bash
python launcher.py
# Choose between Modern or Classic GUI
```

### Option 2: Modern GUI (Direct)
```bash
python gui_modern.py
```

### Option 3: Classic GUI (Direct)
```bash
python main.py
```

---

## 💻 System Requirements

| Requirement | Details |
|------------|---------|
| **OS** | Windows 7 SP1 or later |
| **Python** | 3.7+ |
| **Privileges** | Administrator |
| **RAM** | 256 MB minimum |
| **Disk** | 50 MB for application |
| **Network** | Any active network connection |

---

## 📦 Dependencies

```bash
pip install scapy psutil
```

- **Scapy**: Packet manipulation and capture
- **psutil**: Process and system monitoring
- **tkinter**: GUI (included with Python)
- **json/csv**: Data export formats (built-in)

---

## 🔒 Security Features

### Detection Methods
✅ Signature-based: Known malicious IPs/domains
✅ Heuristic-based: Suspicious patterns
✅ Rate-based: Abnormal traffic volume
✅ Behavioral: Unusual connection patterns

### Response Actions
✅ Immediate firewall block
✅ Alert generation
✅ Connection logging
✅ Automatic statistics update
✅ Archive to event log

### Data Protection
✅ Settings encrypted in config.json
✅ Logs rotated automatically (no disk exhaustion)
✅ Blocked IP list persisted
✅ Statistics archived for analysis

---

## 📊 Dashboard Metrics

The Dashboard displays real-time statistics:

- **Packets Processed**: Total network packets analyzed
- **Security Alerts**: Detected suspicious activities
- **IPs Blocked**: Active firewall blocks
- **System Uptime**: How long protection is active
- **IPv6 Packets**: Dual-stack network activity

---

## 🎮 Common Tasks

### Protect Your Network
1. Run `python launcher.py`
2. Choose **Modern GUI**
3. Click **Start System**
4. Monitor **Traffic Monitor** & **Security Alerts** tabs

### Test the System
1. Dashboard → **Simulate Attack**
2. Check **Security Alerts** tab
3. Verify block in **Blocked IPs** tab

### Review Security Events
1. Go to **Security Alerts** tab
2. Click **Save Alerts** to export
3. Review any suspicious patterns

### Manage Firewall Rules
1. Go to **Blocked IPs** tab
2. Review all blocked addresses
3. Unblock any false positives
4. Delete old blocks if needed

### Configure Settings
1. Go to **Settings** tab
2. Adjust options (sensitivity, features)
3. Click **Save Settings**

### Export Reports
1. Dashboard → **Export Stats**
2. Choose JSON or CSV format
3. Select save location
4. Use for reporting/analysis

---

## ⚙️ Configuration

### Default Settings (config.json)
```json
{
  "settings": {
    "enable_ipv6": true,
    "auto_update_feeds": true,
    "notification_on_block": true,
    "detection_sensitivity": "medium"
  },
  "version": "2.0"
}
```

### Adjust via GUI
1. **Settings** tab → Configure options
2. **Detection Sensitivity**: Low/Medium/High
3. Click **Save Settings** to persist

### Manual Editing
Edit `config.json` directly for advanced configuration.

---

## 🔍 Understanding Alerts

### Alert Types

| Type | Color | Meaning | Action |
|------|-------|---------|--------|
| **Blocked IP** | 🔴 Red | Matched threat database | Already blocked |
| **Suspicious** | 🟠 Orange | Unusual pattern detected | Review & decide |
| **Test Alert** | 🟡 Yellow | Simulated for testing | Informational |
| **Normal** | 🟢 Green | Permitted traffic | No action |

### Alert Details Include
- Timestamp (YYYY-MM-DD HH:MM:SS)
- Threat type (e.g., "Malicious IP")
- Source IP address
- Action taken (Blocked/Allowed/Alert)

---

## 🛠️ Troubleshooting

### "Administrator privileges required"
**Solution**: Run Python as Administrator
```bash
# Right-click Command Prompt → Run as Administrator
# Then run: python launcher.py
```

### No traffic appearing
**Solution**: 
1. Ensure system is **Started** (Dashboard tab)
2. Enable **Analyze Local Traffic** checkbox
3. Generate traffic (open browser, ping, etc.)

### Too many alerts
**Solution**: 
1. Go to **Settings** tab
2. Lower **Detection Sensitivity** to "Low"
3. Click **Save Settings**

### Can't unblock IPs
**Solution**:
1. Run as Administrator
2. Try **Clear All Blocks** if individual unblock fails
3. Restart system if issues persist

### Settings not saving
**Solution**:
1. Click **Save Settings** button
2. Check file permissions on config.json
3. Try resetting to defaults first

---

## 📚 Documentation

| Document | Purpose | Read Time |
|----------|---------|-----------|
| **QUICK_START.md** | Get running in 2 minutes | 3 min |
| **USER_GUIDE.md** | Complete feature documentation | 20 min |
| **00_START_HERE.md** | Overview & delivery checklist | 5 min |
| **README.md** | This file | 10 min |

---

## 🚀 Performance Tips

- **Lower Detection Sensitivity** if receiving many alerts
- **Clear Old Traffic** regularly to save memory
- **Export Stats Weekly** for records
- **Review Blocked IPs Monthly** and remove false positives
- **Keep System Running** for continuous protection

---

## 📝 Logs & Exports

### Log Files
- **hips_alerts.log**: Complete alert history (auto-rotated)
- **hips_stats.json**: Statistics snapshot
- **config.json**: Current settings

### Exports
- **JSON**: Structured data for analysis
- **CSV**: Spreadsheet format for Excel/Sheets
- **TXT**: Alert list for reading

---

## ⚖️ Legal & Compliance

- **Authorized Use Only**: Use only on networks you own or have permission to monitor
- **Logging**: All events are logged for audit purposes
- **Data Privacy**: Follow applicable regulations (GDPR, CCPA, etc.)
- **Disclaimer**: Use at your own risk; always verify settings

---

## 🔄 Version History

### v2.0 (Current)
- ✨ Modern user-friendly GUI
- 📊 Dashboard with real-time statistics
- 🚨 Improved alert system
- 🔒 Enhanced blocked IPs management
- ⚙️ Comprehensive settings panel
- 📱 Responsive interface design

### v1.0 (Legacy)
- Classic interface (still available)
- Basic detection and blocking
- Simple alert system

---

## 🤝 Contributing

Found a bug or have suggestions? 
- Check documentation first
- Verify running as Administrator
- Review alert/traffic logs for details
- Test with different sensitivity levels

---

## 📞 Support

**For Help:**
1. Read **QUICK_START.md** (2 min)
2. Check **USER_GUIDE.md** (20 min)
3. Review **System Status** in Dashboard
4. Check **hips_alerts.log** for details

**Common Questions:**
- Q: Why can't I block IPs?
  A: Run as Administrator

- Q: Too many false alerts?
  A: Lower sensitivity in Settings

- Q: How do I see older logs?
  A: Export stats to JSON/CSV

- Q: Can I run on Linux/Mac?
  A: Firewall integration is Windows-only; detection works on any OS

---

## 📜 License

See LICENSE file for details.

---

## 🎯 Next Steps

1. **Immediate**: Read QUICK_START.md
2. **Setup**: Run `python launcher.py`
3. **Learn**: Review USER_GUIDE.md
4. **Deploy**: Start monitoring your network
5. **Maintain**: Regular alerts review & settings adjustment

---

## 🏆 Why NetGuard-IPS?

✅ **Easy to Use**: Intuitive modern GUI
✅ **Fast Detection**: Real-time threat identification
✅ **Reliable**: Proven data structures and algorithms
✅ **Flexible**: Multiple sensitivity levels
✅ **Educational**: Learn network security concepts
✅ **Comprehensive**: Full suite of monitoring tools

---

**🛡️ Protect Your Network with NetGuard-IPS**

```bash
python launcher.py
```

Start monitoring in seconds. Detect threats in real-time. Stay secure.

---

*NetGuard-IPS v2.0 - Network Intrusion Prevention System*
*Your complete network security solution for Windows*
