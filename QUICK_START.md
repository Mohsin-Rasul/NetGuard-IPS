# 🚀 NetGuard-IPS - Quick Start Guide

## ⚡ 60-Second Setup

### Step 1: Install Dependencies
```bash
pip install scapy psutil
```

### Step 2: Run the Launcher
```bash
python launcher.py
```

### Step 3: Choose Your GUI
- **🚀 Modern GUI** - User-friendly, dashboard-focused (RECOMMENDED)
- **📋 Classic GUI** - Detailed, advanced features

### Step 4: Run as Administrator
Right-click Python → "Run as Administrator"

### Step 5: Start Monitoring
1. Click "Start System"
2. Check Traffic Monitor tab
3. View alerts in Security Alerts tab

---

## 🎯 What Can You Do?

| Task | Steps | Time |
|------|-------|------|
| **Start Monitoring** | Dashboard → Start System | 10s |
| **View Traffic** | Traffic Monitor tab | Real-time |
| **Check Alerts** | Security Alerts tab | Real-time |
| **Test System** | Dashboard → Simulate Attack | 10s |
| **Export Stats** | Dashboard → Export Stats | 30s |
| **Block/Unblock IPs** | Blocked IPs tab → Actions | 20s |
| **Change Settings** | Settings → Configure → Save | 30s |

---

## 📊 Dashboard Overview

```
┌─────────────────────────────────────────────────────────┐
│              🛡️ NetGuard-IPS v2.0                       │
│    ● Status    Packets: 0   Alerts: 0   Blocked: 0     │
├─────────────────────────────────────────────────────────┤
│  [▶ Start] [⏹ Stop] [⚡ Simulate] [📥 Export]         │
├─────────────────────────────────────────────────────────┤
│  Statistics:                                            │
│  ┌──────────────┬──────────────┬──────────────┐        │
│  │ Packets      │ Alerts       │ Blocked IPs  │        │
│  │ 0            │ 0            │ 0            │        │
│  └──────────────┴──────────────┴──────────────┘        │
├─────────────────────────────────────────────────────────┤
│  System Status:                                         │
│  [System initialized and monitoring...]                 │
└─────────────────────────────────────────────────────────┘
```

---

## 5️⃣ Main Features

### 1. 📊 Dashboard
- Start/Stop the system
- View real-time statistics
- Simulate attacks for testing
- Export data

### 2. 📡 Traffic Monitor
- See live network traffic
- Analyze local traffic
- Sort by IP address
- Clear traffic data

### 3. 🚨 Security Alerts
- View detected threats
- See alert timestamps
- Save alerts to file
- Clear old alerts

### 4. 🔒 Blocked IPs
- Manage firewall blocks
- Unblock specific IPs
- Clear all blocks
- View block reasons

### 5. ⚙️ Settings
- Enable/disable features
- Set detection sensitivity
- Configure threat feeds
- Manage preferences

---

## ✅ Checklist: First Run

- [ ] Install Python dependencies
- [ ] Run launcher.py as Administrator
- [ ] Choose Modern GUI
- [ ] Click "Start System"
- [ ] Check Traffic Monitor for traffic
- [ ] Review Settings tab
- [ ] Try "Simulate Attack"
- [ ] Review Security Alerts
- [ ] Test "Export Stats"
- [ ] Read full USER_GUIDE.md for details

---

## 🎮 Common Actions

### Start Protecting Network
```
1. Open launcher.py
2. Click "🚀 Launch Modern GUI"
3. Click "▶ Start System"
✓ System is now active
```

### Test Alert System
```
1. Dashboard tab
2. Click "⚡ Simulate Attack"
3. Go to "🚨 Security Alerts" tab
✓ Should see test alert
```

### Review Traffic
```
1. Click "📡 Traffic Monitor" tab
2. Enable "Analyze Local Traffic" checkbox
3. Open browser or run ping
✓ Traffic appears in table
```

### Export Data
```
1. Dashboard tab
2. Click "📥 Export Stats"
3. Choose .json or .csv format
4. Select save location
✓ Stats file created
```

### Block an IP
```
1. Find IP in "📡 Traffic Monitor" tab
2. Add to blocked list manually
3. Go to "🔒 Blocked IPs" tab
✓ IP appears in blocked list
```

### Unblock an IP
```
1. Go to "🔒 Blocked IPs" tab
2. Select the IP to unblock
3. Click "🔓 Unblock Selected"
✓ IP is now unblocked
```

---

## ⚠️ Important Notes

- **Run as Administrator** - Required for firewall operations
- **Windows Only** - Uses Windows Firewall API
- **Active Network** - Works best with real network activity
- **Leave Running** - Monitor continuously for best protection

---

## 📚 Learn More

- **Full Guide**: See USER_GUIDE.md
- **Technical Details**: See README.md
- **Implementation**: See IMPLEMENTATION_NOTES.md
- **Deployment**: See DEPLOYMENT_CHECKLIST.md

---

## 🆘 Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| No traffic showing | Enable "Analyze Local Traffic" checkbox |
| Too many alerts | Reduce "Detection Sensitivity" to Low |
| Can't block IPs | Run as Administrator |
| Settings not saving | Click "Save Settings" button |
| Alerts won't clear | Make sure system is stopped first |

---

**Ready to protect your network?**

```bash
python launcher.py
```

Choose **Modern GUI** and click **Start System** to begin! 🚀
