# ❓ NetGuard-IPS - Frequently Asked Questions (FAQ)

## Installation & Setup

### Q1: Do I need to install Python first?
**A:** Yes. Download from [python.org](https://www.python.org) version 3.7 or later. During installation, check "Add Python to PATH".

### Q2: How do I install the required packages?
**A:** Open Command Prompt (as Administrator) and run:
```bash
pip install scapy psutil
```

### Q3: Why do I need to run as Administrator?
**A:** NetGuard-IPS uses Windows Firewall to block IPs. Firewall modifications require Administrator privileges.

### Q4: What if I get "permission denied" errors?
**A:** Right-click Command Prompt → "Run as Administrator" → Try again.

### Q5: Can I run this on Linux or Mac?
**A:** Detection works on any OS. Firewall blocking is Windows-only (uses Windows Firewall API).

---

## GUI & Interface

### Q6: What's the difference between Modern GUI and Classic GUI?
**A:**
- **Modern GUI**: Beautiful dashboard, easy to use, tab-based (Recommended)
- **Classic GUI**: Detailed controls, network mapping, advanced features

### Q7: How do I choose which GUI to use?
**A:** Run `python launcher.py` - it shows both options. Choose "Modern GUI" for best experience.

### Q8: Can I use both GUIs at the same time?
**A:** Yes, but not recommended. They share the same firewall, so blocks/unblocks might conflict.

### Q9: The GUI is too small/big on my screen
**A:** Window size is set automatically. You can resize it manually. It will remember the size next time.

### Q10: Why is the interface lagging?
**A:** This usually means too much traffic data. Go to Traffic Monitor → Click "Clear Traffic".

---

## Starting & Monitoring

### Q11: What does "Start System" do?
**A:** Activates network monitoring, threat detection, and firewall blocking. Header changes to "● ONLINE".

### Q12: How do I know the system is running?
**A:** Check top-right corner - should show "● ONLINE" in green. Status bar says "System running".

### Q13: Does stopping the system unblock all IPs?
**A:** No. Stopped system just pauses monitoring. Firewall blocks remain active until you manually unblock.

### Q14: How much does monitoring slow down my internet?
**A:** Minimal impact. Modern systems can handle thousands of packets/second without noticeable slowdown.

### Q15: Can I minimize the window while monitoring?
**A:** Yes. System continues monitoring in background. Bring window back anytime.

---

## Traffic & Packets

### Q16: What's the difference between Local Traffic and Normal Traffic?
**A:**
- **Local Traffic**: Your machine's own connections
- **Normal Traffic**: All network traffic on your connection

Enable "Analyze Local Traffic" to see what your apps are doing.

### Q17: Why is my traffic empty?
**A:** Either:
1. System isn't started (click [▶ Start])
2. Enable "Analyze Local Traffic" checkbox
3. No network activity happening (generate some with browser)

### Q18: What's a "Normal" vs "Blocked" packet?
**A:**
- **Normal**: Traffic from safe IPs
- **Blocked**: Traffic from known malicious IPs

### Q19: How do I understand what's in the Traffic Monitor?
**A:** Read [USER_GUIDE.md](USER_GUIDE.md) → "Traffic Monitor Tab" section.

### Q20: Can I filter traffic by IP?
**A:** Not directly in modern GUI. Sort by IP to group related traffic.

---

## Alerts & Threats

### Q21: What does an alert mean?
**A:** System detected suspicious activity. Most alerts mean an IP was blocked. Review reason and decide if legitimate.

### Q22: Why do I see so many alerts?
**A:** Either high traffic volume or detection sensitivity is too high. Try:
1. Lower sensitivity to "Low" in Settings
2. Check if legitimate traffic is being flagged

### Q23: Are all alerts real threats?
**A:** Most are, but false positives happen. Verify before taking action.

### Q24: How do I know if an alert is a false positive?
**A:** If you recognize the IP/domain as legitimate, it's likely false positive. Unblock it.

### Q25: Where are alert records stored?
**A:** In `hips_alerts.log` file. Also accessible via "Save Alerts" button in Security Alerts tab.

---

## Blocked IPs

### Q26: How do I block an IP manually?
**A:** Currently, IPs are blocked automatically by threats. Future versions will add manual blocking.

### Q27: How do I unblock an IP?
**A:** Go to Blocked IPs tab → Select IP → Click [🔓 Unblock Selected].

### Q28: Can I block all traffic except certain IPs?
**A:** No. NetGuard-IPS only blocks known threats. For whitelist-only, use Windows Firewall directly.

### Q29: What happens when I clear all blocks?
**A:** All currently blocked IPs are immediately unblocked. Currently blocked by NetGuard. Old manual blocks remain.

### Q30: Do blocks survive system restart?
**A:** Firewall blocks do (they're in Windows Firewall). NetGuard's tracking resets. Restart to clear everything.

---

## Settings & Configuration

### Q31: What's "Detection Sensitivity"?
**A:**
- **Low**: Fewer alerts, less safe
- **Medium**: Balanced (Recommended)
- **High**: More alerts, may have false positives

### Q32: Should I enable "IPv6 Detection"?
**A:** Yes, unless you don't use IPv6. Modern internet increasingly uses IPv6.

### Q33: What does "Auto-Update Threat Feeds" do?
**A:** Automatically downloads latest malicious IP lists from threat databases. Keep enabled.

### Q34: Why aren't my settings saving?
**A:** Make sure you click "Save Settings" button. File permission issues with config.json would prevent saving.

### Q35: How do I reset settings to defaults?
**A:** Settings tab → Click [🔄 Reset to Defaults] → Click [💾 Save Settings].

---

## Data & Export

### Q36: What can I export?
**A:** Statistics (packets, alerts, blocked IPs count) in JSON or CSV format.

### Q37: What's the difference between JSON and CSV?
**A:**
- **JSON**: Structured, easy for programs to read
- **CSV**: Spreadsheet format, easy for Excel/Sheets

### Q38: How often should I export?
**A:** Weekly for records, daily if analyzing trends.

### Q39: Can I export traffic details (not just stats)?
**A:** Not directly. Copy/paste from Traffic Monitor or use "Save Alerts" for alert details.

### Q40: Where are exported files saved?
**A:** Wherever you choose in the file save dialog. Default is your Documents folder.

---

## Performance & Optimization

### Q41: How much disk space does NetGuard-IPS use?
**A:** About 50 MB. Logs rotate at 10 MB to prevent disk exhaustion.

### Q42: How much memory does it use?
**A:** Typically 100-200 MB. Can increase if traffic data isn't cleared.

### Q43: Can I run this 24/7?
**A:** Yes, designed for continuous operation. Start on boot if desired.

### Q44: What if the application crashes?
**A:** Firewall blocks remain active. Restart the application. Check hips_alerts.log for error details.

### Q45: How do I improve performance?
**A:**
1. Clear old traffic data periodically
2. Use "Medium" detection sensitivity
3. Clear old alerts
4. Don't keep months of data
5. Restart system occasionally

---

## Security & Safety

### Q46: Is NetGuard-IPS safe to use?
**A:** Yes. It only blocks known malicious IPs, doesn't modify any system files beyond firewall.

### Q47: What if NetGuard-IPS blocks something legitimate?
**A:** Go to Blocked IPs → Select it → Click [🔓 Unblock Selected].

### Q48: Can NetGuard-IPS be bypassed?
**A:** The firewall can be (if user has admin rights), but detection can't be fooled easily.

### Q49: Should I use antivirus with NetGuard-IPS?
**A:** Yes. NetGuard-IPS and antivirus serve different purposes. Use both for defense in depth.

### Q50: Does NetGuard-IPS protect against 0-days?
**A:** No. It protects against known threats. Unknown vulnerabilities aren't detected.

---

## File Locations & Logs

### Q51: Where are the important files?
**A:** In the NetGuard-IPS folder:
- `config.json` - Settings
- `blocked_ips.json` - Blocked IP list
- `hips_alerts.log` - Alert history
- `hips_stats.json` - Statistics

### Q52: Can I edit config.json directly?
**A:** Yes, but use GUI Settings instead (safer). Only edit if you know what you're doing.

### Q53: How do I view alert logs?
**A:** Open `hips_alerts.log` with Notepad or any text editor.

### Q54: Are logs encrypted?
**A:** No, plain text. Keep confidential if sensitive information.

### Q55: How long are logs kept?
**A:** Until file reaches 10 MB, then rotates. 5 backup files kept.

---

## Troubleshooting

### Q56: System won't start
**A:** 
1. Check "Status" at bottom of window
2. Verify running as Administrator
3. Check system requirements met
4. Read troubleshooting section in USER_GUIDE.md

### Q57: No traffic showing
**A:**
1. Click [▶ Start System]
2. Enable "Analyze Local Traffic" checkbox
3. Open browser or run `ping 8.8.8.8`

### Q58: Too many false alerts
**A:** Lower detection sensitivity to "Low" in Settings tab.

### Q59: Can't block IPs
**A:** Run as Administrator. Right-click launcher → "Run as Administrator".

### Q60: Application crashes on startup
**A:** 
1. Check dependencies: `pip install scapy psutil`
2. Ensure Python 3.7+
3. Try Classic GUI instead
4. Check hips_alerts.log for error details

### Q61: Interface freezes
**A:**
1. Clear traffic data
2. Reduce detection sensitivity
3. Wait for large export to complete
4. Restart application

### Q62: Settings won't save
**A:**
1. Click "Save Settings" button
2. Check file permissions on config.json
3. Try different location if on network drive
4. Try resetting to defaults first

### Q63: Can't unblock IPs
**A:**
1. Run as Administrator
2. Try "Clear All Blocks" instead
3. Use netsh command directly (advanced)
4. Restart system

### Q64: Application slow after long use
**A:**
1. Clear traffic data
2. Clear old alerts
3. Export and delete old statistics
4. Restart application

### Q65: What if I accidentally block myself?
**A:** Use unblock function or restart Windows Firewall from Settings.

---

## Advanced Questions

### Q66: Can I customize the detection rules?
**A:** Not in GUI. Modify `core_modules.py` for advanced customization.

### Q67: How do I integrate with SIEM?
**A:** Export statistics as JSON and import into your SIEM system.

### Q68: Can I run multiple instances?
**A:** Technically yes, but not recommended (firewall conflicts).

### Q69: What data structures are used?
**A:** Binary Search Tree (BST), Stack, Queue, and Graph. See `data_structures.py`.

### Q70: How does the detection engine work?
**A:** See `core_modules.py` and technical documentation.

---

## Feature Requests & Feedback

### Q71: Can you add feature X?
**A:** Possibly! Check GitHub or contact developers with specific requests.

### Q72: Where do I report bugs?
**A:** Check existing issues first, then create new bug report with details.

### Q73: Can I contribute to the project?
**A:** Yes! Fork the repository and submit pull requests.

### Q74: Is there a roadmap?
**A:** Yes, check project documentation for planned features.

### Q75: When is version 3.0 coming?
**A:** No official date yet. Follow project for updates.

---

## Common Scenarios

### Q76: I'm getting attacked. What do I do?
**A:**
1. Click [▶ Start System] if not running
2. Monitor Security Alerts tab continuously
3. Note all blocked IPs
4. [💾 Save Alerts] for evidence
5. Consider contacting ISP/security professionals
6. Never stop the system during attack

### Q77: Can I test the system?
**A:**
1. Dashboard tab
2. Click [⚡ Simulate Attack]
3. Check Security Alerts tab
4. Verify IP appears in Blocked IPs
5. Optionally unblock to test

### Q78: I need to backup my settings
**A:**
1. Go to Settings → [💾 Save Settings]
2. Copy `config.json` to safe location
3. Copy `blocked_ips.json` backup
4. Done!

### Q79: I'm moving to new computer
**A:**
1. Export configuration
2. Copy config files to new location
3. Run on new computer
4. Restore from backup files

### Q80: What if I need to restart Windows?
**A:**
1. System can start automatically after reboot
2. Firewall blocks persist
3. Monitoring resumes when NetGuard starts
4. Statistics reset (logged to file though)

---

## Final Tips

### Q81: What's the best way to learn this system?
**A:** Read QUICK_START.md, run it, then USER_GUIDE.md as needed.

### Q82: What's the #1 mistake users make?
**A:** Not running as Administrator. Always do this first.

### Q83: Should I show this to others?
**A:** Yes! Share the documentation. This is great for learning network security.

### Q84: How do I stay secure with NetGuard-IPS?
**A:**
1. Keep it running 24/7
2. Review alerts regularly
3. Update threat feeds
4. Adjust sensitivity as needed
5. Export stats periodically

### Q85: What if I have more questions?
**A:** Check documentation:
- [QUICK_START.md](QUICK_START.md) - Setup
- [USER_GUIDE.md](USER_GUIDE.md) - Features
- [MODERN_GUI_SUMMARY.md](MODERN_GUI_SUMMARY.md) - Interface
- [VISUAL_GUIDE.md](VISUAL_GUIDE.md) - Diagrams

---

## Quick Answer Lookup

| Topic | Answer Lookup |
|-------|---|
| Installation | Q1-Q5 |
| GUI Choice | Q6-Q10 |
| Starting System | Q11-Q15 |
| Traffic Monitor | Q16-Q20 |
| Alerts | Q21-Q25 |
| Blocked IPs | Q26-Q30 |
| Settings | Q31-Q35 |
| Export/Data | Q36-Q40 |
| Performance | Q41-Q45 |
| Security | Q46-Q50 |
| Files/Logs | Q51-Q55 |
| Troubleshooting | Q56-Q65 |
| Advanced | Q66-Q70 |
| Feedback | Q71-Q75 |
| Scenarios | Q76-Q80 |
| Tips | Q81-Q85 |

---

## Didn't Find Your Answer?

1. Check [USER_GUIDE.md](USER_GUIDE.md) - Has comprehensive explanations
2. Check [VISUAL_GUIDE.md](VISUAL_GUIDE.md) - Might have diagram showing it
3. Check [README_UPDATED.md](README_UPDATED.md) - Technical details
4. Check hips_alerts.log - May have error messages
5. Try running as Administrator - Fixes most issues

---

**🛡️ NetGuard-IPS FAQ v2.0**
*Your complete reference for common questions and answers*

For more help, see [GETTING_STARTED.md](GETTING_STARTED.md) for documentation guide.
