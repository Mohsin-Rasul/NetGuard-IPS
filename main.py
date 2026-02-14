import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import queue
import time
import random
import sys
import os
import threading
import ctypes

# Try importing psutil for Process ID mapping
try:
    import psutil
except ImportError:
    psutil = None

# Import Local Modules
import dataStructures
import coreModules
from hostnameResolver import HostnameResolver

class ProfessionalIPS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetGuard-IPS | Advanced Network Security Monitor")
        self.root.geometry("1400x900")
        self.root.configure(bg="#ecf0f1") 

        # --- Data Structures & Logic ---
        self.blacklist = dataStructures.BlacklistBST()
        self.alerts = dataStructures.AlertStack()
        self.graph = dataStructures.NetworkGraph()
        self.pktQueue = queue.Queue()
        self.capturedData = []
        
        self.sniffer = None
        self.detector = None
        self.running = False
        
        # Hostname Resolver
        self.resolver = HostnameResolver(maxCacheSize=2000, timeout=3.0)
        
        # GUI State
        self.paused = tk.BooleanVar(value=False)
        self.showHostnames = tk.BooleanVar(value=True)
        self.statPackets = 0
        self.statBlocked = 0
        self.statAlerts = 0
        self.statInbound = 0
        self.statOutbound = 0
        self.statTcp = 0
        self.statUdp = 0
        self.statIcmp = 0
        self.uniqueSrcIps = set()
        self.uniqueDstIps = set()
        self.darkMode = False

        # --- Build UI ---
        self.setupStyles()
        self.createHeader()
        self.createKpiBoard()
        self.createControls()
        self.createNotebook()  # Tab-based interface

    def setupStyles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Modern Colors
        self.cBg = "#ecf0f1"
        self.cDark = "#2c3e50"
        self.cBlue = "#3498db"
        self.cRed = "#e74c3c"
        self.cGreen = "#2ecc71"
        self.cOrange = "#f39c12"

        # Treeview formatting
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#bdc3c7", foreground=self.cDark)
        style.configure("Treeview", font=("Consolas", 10), rowheight=25, background="white")
        style.map("Treeview", background=[('selected', self.cBlue)])

        # Button Styling
        style.configure("TButton", font=("Segoe UI", 9))
        style.configure("Action.TButton", font=("Segoe UI", 9, "bold"))

    def createHeader(self):
        # Top Header Bar
        headerFrame = tk.Frame(self.root, bg=self.cDark, height=60, padx=20, pady=10)
        headerFrame.pack(fill="x")
        
        # Status LED (Canvas)
        self.statusLed = tk.Canvas(headerFrame, width=20, height=20, bg=self.cDark, highlightthickness=0)
        self.statusLed.pack(side="left", padx=(0, 10))
        self.ledId = self.statusLed.create_oval(2, 2, 18, 18, fill="#95a5a6", outline="") # Grey initially
        
        # Title
        titleLbl = tk.Label(headerFrame, text="NetGuard Security Monitor", font=("Segoe UI", 18, "bold"), bg=self.cDark, fg="white")
        titleLbl.pack(side="left")

        # Version Info
        verLbl = tk.Label(headerFrame, text="v2.2 (Official Release)", font=("Segoe UI", 10), bg=self.cDark, fg="#bdc3c7")
        verLbl.pack(side="right", anchor="s", pady=5)

    def createKpiBoard(self):
        # Key Performance Indicators (Stats)
        kpiFrame = tk.Frame(self.root, bg=self.cBg, padx=20, pady=10)
        kpiFrame.pack(fill="x")

        self.varPkts = tk.StringVar(value="0")
        self.varThreats = tk.StringVar(value="0")
        self.varStatus = tk.StringVar(value="STOPPED")
        self.varInbound = tk.StringVar(value="0")
        self.varOutbound = tk.StringVar(value="0")

        # Helper to create a stat card
        def drawCard(parent, label, var, color):
            card = tk.Frame(parent, bg="white", highlightbackground="#bdc3c7", highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=5)
            
            tk.Label(card, text=label, font=("Segoe UI", 9, "bold"), fg="#7f8c8d", bg="white").pack(pady=(10, 5))
            tk.Label(card, textvariable=var, font=("Segoe UI", 20, "bold"), fg=color, bg="white").pack(pady=(0, 10))

        drawCard(kpiFrame, "SYSTEM STATUS", self.varStatus, self.cDark)
        drawCard(kpiFrame, "PACKETS ANALYZED", self.varPkts, self.cBlue)
        drawCard(kpiFrame, "INBOUND TRAFFIC", self.varInbound, self.cGreen)
        drawCard(kpiFrame, "OUTBOUND TRAFFIC", self.varOutbound, self.cOrange)
        drawCard(kpiFrame, "THREATS BLOCKED", self.varThreats, self.cRed)

    def createControls(self):
        # Toolbar for buttons
        toolbar = tk.Frame(self.root, bg=self.cBg, padx=20, pady=5)
        toolbar.pack(fill="x")

        # Left: Main Actions
        ttk.Button(toolbar, text="▶ START MONITORING", style="Action.TButton", command=self.startSystem).pack(side="left", padx=2)
        ttk.Button(toolbar, text="⏹ STOP SYSTEM", style="Action.TButton", command=self.stopSystem).pack(side="left", padx=2)
        
        # Separator
        ttk.Label(toolbar, text="  |  ", background=self.cBg).pack(side="left")

        # Middle: View Controls
        ttk.Checkbutton(toolbar, text="🔒 Pause Live View", variable=self.paused).pack(side="left", padx=10)
        ttk.Checkbutton(toolbar, text="📍 Show Hostnames", variable=self.showHostnames).pack(side="left", padx=10)
        ttk.Button(toolbar, text="🗑 Clear Table", command=self.clearTable).pack(side="left", padx=2)
        ttk.Button(toolbar, text="⬇ Sort by Size", command=self.sortTrafficBySize).pack(side="left", padx=2)

        # Right: Simulation & Export
        ttk.Button(toolbar, text="⚠ Simulate Attack", command=self.simulateAttack).pack(side="right", padx=2)
        ttk.Button(toolbar, text="💾 Export Logs", command=self.exportLogs).pack(side="right", padx=2)
        ttk.Button(toolbar, text="🌓 Theme", command=self.toggleTheme).pack(side="right", padx=2)

    def createNotebook(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=20, pady=10)
        notebook.bind("<<NotebookTabChanged>>", self.onTabChanged)

        self.tabTraffic = ttk.Frame(notebook)
        notebook.add(self.tabTraffic, text="🌐 Live Traffic Monitor")
        self.createTrafficTab()

        self.tabAlerts = ttk.Frame(notebook)
        notebook.add(self.tabAlerts, text="⚠️ Security Alerts")
        self.createAlertsTab()

        self.tabStats = ttk.Frame(notebook)
        notebook.add(self.tabStats, text="📊 Statistics & Analysis")
        self.createStatsTab()

        self.tabBlocked = ttk.Frame(notebook)
        notebook.add(self.tabBlocked, text="🚫 Blocked IPs")
        self.createBlockedTab()

    def createTrafficTab(self):
        mainFrame = tk.Frame(self.tabTraffic, bg="white")
        mainFrame.pack(fill="both", expand=True, padx=10, pady=10)

        searchFrame = tk.Frame(mainFrame, bg="#f0f0f0", height=40)
        searchFrame.pack(fill="x", pady=(0, 10))
        
        tk.Label(searchFrame, text="Filter:", bg="#f0f0f0", font=("Segoe UI", 9)).pack(side="left", padx=5)
        self.filterVar = tk.StringVar()
        self.filterVar.trace_add("write", lambda *args: self.filterTraffic())
        filterEntry = tk.Entry(searchFrame, textvariable=self.filterVar, width=30, font=("Segoe UI", 9))
        filterEntry.pack(side="left", padx=5)
        
        ttk.Button(searchFrame, text="🔍 Clear Filter", command=lambda: self.filterVar.set("")).pack(side="left", padx=5)

        treeContainer = tk.Frame(mainFrame, bg="white")
        treeContainer.pack(fill="both", expand=True)

        cols = ("Time", "SrcIP", "SrcHost", "DstIP", "DstHost", "Direction", "Protocol", "Size", "Process", "Payload")
        self.tree = ttk.Treeview(treeContainer, columns=cols, show="headings", selectmode="extended", height=25)
        self.tree["displaycolumns"] = ("Time", "SrcIP", "SrcHost", "DstIP", "DstHost", "Direction", "Protocol", "Size", "Process")
        
        vsb = ttk.Scrollbar(treeContainer, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(treeContainer, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        treeContainer.grid_rowconfigure(0, weight=1)
        treeContainer.grid_columnconfigure(0, weight=1)

        columnsConfig = [
            ("Time", 70, "center"),
            ("SrcIP", 110, "w"),
            ("SrcHost", 100, "w"),
            ("DstIP", 110, "w"),
            ("DstHost", 100, "w"),
            ("Direction", 60, "center"),
            ("Protocol", 60, "center"),
            ("Size", 70, "e"),
            ("Process", 120, "w")
        ]
        
        for col, width, anchor in columnsConfig:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor=anchor)

        self.tree.tag_configure('TCP', foreground="#2980b9", background="#ebf5fb")
        self.tree.tag_configure('UDP', foreground="#8e44ad", background="#f4ecf7")
        self.tree.tag_configure('ICMP', foreground="#16a085", background="#e8f8f5")
        self.tree.tag_configure('OUTBOUND', foreground="#27ae60")
        self.tree.tag_configure('INBOUND', foreground="#c0392b")

        self.contextMenu = tk.Menu(self.tree, tearoff=0)
        self.contextMenu.add_command(label="📋 Copy Source IP", command=lambda: self.copyFromRow(1))
        self.contextMenu.add_command(label="📋 Copy Destination IP", command=lambda: self.copyFromRow(3))
        self.contextMenu.add_separator()
        self.contextMenu.add_command(label="🔍 View Packet Payload", command=self.viewPayload)
        self.contextMenu.add_command(label=" Block Source IP", command=self.blockSourceIp)
        self.tree.bind("<Button-3>", self.showContextMenu)

    def createAlertsTab(self):
        mainFrame = tk.Frame(self.tabAlerts, bg="white")
        mainFrame.pack(fill="both", expand=True, padx=10, pady=10)

        infoFrame = tk.Frame(mainFrame, bg="#fff3cd", padx=10, pady=8)
        infoFrame.pack(fill="x", pady=(0, 10))
        tk.Label(infoFrame, text="🔔 Real-time Security Alerts & Blocked Connections", 
                font=("Segoe UI", 10, "bold"), bg="#fff3cd", fg="#856404").pack(anchor="w")

        btnFrame = tk.Frame(mainFrame, bg="white")
        btnFrame.pack(fill="x", pady=(0, 5))
        ttk.Button(btnFrame, text="🗑 Clear All Alerts", command=self.clearLogs).pack(side="right")

        self.logList = tk.Listbox(mainFrame, font=("Consolas", 9), bg="#fef5e7", fg="#c0392b", 
                                   borderwidth=1, highlightthickness=0, selectmode="extended")
        self.logList.pack(fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(mainFrame, orient="vertical", command=self.logList.yview)
        self.logList.configure(yscroll=scrollbar.set)

    def createStatsTab(self):
        mainFrame = tk.Frame(self.tabStats, bg="white")
        mainFrame.pack(fill="both", expand=True, padx=10, pady=10)

        statsContainer = tk.Frame(mainFrame, bg="white")
        statsContainer.pack(fill="x", pady=20)

        self.statVars = {}
        statsData = [
            ("Total Packets Captured", "totalPkts", self.cBlue),
            ("Inbound Packets", "inboundPkts", self.cGreen),
            ("Outbound Packets", "outboundPkts", self.cOrange),
            ("Threats Detected", "threats", self.cRed),
            ("Unique Source IPs", "uniqueSrc", "#9b59b6"),
            ("Unique Dest IPs", "uniqueDst", "#1abc9c"),
            ("TCP Packets", "tcpPkts", "#2980b9"),
            ("UDP Packets", "udpPkts", "#8e44ad"),
        ]

        for idx, (label, key, color) in enumerate(statsData):
            self.statVars[key] = tk.StringVar(value="0")
            row = idx // 2
            col = idx % 2
            
            statFrame = tk.Frame(statsContainer, bg="white", padx=20, pady=15)
            statFrame.grid(row=row, column=col, sticky="ew")
            
            tk.Label(statFrame, text=label, font=("Segoe UI", 11, "bold"), bg="white", fg="#2c3e50").pack(anchor="w")
            tk.Label(statFrame, textvariable=self.statVars[key], font=("Segoe UI", 24, "bold"), bg="white", fg=color).pack(anchor="w")

        statsContainer.grid_columnconfigure(0, weight=1)
        statsContainer.grid_columnconfigure(1, weight=1)

    def createBlockedTab(self):
        mainFrame = tk.Frame(self.tabBlocked, bg="white")
        mainFrame.pack(fill="both", expand=True, padx=10, pady=10)

        btnFrame = tk.Frame(mainFrame, bg="white")
        btnFrame.pack(fill="x", pady=(0, 10))
        ttk.Button(btnFrame, text="✖ Unblock Selected", command=self.unblockSelected).pack(side="left", padx=5)
        ttk.Button(btnFrame, text="🔄 Refresh List", command=self.refreshBlockedList).pack(side="left", padx=5)
        ttk.Button(btnFrame, text="🗑 Clear All", command=self.clearBlockedList).pack(side="right", padx=5)

        treeContainer = tk.Frame(mainFrame, bg="white")
        treeContainer.pack(fill="both", expand=True)

        cols = ("IP Address", "Block Date", "Reason", "Status")
        self.blockedTree = ttk.Treeview(treeContainer, columns=cols, show="headings", selectmode="extended", height=20)
        
        vsb = ttk.Scrollbar(treeContainer, orient="vertical", command=self.blockedTree.yview)
        hsb = ttk.Scrollbar(treeContainer, orient="horizontal", command=self.blockedTree.xview)
        self.blockedTree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.blockedTree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        treeContainer.grid_rowconfigure(0, weight=1)
        treeContainer.grid_columnconfigure(0, weight=1)

        for col, width in [("IP Address", 150), ("Block Date", 150), ("Reason", 200), ("Status", 80)]:
            self.blockedTree.heading(col, text=col)
            self.blockedTree.column(col, width=width)

    def onTabChanged(self, event):
        self.refreshStatsDisplay()

    def refreshStatsDisplay(self):
        if hasattr(self, 'statVars'):
            self.statVars['totalPkts'].set(f"{self.statPackets:,}"); self.statVars['inboundPkts'].set(f"{self.statInbound:,}")
            self.statVars['outboundPkts'].set(f"{self.statOutbound:,}"); self.statVars['threats'].set(f"{self.statBlocked}")
            self.statVars['uniqueSrc'].set(f"{len(self.uniqueSrcIps)}"); self.statVars['uniqueDst'].set(f"{len(self.uniqueDstIps)}")
            self.varPkts.set(f"{self.statPackets:,}"); self.varInbound.set(f"{self.statInbound:,}")
            self.varOutbound.set(f"{self.statOutbound:,}"); self.varThreats.set(f"{self.statBlocked}")

    def toggleTheme(self):
        self.darkMode = not self.darkMode
        if self.darkMode:
            self.cBg, self.cDark, panelBg, self.cFg, treeBg, treeFg = "#2c3e50", "#1a252f", "#34495e", "#ecf0f1", "#34495e", "#ecf0f1"
        else:
            self.cBg, self.cDark, panelBg, self.cFg, treeBg, treeFg = "#ecf0f1", "#2c3e50", "white", "#2c3e50", "white", "black"

        self.root.configure(bg=self.cBg)
        style = ttk.Style()
        style.configure("Treeview", background=treeBg, foreground=treeFg, fieldbackground=treeBg)
        style.configure("Treeview.Heading", background=self.cDark, foreground="white")
        self.updateGuiRecursive(self.root, panelBg)

    def updateGuiRecursive(self, widget, panelBg):
        try:
            wtype = widget.winfo_class()
            bg = widget.cget('bg')
            if self.darkMode:
                if bg == "#ecf0f1": widget.configure(bg=self.cBg)
                elif bg == "#2c3e50": widget.configure(bg=self.cDark)
                elif bg in ["white", "#ffffff", "#f0f0f0"]: widget.configure(bg=panelBg)
                if wtype in ['Label', 'Listbox'] and widget.cget('fg') in ["black", "#2c3e50"]: widget.configure(fg=self.cFg)
            else:
                if bg == "#2c3e50": widget.configure(bg=self.cBg)
                elif bg == "#1a252f": widget.configure(bg=self.cDark)
                elif bg == "#34495e": widget.configure(bg=panelBg)
                if wtype in ['Label', 'Listbox'] and widget.cget('fg') in ["white", "#ecf0f1"]: widget.configure(fg=self.cFg)
        except: pass
        for child in widget.winfo_children(): self.updateGuiRecursive(child, panelBg)

    def startSystem(self):
        if self.running: return
        
        # Security: Enforced Administrator Check
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except AttributeError:
            is_admin = os.getuid() == 0

        if not is_admin:
            messagebox.showerror("Permission Denied", 
                "NetGuard-IPS requires Administrative privileges to apply firewall rules and sniff raw packets.\n\n"
                "Please restart the application as Administrator.")
            return

        # Dependency Check
        if not getattr(coreModules, 'SCAPY_AVAILABLE', False):
            messagebox.showerror("Missing Dependency", "Scapy backend not available. Please install Scapy and Npcap.")
            return

        self.running = True
        self.resolver.start()
        self.statusLed.itemconfig(self.ledId, fill=self.cGreen)
        self.varStatus.set("🟢 ACTIVE")
        
        self.detector = coreModules.DetectionEngine(self.pktQueue, self.guiCallback, self.blacklist, self.alerts, analyzeLocal=True)
        self.sniffer = coreModules.PacketCaptureThread(self.pktQueue)
        
        self.detector.start()
        self.sniffer.start()
        messagebox.showinfo("System Started", "Real-time monitoring and firewall enforcement active.")

    def stopSystem(self):
        self.running = False
        self.resolver.stop()
        self.statusLed.itemconfig(self.ledId, fill=self.cRed)
        self.varStatus.set("🔴 STOPPED")
        if self.sniffer: self.sniffer.stop()
        if self.detector: self.detector.stop()
        messagebox.showinfo("System Stopped", "Network monitoring ceased.")

    def guiCallback(self, msgType, data):
        self.root.after(0, lambda: self.handleUpdate(msgType, data))

    def handleUpdate(self, msgType, data):
        timestamp = time.strftime("%H:%M:%S")
        if msgType == "TRAFFIC":
            self.statPackets += 1
            self.varPkts.set(f"{self.statPackets:,}")
            if hasattr(self, 'statVars'): self.statVars['totalPkts'].set(f"{self.statPackets:,}")
            if self.paused.get(): return

            payload = data[7] if len(data) == 8 else ""
            src, dst, proto, size, sport, dport = data[0], data[2], data[3], data[4], data[5], data[6]

            self.uniqueSrcIps.add(src)
            self.uniqueDstIps.add(dst)
            if 'TCP' in proto: self.statTcp += 1
            elif 'UDP' in proto: self.statUdp += 1
            elif 'ICMP' in proto: self.statIcmp += 1
            
            direction = "↗️ OUT" if self.isPrivateIp(src) and not self.isPrivateIp(dst) else ("↙️ IN" if not self.isPrivateIp(src) and self.isPrivateIp(dst) else "↔️ LOCAL")
            if direction == "↗️ OUT": self.statOutbound += 1
            elif direction == "↙️ IN": self.statInbound += 1
            self.refreshStatsDisplay()

            srcHost, dstHost = self.resolver.getHostname(src) if self.showHostnames.get() else src, self.resolver.getHostname(dst) if self.showHostnames.get() else dst
            procName = "-"
            if psutil:
                try:
                    for conn in psutil.net_connections():
                        if conn.laddr.port in [sport, dport]:
                            procName = psutil.Process(conn.pid).name()
                            break
                except: pass

            row = (timestamp, src, srcHost, dst, dstHost, direction, proto, size, procName, payload)
            self.capturedData.append(row)
            self.tree.insert("", 0, values=row, tags=(('TCP' if 'TCP' in proto else ('UDP' if 'UDP' in proto else 'ICMP')), ('OUTBOUND' if '↗️' in direction else 'INBOUND')))
            if len(self.tree.get_children()) > 200: self.tree.delete(self.tree.get_children()[-1])

        elif msgType == "ALERT":
            self.statBlocked += 1
            self.varThreats.set(f"{self.statBlocked}")
            if hasattr(self, 'statVars'): self.statVars['threats'].set(f"{self.statBlocked}")
            msg = f"[{data[3].upper()}] {data[2]} → {data[0]}" if isinstance(data, tuple) else data
            self.logList.insert(0, f"[{timestamp}] {msg}")

    def isPrivateIp(self, ip):
        try:
            p = [int(x) for x in ip.split('.')]
            return p[0] == 10 or (p[0] == 172 and 16 <= p[1] <= 31) or (p[0] == 192 and p[1] == 168) or p[0] == 127
        except: return False

    def filterTraffic(self):
        term = self.filterVar.get().lower()
        self.tree.delete(*self.tree.get_children())
        for r in self.capturedData:
            if not term or any(term in str(v).lower() for v in r):
                self.tree.insert("", "end", values=r, tags=(('TCP' if 'TCP' in r[6] else ('UDP' if 'UDP' in r[6] else 'ICMP')), ('OUTBOUND' if '↗️' in r[5] else 'INBOUND')))

    def clearTable(self):
        self.tree.delete(*self.tree.get_children())
        self.capturedData.clear()
        self.varPkts.set("0")
        self.statPackets = 0

    def clearLogs(self):
        self.logList.delete(0, tk.END)
        self.varThreats.set("0")
        self.statBlocked = 0

    def unblockSelected(self):
        s = self.blockedTree.selection()
        if not s: return
        for i in s:
            v = self.blockedTree.item(i, 'values')
            if v:
                if self.detector: self.detector.unblock_ip(v[0])
                else: 
                    coreModules.FirewallManager.unblockIp(v[0])
                    self.blacklist.delete(v[0])
                self.blockedTree.delete(i)
        messagebox.showinfo("Success", "IP(s) unblocked.")

    def refreshBlockedList(self):
        self.blockedTree.delete(*self.blockedTree.get_children())
        for ip in self.getBlockedIps(): self.blockedTree.insert("", "end", values=(ip, "Active", "Security", "🔒 Blocked"))

    def clearBlockedList(self):
        if messagebox.askyesno("Confirm", "Unblock ALL?"):
            for i in self.blockedTree.get_children():
                v = self.blockedTree.item(i, 'values')
                if v: coreModules.FirewallManager.unblockIp(v[0])
            self.blockedTree.delete(*self.blockedTree.get_children())

    def getBlockedIps(self):
        res = []
        def tr(n):
            if n:
                tr(n.left)
                res.append(n.ip)
                tr(n.right)
        tr(self.blacklist.root)
        return res

    def sortTrafficBySize(self):
        if not self.capturedData: return
        self.capturedData.sort(key=lambda x: int(x[7]), reverse=True)
        self.tree.delete(*self.tree.get_children())
        for r in self.capturedData:
            self.tree.insert("", "end", values=r, tags=(('TCP' if 'TCP' in r[6] else ('UDP' if 'UDP' in r[6] else 'ICMP')), ('OUTBOUND' if '↗️' in r[5] else 'INBOUND')))
        messagebox.showinfo("Sorted", "Traffic sorted by packet size.")

    def exportLogs(self):
        if not self.capturedData: return
        try:
            fn = f"netguard_export_{time.strftime('%Y%m%d_%H%M%S')}.csv"
            with open(fn, 'w') as f:
                f.write("Time,SourceIP,SourceHost,DestIP,DestHost,Direction,Protocol,SizeBytes,Process\n")
                for r in self.capturedData: f.write(",".join(str(v) for v in r) + "\n")
            messagebox.showinfo("Exported", f"Logs saved to {fn}")
        except Exception as e: messagebox.showerror("Error", str(e))

    def simulateAttack(self):
        ip = f"10.50.1.{random.randint(10,99)}"
        self.guiCallback("ALERT", f"[HIGH] Simulated SYN Flood Detected: {ip}")

    def showContextMenu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.contextMenu.post(event.x_root, event.y_root)

    def copyFromRow(self, col):
        s = self.tree.selection()
        if s:
            val = self.tree.item(s[0])['values'][col]
            self.root.clipboard_clear()
            self.root.clipboard_append(val)

    def blockSourceIp(self):
        s = self.tree.selection()
        if s:
            ip = self.tree.item(s[0])['values'][1]
            try:
                coreModules.FirewallManager.blockIp(ip)
                self.guiCallback("ALERT", (ip, "Manual", "Admin Manual Block", "HIGH"))
            except Exception as e: messagebox.showerror("Error", str(e))

    def viewPayload(self):
        s = self.tree.selection()
        if s:
            v = self.tree.item(s[0])['values']
            if len(v) > 9: self.showPayloadWindow(v[9])

    def showPayloadWindow(self, p):
        top = tk.Toplevel(self.root)
        top.title("Payload Viewer")
        top.geometry("600x400")
        def save():
            path = filedialog.asksaveasfilename(defaultextension=".txt")
            if path:
                with open(path, "w") as f: f.write(p)
        ttk.Button(top, text="💾 Save", command=save).pack(pady=5)
        txt = tk.Text(top, font=("Consolas", 10))
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", p)
        txt.configure(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = ProfessionalIPS_GUI(root)
    root.mainloop()