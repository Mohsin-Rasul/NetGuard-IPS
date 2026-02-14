import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import queue
import time
import random
import sys
import os
import threading

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
        self.resolver = HostnameResolver(max_cache_size=2000, timeout=3.0)
        
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
        verLbl = tk.Label(headerFrame, text="v2.1 (Stable)", font=("Segoe UI", 10), bg=self.cDark, fg="#bdc3c7")
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
        """Create tabbed interface with multiple views"""
        # Main Notebook (Tab Container)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Bind tab change event to refresh stats
        notebook.bind("<<NotebookTabChanged>>", self.onTabChanged)

        # --- TAB 1: LIVE TRAFFIC ---
        self.tabTraffic = ttk.Frame(notebook)
        notebook.add(self.tabTraffic, text="🌐 Live Traffic Monitor")
        self.createTrafficTab()

        # --- TAB 2: SECURITY ALERTS ---
        self.tabAlerts = ttk.Frame(notebook)
        notebook.add(self.tabAlerts, text="⚠️ Security Alerts")
        self.createAlertsTab()

        # --- TAB 3: STATISTICS ---
        self.tabStats = ttk.Frame(notebook)
        notebook.add(self.tabStats, text="📊 Statistics & Analysis")
        self.createStatsTab()

        # --- TAB 4: BLOCKED IPs ---
        self.tabBlocked = ttk.Frame(notebook)
        notebook.add(self.tabBlocked, text="🚫 Blocked IPs")
        self.createBlockedTab()

    def createTrafficTab(self):
        """Live network traffic table with bidirectional arrows"""
        mainFrame = tk.Frame(self.tabTraffic, bg="white")
        mainFrame.pack(fill="both", expand=True, padx=10, pady=10)

        # Search/Filter Bar
        searchFrame = tk.Frame(mainFrame, bg="#f0f0f0", height=40)
        searchFrame.pack(fill="x", pady=(0, 10))
        
        tk.Label(searchFrame, text="Filter:", bg="#f0f0f0", font=("Segoe UI", 9)).pack(side="left", padx=5)
        self.filterVar = tk.StringVar()
        self.filterVar.trace_add("write", lambda *args: self.filterTraffic())
        filterEntry = tk.Entry(searchFrame, textvariable=self.filterVar, width=30, font=("Segoe UI", 9))
        filterEntry.pack(side="left", padx=5)
        
        ttk.Button(searchFrame, text="🔍 Clear Filter", command=lambda: self.filterVar.set("")).pack(side="left", padx=5)

        # Create container frame for table and scrollbars (use grid inside)
        treeContainer = tk.Frame(mainFrame, bg="white")
        treeContainer.pack(fill="both", expand=True)

        # Traffic Table with Hostname columns
        cols = ("Time", "SrcIP", "SrcHost", "DstIP", "DstHost", "Direction", "Protocol", "Size", "Process", "Payload")
        self.tree = ttk.Treeview(treeContainer, columns=cols, show="headings", selectmode="extended", height=25)
        self.tree["displaycolumns"] = ("Time", "SrcIP", "SrcHost", "DstIP", "DstHost", "Direction", "Protocol", "Size", "Process")
        
        # Scrollbars
        vsb = ttk.Scrollbar(treeContainer, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(treeContainer, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        treeContainer.grid_rowconfigure(0, weight=1)
        treeContainer.grid_columnconfigure(0, weight=1)

        # Configure Columns
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

        # Row Colors based on protocol
        self.tree.tag_configure('TCP', foreground="#2980b9", background="#ebf5fb")
        self.tree.tag_configure('UDP', foreground="#8e44ad", background="#f4ecf7")
        self.tree.tag_configure('ICMP', foreground="#16a085", background="#e8f8f5")
        self.tree.tag_configure('OUTBOUND', foreground="#27ae60")
        self.tree.tag_configure('INBOUND', foreground="#c0392b")

        # Context Menu
        self.contextMenu = tk.Menu(self.tree, tearoff=0)
        self.contextMenu.add_command(label="📋 Copy Source IP", command=lambda: self.copyFromRow(1))
        self.contextMenu.add_command(label="📋 Copy Destination IP", command=lambda: self.copyFromRow(3))
        self.contextMenu.add_separator()
        self.contextMenu.add_command(label="🔍 View Packet Payload", command=self.viewPayload)
        self.contextMenu.add_command(label=" Block Source IP", command=self.blockSourceIp)
        self.tree.bind("<Button-3>", self.showContextMenu)

    def createAlertsTab(self):
        """Security alerts and threat log"""
        mainFrame = tk.Frame(self.tabAlerts, bg="white")
        mainFrame.pack(fill="both", expand=True, padx=10, pady=10)

        # Alert Info Bar
        infoFrame = tk.Frame(mainFrame, bg="#fff3cd", padx=10, pady=8)
        infoFrame.pack(fill="x", pady=(0, 10))
        tk.Label(infoFrame, text="🔔 Real-time Security Alerts & Blocked Connections", 
                font=("Segoe UI", 10, "bold"), bg="#fff3cd", fg="#856404").pack(anchor="w")

        # Clear button
        btnFrame = tk.Frame(mainFrame, bg="white")
        btnFrame.pack(fill="x", pady=(0, 5))
        ttk.Button(btnFrame, text="🗑 Clear All Alerts", command=self.clearLogs).pack(side="right")

        # Alert Listbox with colors
        self.logList = tk.Listbox(mainFrame, font=("Consolas", 9), bg="#fef5e7", fg="#c0392b", 
                                   borderwidth=1, highlightthickness=0, selectmode="extended")
        self.logList.pack(fill="both", expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(mainFrame, orient="vertical", command=self.logList.yview)
        self.logList.configure(yscroll=scrollbar.set)

    def createStatsTab(self):
        """Statistics and analysis view"""
        mainFrame = tk.Frame(self.tabStats, bg="white")
        mainFrame.pack(fill="both", expand=True, padx=10, pady=10)

        # Stats Grid with proper container
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
        """Blocked IPs management"""
        mainFrame = tk.Frame(self.tabBlocked, bg="white")
        mainFrame.pack(fill="both", expand=True, padx=10, pady=10)

        # Action buttons
        btnFrame = tk.Frame(mainFrame, bg="white")
        btnFrame.pack(fill="x", pady=(0, 10))
        ttk.Button(btnFrame, text="✖ Unblock Selected", command=self.unblockSelected).pack(side="left", padx=5)
        ttk.Button(btnFrame, text="🔄 Refresh List", command=self.refreshBlockedList).pack(side="left", padx=5)
        ttk.Button(btnFrame, text="🗑 Clear All", command=self.clearBlockedList).pack(side="right", padx=5)

        # Create container for tree and scrollbars
        treeContainer = tk.Frame(mainFrame, bg="white")
        treeContainer.pack(fill="both", expand=True)

        # Blocked IPs List
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

    # --- Logic ---

    def onTabChanged(self, event):
        """Refresh stats when stats tab is selected"""
        self.refreshStatsDisplay()

    def refreshStatsDisplay(self):
        """Update stats display values"""
        if hasattr(self, 'statVars'):
            self.statVars['totalPkts'].set(f"{self.statPackets:,}")
            self.statVars['inboundPkts'].set(f"{self.statInbound:,}")
            self.statVars['outboundPkts'].set(f"{self.statOutbound:,}")
            self.statVars['threats'].set(f"{self.statBlocked}")
            self.statVars['uniqueSrc'].set(f"{len(self.uniqueSrcIps)}")
            self.statVars['uniqueDst'].set(f"{len(self.uniqueDstIps)}")
            if 'tcpPkts' in self.statVars:
                self.statVars['tcpPkts'].set(f"{self.statTcp:,}")
                self.statVars['udpPkts'].set(f"{self.statUdp:,}")

    def toggleTheme(self):
        self.darkMode = not self.darkMode
        
        # Define Colors
        if self.darkMode:
            self.cBg = "#2c3e50"
            self.cDark = "#1a252f"
            panelBg = "#34495e"
            self.cFg = "#ecf0f1"
            treeBg = "#34495e"
            treeFg = "#ecf0f1"
        else:
            self.cBg = "#ecf0f1"
            self.cDark = "#2c3e50"
            panelBg = "white"
            self.cFg = "#2c3e50"
            treeBg = "white"
            treeFg = "black"

        # Apply to Root
        self.root.configure(bg=self.cBg)
        
        # Apply to Styles
        style = ttk.Style()
        style.configure("Treeview", background=treeBg, foreground=treeFg, fieldbackground=treeBg)
        style.configure("Treeview.Heading", background=self.cDark, foreground="white")
        
        # Recursive Update
        self.updateGuiRecursive(self.root, panelBg)

    def updateGuiRecursive(self, widget, panelBg):
        try:
            wtype = widget.winfo_class()
            bg = widget.cget('bg')
            
            if self.darkMode:
                # Switching TO Dark
                if bg == "#ecf0f1": widget.configure(bg=self.cBg)
                elif bg == "#2c3e50": widget.configure(bg=self.cDark)
                elif bg in ["white", "#ffffff", "#f0f0f0"]: widget.configure(bg=panelBg)
                if wtype in ['Label', 'Listbox'] and widget.cget('fg') in ["black", "#2c3e50"]:
                    widget.configure(fg=self.cFg)
            else:
                # Switching TO Light
                if bg == "#2c3e50": widget.configure(bg=self.cBg)
                elif bg == "#1a252f": widget.configure(bg=self.cDark)
                elif bg == "#34495e": widget.configure(bg=panelBg)
                if wtype in ['Label', 'Listbox'] and widget.cget('fg') in ["white", "#ecf0f1"]:
                    widget.configure(fg=self.cFg)
        except: pass
        
        for child in widget.winfo_children():
            self.updateGuiRecursive(child, panelBg)

    def startSystem(self):
        if self.running: return
        self.running = True
        
        # Verify packet capture backend (Scapy) is available
        if not getattr(coreModules, 'SCAPY_AVAILABLE', False):
            messagebox.showerror("Missing Dependency", (
                "Scapy (packet capture backend) is not installed or not available.\n\n"
                "Please install Scapy and Npcap (on Windows) or libpcap (on Unix).\n"
                "Windows: install Npcap from https://nmap.org/npcap/ and enable 'WinPcap API-compatible' during install.\n"
                "Then install Scapy in your Python environment: run 'pip install scapy' and restart this application."))
            self.running = False
            return

        # Start hostname resolver
        self.resolver.start()
        
        # UI Updates
        self.statusLed.itemconfig(self.ledId, fill=self.cGreen) # Turn Green
        self.varStatus.set("🟢 ACTIVE")
        
        # Init Backend
        self.detector = coreModules.DetectionEngine(
            self.pktQueue, self.guiCallback, self.blacklist, self.alerts, analyzeLocal=True
        )
        self.sniffer = coreModules.PacketCaptureThread(self.pktQueue)
        
        self.detector.start()
        self.sniffer.start()
        
        messagebox.showinfo("System Started", "Network monitoring started. Capturing live traffic...")

    def stopSystem(self):
        self.running = False
        
        # Stop resolver
        self.resolver.stop()
        
        # UI Updates
        self.statusLed.itemconfig(self.ledId, fill=self.cRed) # Turn Red
        self.varStatus.set("🔴 STOPPED")
        
        if self.sniffer: self.sniffer.stop()
        if self.detector: self.detector.stop()
        
        messagebox.showinfo("System Stopped", "Network monitoring stopped.")

    def guiCallback(self, msgType, data):
        # Thread-safe GUI update
        self.root.after(0, lambda: self.handleUpdate(msgType, data))

    def handleUpdate(self, msgType, data):
        timestamp = time.strftime("%H:%M:%S")

        if msgType == "TRAFFIC":
            self.statPackets += 1
            self.varPkts.set(f"{self.statPackets:,}")
            
            # Update stats tab total packets
            if hasattr(self, 'statVars'):
                self.statVars['totalPkts'].set(f"{self.statPackets:,}")

            if self.paused.get(): return # Skip table update if paused

            # Handle 6, 7, or 8 items (Compatibility Mode)
            payload = ""
            if len(data) == 8:
                src, _, dst, proto, size, sport, dport, payload = data
            elif len(data) == 7:
                src, _, dst, proto, size, sport, dport = data
            else:
                src, dst, proto, size, sport, dport = data

            # Track unique IPs
            self.uniqueSrcIps.add(src)
            self.uniqueDstIps.add(dst)
            if hasattr(self, 'statVars'):
                self.statVars['uniqueSrc'].set(f"{len(self.uniqueSrcIps)}")
                self.statVars['uniqueDst'].set(f"{len(self.uniqueDstIps)}")

            # Update Protocol Stats
            if 'TCP' in proto: self.statTcp += 1
            elif 'UDP' in proto: self.statUdp += 1
            elif 'ICMP' in proto: self.statIcmp += 1
            self.refreshStatsDisplay()

            # Determine traffic direction (basic heuristic)
            isSrcPrivate = self.isPrivateIp(src)
            isDstPrivate = self.isPrivateIp(dst)
            
            if isSrcPrivate and not isDstPrivate:
                direction = "↗️ OUT"
                self.statOutbound += 1
                self.varOutbound.set(f"{self.statOutbound:,}")
                if hasattr(self, 'statVars'):
                    self.statVars['outboundPkts'].set(f"{self.statOutbound:,}")
            elif not isSrcPrivate and isDstPrivate:
                direction = "↙️ IN"
                self.statInbound += 1
                self.varInbound.set(f"{self.statInbound:,}")
                if hasattr(self, 'statVars'):
                    self.statVars['inboundPkts'].set(f"{self.statInbound:,}")
            else:
                direction = "↔️ LOCAL"

            # Get Hostnames (with fallback to IP)
            srcHost = self.resolver.get_hostname(src) if self.showHostnames.get() else src
            dstHost = self.resolver.get_hostname(dst) if self.showHostnames.get() else dst

            # Get Process Name
            procName = "-"
            if psutil:
                try:
                    for conn in psutil.net_connections():
                        if conn.laddr.port == sport or conn.laddr.port == dport:
                            procName = psutil.Process(conn.pid).name()
                            break
                except: pass

            row = (timestamp, src, srcHost, dst, dstHost, direction, proto, size, procName, payload)
            self.capturedData.append(row)

            # Insert into table
            tagProto = 'TCP' if 'TCP' in proto else ('UDP' if 'UDP' in proto else 'ICMP')
            tagDir = 'OUTBOUND' if '↗️' in direction else ('INBOUND' if '↙️' in direction else '')
            self.tree.insert("", 0, values=row, tags=(tagProto, tagDir))
            
            # Buffer Management (Keep list manageable)
            if len(self.tree.get_children()) > 200:
                self.tree.delete(self.tree.get_children()[-1])

        elif msgType == "ALERT":
            self.statBlocked += 1
            self.varThreats.set(f"{self.statBlocked}")
            
            # Update stats tab threats
            if hasattr(self, 'statVars'):
                self.statVars['threats'].set(f"{self.statBlocked}")

            # Handle formats
            if isinstance(data, tuple):
                src, _, reason, severity = data
                msg = f"[{severity.upper()}] {reason} → {src}"
            else:
                msg = data
            
            self.logList.insert(0, f"[{timestamp}] {msg}")

    def isPrivateIp(self, ipAddress):
        """Check if IP is in private ranges"""
        try:
            parts = [int(x) for x in ipAddress.split('.')]
            if parts[0] == 10: return True
            if parts[0] == 172 and 16 <= parts[1] <= 31: return True
            if parts[0] == 192 and parts[1] == 168: return True
            if parts[0] == 127: return True
            if parts[0] == 169 and parts[1] == 254: return True
            return False
        except:
            return False

    def filterTraffic(self):
        """Filter table by search term"""
        searchTerm = self.filterVar.get().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for row in self.capturedData:
            if not searchTerm or any(searchTerm in str(val).lower() for val in row):
                tagProto = 'TCP' if 'TCP' in row[6] else ('UDP' if 'UDP' in row[6] else 'ICMP')
                tagDir = 'OUTBOUND' if '↗️' in row[5] else ('INBOUND' if '↙️' in row[5] else '')
                self.tree.insert("", "end", values=row, tags=(tagProto, tagDir))

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
        selected = self.blockedTree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select IPs to unblock.")
            return
        
        for item in selected:
            values = self.blockedTree.item(item, 'values')
            if values:
                ipToUnblock = values[0]
                if self.detector:
                    self.detector.unblock_ip(ipToUnblock)
                else:
                    coreModules.FirewallManager.unblock_ip(ipToUnblock)
                    self.blacklist.delete(ipToUnblock)
                self.blockedTree.delete(item)
        
        messagebox.showinfo("Success", f"Unblocked {len(selected)} IP(s)")

    def refreshBlockedList(self):
        """Refresh the blocked IPs list"""
        self.blockedTree.delete(*self.blockedTree.get_children())
        for ip in self.getBlockedIps():
            self.blockedTree.insert("", "end", values=(ip, "N/A", "Security", "🔒 Active"))

    def clearBlockedList(self):
        """Clear all blocked IPs"""
        if messagebox.askyesno("Confirm", "Unblock ALL IPs?"):
            for item in self.blockedTree.get_children():
                values = self.blockedTree.item(item, 'values')
                if values:
                    coreModules.FirewallManager.unblock_ip(values[0])
            self.blockedTree.delete(*self.blockedTree.get_children())

    def getBlockedIps(self):
        """Extract blocked IPs from BST (traverse in-order)"""
        result = []
        def traverse(node):
            if node is None:
                return
            traverse(node.left)
            result.append(node.ip)
            traverse(node.right)
        traverse(self.blacklist.root)
        return result

    def sortTrafficBySize(self):
        """Sort data using built-in Timsort for efficiency"""
        if not self.capturedData:
            return
        
        self.capturedData.sort(key=lambda x: int(x[7]), reverse=True)
        
        self.tree.delete(*self.tree.get_children())
        for row in self.capturedData:
            tagProto = 'TCP' if 'TCP' in row[6] else ('UDP' if 'UDP' in row[6] else 'ICMP')
            tagDir = 'OUTBOUND' if '↗️' in row[5] else ('INBOUND' if '↙️' in row[5] else '')
            self.tree.insert("", "end", values=row, tags=(tagProto, tagDir))
        
        messagebox.showinfo("Sorted", f"Sorted {len(self.capturedData)} packets by Size.")

    def exportLogs(self):
        """Export current traffic data to CSV"""
        if not self.capturedData:
            messagebox.showwarning("No Data", "No traffic captured yet.")
            return
        
        try:
            filename = f"netguard_export_{time.strftime('%Y%m%d_%H%M%S')}.csv"
            with open(filename, 'w') as f:
                f.write("Time,SourceIP,SourceHost,DestIP,DestHost,Direction,Protocol,SizeBytes,Process\n")
                for row in self.capturedData:
                    f.write(",".join(str(v) for v in row) + "\n")
            
            messagebox.showinfo("Export Successful", f"Data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def simulateAttack(self):
        ip = f"10.50.1.{random.randint(10,99)}"
        self.guiCallback("ALERT", f"[HIGH] Blocked {ip}: Simulated SYN Flood Attack Detected")

    # --- Context Menu Helpers ---
    def showContextMenu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.contextMenu.post(event.x_root, event.y_root)

    def copyFromRow(self, colIndex):
        selected = self.tree.selection()
        if selected:
            val = self.tree.item(selected[0])['values'][colIndex]
            self.root.clipboard_clear()
            self.root.clipboard_append(val)
            messagebox.showinfo("Copied", f"Copied to clipboard: {val}")

    def blockSourceIp(self):
        selected = self.tree.selection()
        if selected:
            srcIp = self.tree.item(selected[0])['values'][1]
            try:
                coreModules.FirewallManager.block_ip(srcIp)
                self.guiCallback("ALERT", (srcIp, None, "Manual Block via Context Menu", "HIGH"))
                messagebox.showinfo("Blocked", f"IP {srcIp} has been blocked.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not block IP: {e}")

    def viewPayload(self):
        selected = self.tree.selection()
        if selected:
            vals = self.tree.item(selected[0])['values']
            if len(vals) > 9:
                payload = vals[9]
                self.showPayloadWindow(payload)
            else:
                messagebox.showinfo("Info", "No payload captured for this packet.")

    def showPayloadWindow(self, payload):
        top = tk.Toplevel(self.root)
        top.title("Packet Payload Viewer")
        top.geometry("600x400")
        
        toolbar = tk.Frame(top)
        toolbar.pack(fill="x", side="top", padx=5, pady=5)
        
        def savePayload():
            path = filedialog.asksaveasfilename(parent=top, defaultextension=".txt",
                                              filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
            if path:
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(payload)
                    messagebox.showinfo("Saved", f"Payload saved to {path}", parent=top)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save: {e}", parent=top)

        ttk.Button(toolbar, text="💾 Save to File", command=savePayload).pack(side="left")
        
        txt = tk.Text(top, font=("Consolas", 10), wrap="word")
        txt.pack(fill="both", expand=True)
        scroll = ttk.Scrollbar(txt, command=txt.yview)
        txt.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        
        txt.insert("1.0", payload)
        txt.configure(state="disabled")

if __name__ == "__main__":
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    root = tk.Tk()
    if not is_admin:
        messagebox.showwarning("Admin Privileges Required", 
            "⚠️ Application is not running as Administrator.\n\n"
            "Some features will not work:\n"
            "• IP Blocking may fail\n"
            "• Low-level packet capture may be limited\n\n"
            "Please run as Administrator for full functionality.")
    
    app = ProfessionalIPS_GUI(root)
    root.mainloop()
    
    if app.resolver:
        app.resolver.stop()