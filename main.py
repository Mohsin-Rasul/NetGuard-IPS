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
import data_structures
import core_modules
from hostname_resolver import HostnameResolver

class ProfessionalIPS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetGuard-IPS | Advanced Network Security Monitor")
        self.root.geometry("1400x900")
        self.root.configure(bg="#ecf0f1") 

        # --- Data Structures & Logic ---
        self.blacklist = data_structures.BlacklistBST()
        self.alerts = data_structures.AlertStack()
        self.graph = data_structures.NetworkGraph()
        self.pktqueue = queue.Queue()
        self.captureddata = []
        
        self.sniffer = None
        self.detector = None
        self.running = False
        
        # Hostname Resolver
        self.resolver = HostnameResolver(max_cache_size=2000, timeout=3.0)
        
        # GUI State
        self.paused = tk.BooleanVar(value=False)
        self.show_hostnames = tk.BooleanVar(value=True)
        self.stat_packets = 0
        self.stat_blocked = 0
        self.stat_alerts = 0
        self.stat_inbound = 0
        self.stat_outbound = 0
        self.stat_tcp = 0
        self.stat_udp = 0
        self.stat_icmp = 0
        self.unique_src_ips = set()
        self.unique_dst_ips = set()
        self.dark_mode = False

        # --- Build UI ---
        self.setup_styles()
        self.create_header()
        self.create_kpi_board()
        self.create_controls()
        self.create_notebook()  # Tab-based interface

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Modern Colors
        self.c_bg = "#ecf0f1"
        self.c_dark = "#2c3e50"
        self.c_blue = "#3498db"
        self.c_red = "#e74c3c"
        self.c_green = "#2ecc71"
        self.c_orange = "#f39c12"

        # Treeview formatting
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#bdc3c7", foreground=self.c_dark)
        style.configure("Treeview", font=("Consolas", 10), rowheight=25, background="white")
        style.map("Treeview", background=[('selected', self.c_blue)])

        # Button Styling
        style.configure("TButton", font=("Segoe UI", 9))
        style.configure("Action.TButton", font=("Segoe UI", 9, "bold"))

    def create_header(self):
        # Top Header Bar
        header_frame = tk.Frame(self.root, bg=self.c_dark, height=60, padx=20, pady=10)
        header_frame.pack(fill="x")
        
        # Status LED (Canvas)
        self.status_led = tk.Canvas(header_frame, width=20, height=20, bg=self.c_dark, highlightthickness=0)
        self.status_led.pack(side="left", padx=(0, 10))
        self.led_id = self.status_led.create_oval(2, 2, 18, 18, fill="#95a5a6", outline="") # Grey initially
        
        # Title
        title_lbl = tk.Label(header_frame, text="NetGuard Security Monitor", font=("Segoe UI", 18, "bold"), bg=self.c_dark, fg="white")
        title_lbl.pack(side="left")

        # Version Info
        ver_lbl = tk.Label(header_frame, text="v2.1 (Stable)", font=("Segoe UI", 10), bg=self.c_dark, fg="#bdc3c7")
        ver_lbl.pack(side="right", anchor="s", pady=5)

    def create_kpi_board(self):
        # Key Performance Indicators (Stats)
        kpi_frame = tk.Frame(self.root, bg=self.c_bg, padx=20, pady=10)
        kpi_frame.pack(fill="x")

        self.var_pkts = tk.StringVar(value="0")
        self.var_threats = tk.StringVar(value="0")
        self.var_status = tk.StringVar(value="STOPPED")
        self.var_inbound = tk.StringVar(value="0")
        self.var_outbound = tk.StringVar(value="0")

        # Helper to create a stat card
        def draw_card(parent, label, var, color):
            card = tk.Frame(parent, bg="white", highlightbackground="#bdc3c7", highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=5)
            
            tk.Label(card, text=label, font=("Segoe UI", 9, "bold"), fg="#7f8c8d", bg="white").pack(pady=(10, 5))
            tk.Label(card, textvariable=var, font=("Segoe UI", 20, "bold"), fg=color, bg="white").pack(pady=(0, 10))

        draw_card(kpi_frame, "SYSTEM STATUS", self.var_status, self.c_dark)
        draw_card(kpi_frame, "PACKETS ANALYZED", self.var_pkts, self.c_blue)
        draw_card(kpi_frame, "INBOUND TRAFFIC", self.var_inbound, self.c_green)
        draw_card(kpi_frame, "OUTBOUND TRAFFIC", self.var_outbound, self.c_orange)
        draw_card(kpi_frame, "THREATS BLOCKED", self.var_threats, self.c_red)

    def create_controls(self):
        # Toolbar for buttons
        toolbar = tk.Frame(self.root, bg=self.c_bg, padx=20, pady=5)
        toolbar.pack(fill="x")

        # Left: Main Actions
        ttk.Button(toolbar, text="▶ START MONITORING", style="Action.TButton", command=self.start_system).pack(side="left", padx=2)
        ttk.Button(toolbar, text="⏹ STOP SYSTEM", style="Action.TButton", command=self.stop_system).pack(side="left", padx=2)
        
        # Separator
        ttk.Label(toolbar, text="  |  ", background=self.c_bg).pack(side="left")

        # Middle: View Controls
        ttk.Checkbutton(toolbar, text="🔒 Pause Live View", variable=self.paused).pack(side="left", padx=10)
        ttk.Checkbutton(toolbar, text="📍 Show Hostnames", variable=self.show_hostnames).pack(side="left", padx=10)
        ttk.Button(toolbar, text="🗑 Clear Table", command=self.clear_table).pack(side="left", padx=2)
        ttk.Button(toolbar, text="⬇ Sort by Size", command=self.bubblesort).pack(side="left", padx=2)

        # Right: Simulation & Export
        ttk.Button(toolbar, text="⚠ Simulate Attack", command=self.simulate_attack).pack(side="right", padx=2)
        ttk.Button(toolbar, text="💾 Export Logs", command=self.export_logs).pack(side="right", padx=2)
        ttk.Button(toolbar, text="🌓 Theme", command=self.toggle_theme).pack(side="right", padx=2)

    def create_notebook(self):
        """Create tabbed interface with multiple views"""
        # Main Notebook (Tab Container)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Bind tab change event to refresh stats
        notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

        # --- TAB 1: LIVE TRAFFIC ---
        self.tab_traffic = ttk.Frame(notebook)
        notebook.add(self.tab_traffic, text="🌐 Live Traffic Monitor")
        self.create_traffic_tab()

        # --- TAB 2: SECURITY ALERTS ---
        self.tab_alerts = ttk.Frame(notebook)
        notebook.add(self.tab_alerts, text="⚠️ Security Alerts")
        self.create_alerts_tab()

        # --- TAB 3: STATISTICS ---
        self.tab_stats = ttk.Frame(notebook)
        notebook.add(self.tab_stats, text="📊 Statistics & Analysis")
        self.create_stats_tab()

        # --- TAB 4: BLOCKED IPs ---
        self.tab_blocked = ttk.Frame(notebook)
        notebook.add(self.tab_blocked, text="🚫 Blocked IPs")
        self.create_blocked_tab()

    def create_traffic_tab(self):
        """Live network traffic table with bidirectional arrows"""
        main_frame = tk.Frame(self.tab_traffic, bg="white")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Search/Filter Bar
        search_frame = tk.Frame(main_frame, bg="#f0f0f0", height=40)
        search_frame.pack(fill="x", pady=(0, 10))
        
        tk.Label(search_frame, text="Filter:", bg="#f0f0f0", font=("Segoe UI", 9)).pack(side="left", padx=5)
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *args: self.filter_traffic())
        filter_entry = tk.Entry(search_frame, textvariable=self.filter_var, width=30, font=("Segoe UI", 9))
        filter_entry.pack(side="left", padx=5)
        
        ttk.Button(search_frame, text="🔍 Clear Filter", command=lambda: self.filter_var.set("")).pack(side="left", padx=5)

        # Create container frame for table and scrollbars (use grid inside)
        tree_container = tk.Frame(main_frame, bg="white")
        tree_container.pack(fill="both", expand=True)

        # Traffic Table with Hostname columns
        cols = ("Time", "SrcIP", "SrcHost", "DstIP", "DstHost", "Direction", "Protocol", "Size", "Process", "Payload")
        self.tree = ttk.Treeview(tree_container, columns=cols, show="headings", selectmode="extended", height=25)
        self.tree["displaycolumns"] = ("Time", "SrcIP", "SrcHost", "DstIP", "DstHost", "Direction", "Protocol", "Size", "Process")
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)

        # Configure Columns
        columns_config = [
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
        
        for col, width, anchor in columns_config:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor=anchor)

        # Row Colors based on protocol
        self.tree.tag_configure('TCP', foreground="#2980b9", background="#ebf5fb")
        self.tree.tag_configure('UDP', foreground="#8e44ad", background="#f4ecf7")
        self.tree.tag_configure('ICMP', foreground="#16a085", background="#e8f8f5")
        self.tree.tag_configure('OUTBOUND', foreground="#27ae60")
        self.tree.tag_configure('INBOUND', foreground="#c0392b")

        # Context Menu
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="📋 Copy Source IP", command=lambda: self.copy_from_row(1))
        self.context_menu.add_command(label="📋 Copy Destination IP", command=lambda: self.copy_from_row(3))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🔍 View Packet Payload", command=self.view_payload)
        self.context_menu.add_command(label=" Block Source IP", command=self.block_source_ip)
        self.tree.bind("<Button-3>", self.show_context_menu)

    def create_alerts_tab(self):
        """Security alerts and threat log"""
        main_frame = tk.Frame(self.tab_alerts, bg="white")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Alert Info Bar
        info_frame = tk.Frame(main_frame, bg="#fff3cd", padx=10, pady=8)
        info_frame.pack(fill="x", pady=(0, 10))
        tk.Label(info_frame, text="🔔 Real-time Security Alerts & Blocked Connections", 
                font=("Segoe UI", 10, "bold"), bg="#fff3cd", fg="#856404").pack(anchor="w")

        # Clear button
        btn_frame = tk.Frame(main_frame, bg="white")
        btn_frame.pack(fill="x", pady=(0, 5))
        ttk.Button(btn_frame, text="🗑 Clear All Alerts", command=self.clear_logs).pack(side="right")

        # Alert Listbox with colors
        self.log_list = tk.Listbox(main_frame, font=("Consolas", 9), bg="#fef5e7", fg="#c0392b", 
                                   borderwidth=1, highlightthickness=0, selectmode="extended")
        self.log_list.pack(fill="both", expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.log_list.yview)
        self.log_list.configure(yscroll=scrollbar.set)

    def create_stats_tab(self):
        """Statistics and analysis view"""
        main_frame = tk.Frame(self.tab_stats, bg="white")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Stats Grid with proper container
        stats_container = tk.Frame(main_frame, bg="white")
        stats_container.pack(fill="x", pady=20)

        self.stat_vars = {}
        stats_data = [
            ("Total Packets Captured", "total_pkts", self.c_blue),
            ("Inbound Packets", "inbound_pkts", self.c_green),
            ("Outbound Packets", "outbound_pkts", self.c_orange),
            ("Threats Detected", "threats", self.c_red),
            ("Unique Source IPs", "unique_src", "#9b59b6"),
            ("Unique Dest IPs", "unique_dst", "#1abc9c"),
            ("TCP Packets", "tcp_pkts", "#2980b9"),
            ("UDP Packets", "udp_pkts", "#8e44ad"),
        ]

        for idx, (label, key, color) in enumerate(stats_data):
            self.stat_vars[key] = tk.StringVar(value="0")
            row = idx // 2
            col = idx % 2
            
            stat_frame = tk.Frame(stats_container, bg="white", padx=20, pady=15)
            stat_frame.grid(row=row, column=col, sticky="ew")
            
            tk.Label(stat_frame, text=label, font=("Segoe UI", 11, "bold"), bg="white", fg="#2c3e50").pack(anchor="w")
            tk.Label(stat_frame, textvariable=self.stat_vars[key], font=("Segoe UI", 24, "bold"), bg="white", fg=color).pack(anchor="w")

        stats_container.grid_columnconfigure(0, weight=1)
        stats_container.grid_columnconfigure(1, weight=1)

    def create_blocked_tab(self):
        """Blocked IPs management"""
        main_frame = tk.Frame(self.tab_blocked, bg="white")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Action buttons
        btn_frame = tk.Frame(main_frame, bg="white")
        btn_frame.pack(fill="x", pady=(0, 10))
        ttk.Button(btn_frame, text="✖ Unblock Selected", command=self.unblock_selected).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🔄 Refresh List", command=self.refresh_blocked_list).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🗑 Clear All", command=self.clear_blocked_list).pack(side="right", padx=5)

        # Create container for tree and scrollbars
        tree_container = tk.Frame(main_frame, bg="white")
        tree_container.pack(fill="both", expand=True)

        # Blocked IPs List
        cols = ("IP Address", "Block Date", "Reason", "Status")
        self.blocked_tree = ttk.Treeview(tree_container, columns=cols, show="headings", selectmode="extended", height=20)
        
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=self.blocked_tree.yview)
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=self.blocked_tree.xview)
        self.blocked_tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.blocked_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)

        for col, width in [("IP Address", 150), ("Block Date", 150), ("Reason", 200), ("Status", 80)]:
            self.blocked_tree.heading(col, text=col)
            self.blocked_tree.column(col, width=width)

    def create_split_view(self):
        """Legacy method - replaced by create_notebook"""
        pass


    # --- Logic ---

    def on_tab_changed(self, event):
        """Refresh stats when stats tab is selected"""
        self.refresh_stats_display()

    def refresh_stats_display(self):
        """Update stats display values"""
        if hasattr(self, 'stat_vars'):
            self.stat_vars['total_pkts'].set(f"{self.stat_packets:,}")
            self.stat_vars['inbound_pkts'].set(f"{self.stat_inbound:,}")
            self.stat_vars['outbound_pkts'].set(f"{self.stat_outbound:,}")
            self.stat_vars['threats'].set(f"{self.stat_blocked}")
            self.stat_vars['unique_src'].set(f"{len(self.unique_src_ips)}")
            self.stat_vars['unique_dst'].set(f"{len(self.unique_dst_ips)}")
            if 'tcp_pkts' in self.stat_vars:
                self.stat_vars['tcp_pkts'].set(f"{self.stat_tcp:,}")
                self.stat_vars['udp_pkts'].set(f"{self.stat_udp:,}")

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        
        # Define Colors
        if self.dark_mode:
            self.c_bg = "#2c3e50"
            self.c_dark = "#1a252f"
            panel_bg = "#34495e"
            self.c_fg = "#ecf0f1"
            tree_bg = "#34495e"
            tree_fg = "#ecf0f1"
        else:
            self.c_bg = "#ecf0f1"
            self.c_dark = "#2c3e50"
            panel_bg = "white"
            self.c_fg = "#2c3e50"
            tree_bg = "white"
            tree_fg = "black"

        # Apply to Root
        self.root.configure(bg=self.c_bg)
        
        # Apply to Styles
        style = ttk.Style()
        style.configure("Treeview", background=tree_bg, foreground=tree_fg, fieldbackground=tree_bg)
        style.configure("Treeview.Heading", background=self.c_dark, foreground="white")
        
        # Recursive Update
        self.update_gui_recursive(self.root, panel_bg)

    def update_gui_recursive(self, widget, panel_bg):
        try:
            wtype = widget.winfo_class()
            bg = widget.cget('bg')
            
            if self.dark_mode:
                # Switching TO Dark
                if bg == "#ecf0f1": widget.configure(bg=self.c_bg)
                elif bg == "#2c3e50": widget.configure(bg=self.c_dark)
                elif bg in ["white", "#ffffff", "#f0f0f0"]: widget.configure(bg=panel_bg)
                if wtype in ['Label', 'Listbox'] and widget.cget('fg') in ["black", "#2c3e50"]:
                    widget.configure(fg=self.c_fg)
            else:
                # Switching TO Light
                if bg == "#2c3e50": widget.configure(bg=self.c_bg)
                elif bg == "#1a252f": widget.configure(bg=self.c_dark)
                elif bg == "#34495e": widget.configure(bg=panel_bg)
                if wtype in ['Label', 'Listbox'] and widget.cget('fg') in ["white", "#ecf0f1"]:
                    widget.configure(fg=self.c_fg)
        except: pass
        
        for child in widget.winfo_children():
            self.update_gui_recursive(child, panel_bg)

    def start_system(self):
        if self.running: return
        self.running = True
        
        # Start hostname resolver
        self.resolver.start()
        
        # UI Updates
        self.status_led.itemconfig(self.led_id, fill=self.c_green) # Turn Green
        self.var_status.set("🟢 ACTIVE")
        
        # Init Backend
        self.detector = core_modules.DetectionEngine(
            self.pktqueue, self.gui_callback, self.blacklist, self.alerts, analyze_local=True
        )
        self.sniffer = core_modules.PacketCaptureThread(self.pktqueue)
        
        self.detector.start()
        self.sniffer.start()
        
        messagebox.showinfo("System Started", "Network monitoring started. Capturing live traffic...")

    def stop_system(self):
        self.running = False
        
        # Stop resolver
        self.resolver.stop()
        
        # UI Updates
        self.status_led.itemconfig(self.led_id, fill=self.c_red) # Turn Red
        self.var_status.set("🔴 STOPPED")
        
        if self.sniffer: self.sniffer.stop()
        if self.detector: self.detector.stop()
        
        messagebox.showinfo("System Stopped", "Network monitoring stopped.")

    def gui_callback(self, msgtype, data):
        # Thread-safe GUI update
        self.root.after(0, lambda: self.handle_update(msgtype, data))

    def handle_update(self, msgtype, data):
        timestamp = time.strftime("%H:%M:%S")

        if msgtype == "TRAFFIC":
            self.stat_packets += 1
            self.var_pkts.set(f"{self.stat_packets:,}")
            
            # Update stats tab total packets
            if hasattr(self, 'stat_vars'):
                self.stat_vars['total_pkts'].set(f"{self.stat_packets:,}")

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
            self.unique_src_ips.add(src)
            self.unique_dst_ips.add(dst)
            if hasattr(self, 'stat_vars'):
                self.stat_vars['unique_src'].set(f"{len(self.unique_src_ips)}")
                self.stat_vars['unique_dst'].set(f"{len(self.unique_dst_ips)}")

            # Update Protocol Stats
            if 'TCP' in proto: self.stat_tcp += 1
            elif 'UDP' in proto: self.stat_udp += 1
            elif 'ICMP' in proto: self.stat_icmp += 1
            self.refresh_stats_display()

            # Determine traffic direction (basic heuristic)
            # Private IP ranges: 10.x, 172.16-31.x, 192.168.x, 127.x
            is_src_private = self.is_private_ip(src)
            is_dst_private = self.is_private_ip(dst)
            
            if is_src_private and not is_dst_private:
                direction = "↗️ OUT"
                self.stat_outbound += 1
                self.var_outbound.set(f"{self.stat_outbound:,}")
                if hasattr(self, 'stat_vars'):
                    self.stat_vars['outbound_pkts'].set(f"{self.stat_outbound:,}")
            elif not is_src_private and is_dst_private:
                direction = "↙️ IN"
                self.stat_inbound += 1
                self.var_inbound.set(f"{self.stat_inbound:,}")
                if hasattr(self, 'stat_vars'):
                    self.stat_vars['inbound_pkts'].set(f"{self.stat_inbound:,}")
            else:
                direction = "↔️ LOCAL"

            # Get Hostnames (with fallback to IP)
            src_host = self.resolver.get_hostname(src) if self.show_hostnames.get() else src
            dst_host = self.resolver.get_hostname(dst) if self.show_hostnames.get() else dst

            # Get Process Name
            proc_name = "-"
            if psutil:
                try:
                    for conn in psutil.net_connections():
                        if conn.laddr.port == sport or conn.laddr.port == dport:
                            proc_name = psutil.Process(conn.pid).name()
                            break
                except: pass

            row = (timestamp, src, src_host, dst, dst_host, direction, proto, size, proc_name, payload)
            self.captureddata.append(row)

            # Insert into table
            tag_proto = 'TCP' if 'TCP' in proto else ('UDP' if 'UDP' in proto else 'ICMP')
            tag_dir = 'OUTBOUND' if '↗️' in direction else ('INBOUND' if '↙️' in direction else '')
            self.tree.insert("", 0, values=row, tags=(tag_proto, tag_dir))
            
            # Buffer Management (Keep list manageable)
            if len(self.tree.get_children()) > 200:
                self.tree.delete(self.tree.get_children()[-1])

        elif msgtype == "ALERT":
            self.stat_blocked += 1
            self.var_threats.set(f"{self.stat_blocked}")
            
            # Update stats tab threats
            if hasattr(self, 'stat_vars'):
                self.stat_vars['threats'].set(f"{self.stat_blocked}")

            # Handle formats
            if isinstance(data, tuple):
                src, _, reason, severity = data
                msg = f"[{severity.upper()}] {reason} → {src}"
            else:
                msg = data
            
            self.log_list.insert(0, f"[{timestamp}] {msg}")

    def is_private_ip(self, ip_address):
        """Check if IP is in private ranges"""
        try:
            parts = [int(x) for x in ip_address.split('.')]
            if parts[0] == 10: return True
            if parts[0] == 172 and 16 <= parts[1] <= 31: return True
            if parts[0] == 192 and parts[1] == 168: return True
            if parts[0] == 127: return True
            if parts[0] == 169 and parts[1] == 254: return True
            return False
        except:
            return False

    def filter_traffic(self):
        """Filter table by search term"""
        search_term = self.filter_var.get().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for row in self.captureddata:
            if not search_term or any(search_term in str(val).lower() for val in row):
                tag_proto = 'TCP' if 'TCP' in row[6] else ('UDP' if 'UDP' in row[6] else 'ICMP')
                tag_dir = 'OUTBOUND' if '↗️' in row[5] else ('INBOUND' if '↙️' in row[5] else '')
                self.tree.insert("", "end", values=row, tags=(tag_proto, tag_dir))

    def clear_table(self):
        self.tree.delete(*self.tree.get_children())
        self.captureddata.clear()
        self.var_pkts.set("0")
        self.stat_packets = 0

    def clear_logs(self):
        self.log_list.delete(0, tk.END)
        self.var_threats.set("0")
        self.stat_blocked = 0

    def unblock_selected(self):
        selected = self.blocked_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select IPs to unblock.")
            return
        
        for item in selected:
            values = self.blocked_tree.item(item, 'values')
            if values:
                ip_to_unblock = values[0]
                if self.detector:
                    self.detector.unblock_ip(ip_to_unblock)
                else:
                    core_modules.FirewallManager.unblock_ip(ip_to_unblock)
                    self.blacklist.delete(ip_to_unblock)
                self.blocked_tree.delete(item)
        
        messagebox.showinfo("Success", f"Unblocked {len(selected)} IP(s)")

    def refresh_blocked_list(self):
        """Refresh the blocked IPs list"""
        self.blocked_tree.delete(*self.blocked_tree.get_children())
        # Populate from data structure
        for ip in self.get_blocked_ips():
            self.blocked_tree.insert("", "end", values=(ip, "N/A", "Security", "🔒 Active"))

    def clear_blocked_list(self):
        """Clear all blocked IPs"""
        if messagebox.askyesno("Confirm", "Unblock ALL IPs?"):
            for item in self.blocked_tree.get_children():
                values = self.blocked_tree.item(item, 'values')
                if values:
                    core_modules.FirewallManager.unblock_ip(values[0])
            self.blocked_tree.delete(*self.blocked_tree.get_children())

    def get_blocked_ips(self):
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

    def bubblesort(self):
        data = self.captureddata
        n = len(data)
        # Bubble Sort implementation - sort by Size (index 7)
        for i in range(n):
            for j in range(0, n - i - 1):
                if int(data[j][7]) < int(data[j + 1][7]):
                    data[j], data[j + 1] = data[j + 1], data[j]
        
        # Redraw Table
        self.tree.delete(*self.tree.get_children())
        for row in data:
            tag_proto = 'TCP' if 'TCP' in row[6] else ('UDP' if 'UDP' in row[6] else 'ICMP')
            tag_dir = 'OUTBOUND' if '↗️' in row[5] else ('INBOUND' if '↙️' in row[5] else '')
            self.tree.insert("", "end", values=row, tags=(tag_proto, tag_dir))
        
        messagebox.showinfo("Sorted", f"Sorted {n} packets by Size (Descending).")

    def export_logs(self):
        """Export current traffic data to CSV"""
        if not self.captureddata:
            messagebox.showwarning("No Data", "No traffic captured yet.")
            return
        
        try:
            filename = f"netguard_export_{time.strftime('%Y%m%d_%H%M%S')}.csv"
            with open(filename, 'w') as f:
                # Header
                f.write("Time,SourceIP,SourceHost,DestIP,DestHost,Direction,Protocol,SizeBytes,Process\n")
                # Data
                for row in self.captureddata:
                    f.write(",".join(str(v) for v in row) + "\n")
            
            messagebox.showinfo("Export Successful", f"Data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def simulate_attack(self):
        ip = f"10.50.1.{random.randint(10,99)}"
        self.gui_callback("ALERT", f"[HIGH] Blocked {ip}: Simulated SYN Flood Attack Detected")

    # --- Context Menu Helpers ---
    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def copy_from_row(self, col_index):
        selected = self.tree.selection()
        if selected:
            val = self.tree.item(selected[0])['values'][col_index]
            self.root.clipboard_clear()
            self.root.clipboard_append(val)
            messagebox.showinfo("Copied", f"Copied to clipboard: {val}")

    def block_source_ip(self):
        selected = self.tree.selection()
        if selected:
            src_ip = self.tree.item(selected[0])['values'][1]
            try:
                # Attempt to block via core module
                core_modules.FirewallManager.block_ip(src_ip)
                self.gui_callback("ALERT", (src_ip, None, "Manual Block via Context Menu", "HIGH"))
                messagebox.showinfo("Blocked", f"IP {src_ip} has been blocked.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not block IP: {e}")

    def view_payload(self):
        selected = self.tree.selection()
        if selected:
            vals = self.tree.item(selected[0])['values']
            # Payload is at index 9 (hidden column)
            if len(vals) > 9:
                payload = vals[9]
                self.show_payload_window(payload)
            else:
                messagebox.showinfo("Info", "No payload captured for this packet.")

    def show_payload_window(self, payload):
        top = tk.Toplevel(self.root)
        top.title("Packet Payload Viewer")
        top.geometry("600x400")
        
        # Toolbar
        toolbar = tk.Frame(top)
        toolbar.pack(fill="x", side="top", padx=5, pady=5)
        
        def save_payload():
            path = filedialog.asksaveasfilename(parent=top, defaultextension=".txt",
                                              filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
            if path:
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(payload)
                    messagebox.showinfo("Saved", f"Payload saved to {path}", parent=top)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save: {e}", parent=top)

        ttk.Button(toolbar, text="💾 Save to File", command=save_payload).pack(side="left")
        
        txt = tk.Text(top, font=("Consolas", 10), wrap="word")
        txt.pack(fill="both", expand=True)
        
        # Add scrollbar
        scroll = ttk.Scrollbar(txt, command=txt.yview)
        txt.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        
        txt.insert("1.0", payload)
        txt.configure(state="disabled") # Read-only

if __name__ == "__main__":
    # Check Admin
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
    
    # Cleanup
    if app.resolver:
        app.resolver.stop()
        