import tkinter as tk
from tkinter import ttk, messagebox
import queue
import time
import random
import sys
import os

# Try importing psutil for Process ID mapping
try:
    import psutil
except ImportError:
    psutil = None

# Import Local Modules
import data_structures
import core_modules

class ProfessionalIPS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetGuard-IPS | Professional Dashboard")
        self.root.geometry("1200x800")
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
        
        # GUI State
        self.paused = tk.BooleanVar(value=False)
        self.stat_packets = 0
        self.stat_blocked = 0
        self.stat_alerts = 0

        # --- Build UI ---
        self.setup_styles()
        self.create_header()
        self.create_kpi_board()
        self.create_controls()
        self.create_split_view()

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

        # Helper to create a stat card
        def draw_card(parent, label, var, color):
            card = tk.Frame(parent, bg="white", highlightbackground="#bdc3c7", highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=5)
            
            tk.Label(card, text=label, font=("Segoe UI", 9, "bold"), fg="#7f8c8d", bg="white").pack(pady=(10, 5))
            tk.Label(card, textvariable=var, font=("Segoe UI", 20, "bold"), fg=color, bg="white").pack(pady=(0, 10))

        draw_card(kpi_frame, "SYSTEM STATUS", self.var_status, self.c_dark)
        draw_card(kpi_frame, "PACKETS ANALYZED", self.var_pkts, self.c_blue)
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
        ttk.Checkbutton(toolbar, text="Pause Live View (Freeze Table)", variable=self.paused).pack(side="left", padx=10)
        ttk.Button(toolbar, text="🗑 Clear Table", command=self.clear_table).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Sort by Size", command=self.bubblesort).pack(side="left", padx=2)

        # Right: Simulation
        ttk.Button(toolbar, text="⚠ Simulate Attack", command=self.simulate_attack).pack(side="right", padx=2)

    def create_split_view(self):
        # PanedWindow allows resizing (Split View)
        paned = tk.PanedWindow(self.root, orient="vertical", bg=self.c_bg, sashwidth=6, sashrelief="raised")
        paned.pack(fill="both", expand=True, padx=20, pady=10)

        # --- TOP: Traffic Table ---
        top_frame = tk.LabelFrame(paned, text=" Live Network Traffic ", bg="white", font=("Segoe UI", 11, "bold"))
        paned.add(top_frame, height=450) # Default height

        cols = ("Time", "Source", "Destination", "Protocol", "Size", "Process")
        self.tree = ttk.Treeview(top_frame, columns=cols, show="headings", selectmode="extended")
        
        # Scrollbars
        vsb = ttk.Scrollbar(top_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(top_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        top_frame.grid_rowconfigure(0, weight=1)
        top_frame.grid_columnconfigure(0, weight=1)

        # Configure Columns
        self.tree.heading("Time", text="Time")
        self.tree.column("Time", width=90, anchor="center")
        
        self.tree.heading("Source", text="Source IP")
        self.tree.column("Source", width=140)
        
        self.tree.heading("Destination", text="Destination IP")
        self.tree.column("Destination", width=140)
        
        self.tree.heading("Protocol", text="Proto")
        self.tree.column("Protocol", width=70, anchor="center")
        
        self.tree.heading("Size", text="Size (B)")
        self.tree.column("Size", width=80, anchor="e") # Right aligned numbers
        
        self.tree.heading("Process", text="Application / PID")
        self.tree.column("Process", width=150)

        # Row Colors
        self.tree.tag_configure('TCP', foreground="#2980b9")
        self.tree.tag_configure('UDP', foreground="#8e44ad")
        self.tree.tag_configure('IPv6', foreground="#16a085")

        # --- BOTTOM: Alerts ---
        bot_frame = tk.LabelFrame(paned, text=" Security Alerts & Blocks ", bg="white", fg=self.c_red, font=("Segoe UI", 11, "bold"))
        paned.add(bot_frame, minsize=150)

        # Toolbar inside Alerts
        alert_tools = tk.Frame(bot_frame, bg="white")
        alert_tools.pack(fill="x", side="bottom", pady=2)
        ttk.Button(alert_tools, text="Clear Logs", command=self.clear_logs).pack(side="right", padx=5)

        self.log_list = tk.Listbox(bot_frame, font=("Consolas", 10), bg="#fff5f5", fg="#c0392b", borderwidth=0, highlightthickness=0)
        self.log_list.pack(fill="both", expand=True, padx=5, pady=5)


    # --- Logic ---

    def start_system(self):
        if self.running: return
        self.running = True
        
        # UI Updates
        self.status_led.itemconfig(self.led_id, fill=self.c_green) # Turn Green
        self.var_status.set("ACTIVE")
        
        # Init Backend
        self.detector = core_modules.DetectionEngine(
            self.pktqueue, self.gui_callback, self.blacklist, self.alerts, self.graph
        )
        self.sniffer = core_modules.PacketCaptureThread(self.pktqueue)
        
        self.detector.start()
        self.sniffer.start()

    def stop_system(self):
        self.running = False
        
        # UI Updates
        self.status_led.itemconfig(self.led_id, fill=self.c_red) # Turn Red
        self.var_status.set("STOPPED")
        
        if self.sniffer: self.sniffer.stop()
        if self.detector: self.detector.stop()

    def gui_callback(self, msgtype, data):
        # Thread-safe GUI update
        self.root.after(0, lambda: self.handle_update(msgtype, data))

    def handle_update(self, msgtype, data):
        timestamp = time.strftime("%H:%M:%S")

        if msgtype == "TRAFFIC":
            self.stat_packets += 1
            self.var_pkts.set(f"{self.stat_packets:,}")

            if self.paused.get(): return # Skip table update if paused

            # Handle 6 or 7 items (Compatibility Mode)
            if len(data) == 7:
                 src, _, dst, proto, size, sport, dport = data
            else:
                 src, dst, proto, size, sport, dport = data

            # Get Process Name
            proc_name = "-"
            if psutil:
                try:
                    for conn in psutil.net_connections():
                        if conn.laddr.port == sport or conn.laddr.port == dport:
                            proc_name = psutil.Process(conn.pid).name()
                            break
                except: pass

            row = (timestamp, src, dst, proto, size, proc_name)
            self.captureddata.append(row)

            # Insert into table
            tag = 'TCP' if 'TCP' in proto else ('UDP' if 'UDP' in proto else 'IPv6')
            self.tree.insert("", 0, values=row, tags=(tag,))
            
            # Buffer Management (Keep list manageable)
            if len(self.tree.get_children()) > 100:
                self.tree.delete(self.tree.get_children()[-1])

        elif msgtype == "ALERT":
            self.stat_blocked += 1
            self.var_threats.set(f"{self.stat_blocked}")

            # Handle formats
            if isinstance(data, tuple):
                 src, _, reason, severity = data
                 msg = f"[{severity.upper()}] {reason} -> {src}"
            else:
                 msg = data
            
            self.log_list.insert(0, f"[{timestamp}] {msg}")

    def clear_table(self):
        self.tree.delete(*self.tree.get_children())
        self.captureddata.clear()

    def clear_logs(self):
        self.log_list.delete(0, tk.END)

    def bubblesort(self):
        data = self.captureddata
        n = len(data)
        # Bubble Sort implementation
        for i in range(n):
            for j in range(0, n - i - 1):
                if data[j][4] < data[j + 1][4]: # Sort by Size (index 4)
                    data[j], data[j + 1] = data[j + 1], data[j]
        
        # Redraw Table
        self.tree.delete(*self.tree.get_children())
        for row in data:
            tag = 'TCP' if 'TCP' in row[3] else ('UDP' if 'UDP' in row[3] else 'IPv6')
            self.tree.insert("", "end", values=row, tags=(tag,))
        
        messagebox.showinfo("Sorted", f"Sorted {n} packets by Size.")

    def simulate_attack(self):
        ip = f"10.50.1.{random.randint(10,99)}"
        self.gui_callback("ALERT", f"[HIGH] Blocked {ip}: Simulated SYN Flood")

if __name__ == "__main__":
    # Check Admin
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    root = tk.Tk()
    if not is_admin:
        messagebox.showwarning("Admin Privileges", "Warning: Application is not running as Administrator.\nBlocking features will not work.")
    
    app = ProfessionalIPS_GUI(root)
    root.mainloop()