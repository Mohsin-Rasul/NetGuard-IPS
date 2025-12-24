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

class ModernIPS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetGuard-IPS | Dashboard")
        self.root.geometry("1100x750")
        self.root.configure(bg="#f4f6f9") # Light grey background

        # --- Logic / Data ---
        self.blacklist = data_structures.BlacklistBST()
        self.alerts = data_structures.AlertStack()
        self.graph = data_structures.NetworkGraph()
        self.pktqueue = queue.Queue()
        self.captureddata = []
        
        self.sniffer = None
        self.detector = None
        self.running = False
        
        # Stats Counters
        self.stat_packets = 0
        self.stat_blocked = 0
        self.stat_alerts = 0

        # --- Styling ---
        self.setup_styles()
        
        # --- UI Layout ---
        self.create_header()
        self.create_dashboard_cards()
        self.create_main_content()
        self.create_footer_alerts()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Colors
        self.col_primary = "#3498db"
        self.col_danger = "#e74c3c"
        self.col_success = "#2ecc71"
        self.col_dark = "#2c3e50"
        
        # Treeview Styles
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#dfe6e9")
        style.configure("Treeview", font=("Consolas", 9), rowheight=25)
        
        # Button Styles
        style.configure("Start.TButton", font=("Segoe UI", 10, "bold"), foreground="green")
        style.configure("Stop.TButton", font=("Segoe UI", 10, "bold"), foreground="red")

    def create_header(self):
        # Top Bar with Title and Controls
        header = tk.Frame(self.root, bg=self.col_dark, height=60, pady=10, padx=20)
        header.pack(fill="x")
        
        lbl_title = tk.Label(header, text="NetGuard Intrusion Prevention System", 
                             font=("Segoe UI", 18, "bold"), bg=self.col_dark, fg="white")
        lbl_title.pack(side="left")
        
        # Control Buttons in Header
        btn_frame = tk.Frame(header, bg=self.col_dark)
        btn_frame.pack(side="right")
        
        self.btn_start = ttk.Button(btn_frame, text="▶ START SYSTEM", style="Start.TButton", command=self.start_system)
        self.btn_start.pack(side="left", padx=5)
        
        self.btn_stop = ttk.Button(btn_frame, text="⏹ STOP", style="Stop.TButton", command=self.stop_system, state="disabled")
        self.btn_stop.pack(side="left", padx=5)

        self.btn_sim = ttk.Button(btn_frame, text="⚠ Simulate Attack", command=self.simulate_attack)
        self.btn_sim.pack(side="left", padx=15)

    def create_dashboard_cards(self):
        # Frame for Stats
        dash_frame = tk.Frame(self.root, bg="#f4f6f9", pady=15, padx=20)
        dash_frame.pack(fill="x")
        
        # Helper to make cards
        def make_card(parent, title, value_var, color):
            card = tk.Frame(parent, bg="white", highlightthickness=1, highlightbackground="#dcdcdc")
            card.pack(side="left", fill="both", expand=True, padx=10)
            
            tk.Label(card, text=title, font=("Segoe UI", 10, "bold"), bg="white", fg="#7f8c8d").pack(pady=(10,0))
            lbl_val = tk.Label(card, textvariable=value_var, font=("Segoe UI", 24, "bold"), bg="white", fg=color)
            lbl_val.pack(pady=(0,10))
            return card

        self.var_pkts = tk.StringVar(value="0")
        self.var_blocked = tk.StringVar(value="0")
        self.var_alerts = tk.StringVar(value="0")

        make_card(dash_frame, "TOTAL PACKETS", self.var_pkts, self.col_primary)
        make_card(dash_frame, "THREATS BLOCKED", self.var_blocked, self.col_danger)
        make_card(dash_frame, "ALERTS TRIGGERED", self.var_alerts, "#e67e22")

    def create_main_content(self):
        # Paned Window for Traffic (Left) and Graph (Right)
        paned = tk.PanedWindow(self.root, orient="horizontal", bg="#f4f6f9")
        paned.pack(fill="both", expand=True, padx=20, pady=5)
        
        # --- LEFT: Traffic Table ---
        left_frame = tk.LabelFrame(paned, text=" Live Network Traffic ", font=("Segoe UI", 11, "bold"), bg="white")
        paned.add(left_frame, minsize=500)
        
        cols = ("Time", "Source", "Destination", "Proto", "Size", "Process")
        self.tree = ttk.Treeview(left_frame, columns=cols, show="headings", selectmode="browse")
        
        # Scrollbar
        vsb = ttk.Scrollbar(left_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        
        # Column Config
        self.tree.heading("Time", text="Time")
        self.tree.column("Time", width=80)
        self.tree.heading("Source", text="Source IP")
        self.tree.column("Source", width=120)
        self.tree.heading("Destination", text="Dest IP")
        self.tree.column("Destination", width=120)
        self.tree.heading("Proto", text="Protocol")
        self.tree.column("Proto", width=70, anchor="center")
        self.tree.heading("Size", text="Size")
        self.tree.column("Size", width=60, anchor="e")
        self.tree.heading("Process", text="App/PID")
        self.tree.column("Process", width=100)
        
        # Tag Colors
        self.tree.tag_configure('TCP', foreground='#2980b9')
        self.tree.tag_configure('UDP', foreground='#8e44ad')
        self.tree.tag_configure('Other', foreground='black')

        # Bubble Sort Button
        btn_sort = ttk.Button(left_frame, text="Sort by Size (Bubble Sort)", command=self.bubblesort)
        btn_sort.pack(side="bottom", fill="x")

        # --- RIGHT: Network Map ---
        right_frame = tk.LabelFrame(paned, text=" Topology Map ", font=("Segoe UI", 11, "bold"), bg="white")
        paned.add(right_frame, minsize=300)
        
        self.canvas = tk.Canvas(right_frame, bg="white")
        self.canvas.pack(fill="both", expand=True)
        
        # Draw Center Node
        cx, cy = 150, 150
        self.canvas.create_oval(cx-20, cy-20, cx+20, cy+20, fill=self.col_dark, outline="")
        self.canvas.create_text(cx, cy+30, text="Localhost", font=("Segoe UI", 10, "bold"))
        self.nodes = {}

    def create_footer_alerts(self):
        # Bottom section for alerts
        frame = tk.LabelFrame(self.root, text=" Security Alerts Log ", font=("Segoe UI", 11, "bold"), bg="white", fg=self.col_danger)
        frame.pack(fill="x", padx=20, pady=(5, 20), ipady=5)
        
        self.alert_list = tk.Listbox(frame, height=5, font=("Consolas", 10), 
                                     bg="#fff0f0", fg="#c0392b", selectbackground="#e74c3c", borderwidth=0)
        self.alert_list.pack(fill="both", expand=True, padx=5, pady=5)

    # --- System Logic ---

    def start_system(self):
        if self.running: return
        self.running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        
        self.detector = core_modules.DetectionEngine(
            self.pktqueue, self.update_gui_threadsafe, self.blacklist, self.alerts, self.graph
        )
        self.sniffer = core_modules.PacketCaptureThread(self.pktqueue)
        
        self.detector.start()
        self.sniffer.start()

    def stop_system(self):
        self.running = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        if self.sniffer: self.sniffer.stop()
        if self.detector: self.detector.stop()

    def update_gui_threadsafe(self, msgtype, data):
        self.root.after(0, lambda: self.process_update(msgtype, data))

    def process_update(self, msgtype, data):
        timestamp = time.strftime("%H:%M:%S")

        if msgtype == "TRAFFIC":
            self.stat_packets += 1
            self.var_pkts.set(str(self.stat_packets))

            # Robust unpacking (Handle old vs new core_modules)
            if len(data) == 7:
                src, _, dst, proto, size, sport, dport = data
            else:
                src, dst, proto, size, sport, dport = data
            
            # Process ID Lookup
            processname = "-"
            if psutil:
                try:
                    for conn in psutil.net_connections():
                        if conn.laddr.port == sport or conn.laddr.port == dport:
                            processname = psutil.Process(conn.pid).name()
                            break
                except: pass

            row = (timestamp, src, dst, proto, size, processname)
            self.captureddata.append(row)
            
            # Insert with color tag
            tag = 'TCP' if 'TCP' in proto else ('UDP' if 'UDP' in proto else 'Other')
            self.tree.insert("", 0, values=row, tags=(tag,))
            
            if len(self.tree.get_children()) > 50:
                self.tree.delete(self.tree.get_children()[-1])

            self.update_graph(src)

        elif msgtype == "ALERT":
            self.stat_alerts += 1
            self.stat_blocked += 1
            self.var_alerts.set(str(self.stat_alerts))
            self.var_blocked.set(str(self.stat_blocked))
            
            # Handle tuple vs string format from core_modules
            if isinstance(data, tuple):
                 src, _, reason, severity = data
                 msg = f"[{severity.upper()}] {reason} -> {src}"
            else:
                 msg = data
            
            self.alert_list.insert(0, f"{timestamp} {msg}")

    def update_graph(self, ip):
        # Draw "Satellite" nodes around the center
        if ip not in self.nodes:
            angle = random.uniform(0, 6.28)
            dist = random.randint(50, 120)
            cx, cy = 150, 150 # Canvas Center
            
            x = cx + int(dist * 1.5 * random.random() * (1 if random.random() > 0.5 else -1))
            y = cy + int(dist * random.random() * (1 if random.random() > 0.5 else -1))
            
            # Keep inside bounds
            x = max(20, min(x, 280))
            y = max(20, min(y, 250))
            
            # Draw Line first
            self.canvas.create_line(cx, cy, x, y, fill="#bdc3c7", width=1)
            # Draw Node
            self.canvas.create_oval(x-5, y-5, x+5, y+5, fill=self.col_primary, outline="")
            self.nodes[ip] = (x, y)

    def bubblesort(self):
        data = self.captureddata
        n = len(data)
        for i in range(n):
            for j in range(0, n - i - 1):
                if data[j][4] < data[j + 1][4]:
                    data[j], data[j + 1] = data[j + 1], data[j]
        
        self.tree.delete(*self.tree.get_children())
        for row in data:
            tag = 'TCP' if 'TCP' in row[3] else ('UDP' if 'UDP' in row[3] else 'Other')
            self.tree.insert("", "end", values=row, tags=(tag,))
        
        messagebox.showinfo("Bubble Sort", f"Sorted {n} packets by Size.")

    def simulate_attack(self):
        ip = f"192.168.1.{random.randint(100,200)}"
        self.update_gui_threadsafe("ALERT", f"[HIGH] Blocked {ip}: Simulated SQL Injection")

if __name__ == "__main__":
    # Admin Check
    try:
        isadmin = os.getuid() == 0
    except AttributeError:
        import ctypes
        isadmin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
    root = tk.Tk()
    if not isadmin:
        messagebox.showwarning("Admin Rights", "Run as Administrator for blocking to work!")
    
    app = ModernIPS_GUI(root)
    root.mainloop()