import tkinter as tk
from tkinter import ttk, messagebox
import queue
import time
import random
import sys
import os

# Process ID Library
try:
    import psutil
except ImportError:
    psutil = None

# Local Modules
import data_structures
import core_modules

class NetGuardGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetGuard-IPS (Student Project)")
        self.root.geometry("1000x700")

        # Initialize Data Structures
        self.blacklist = data_structures.BlacklistBST()
        self.alerts = data_structures.AlertStack()
        self.graph = data_structures.NetworkGraph()
        self.pktqueue = queue.Queue()

        # Threads
        self.sniffer = None
        self.detector = None
        self.running = False
        self.captureddata = [] 

        self.setupui()

    def setupui(self):
        # Top Frame: Controls
        topframe = tk.Frame(self.root, pady=10)
        topframe.pack(fill="x")

        self.btnstart = ttk.Button(topframe, text="Start System", command=self.startsystem)
        self.btnstart.pack(side="left", padx=5)

        self.btnstop = ttk.Button(topframe, text="Stop System", command=self.stopsystem, state="disabled")
        self.btnstop.pack(side="left", padx=5)

        self.btnsort = ttk.Button(topframe, text="Sort Traffic (Bubble Sort)", command=self.bubblesort)
        self.btnsort.pack(side="left", padx=5)
        
        self.btnsim = ttk.Button(topframe, text="Simulate Attack", command=self.simulateattack)
        self.btnsim.pack(side="right", padx=5)

        # Middle Frame: Traffic & Graph
        midframe = tk.PanedWindow(self.root, orient="horizontal")
        midframe.pack(fill="both", expand=True, padx=5, pady=5)

        # Left: Traffic Table
        tableframe = tk.LabelFrame(midframe, text="Live Traffic")
        midframe.add(tableframe)
        
        cols = ("Time", "Source", "Dest", "Proto", "Size", "Process")
        self.treeview = ttk.Treeview(tableframe, columns=cols, show="headings")
        for c in cols:
            self.treeview.heading(c, text=c)
            self.treeview.column(c, width=100)
        self.treeview.pack(fill="both", expand=True)

        # Right: Graph Canvas
        graphframe = tk.LabelFrame(midframe, text="Network Map")
        midframe.add(graphframe)
        self.canvas = tk.Canvas(graphframe, bg="white", width=300)
        self.canvas.pack(fill="both", expand=True)
        self.nodes = {}

        # Bottom Frame: Alerts
        botframe = tk.LabelFrame(self.root, text="Security Alerts (Stack)", height=150)
        botframe.pack(fill="x", padx=5, pady=5)
        
        self.listbox = tk.Listbox(botframe, fg="red")
        self.listbox.pack(fill="both", expand=True)

    def startsystem(self):
        if self.running: return
        self.running = True
        self.btnstart.config(state="disabled")
        self.btnstop.config(state="normal")
        
        # Start Threads
        self.detector = core_modules.DetectionEngine(
            self.pktqueue, self.updategui, self.blacklist, self.alerts, self.graph
        )
        self.sniffer = core_modules.PacketCaptureThread(self.pktqueue)
        
        self.detector.start()
        self.sniffer.start()

    def stopsystem(self):
        self.running = False
        self.btnstart.config(state="normal")
        self.btnstop.config(state="disabled")
        if self.sniffer: self.sniffer.stop()
        if self.detector: self.detector.stop()

    def updategui(self, msgtype, data):
        self.root.after(0, lambda: self.processupdate(msgtype, data))

    def processupdate(self, msgtype, data):
        timestamp = time.strftime("%H:%M:%S")

        if msgtype == "TRAFFIC":
            # --- CRITICAL FIX: Handle Old vs New Data Format ---
            if len(data) == 7:
                # Old Format: (src, hostname, dst, proto, size, sport, dport)
                # We discard 'hostname' to prevent the crash
                src, _, dst, proto, size, sport, dport = data
            else:
                # New Format: (src, dst, proto, size, sport, dport)
                src, dst, proto, size, sport, dport = data
            
            # Identify Process
            processname = "Unknown"
            if psutil:
                try:
                    for conn in psutil.net_connections():
                        if conn.laddr.port == sport or conn.laddr.port == dport:
                            proc = psutil.Process(conn.pid)
                            processname = proc.name()
                            break
                except:
                    pass

            row = (timestamp, src, dst, proto, size, processname)
            self.captureddata.append(row)
            self.treeview.insert("", 0, values=row)
            
            # Limit rows
            if len(self.treeview.get_children()) > 50:
                self.treeview.delete(self.treeview.get_children()[-1])

            self.drawnode(src)

        elif msgtype == "ALERT":
            # Handle Old (Tuple) vs New (String) format
            if isinstance(data, tuple):
                 src, _, reason, severity = data
                 msg = f"[{severity}] Blocked {src}: {reason}"
            else:
                 msg = data
            
            self.listbox.insert(0, msg)
            self.listbox.config(bg="#ffe0e0")

    def bubblesort(self):
        data = self.captureddata
        n = len(data)
        for i in range(n):
            for j in range(0, n - i - 1):
                if data[j][4] < data[j + 1][4]:
                    data[j], data[j + 1] = data[j + 1], data[j]
        
        self.treeview.delete(*self.treeview.get_children())
        for row in data:
            self.treeview.insert("", "end", values=row)
        messagebox.showinfo("Sort", "Traffic sorted by Size using Bubble Sort")

    def simulateattack(self):
        fakeip = f"192.168.1.{random.randint(50, 200)}"
        msg = f"[High] Blocked {fakeip}: Simulation - SQL Injection Detected"
        self.updategui("ALERT", msg)

    def drawnode(self, ip):
        if ip not in self.nodes:
            x = random.randint(20, 280)
            y = random.randint(20, 200)
            self.canvas.create_oval(x, y, x+10, y+10, fill="blue")
            self.canvas.create_text(x, y-10, text=ip, font=("Arial", 8))
            self.nodes[ip] = (x, y)
            self.canvas.create_line(150, 150, x+5, y+5, fill="gray")

if __name__ == "__main__":
    try:
        isadmin = os.getuid() == 0
    except AttributeError:
        import ctypes
        isadmin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if not isadmin:
        print("Warning: Please run as Administrator for blocking to work.")

    root = tk.Tk()
    app = NetGuardGUI(root)
    root.mainloop()