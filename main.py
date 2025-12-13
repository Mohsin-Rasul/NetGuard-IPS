import tkinter as tk
from tkinter import ttk, messagebox
import queue
import subprocess
import random
import sys
import time # Added missing import

# Import custom modules
try:
    from data_structures import BlacklistBST, AlertStack, NetworkGraph
    from core_modules import PacketCaptureThread, DetectionEngine, FirewallManager, Logger
except ImportError as e:
    # If standard import fails, try relative import if running as a package
    # or just print error
    print(f"Import Error: {e}")
    print("Ensure 'data_structures.py' and 'core_modules.py' are in the same directory as 'main.py'.")
    # For some IDEs/environments, current dir might not be in path
    sys.path.append(".")
    try:
        from data_structures import BlacklistBST, AlertStack, NetworkGraph
        from core_modules import PacketCaptureThread, DetectionEngine, FirewallManager, Logger
    except ImportError as e2:
        print(f"Retry Import Error: {e2}")
        sys.exit(1)

# Check for Scapy
try:
    import scapy.all
except ImportError:
    messagebox.showerror("Missing Dependency", "Scapy is not installed.\nPlease run: pip install scapy")
    sys.exit(1)

# ==========================================
# PART 3: VISUALIZATION (GUI)
# ==========================================

class HipsDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("HIPS - Intrusion Prevention System (Data Structures Project)")
        self.root.geometry("1100x750")
        
        # Initialize Labs Logic
        self.blacklist_bst = BlacklistBST()
        self.alert_stack = AlertStack()
        self.network_graph = NetworkGraph()
        
        # [Lab 7] Queue Implementation: Created here and passed to threads
        self.packet_queue = queue.Queue()
        
        self.populate_dummy_blacklist()

        # Styles
        style = ttk.Style()
        style.configure("Treeview", font=('Consolas', 10))
        style.configure("TLabel", font=('Arial', 10))

        # --- Layout ---
        control_frame = ttk.LabelFrame(root, text="Controls", padding=10)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        self.btn_start = ttk.Button(control_frame, text="Start System", command=self.start_system)
        self.btn_start.pack(side="left", padx=5)
        
        self.btn_stop = ttk.Button(control_frame, text="Stop System", command=self.stop_system, state="disabled")
        self.btn_stop.pack(side="left", padx=5)

        # [Lab 11] Sorting Button
        self.btn_sort = ttk.Button(control_frame, text="Sort Traffic (Bubble Sort)", command=self.sort_traffic)
        self.btn_sort.pack(side="left", padx=5)

        self.btn_sim = ttk.Button(control_frame, text="Simulate Attack", command=self.simulate_attack)
        self.btn_sim.pack(side="right", padx=5)

        self.lbl_status = ttk.Label(control_frame, text="Status: Ready (Check 'hips_alerts.log' for history)", foreground="blue")
        self.lbl_status.pack(side="left", padx=20)

        mid_frame = tk.Frame(root)
        mid_frame.pack(fill="both", expand=True, padx=10, pady=5)

        traffic_frame = ttk.LabelFrame(mid_frame, text="Live Traffic (Queue Buffer)", padding=5)
        traffic_frame.pack(side="left", fill="both", expand=True)

        columns = ("Time", "Source", "Destination", "Protocol", "Size")
        self.tree = ttk.Treeview(traffic_frame, columns=columns, show="headings", height=15)
        for col in columns:
            self.tree.heading(col, text=col)
            width = 150 if col == "Source" else 90
            self.tree.column(col, width=width)
        self.tree.pack(fill="both", expand=True)

        map_frame = ttk.LabelFrame(mid_frame, text="Network Map (Graph)", padding=5)
        map_frame.pack(side="right", fill="both", expand=True)
        
        self.canvas = tk.Canvas(map_frame, bg="white", width=400, height=350)
        self.canvas.pack(fill="both", expand=True)
        self.nodes_drawn = {} 

        alert_frame = ttk.LabelFrame(root, text="Security Alerts (Linked List Stack)", padding=10)
        alert_frame.pack(fill="x", padx=10, pady=5)

        self.alert_list = tk.Listbox(alert_frame, height=6, fg="red", font=('Consolas', 10, 'bold'))
        self.alert_list.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.btn_unblock = ttk.Button(alert_frame, text="Unblock IP", command=self.unblock_selected_ip)
        self.btn_unblock.pack(side="right", padx=5)

        self.sniffer = None
        self.detector = None
        self.is_running = False
        self.captured_packets_data = [] 

        self.center_x, self.center_y = 200, 175
        self.draw_node("LocalHost", self.center_x, self.center_y, "blue")

    def populate_dummy_blacklist(self):
        threats = ["192.168.1.100", "10.0.0.5", "172.16.0.25"]
        for ip in threats:
            self.blacklist_bst.insert(ip)

    # --- [Lab 11] Bubble Sort Implementation ---
    def sort_traffic(self):
        """Sorts the traffic table by packet size."""
        data = self.captured_packets_data
        n = len(data)
        if n < 2: return

        # Bubble Sort
        for i in range(n):
            for j in range(0, n-i-1):
                if data[j][4] < data[j+1][4]: # Sort Descending
                    data[j], data[j+1] = data[j+1], data[j]
        
        # Update UI
        self.tree.delete(*self.tree.get_children())
        for row in data:
            self.tree.insert("", "end", values=row)
        messagebox.showinfo("Sorting", f"Sorted {n} packets using Bubble Sort.")

    def draw_node(self, name, x, y, color="gray"):
        r = 20
        self.canvas.create_oval(x-r, y-r, x+r, y+r, fill=color, outline="black")
        display_name = name
        if len(display_name) > 15:
            display_name = display_name[:12] + "..."
        self.canvas.create_text(x, y, text=display_name, font=("Arial", 8))
        self.nodes_drawn[name] = (x, y) 

    def draw_edge(self, src, dst, color="black"):
        if src in self.nodes_drawn and dst in self.nodes_drawn:
            x1, y1 = self.nodes_drawn[src]
            x2, y2 = self.nodes_drawn[dst]
            self.canvas.create_line(x1, y1, x2, y2, fill=color, arrow=tk.LAST)

    def get_valid_node_position(self):
        min_dist = 50 
        width = int(self.canvas.cget("width"))
        height = int(self.canvas.cget("height"))
        for _ in range(50):
            rx = random.randint(40, width - 40)
            ry = random.randint(40, height - 40)
            dist_center = ((rx - self.center_x)**2 + (ry - self.center_y)**2)**0.5
            if dist_center < min_dist: continue
            overlap = False
            for (nx, ny) in self.nodes_drawn.values():
                dist = ((rx - nx)**2 + (ry - ny)**2)**0.5
                if dist < min_dist:
                    overlap = True
                    break
            if not overlap: return rx, ry
        return random.randint(40, width - 40), random.randint(40, height - 40)
    
    def simulate_attack(self):
        sim_ip = "45.155.205.10"
        sim_host = "Attacker (Russia)"
        sim_reason = "Signature Match: SQL Injection (Simulation)"
        sim_severity = "High"
        
        self.update_gui("ALERT", (sim_ip, sim_host, sim_reason, sim_severity))
        Logger.log_alert(sim_ip, sim_reason, sim_severity)
        messagebox.showinfo("Simulation", "Simulated Attack Injected!")

    def unblock_selected_ip(self):
        selection = self.alert_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Select an alert first.")
            return
        msg = self.alert_list.get(selection[0])
        try:
            # Format: "[SEVERITY] BLOCKED IP (Host): Reason"
            # Split by spaces. IP is typically the 3rd word.
            parts = msg.split()
            # Example: ["[HIGH]", "BLOCKED", "1.2.3.4", ...]
            ip_to_unblock = parts[2]
            
            if FirewallManager.unblock_ip(ip_to_unblock):
                if self.detector and ip_to_unblock in self.detector.blocked_ips:
                    self.detector.blocked_ips.remove(ip_to_unblock)
                messagebox.showinfo("Success", f"IP {ip_to_unblock} has been unblocked.")
                self.alert_list.delete(selection[0])
        except Exception as e:
            messagebox.showerror("Error", f"Could not unblock: {e}")

    def update_gui(self, type, data):
        self.root.after(0, lambda: self._process_gui_update(type, data))

    def _process_gui_update(self, type, data):
        if not self.is_running: return

        timestamp = time.strftime("%H:%M:%S")

        if type == "TRAFFIC":
            src_ip, src_host, dst, proto, length = data
            
            row_data = (timestamp, src_host, dst, proto, length)
            self.captured_packets_data.append(row_data)
            
            self.tree.insert("", 0, values=row_data)
            if len(self.tree.get_children()) > 50:
                self.tree.delete(self.tree.get_children()[-1])
                if len(self.captured_packets_data) > 50:
                    self.captured_packets_data.pop(0)

            node_key = src_host 
            if node_key not in self.nodes_drawn:
                rx, ry = self.get_valid_node_position()
                self.draw_node(node_key, rx, ry, "green")
                self.draw_edge("LocalHost", node_key)
            
        elif type == "ALERT":
            src, hostname, reason, severity = data
            # Format: [SEVERITY] BLOCKED IP (Host) : Reason
            msg = f"[{severity.upper()}] BLOCKED {src} ({hostname}) : {reason}"
            
            self.alert_list.insert(0, msg)
            
            if hostname in self.nodes_drawn:
                x, y = self.nodes_drawn[hostname]
                self.draw_node(hostname, x, y, "red")
            elif src in self.nodes_drawn: 
                x, y = self.nodes_drawn[src]
                self.draw_node(src, x, y, "red")

    def start_system(self):
        if self.is_running: return
        self.is_running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.lbl_status.config(text="Status: SYSTEM ACTIVE - Logging to file", foreground="green")

        # Create sniffer and pass queue
        self.sniffer = PacketCaptureThread(self.packet_queue)
        
        # Create detector and pass queue + other structures
        self.detector = DetectionEngine(
            self.packet_queue, 
            self.update_gui, 
            self.blacklist_bst, 
            self.alert_stack, 
            self.network_graph
        )
        
        self.sniffer.start()
        self.detector.start()

    def stop_system(self):
        if not self.is_running: return
        self.is_running = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.lbl_status.config(text="Status: STOPPED", foreground="red")

        if self.sniffer: self.sniffer.stop()
        if self.detector: self.detector.stop()

if __name__ == "__main__":
    try:
        is_admin = (subprocess.run("net session", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0)
    except:
        is_admin = False

    if not is_admin:
        print("WARNING: Not running as Administrator. Packet sniffing and Blocking may fail.")
    
    root = tk.Tk()
    app = HipsDashboard(root)
    root.mainloop()