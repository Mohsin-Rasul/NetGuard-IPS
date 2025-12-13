import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
import time
import subprocess
import random
import sys
import socket # NEW: Imported for finding hostnames (DNS)

# Try importing scapy; handle error if missing
try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    messagebox.showerror("Missing Dependency", "Scapy is not installed.\nPlease run: pip install scapy")
    sys.exit(1)

# ==========================================
# PART 1: DATA STRUCTURES (As per Proposal)
# ==========================================

# 1. QUEUE for Traffic Buffering
packet_queue = queue.Queue()

# 2. BINARY SEARCH TREE (BST) for Blacklist Search
class BSTNode:
    def __init__(self, ip):
        self.ip = ip
        self.left = None
        self.right = None

class BlacklistBST:
    def __init__(self):
        self.root = None

    def insert(self, ip):
        if not self.root:
            self.root = BSTNode(ip)
        else:
            self._insert_recursive(self.root, ip)

    def _insert_recursive(self, node, ip):
        if ip < node.ip:
            if node.left is None:
                node.left = BSTNode(ip)
            else:
                self._insert_recursive(node.left, ip)
        elif ip > node.ip:
            if node.right is None:
                node.right = BSTNode(ip)
            else:
                self._insert_recursive(node.right, ip)

    def search(self, ip):
        return self._search_recursive(self.root, ip)

    def _search_recursive(self, node, ip):
        if node is None:
            return False
        if ip == node.ip:
            return True
        elif ip < node.ip:
            return self._search_recursive(node.left, ip)
        else:
            return self._search_recursive(node.right, ip)

# 3. STACK for Alert Management
class AlertStack:
    def __init__(self):
        self.stack = []

    def push(self, alert):
        self.stack.append(alert)

    def pop(self):
        if not self.is_empty():
            return self.stack.pop()
        return None

    def is_empty(self):
        return len(self.stack) == 0

# 4. GRAPH for Visual Mapping (Adjacency List)
class NetworkGraph:
    def __init__(self):
        self.adj_list = {} 

    def add_connection(self, src, dst):
        if src not in self.adj_list:
            self.adj_list[src] = set()
        self.adj_list[src].add(dst)

# ==========================================
# PART 2: CORE MODULES
# ==========================================

class FirewallManager:
    """Handles interaction with Windows Firewall via netsh."""
    
    @staticmethod
    def block_ip(ip_address):
        rule_name = f"HIPS_BLOCK_{ip_address}"
        command = (
            f"netsh advfirewall firewall add rule name=\"{rule_name}\" "
            f"dir=in action=block remoteip={ip_address}"
        )
        try:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL)
            print(f"[FIREWALL] Blocked IP: {ip_address}")
            return True
        except subprocess.CalledProcessError:
            print(f"[ERROR] Failed to block {ip_address}. Are you running as Admin?")
            return False

    @staticmethod
    def unblock_ip(ip_address):
        """Removes the blocking rule from Windows Firewall."""
        rule_name = f"HIPS_BLOCK_{ip_address}"
        command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        try:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL)
            print(f"[FIREWALL] Unblocked IP: {ip_address}")
            return True
        except subprocess.CalledProcessError:
            print(f"[ERROR] Failed to unblock {ip_address}. Rule might not exist.")
            return False

class PacketCaptureThread(threading.Thread):
    """Captures packets and pushes them to the Queue."""
    
    def __init__(self):
        super().__init__()
        self.stop_event = threading.Event()
        self.daemon = True

    def run(self):
        print("[SNIFFER] Started...")
        while not self.stop_event.is_set():
            try:
                sniff(count=1, prn=self.process_packet, store=0, timeout=1)
            except Exception as e:
                print(f"[SNIFFER ERROR] {e}")
                time.sleep(2)

    def process_packet(self, packet):
        if IP in packet:
            packet_queue.put(packet)

    def stop(self):
        self.stop_event.set()

class DetectionEngine(threading.Thread):
    """Pulls from Queue, analyzes using BST and Counters."""
    
    def __init__(self, gui_callback, blacklist_bst):
        super().__init__()
        self.stop_event = threading.Event()
        self.daemon = True
        self.gui_callback = gui_callback
        self.blacklist = blacklist_bst
        self.alert_stack = AlertStack()
        
        # Anomaly Detection Data
        self.packet_counts = {} 
        self.port_map = {} # NEW: Tracks distinct ports accessed by an IP
        self.blocked_ips = set() 
        self.start_time = time.time()
        
        # TUNED THRESHOLD: 150 PPS (Packets Per Second)
        self.THRESHOLD_PPS = 150 
        self.PORT_SCAN_THRESHOLD = 5 # If > 5 ports accessed in 1 sec = Attack
        
        # DNS Cache to store resolved names {ip: hostname}
        self.dns_cache = {}

        # NEW: Determine Local IP to filter out other devices
        self.local_ip = self.get_local_ip()
        print(f"[DETECTION] Local IP detected as: {self.local_ip}")

    def get_local_ip(self):
        """Finds the local IP address of this machine."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to a public DNS (doesn't send data) to get correct local interface IP
            s.connect(('8.8.8.8', 80))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def get_hostname(self, ip):
        """Resolves IP to Hostname with caching to prevent lag."""
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        
        try:
            # We set a short timeout so the GUI doesn't freeze if DNS is slow
            # Note: This affects global socket, handled carefully here
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(0.2) 
            
            hostname = socket.gethostbyaddr(ip)[0]
            
            # Common Cleanup: Google/YouTube servers are often named '1e100.net'
            if "1e100.net" in hostname:
                hostname = "Google/YouTube Service"
            elif "google" in hostname:
                hostname = "Google Service"
            elif "fbcdn" in hostname:
                hostname = "Facebook/Meta"
                
            socket.setdefaulttimeout(old_timeout)
        except:
            hostname = ip # Fallback: Just use the IP if resolution fails
        
        self.dns_cache[ip] = hostname
        return hostname

    def run(self):
        print("[DETECTION] Engine Started...")
        while not self.stop_event.is_set():
            try:
                if not packet_queue.empty():
                    pkt = packet_queue.get()
                    self.analyze(pkt)
                else:
                    time.sleep(0.1)
            except Exception as e:
                print(f"[DETECTION ERROR] {e}")

    def analyze(self, pkt):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
        length = len(pkt)

        # Filter: Only show traffic that belongs to MY computer
        if src_ip != self.local_ip and dst_ip != self.local_ip:
            return
            
        # SAFETY: Never block ourselves
        if src_ip == self.local_ip:
            # We update GUI for outbound traffic but skip threat detection against ourselves
            hostname = self.get_hostname(src_ip)
            self.gui_callback("TRAFFIC", (src_ip, hostname, dst_ip, proto, length))
            return

        # 0. Check if already blocked (prevent alert spam)
        if src_ip in self.blocked_ips:
            return

        # 1. Signature Matching (BST Search)
        is_blacklisted = self.blacklist.search(src_ip)
        
        # 2. Anomaly Detection (Rate Limiting & Port Scanning)
        current_time = time.time()
        if current_time - self.start_time > 1.0:
            self.packet_counts = {}
            self.port_map = {} # Reset port counters
            self.start_time = current_time
        
        # Count Packets
        self.packet_counts[src_ip] = self.packet_counts.get(src_ip, 0) + 1
        
        # Track Ports (New Logic)
        dport = 0
        if TCP in pkt: dport = pkt[TCP].dport
        elif UDP in pkt: dport = pkt[UDP].dport
        
        if dport > 0:
            if src_ip not in self.port_map:
                self.port_map[src_ip] = set()
            self.port_map[src_ip].add(dport)
        
        threat_detected = False
        reason = ""

        if is_blacklisted:
            threat_detected = True
            reason = "Blacklisted IP"
        elif self.packet_counts[src_ip] > self.THRESHOLD_PPS:
            threat_detected = True
            reason = "High Traffic (DoS)"
        elif len(self.port_map.get(src_ip, set())) > self.PORT_SCAN_THRESHOLD:
            threat_detected = True
            reason = "Port Scanning Detected"

        # 3. Action
        if threat_detected:
            # Block first for speed
            success = FirewallManager.block_ip(src_ip)
            if success:
                self.blocked_ips.add(src_ip)
                
                # Resolve name for alert
                hostname = self.get_hostname(src_ip)

                alert_msg = f"BLOCKED {src_ip} ({hostname}): {reason}"
                self.alert_stack.push(alert_msg)
                
                # Pass hostname to GUI
                self.gui_callback("ALERT", (src_ip, hostname, reason))
        else:
            # Resolve name for visual map (only do this for traffic occasionally or always)
            hostname = self.get_hostname(src_ip)
            self.gui_callback("TRAFFIC", (src_ip, hostname, dst_ip, proto, length))

    def stop(self):
        self.stop_event.set()

# ==========================================
# PART 3: VISUALIZATION MODULE (GUI)
# ==========================================

class HipsDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("HIPS - Intrusion Prevention System")
        self.root.geometry("1100x750")
        
        # Initialize Data Structures
        self.blacklist_bst = BlacklistBST()
        self.populate_dummy_blacklist()
        self.network_graph = NetworkGraph()

        # Styles
        style = ttk.Style()
        style.configure("Treeview", font=('Consolas', 10))
        style.configure("TLabel", font=('Arial', 10))

        # --- Layout ---
        
        # Top Frame: Controls
        control_frame = ttk.LabelFrame(root, text="Controls", padding=10)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        self.btn_start = ttk.Button(control_frame, text="Start HIPS", command=self.start_system)
        self.btn_start.pack(side="left", padx=5)
        
        self.btn_stop = ttk.Button(control_frame, text="Stop HIPS", command=self.stop_system, state="disabled")
        self.btn_stop.pack(side="left", padx=5)

        # NEW: Simulation Button
        self.btn_sim = ttk.Button(control_frame, text="Simulate Attack", command=self.simulate_attack)
        self.btn_sim.pack(side="right", padx=5)

        lbl_status = ttk.Label(control_frame, text="Status: Ready (Run as Admin for Block)", foreground="blue")
        lbl_status.pack(side="left", padx=20)
        self.lbl_status = lbl_status

        # Middle Frame: Split into Traffic Log and Visual Map
        mid_frame = tk.Frame(root)
        mid_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Left: Live Traffic Table
        traffic_frame = ttk.LabelFrame(mid_frame, text="Live Traffic Monitor (Queue Processing)", padding=5)
        traffic_frame.pack(side="left", fill="both", expand=True)

        columns = ("Time", "Source", "Destination", "Protocol", "Size")
        self.tree = ttk.Treeview(traffic_frame, columns=columns, show="headings", height=15)
        for col in columns:
            self.tree.heading(col, text=col)
            # Make Source column wider to fit hostnames
            width = 150 if col == "Source" else 90
            self.tree.column(col, width=width)
            
        self.tree.pack(fill="both", expand=True)

        # Right: Visual Map (Graph)
        map_frame = ttk.LabelFrame(mid_frame, text="Network Map Visualization (Graph)", padding=5)
        map_frame.pack(side="right", fill="both", expand=True)
        
        self.canvas = tk.Canvas(map_frame, bg="white", width=400, height=350)
        self.canvas.pack(fill="both", expand=True)
        self.nodes_drawn = {} 

        # Bottom Frame: Alerts (Stack)
        alert_frame = ttk.LabelFrame(root, text="Security Alerts (Stack Management)", padding=10)
        alert_frame.pack(fill="x", padx=10, pady=5)

        # Listbox for alerts
        self.alert_list = tk.Listbox(alert_frame, height=6, fg="red", font=('Consolas', 10, 'bold'))
        self.alert_list.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # NEW: Unblock Button
        self.btn_unblock = ttk.Button(alert_frame, text="Unblock Selected IP", command=self.unblock_selected_ip)
        self.btn_unblock.pack(side="right", padx=5)

        # System State
        self.sniffer = None
        self.detector = None
        self.is_running = False

        # Draw "LocalHost" center node
        self.center_x, self.center_y = 200, 175
        self.draw_node("LocalHost", self.center_x, self.center_y, "blue")

    def populate_dummy_blacklist(self):
        # Add some dummy malicious IPs for the BST
        threats = ["192.168.1.100", "10.0.0.5", "172.16.0.25"]
        for ip in threats:
            self.blacklist_bst.insert(ip)

    def draw_node(self, name, x, y, color="gray"):
        """Draws a node on the canvas."""
        r = 20
        self.canvas.create_oval(x-r, y-r, x+r, y+r, fill=color, outline="black")
        # Truncate long names for the graph bubble
        display_name = name
        if len(display_name) > 15:
            display_name = display_name[:12] + "..."
            
        self.canvas.create_text(x, y, text=display_name, font=("Arial", 8))
        self.nodes_drawn[name] = (x, y) # Store by Full Name/IP key

    def draw_edge(self, src, dst, color="black"):
        """Draws a line between nodes."""
        if src in self.nodes_drawn and dst in self.nodes_drawn:
            x1, y1 = self.nodes_drawn[src]
            x2, y2 = self.nodes_drawn[dst]
            self.canvas.create_line(x1, y1, x2, y2, fill=color, arrow=tk.LAST)

    def get_valid_node_position(self):
        """Finds a random position on canvas that doesn't overlap with existing nodes."""
        min_dist = 50 
        width = int(self.canvas.cget("width"))
        height = int(self.canvas.cget("height"))
        
        for _ in range(50):
            rx = random.randint(40, width - 40)
            ry = random.randint(40, height - 40)
            
            dist_center = ((rx - self.center_x)**2 + (ry - self.center_y)**2)**0.5
            if dist_center < min_dist:
                continue

            overlap = False
            for (nx, ny) in self.nodes_drawn.values():
                dist = ((rx - nx)**2 + (ry - ny)**2)**0.5
                if dist < min_dist:
                    overlap = True
                    break
            
            if not overlap:
                return rx, ry
        
        return random.randint(40, width - 40), random.randint(40, height - 40)
    
    def simulate_attack(self):
        """Manually trigger an alert for demonstration purposes."""
        sim_ip = "45.155.205.10"
        sim_host = "Simulated Attacker (Russia)"
        sim_reason = "Signature Match: SQL Injection Attempt"
        
        # Inject directly into GUI Alert list (Bypassing detection engine logic for safety)
        self.update_gui("ALERT", (sim_ip, sim_host, sim_reason))
        messagebox.showinfo("Simulation", "Simulated Attack Injected! Check Alerts.")

    def unblock_selected_ip(self):
        """Unblocks the IP currently selected in the Alert Listbox."""
        selection = self.alert_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an alert (row) from the list to unblock.")
            return
        
        # Get text: "[HH:MM:SS] BLOCKED 1.2.3.4 (Hostname) : Reason..."
        msg = self.alert_list.get(selection[0])
        try:
            # Parse the IP from the string (It's the 3rd word, index 2)
            parts = msg.split()
            # parts example: ['[16:40:00]', 'BLOCKED', '142.250.x.x', '(google.com)', ':', ...]
            ip_to_unblock = parts[2]
            
            # 1. Remove Firewall Rule
            if FirewallManager.unblock_ip(ip_to_unblock):
                # 2. Allow detection engine to see it again (remove from ignore list)
                if self.detector and ip_to_unblock in self.detector.blocked_ips:
                    self.detector.blocked_ips.remove(ip_to_unblock)
                
                # 3. Update Visuals (Turn node Green)
                # Note: Nodes are now keyed by Hostname in traffic, but might be IP in manual unblock.
                # Simplification: We just try to unblock firewall. Visual update relies on exact key match.
                # If we want to turn the node green, we'd need to know its display name.
                # We can iterate to find it.
                
                messagebox.showinfo("Success", f"IP {ip_to_unblock} has been unblocked.")
                self.alert_list.delete(selection[0])
                
        except Exception as e:
            messagebox.showerror("Error", f"Could not parse IP or unblock: {e}")

    def update_gui(self, type, data):
        """Callback from threads to update GUI safely."""
        self.root.after(0, lambda: self._process_gui_update(type, data))

    def _process_gui_update(self, type, data):
        if not self.is_running: return

        timestamp = time.strftime("%H:%M:%S")

        if type == "TRAFFIC":
            src_ip, src_host, dst, proto, length = data
            
            # Use Hostname in Table
            self.tree.insert("", 0, values=(timestamp, src_host, dst, proto, length))
            if len(self.tree.get_children()) > 50:
                self.tree.delete(self.tree.get_children()[-1])
            
            # Use Hostname in Graph
            node_key = src_host # Key the node by Name (e.g., "Google Service")
            
            if node_key not in self.nodes_drawn:
                rx, ry = self.get_valid_node_position()
                self.draw_node(node_key, rx, ry, "green")
                self.draw_edge("LocalHost", node_key)
            
        elif type == "ALERT":
            src, hostname, reason = data
            msg = f"[{timestamp}] BLOCKED {src} ({hostname}) : {reason}"
            self.alert_list.insert(0, msg)
            
            # Update Visuals to Red
            # We must match the key used in TRAFFIC (hostname)
            if hostname in self.nodes_drawn:
                x, y = self.nodes_drawn[hostname]
                self.draw_node(hostname, x, y, "red")
            elif src in self.nodes_drawn: # Fallback if keyed by IP
                x, y = self.nodes_drawn[src]
                self.draw_node(src, x, y, "red")

    def start_system(self):
        if self.is_running: return
        
        self.is_running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.lbl_status.config(text="Status: SYSTEM ACTIVE - Monitoring...", foreground="green")

        self.sniffer = PacketCaptureThread()
        self.detector = DetectionEngine(self.update_gui, self.blacklist_bst)
        
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

# ==========================================
# ENTRY POINT
# ==========================================
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