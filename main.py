import tkinter as tk
from tkinter import ttk, messagebox
import queue
import subprocess
import random
import sys
import time
import os
import socket
import json
import csv
try:
    import psutil
except Exception:
    psutil = None

# --- CRITICAL FIX: Ensure modules are found ---
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Import custom modules
try:
    from data_structures import BlacklistBST, AlertStack, NetworkGraph
    from core_modules import PacketCaptureThread, DetectionEngine, FirewallManager, Logger
except ImportError as e:
    print(f"CRITICAL IMPORT ERROR: {e}")
    sys.exit(1)

# Check for Scapy
try:
    import scapy.all
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Missing Dependency", "Scapy is not installed.\nPlease run: pip install scapy")
    sys.exit(1)

# ==========================================
# PART 3: VISUALIZATION (GUI)
# ==========================================

class HipsDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("HIPS - Intrusion Prevention System (Data Structures and Algorithm Project)")
        self.root.geometry("1100x750")
        
        # Initialize Labs Logic
        self.blacklist_bst = BlacklistBST()
        self.alert_stack = AlertStack()
        self.network_graph = NetworkGraph()
        
        # [Lab 7] Queue Implementation
        self.packet_queue = queue.Queue()
        
        self.populate_dummy_blacklist()
        self.captured_packets_data = [] 

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

        self.btn_sort = ttk.Button(control_frame, text="Sort Traffic (Bubble Sort)", command=self.sort_traffic)
        self.btn_sort.pack(side="left", padx=5)

        self.btn_sim = ttk.Button(control_frame, text="Simulate Attack", command=self.simulate_attack)
        self.btn_sim.pack(side="right", padx=5)

        # Toggle to analyze local outgoing/incoming traffic (e.g., browser)
        self.analyze_local_var = tk.BooleanVar(value=False)
        self.chk_analyze_local = ttk.Checkbutton(control_frame, text="Analyze Local Traffic", variable=self.analyze_local_var, command=self.toggle_analyze_local)
        self.chk_analyze_local.pack(side="right", padx=5)

        self.btn_privacy = ttk.Button(control_frame, text="Privacy Info", command=self.show_privacy_info)
        self.btn_privacy.pack(side="right", padx=5)
        
        self.btn_manage_blocks = ttk.Button(control_frame, text="Manage Blocks", command=self.manage_blocks)
        self.btn_manage_blocks.pack(side="right", padx=5)
        
        self.btn_export_stats = ttk.Button(control_frame, text="Export Stats", command=self.export_stats)
        self.btn_export_stats.pack(side="right", padx=5)

        self.lbl_status = ttk.Label(control_frame, text="Status: Ready (Check 'hips_alerts.log' for history)", foreground="blue")
        self.lbl_status.pack(side="left", padx=20)
        
        self.lbl_stats = ttk.Label(control_frame, text="[Stats: -- ]", foreground="darkgreen")
        self.lbl_stats.pack(side="left", padx=10)

        mid_frame = tk.Frame(root)
        mid_frame.pack(fill="both", expand=True, padx=10, pady=5)

        traffic_frame = ttk.LabelFrame(mid_frame, text="Live Traffic (Queue Buffer)", padding=5)
        traffic_frame.pack(side="left", fill="both", expand=True)

        columns = ("Time", "Source", "Source IP", "Destination", "Dest Name", "S.Port", "D.Port", "Protocol", "Size", "PID/Proc")
        self.tree = ttk.Treeview(traffic_frame, columns=columns, show="headings", height=15)
        for col in columns:
            self.tree.heading(col, text=col)
            if col == "Source":
                self.tree.column(col, width=180)
            elif col == "Source IP" or col == "Destination" or col == "Dest Name":
                self.tree.column(col, width=130)
            elif col in ("S.Port", "D.Port", "Protocol", "Size"):
                self.tree.column(col, width=60, anchor='center')
            else:
                self.tree.column(col, width=100)
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
        
        # Listbox to show local traffic activity when analysis is enabled
        self.activity_list = tk.Listbox(alert_frame, height=6, fg="black", font=('Consolas', 9))
        self.activity_list.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.btn_unblock = ttk.Button(alert_frame, text="Unblock IP", command=self.unblock_selected_ip)
        self.btn_unblock.pack(side="right", padx=5)

        self.btn_clear_activity = ttk.Button(alert_frame, text="Clear Activity", command=self.clear_activity)
        self.btn_clear_activity.pack(side="right", padx=5)

        self.sniffer = None
        self.detector = None
        self.is_running = False
        
        self.center_x, self.center_y = 200, 175
        self.draw_node("LocalHost", self.center_x, self.center_y, "blue")

    def get_process_for_connection(self, local_side_is_self, local_ip, remote_ip, remote_port):
        """Try to map a connection to a PID/process name using psutil (best-effort)."""
        if not psutil:
            return "(psutil missing)"
        try:
            conns = psutil.net_connections()
            for c in conns:
                r = c.raddr
                if not r:
                    continue
                try:
                    raddr = r.ip
                    rport = r.port
                except Exception:
                    continue
                if raddr == remote_ip and rport == remote_port:
                    try:
                        p = psutil.Process(c.pid)
                        return f"{c.pid}/{p.name()}"
                    except Exception:
                        return f"{c.pid}"
        except Exception:
            return "(lookup-failed)"
        return ""

    def resolve_local_device(self, ip):
        """Resolve a LAN device name for a local IP: try reverse DNS then arp table."""
        try:
            name = None
            try:
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                name = None
            if name:
                return name
            # Fallback: parse `arp -a`
            try:
                out = subprocess.check_output(["arp", "-a"], universal_newlines=True)
                for line in out.splitlines():
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
            except Exception:
                pass
        except Exception:
            pass
        return ip

    def populate_dummy_blacklist(self):
        threats = ["192.168.1.100", "10.0.0.5", "172.16.0.25"]
        for ip in threats:
            self.blacklist_bst.insert(ip)

    def export_stats(self):
        """Export metrics to JSON and CSV files."""
        if not self.detector:
            messagebox.showwarning("Export Stats", "System not started yet.")
            return
        
        from datetime import datetime
        
        metrics = self.detector.metrics.copy()
        uptime = time.time() - metrics.get('start_time', time.time())
        metrics['uptime_seconds'] = uptime
        metrics['start_time'] = datetime.fromtimestamp(metrics['start_time']).isoformat()
        
        try:
            # Export JSON
            json_file = "hips_stats.json"
            with open(json_file, 'w') as f:
                json.dump(metrics, f, indent=2)
            
            # Export CSV
            csv_file = "hips_stats.csv"
            with open(csv_file, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(["Metric", "Value"])
                for k, v in metrics.items():
                    w.writerow([k, v])
            
            messagebox.showinfo("Export Stats", f"Exported to {json_file} and {csv_file}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def sort_traffic(self):
        data = self.captured_packets_data
        n = len(data)
        if n < 2: return
        for i in range(n):
            for j in range(0, n-i-1):
                # Column 8 is Size/Length in our row_data
                if data[j][8] < data[j+1][8]: 
                    data[j], data[j+1] = data[j+1], data[j]
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
    
    def generate_random_ip(self):
        """Generate a random IP address from worldwide ranges"""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

    def get_random_host(self):
        """Get random hostname/host"""
        hosts = [
            "Attacker (industrialhacker.com)",
            "Unknown (suspicious-ip.net)",
            "Botnet Node (malware-c2.ru)",
            "Compromised Server (hacked-site.org)",
            "Proxy (anonymizing-vpn.xyz)",
            "Spoofed Host (fake-domain.com)",
            "Zombie PC (infected-machine.ir)",
            "Attacker (darknet-actor.onion)"
        ]
        return random.choice(hosts)

    def get_random_reason(self):
        """Get random attack reason"""
        reasons = [
            "Signature Match: SQL Injection (Simulation)",
            "Anomaly Detected: Port Scanning Activity",
            "Threat Intel: Known Malicious IP",
            "Behavior Analysis: Brute Force Attempt",
            "Signature Match: XSS Attack Vector",
            "Policy Violation: Unauthorized Access",
            "Signature Match: DDoS Attack Pattern",
            "Anomaly: Unusual Traffic Volume",
            "Signature Match: Ransomware Signature",
            "Threat Alert: Known C&C Communication"
        ]
        return random.choice(reasons)

    def get_random_severity(self):
        """Get random severity level"""
        severities = ["Low", "Medium", "High", "Critical"]
        return random.choice(severities)

    def simulate_attack(self):
        # Generate random IP that is NOT already blocked
        sim_ip = self.generate_random_ip()
        attempts = 0
        while self.detector and attempts < 50:
            blocked = False
            try:
                with self.detector.blocked_lock:
                    blocked = (sim_ip in self.detector.blocked_ips)
            except Exception:
                blocked = (sim_ip in getattr(self.detector, 'blocked_ips', set()))
            if not blocked:
                break
            sim_ip = self.generate_random_ip()
            attempts += 1
        
        sim_host = self.get_random_host()
        sim_reason = self.get_random_reason()
        sim_severity = self.get_random_severity()
        # Show simulated alert in GUI and log it
        self.update_gui("ALERT", (sim_ip, sim_host, sim_reason, sim_severity))
        Logger.log_alert(sim_ip, sim_reason, sim_severity)
        messagebox.showinfo("Simulation", f"Simulated Attack Injected!\nIP: {sim_ip}\nSeverity: {sim_severity}")

        # Ensure the simulated IP is actually blocked by the detection engine
        try:
            if self.detector:
                # Use the same alert path as real detections
                self.detector.trigger_alert(sim_ip, sim_reason, sim_severity)
        except Exception as e:
            # Log any error but don't crash the GUI
            print(f"[SIMULATE] Failed to trigger alert for {sim_ip}: {e}")

    def unblock_selected_ip(self):
        selection = self.alert_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Select an alert first.")
            return
        msg = self.alert_list.get(selection[0])
        try:
            import re
            # Try to extract an IP (IPv4 or IPv6) after the word BLOCKED
            m = re.search(r"BLOCKED\s+([^\s(]+)", msg)
            if not m:
                # Fallback: split and take the 3rd token
                parts = msg.split()
                ip_to_unblock = parts[2]
            else:
                ip_to_unblock = m.group(1)

            # First, remove from in-memory blocked set and persist so UI reflects unblocked state
            if self.detector:
                try:
                    with self.detector.blocked_lock:
                        if ip_to_unblock in self.detector.blocked_ips:
                            self.detector.blocked_ips.remove(ip_to_unblock)
                    try:
                        self.detector._save_persisted_blocks()
                    except Exception:
                        pass
                except Exception as e:
                    print(f"[UNBLOCK] Error removing from in-memory set: {e}")

            # Then attempt OS-level unblock; if it fails, inform the user but UI state is already updated
            if FirewallManager.unblock_ip(ip_to_unblock):
                messagebox.showinfo("Success", f"IP {ip_to_unblock} has been unblocked.")
            else:
                messagebox.showwarning("Partial Success", f"IP {ip_to_unblock} removed from application blocklist, but OS firewall rule may require admin rights to remove.")
            # Remove alert from list UI
            try:
                self.alert_list.delete(selection[0])
            except Exception:
                pass
        except Exception as e:
            messagebox.showerror("Error", f"Could not unblock: {e}")

    # --- Thread-Safe GUI Update ---
    def update_gui(self, type, data):
        # We use 'after' to schedule the update on the main thread
        self.root.after(0, lambda: self._process_gui_update(type, data))

    def _process_gui_update(self, type, data):
        if not self.is_running: return

        timestamp = time.strftime("%H:%M:%S")

        if type == "TRAFFIC":
            # data: (src_ip, src_host, dst_ip, proto, length, sport, dport)
            src_ip, src_host, dst, proto, length, sport, dport = data

            # Show friendly host and IP together
            display_source = f"{src_host} ({src_ip})"
            # Resolve local device names for local destinations
            local_ip = getattr(self.detector, 'local_ip', None)
            dst_display = dst
            try:
                if local_ip and dst == local_ip:
                    dst_display = self.resolve_local_device(dst)
            except Exception:
                dst_display = dst

            # Try to map to PID/process (best-effort)
            pidinfo = ""
            try:
                if local_ip:
                    if src_ip == local_ip:
                        pidinfo = self.get_process_for_connection(True, local_ip, dst, int(dport) if dport else 0)
                    elif dst == local_ip:
                        pidinfo = self.get_process_for_connection(False, local_ip, src_ip, int(sport) if sport else 0)
            except Exception:
                pidinfo = ""

            row_data = (timestamp, display_source, src_ip, dst, dst_display, sport, dport, proto, length, pidinfo)
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
            # Unpack the 4 items sent by detection engine
            src, hostname, reason, severity = data
            
            msg = f"[{severity.upper()}] BLOCKED {src} ({hostname}) : {reason}"
            
            # Insert at the top (index 0) so newest alerts are first
            self.alert_list.insert(0, msg)
            
            # Turn node RED
            if hostname in self.nodes_drawn:
                x, y = self.nodes_drawn[hostname]
                self.draw_node(hostname, x, y, "red")
            elif src in self.nodes_drawn: 
                x, y = self.nodes_drawn[src]
                self.draw_node(src, x, y, "red")

        elif type == 'LOCAL_ACTIVITY':
            # data: (direction, src_ip, dst_ip, snippet)
            direction, src_ip, dst_ip, snippet = data
            ts = time.strftime("%H:%M:%S")
            entry = f"{ts} [{direction}] {src_ip} -> {dst_ip} : {snippet}"
            self.activity_list.insert(0, entry)
            if self.activity_list.size() > 200:
                self.activity_list.delete(tk.END)

    def clear_activity(self):
        # Clear activity listbox
        try:
            self.activity_list.delete(0, tk.END)
        except Exception:
            pass

        # Remove local-related rows from traffic view and captured_packets_data
        try:
            removed = []
            for iid in list(self.tree.get_children()):
                vals = self.tree.item(iid, 'values')
                # values layout: (Time, Source, Source IP, Destination, S.Port, D.Port, Protocol, Size, PID/Proc)
                try:
                    src_ip = vals[2]
                    dst = vals[3]
                except Exception:
                    continue
                if src_ip == getattr(self.detector, 'local_ip', None) or dst == getattr(self.detector, 'local_ip', None):
                    removed.append(iid)
            for iid in removed:
                try:
                    self.tree.delete(iid)
                except Exception:
                    pass

            # Filter captured_packets_data
            try:
                local = getattr(self.detector, 'local_ip', None)
                if local:
                    self.captured_packets_data = [r for r in self.captured_packets_data if not (r[2] == local or r[3] == local)]
            except Exception:
                pass
        except Exception:
            pass

    def start_system(self):
        if self.is_running: return
        self.is_running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.lbl_status.config(text="Status: SYSTEM ACTIVE - Logging to file", foreground="green")

        # Create detector first so we can share its blocked_ips with the sniffer.
        self.detector = DetectionEngine(
            self.packet_queue,
            self.update_gui,
            self.blacklist_bst,
            self.alert_stack,
            self.network_graph,
            analyze_local=self.analyze_local_var.get()
        )

        # Pass a reference to the detector's blocked_ips set so the sniffer can
        # drop blocked packets before they reach the queue. Also pass lock.
        self.sniffer = PacketCaptureThread(self.packet_queue, blocked_ips=self.detector.blocked_ips, blocked_lock=self.detector.blocked_lock)

        # Start detector first so it is ready to consume packets.
        self.detector.start()
        self.sniffer.start()
        
        # Start periodic stats update
        self.update_stats_display()

    def toggle_analyze_local(self):
        # Update detector setting if running; otherwise the value is used when starting.
        val = self.analyze_local_var.get()
        if self.detector:
            self.detector.analyze_local = val
        # Clear activity list when turning off
        if not val:
            self.activity_list.delete(0, tk.END)

    def clear_activity(self):
        try:
            self.activity_list.delete(0, tk.END)
        except Exception:
            pass

    def show_privacy_info(self):
        message = (
            "When 'Analyze Local Traffic' is enabled the system will inspect small payload snippets\n"
            "from local inbound/outbound packets and display them in the Activity pane.\n\n"
            "Privacy note: snippets may contain parts of URLs or request headers.\n"
            "Do not enable this option on multi-user systems or when handling sensitive data."
        )
        messagebox.showinfo("Privacy Info", message)
    
    def update_stats_display(self):
        """Update the stats label periodically."""
        if self.detector and self.is_running:
            m = self.detector.metrics
            stats_text = (f"[Stats: {m['packets_processed']} pkts | "
                         f"{m['alerts_triggered']} alerts | "
                         f"{m['ips_blocked']} blocked IPs | "
                         f"{m['ipv6_blocked']} IPv6]")
            self.lbl_stats.config(text=stats_text)
        self.root.after(1000, self.update_stats_display)

    def stop_system(self):
        if not self.is_running: return
        self.is_running = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.lbl_status.config(text="Status: STOPPED", foreground="red")

        if self.sniffer: self.sniffer.stop()
        if self.detector: self.detector.stop()

    def manage_blocks(self):
        if not self.detector:
            messagebox.showwarning("Manage Blocks", "Start the system before managing blocks.")
            return

        win = tk.Toplevel(self.root)
        win.title("Manage Blocked IPs")
        win.geometry("400x300")

        lb = tk.Listbox(win, font=('Consolas', 11))
        lb.pack(fill='both', expand=True, padx=8, pady=8)

        def refresh_list():
            lb.delete(0, tk.END)
            with self.detector.blocked_lock:
                items = sorted(list(self.detector.blocked_ips))
            for ip in items:
                lb.insert(tk.END, ip)

        def unblock_selected():
            sel = lb.curselection()
            if not sel:
                messagebox.showwarning("Unblock", "Select an IP first.")
                return
            ip = lb.get(sel[0])
            ok, msg = FirewallManager.unblock_ip(ip)
            # Regardless of OS-level success, ensure application-level state is consistent
            try:
                with self.detector.blocked_lock:
                    if ip in self.detector.blocked_ips:
                        self.detector.blocked_ips.remove(ip)
                try:
                    self.detector._save_persisted_blocks()
                except Exception:
                    pass
            except Exception as e:
                print(f"[UNBLOCK] Error updating in-memory blocks: {e}")
            refresh_list()
            # Remove alert entries that mention this IP
            for i in range(self.alert_list.size()-1, -1, -1):
                try:
                    if ip in self.alert_list.get(i):
                        self.alert_list.delete(i)
                except Exception:
                    pass
            if ok:
                messagebox.showinfo("Unblock", f"IP {ip} unblocked.")
            else:
                messagebox.showwarning("Unblock", f"IP {ip} removed from app blocklist, but OS unblock failed: {msg}\nRun the app as Administrator to remove OS firewall rule.")

        btn_frame = tk.Frame(win)
        btn_frame.pack(fill='x', padx=8, pady=(0,8))
        ttk.Button(btn_frame, text="Refresh", command=refresh_list).pack(side='left', padx=4)
        ttk.Button(btn_frame, text="Unblock Selected", command=unblock_selected).pack(side='left', padx=4)
        ttk.Button(btn_frame, text="Close", command=win.destroy).pack(side='right', padx=4)

        refresh_list()

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