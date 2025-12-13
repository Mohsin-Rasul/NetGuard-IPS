import threading
import time
import subprocess
import socket
import datetime
import sys

# Handle Scapy import
try:
    from scapy.all import sniff, IP, TCP, UDP, ARP, Raw
except ImportError:
    pass 

# ==========================================
# PART 2: FUNCTIONAL MODULES
# ==========================================

class FirewallManager:
    """Response Module: Interact with Windows Firewall"""
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
            print(f"[ERROR] Failed to block {ip_address}. Run as Admin.")
            return False

    @staticmethod
    def unblock_ip(ip_address):
        rule_name = f"HIPS_BLOCK_{ip_address}"
        command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        try:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL)
            print(f"[FIREWALL] Unblocked IP: {ip_address}")
            return True
        except subprocess.CalledProcessError:
            return False

class Logger:
    """Feature 4: Alert System - Log File Entry"""
    @staticmethod
    def log_alert(ip, reason, severity):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{severity.upper()}] IP: {ip} - {reason}\n"
        try:
            with open("hips_alerts.log", "a") as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Logging Error: {e}")

class PacketCaptureThread(threading.Thread):
    """Packet Capture Module: Multithreaded Sniffer"""
    def __init__(self, packet_queue):
        super().__init__()
        self.packet_queue = packet_queue
        self.stop_event = threading.Event()
        self.daemon = True

    def run(self):
        print("[SNIFFER] Started...")
        while not self.stop_event.is_set():
            try:
                # Capture 1 packet at a time. Feature 1: Real-Time Packet Capture
                sniff(count=1, prn=self.process_packet, store=0, timeout=1)
            except Exception as e:
                time.sleep(2)

    def process_packet(self, packet):
        # Feature 1: Extract packets. We accept IP and ARP.
        if IP in packet or ARP in packet:
            self.packet_queue.put(packet)

    def stop(self):
        self.stop_event.set()

class DetectionEngine(threading.Thread):
    """Detection Engine: Signature Matching & Anomaly Detection"""
    def __init__(self, packet_queue, gui_callback, blacklist_bst, alert_stack, network_graph):
        super().__init__()
        self.packet_queue = packet_queue
        self.stop_event = threading.Event()
        self.daemon = True
        self.gui_callback = gui_callback
        self.blacklist = blacklist_bst
        self.alert_stack = alert_stack
        self.network_graph = network_graph
        
        # Detection States
        self.packet_counts = {} 
        self.port_map = {} 
        self.syn_track = {} # Feature 2: SYN Flood Detection
        self.blocked_ips = set() 
        self.start_time = time.time()
        
        # Feature 6: ARP Spoofing Prevention Data
        self.arp_table = {} # Stores IP -> MAC mappings
        
        # Feature 7: Whitelist Management
        self.whitelist = set()
        self.local_ip = self.get_local_ip()
        self.whitelist.add(self.local_ip)
        self.whitelist.add("127.0.0.1")
        self.whitelist.add("0.0.0.0")
        
        # Thresholds
        self.THRESHOLD_PPS = 150 # Rate Limiting (Feature 5)
        self.PORT_SCAN_THRESHOLD = 5 # Port Scanning (Feature 2)
        self.SYN_THRESHOLD = 20 # SYN packets per second
        self.dns_cache = {}

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def get_hostname(self, ip):
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(0.2) 
            hostname = socket.gethostbyaddr(ip)[0]
            if "1e100.net" in hostname:
                hostname = "Google/YouTube Service"
            elif "google" in hostname:
                hostname = "Google Service"
            elif "fbcdn" in hostname:
                hostname = "Facebook/Meta"
            socket.setdefaulttimeout(old_timeout)
        except:
            hostname = ip
        self.dns_cache[ip] = hostname
        return hostname

    def run(self):
        print("[DETECTION] Engine Started...")
        while not self.stop_event.is_set():
            try:
                if not self.packet_queue.empty():
                    pkt = self.packet_queue.get()
                    self.analyze(pkt)
                else:
                    time.sleep(0.1)
            except Exception as e:
                print(f"[DETECTION ERROR] {e}")

    def analyze(self, pkt):
        # Feature 6: ARP Spoofing Prevention
        if ARP in pkt:
            if pkt[ARP].op == 2:
                ip_src = pkt[ARP].psrc
                mac_src = pkt[ARP].hwsrc
                
                if ip_src in self.arp_table:
                    if self.arp_table[ip_src] != mac_src:
                        self.trigger_alert(ip_src, "ARP Spoofing Detected", "High")
                        return
                
                self.arp_table[ip_src] = mac_src
            return 

        if IP not in pkt:
            return

        # Extract Core Information
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
        length = len(pkt)
        
        sport = 0
        dport = 0
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        # Filter local traffic
        if src_ip != self.local_ip and dst_ip != self.local_ip:
            return
            
        # Update Graph
        self.network_graph.add_connection(src_ip, dst_ip)

        # Whitelist Check
        if src_ip in self.whitelist:
            if src_ip == self.local_ip:
                hostname = self.get_hostname(src_ip)
                self.gui_callback("TRAFFIC", (src_ip, hostname, dst_ip, proto, length))
            return

        if src_ip in self.blocked_ips:
            return

        # Reset counters
        current_time = time.time()
        if current_time - self.start_time > 1.0:
            self.packet_counts = {}
            self.port_map = {} 
            self.syn_track = {}
            self.start_time = current_time

        threat_detected = False
        reason = ""
        severity = "Low"

        # 1. Signature Matching
        if Raw in pkt:
            try:
                payload = str(pkt[Raw].load)
                if "password" in payload.lower() or "admin" in payload.lower():
                    threat_detected = True
                    reason = "Suspicious Payload (Keyword Match)"
                    severity = "Medium"
            except:
                pass

        # 2. SYN Flood Detection
        if TCP in pkt and pkt[TCP].flags == 'S': 
            self.syn_track[src_ip] = self.syn_track.get(src_ip, 0) + 1
            if self.syn_track[src_ip] > self.SYN_THRESHOLD:
                threat_detected = True
                reason = "SYN Flood Attack (Flooding)"
                severity = "High"

        # 3. Port Scanning Detection
        if dport > 0:
            if src_ip not in self.port_map:
                self.port_map[src_ip] = set()
            self.port_map[src_ip].add(dport)
            if len(self.port_map[src_ip]) > self.PORT_SCAN_THRESHOLD:
                threat_detected = True
                reason = "Port Scanning Detected (Scanning)"
                severity = "Medium"

        # 4. Rate Limiting / DoS
        self.packet_counts[src_ip] = self.packet_counts.get(src_ip, 0) + 1
        if self.packet_counts[src_ip] > self.THRESHOLD_PPS:
            threat_detected = True
            reason = "High Traffic Rate (DoS/Flooding)"
            severity = "High"

        # 5. Blacklist Check
        if self.blacklist.search(src_ip):
            threat_detected = True
            reason = "Blacklisted IP (Known Attacker)"
            severity = "High"

        if threat_detected:
            self.trigger_alert(src_ip, reason, severity)
        else:
            hostname = self.get_hostname(src_ip)
            self.gui_callback("TRAFFIC", (src_ip, hostname, dst_ip, proto, length))

    def trigger_alert(self, src_ip, reason, severity):
        success = FirewallManager.block_ip(src_ip)
        if success:
            self.blocked_ips.add(src_ip)
            hostname = self.get_hostname(src_ip)
            
            print(f"[ALERT] {severity.upper()}: {src_ip} - {reason}")
            Logger.log_alert(src_ip, reason, severity)
            
            alert_msg = f"[{severity.upper()}] BLOCKED {src_ip} ({hostname}): {reason}"
            self.alert_stack.push(alert_msg)
            self.gui_callback("ALERT", (src_ip, hostname, reason, severity))

    def stop(self):
        self.stop_event.set()