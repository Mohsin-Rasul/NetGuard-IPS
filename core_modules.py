import threading
import time
import subprocess
import socket
import datetime
import sys
import json
import os
import hmac
import hashlib

# Handle Scapy import gracefully
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ARP, Raw
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
            # Try normal (may fail if not elevated)
            res = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(f"[FIREWALL] Unblocked IP: {ip_address}")
            return True, res.stdout.strip()
        except subprocess.CalledProcessError as e:
            err = (e.stderr or str(e)).strip()
            print(f"[WARN] Unblock failed (non-elevated): {err}")
            # Attempt elevated removal via PowerShell Start-Process (will prompt UAC)
            try:
                ps_cmd = f"Start-Process netsh -ArgumentList 'advfirewall firewall delete rule name=\"{rule_name}\"' -Verb RunAs -Wait"
                subprocess.run(["powershell", "-Command", ps_cmd], check=True)
                print(f"[FIREWALL] Unblocked IP via elevation: {ip_address}")
                return True, "Unblocked via elevation"
            except Exception as e2:
                err2 = str(e2)
                print(f"[ERROR] Elevated unblock failed: {err2}")
                return False, f"{err}; {err2}"

class Logger:
    """Feature 4: Alert System - Log File Entry with Rotation"""
    LOG_FILE = "hips_alerts.log"
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
    MAX_LOG_FILES = 5

    @staticmethod
    def _rotate_logs():
        """Rotate log files when max size reached."""
        try:
            if os.path.isfile(Logger.LOG_FILE) and os.path.getsize(Logger.LOG_FILE) > Logger.MAX_LOG_SIZE:
                # Shift existing logs
                for i in range(Logger.MAX_LOG_FILES - 1, 0, -1):
                    old_file = f"{Logger.LOG_FILE}.{i}"
                    new_file = f"{Logger.LOG_FILE}.{i+1}"
                    if os.path.isfile(old_file):
                        if os.path.isfile(new_file):
                            os.remove(new_file)
                        os.rename(old_file, new_file)
                # Rename current log
                if os.path.isfile(f"{Logger.LOG_FILE}.1"):
                    os.remove(f"{Logger.LOG_FILE}.1")
                os.rename(Logger.LOG_FILE, f"{Logger.LOG_FILE}.1")
        except Exception as e:
            print(f"[WARN] Log rotation failed: {e}")

    @staticmethod
    def log_alert(ip, reason, severity):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{severity.upper()}] IP: {ip} - {reason}\n"
        try:
            Logger._rotate_logs()
            with open(Logger.LOG_FILE, "a") as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Logging Error: {e}")

class PacketCaptureThread(threading.Thread):
    """Packet Capture Module: Multithreaded Sniffer"""
    def __init__(self, packet_queue, blocked_ips=None, blocked_lock=None):
        super().__init__()
        self.packet_queue = packet_queue
        self.stop_event = threading.Event()
        self.daemon = True
        # Optional shared set of blocked IPs (DetectionEngine.blocked_ips)
        self.blocked_ips = blocked_ips
        self.blocked_lock = blocked_lock

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
        # Drop packets from IPs that are already blocked (filter early).
        # IPv4 early-drop
        if IP in packet:
            try:
                src_ip = packet[IP].src
                if self.blocked_ips:
                    if self.blocked_lock:
                        with self.blocked_lock:
                            if src_ip in self.blocked_ips:
                                return
                    else:
                        if src_ip in self.blocked_ips:
                            return
            except Exception:
                pass

        # IPv6 early-drop (ensure blocked IPv6 addresses are filtered too)
        try:
            if IPv6 in packet:
                try:
                    src6 = packet[IPv6].src
                    if self.blocked_ips:
                        if self.blocked_lock:
                            with self.blocked_lock:
                                if src6 in self.blocked_ips:
                                    return
                        else:
                            if src6 in self.blocked_ips:
                                return
                except Exception:
                    pass
        except NameError:
            # IPv6 not available in this environment; ignore
            pass

        if IP in packet or ARP in packet:
            self.packet_queue.put(packet)

    def stop(self):
        self.stop_event.set()


class DetectionEngine(threading.Thread):
    """Detection Engine: Signature Matching & Anomaly Detection"""
    def __init__(self, packet_queue, gui_callback, blacklist_bst, alert_stack, network_graph, analyze_local=False):
        super().__init__()
        self.packet_queue = packet_queue
        self.stop_event = threading.Event()
        self.daemon = True
        self.gui_callback = gui_callback
        self.blacklist = blacklist_bst
        self.alert_stack = alert_stack
        self.network_graph = network_graph
        # Whether to analyze local (self) traffic. When False, local_ip is treated as whitelisted.
        self.analyze_local = analyze_local
        
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
        
        # Feature 8: DNS/SNI Malicious Domain Detection
        self.malicious_domains = set()
        self.dns_query_cache = {}  # domain -> last query time
        self.try_load_malicious_domains()
        self.try_fetch_threat_intel()
        
        # Feature 11: Metrics Tracking
        self.metrics = {
            'packets_processed': 0,
            'alerts_triggered': 0,
            'ips_blocked': 0,
            'ipv6_blocked': 0,
            'domains_blocked': 0,
            'start_time': time.time()
        }
        
        # Thresholds
        self.THRESHOLD_PPS = 150 # Rate Limiting (Feature 5)
        self.PORT_SCAN_THRESHOLD = 5 # Port Scanning (Feature 2)
        self.SYN_THRESHOLD = 20 # SYN packets per second
        self.dns_cache = {}

        # Thread-safety for blocked IPs
        self.blocked_lock = threading.Lock()

        # Persistence file for blocked IPs
        self._blocked_store = os.path.join(os.path.dirname(__file__), "blocked_ips.json")

        # Load persisted blocked IPs (if any) and attempt to re-apply OS blocks
        try:
            self._load_persisted_blocks()
        except Exception as e:
            print(f"[WARN] Could not load persisted blocks: {e}")

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
                    self.metrics['packets_processed'] += 1
                    self.analyze(pkt)
                else:
                    time.sleep(0.1)
            except Exception as e:
                print(f"[DETECTION ERROR] {e}")

    def analyze(self, pkt):
        # Feature 9: IPv6 Support
        if IPv6 in pkt and IP not in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
            length = len(pkt)
            sport, dport = 0, 0
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            
            # Process IPv6 with same rules as IPv4
            with self.blocked_lock:
                if src_ip in self.blocked_ips:
                    return
            
            if src_ip in self.whitelist:
                return
            
            threat_detected = False
            reason = ""
            severity = "Low"
            
            # Blacklist check
            if self.blacklist.search(src_ip):
                threat_detected = True
                reason = "Blacklisted IPv6 (Known Attacker)"
                severity = "High"
            
            # Rate limiting
            self.packet_counts[src_ip] = self.packet_counts.get(src_ip, 0) + 1
            if self.packet_counts[src_ip] > self.THRESHOLD_PPS:
                threat_detected = True
                reason = "High IPv6 Traffic Rate (DoS)"
                severity = "High"
            
            if threat_detected:
                self.metrics['ipv6_blocked'] += 1
                self.trigger_alert(src_ip, reason, severity)
            else:
                hostname = self.get_hostname(src_ip)
                self.gui_callback("TRAFFIC", (src_ip, hostname, dst_ip, proto, length, sport, dport))
            return
        
        # Feature 6: ARP Spoofing Prevention (Moved BEFORE IP filtering)
        if ARP in pkt:
            # op=2 means 'is-at' (ARP Reply)
            if pkt[ARP].op == 2:
                ip_src = pkt[ARP].psrc
                mac_src = pkt[ARP].hwsrc
                
                # Check if we have seen this IP before
                if ip_src in self.arp_table:
                    # If the MAC address has changed for the same IP, it's spoofing!
                    if self.arp_table[ip_src] != mac_src:
                        self.trigger_alert(ip_src, "ARP Spoofing Detected (MAC Change)", "High")
                        return
                
                # Update table with current mapping
                self.arp_table[ip_src] = mac_src
            return # Done with ARP

        # Feature 8: DNS/SNI Threat Detection
        try:
            # Check DNS queries for malicious domains
            dns_domain = self.extract_dns_query_domain(pkt)
            if dns_domain:
                if dns_domain in self.malicious_domains:
                    # Extract source from DNS query
                    if IP in pkt:
                        src_ip = pkt[IP].src
                        self.trigger_alert(src_ip, f"Malicious DNS Query: {dns_domain}", "High")
                        return
            # Check TLS SNI for malicious domains
            sni_domain = self.extract_sni_from_packet(pkt)
            if sni_domain:
                if sni_domain in self.malicious_domains:
                    if IP in pkt:
                        src_ip = pkt[IP].src
                        self.trigger_alert(src_ip, f"Malicious TLS SNI: {sni_domain}", "High")
                        return
        except Exception:
            pass

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

        # Filter local traffic visualization (This stops us from seeing non-local traffic in GUI)
        # BUT we already processed ARP above, so we don't miss spoofing.
        if src_ip != self.local_ip and dst_ip != self.local_ip:
            return
            
        # Update Graph
        self.network_graph.add_connection(src_ip, dst_ip)

        # Whitelist Check
        if src_ip in self.whitelist:
            if src_ip == self.local_ip:
                # If configured to analyze local traffic, allow normal analysis to continue.
                if not self.analyze_local:
                    hostname = self.get_hostname(src_ip)
                    self.gui_callback("TRAFFIC", (src_ip, hostname, dst_ip, proto, length, sport, dport))
                    return
            else:
                return

        with self.blocked_lock:
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

        # If analyzing local traffic, also emit a LOCAL_ACTIVITY event with a small payload snippet
        try:
            if self.analyze_local and (src_ip == self.local_ip or dst_ip == self.local_ip) and Raw in pkt:
                raw_bytes = pkt[Raw].load
                try:
                    raw_text = raw_bytes.decode('utf-8', errors='replace')
                except Exception:
                    raw_text = str(raw_bytes)
                snippet = raw_text.replace('\r', ' ').split('\n')[0][:300]
                direction = 'OUT' if src_ip == self.local_ip else 'IN'
                self.gui_callback('LOCAL_ACTIVITY', (direction, src_ip, dst_ip, snippet))
        except Exception:
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
            self.metrics['alerts_triggered'] += 1
            self.trigger_alert(src_ip, reason, severity)
        else:
            hostname = self.get_hostname(src_ip)
            self.gui_callback("TRAFFIC", (src_ip, hostname, dst_ip, proto, length, sport, dport))

    def trigger_alert(self, src_ip, reason, severity):
        # Immediately add to in-memory blocked list so subsequent packets
        # are ignored without waiting for the OS firewall call to finish.
        with self.blocked_lock:
            self.blocked_ips.add(src_ip)
        
        self.metrics['ips_blocked'] += 1
        if "IPv6" in reason or "ipv6" in reason.lower():
            self.metrics['ipv6_blocked'] += 1
        if "DNS" in reason or "SNI" in reason:
            self.metrics['domains_blocked'] += 1
        
        # Persist the updated blocked set immediately
        try:
            self._save_persisted_blocks()
        except Exception as e:
            print(f"[WARN] Could not persist blocked IPs: {e}")

        hostname = self.get_hostname(src_ip)

        print(f"[ALERT] {severity.upper()}: {src_ip} - {reason}")
        Logger.log_alert(src_ip, reason, severity)

        alert_msg = f"[{severity.upper()}] BLOCKED {src_ip} ({hostname}): {reason}"
        self.alert_stack.push(alert_msg)
        self.gui_callback("ALERT", (src_ip, hostname, reason, severity))

        # Perform the OS-level firewall block asynchronously so we don't
        # delay packet processing (netsh can be slow or require admin).
        def _block_and_retry(ip, attempt=1, max_attempts=5):
            try:
                success = FirewallManager.block_ip(ip)
                if not success and attempt < max_attempts:
                    delay = [5, 15, 30, 60, 120][min(attempt-1, 4)]
                    print(f"[WARN] Firewall block failed for {ip}, retrying in {delay}s (attempt {attempt + 1})")
                    Logger.log_alert(ip, f"Firewall block failed, retrying in {delay}s (attempt {attempt + 1})", "Warning")
                    t = threading.Timer(delay, _block_and_retry, args=(ip, attempt+1, max_attempts))
                    t.daemon = True
                    t.start()
                elif not success:
                    print(f"[ERROR] Firewall block ultimately failed for {ip} after {max_attempts} attempts")
                    Logger.log_alert(ip, f"Firewall block ultimately failed after {max_attempts} attempts", "Error")
            except Exception as e:
                print(f"[ERROR] Blocking thread error for {ip}: {e}")
                Logger.log_alert(ip, f"Blocking thread error: {e}", "Error")

        t = threading.Thread(target=_block_and_retry, args=(src_ip,), daemon=True)
        t.start()

    def _save_persisted_blocks(self):
        try:
            with self.blocked_lock:
                data = list(self.blocked_ips)
            payload = {'blocked': data}
            payload_json = json.dumps(payload)
            # Sign with HMAC-SHA256 using a simple key derived from local_ip (basic protection)
            key = hashlib.sha256(self.local_ip.encode()).digest()
            signature = hmac.new(key, payload_json.encode(), hashlib.sha256).hexdigest()
            with open(self._blocked_store, 'w') as fh:
                json.dump({'blocked': data, 'signature': signature}, fh)
        except Exception as e:
            print(f"[WARN] Failed to write blocked_ips file: {e}")
            Logger.log_alert("local", f"Failed to write blocked_ips file: {e}", "Warning")

    def _load_persisted_blocks(self):
        if not os.path.isfile(self._blocked_store):
            return
        try:
            with open(self._blocked_store, 'r') as fh:
                j = json.load(fh)
                items = j.get('blocked', [])
                stored_sig = j.get('signature', '')
                # Verify HMAC-SHA256 signature
                payload_json = json.dumps({'blocked': items})
                key = hashlib.sha256(self.local_ip.encode()).digest()
                expected_sig = hmac.new(key, payload_json.encode(), hashlib.sha256).hexdigest()
                if stored_sig and stored_sig != expected_sig:
                    print(f"[WARN] Signature mismatch for blocked_ips.json — file may be tampered. Skipping load.")
                    Logger.log_alert("local", "Signature mismatch for blocked_ips.json — possible tampering", "Warning")
                    return
                for ip in items:
                    with self.blocked_lock:
                        if ip not in self.blocked_ips:
                            self.blocked_ips.add(ip)
                            # Try to re-apply OS-level block asynchronously
                            t = threading.Thread(target=FirewallManager.block_ip, args=(ip,), daemon=True)
                            t.start()
        except Exception as e:
            print(f"[WARN] Failed to load blocked_ips file: {e}")
            Logger.log_alert("local", f"Failed to load blocked_ips file: {e}", "Warning")

    def try_load_malicious_domains(self):
        """Load malicious domains from local file."""
        try:
            if os.path.isfile("malicious_domains.txt"):
                with open("malicious_domains.txt", "r") as f:
                    for line in f:
                        domain = line.strip()
                        if domain and not domain.startswith("#"):
                            self.malicious_domains.add(domain.lower())
                print(f"[DETECTION] Loaded {len(self.malicious_domains)} malicious domains")
        except Exception as e:
            print(f"[DETECTION] Failed to load malicious domains: {e}")

    def try_fetch_threat_intel(self):
        """Fetch malicious IPs/domains from public threat intel feeds."""
        print("[DETECTION] Fetching threat intelligence feeds...")
        try:
            # Example: Parse abuse.ch IP list (simple format: one IP per line)
            import urllib.request
            feeds = [
                ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "ip"),
                # Uncomment for more feeds as needed
            ]
            for feed_url, feed_type in feeds:
                try:
                    with urllib.request.urlopen(feed_url, timeout=5) as response:
                        for line in response:
                            entry = line.decode('utf-8').strip()
                            if entry and not entry.startswith("#") and feed_type == "ip":
                                self.blacklist.insert(entry)
                    print(f"[DETECTION] Updated threat intel from {feed_url}")
                except Exception as e:
                    print(f"[DETECTION] Warning: Could not fetch {feed_url}: {e}")
        except Exception as e:
            print(f"[DETECTION] Threat intel fetch failed (non-critical): {e}")

    def try_load_malicious_domains(self):
        """Load a simple list of known-malicious domains from a file (if it exists)."""
        try:
            domain_file = os.path.join(os.path.dirname(__file__), "malicious_domains.txt")
            if os.path.isfile(domain_file):
                with open(domain_file, 'r') as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith('#'):
                            self.malicious_domains.add(domain)
                print(f"[INFO] Loaded {len(self.malicious_domains)} malicious domains.")
        except Exception as e:
            print(f"[WARN] Could not load malicious_domains.txt: {e}")

    def extract_sni_from_packet(self, pkt):
        """Extract Server Name Indication (SNI) from TLS ClientHello."""
        try:
            if Raw in pkt:
                raw_load = bytes(pkt[Raw].load)
                if len(raw_load) > 43:
                    # TLS record type (0x16 = Handshake) at byte 0
                    if raw_load[0:1] == b'\x16':
                        # Handshake type at byte 5 (0x01 = ClientHello)
                        if raw_load[5:6] == b'\x01':
                            # Parse ClientHello for SNI (simplified parser)
                            # Session ID length at byte 43
                            offset = 44 + (raw_load[43] if len(raw_load) > 43 else 0)
                            # Cipher suites length (2 bytes, big-endian) at offset
                            if offset + 2 <= len(raw_load):
                                cipher_len = int.from_bytes(raw_load[offset:offset+2], 'big')
                                offset += 2 + cipher_len
                                # Compression methods length at offset
                                if offset + 1 <= len(raw_load):
                                    comp_len = raw_load[offset]
                                    offset += 1 + comp_len
                                    # Extensions length (2 bytes) at offset
                                    if offset + 2 <= len(raw_load):
                                        ext_len = int.from_bytes(raw_load[offset:offset+2], 'big')
                                        offset += 2
                                        # Parse extensions looking for SNI (type 0)
                                        ext_end = offset + ext_len
                                        while offset + 4 <= ext_end:
                                            ext_type = int.from_bytes(raw_load[offset:offset+2], 'big')
                                            ext_data_len = int.from_bytes(raw_load[offset+2:offset+4], 'big')
                                            offset += 4
                                            if ext_type == 0:  # SNI extension
                                                if offset + 5 <= ext_end:
                                                    sni_name_len = int.from_bytes(raw_load[offset+3:offset+5], 'big')
                                                    if offset + 5 + sni_name_len <= ext_end:
                                                        sni_name = raw_load[offset+5:offset+5+sni_name_len].decode('utf-8', errors='ignore')
                                                        return sni_name
                                            else:
                                                offset += ext_data_len
        except Exception:
            pass
        return None

    def extract_dns_query_domain(self, pkt):
        """Extract domain name from DNS query packets."""
        try:
            # Check for DNS layer (UDP port 53)
            if UDP in pkt and (pkt[UDP].sport == 53 or pkt[UDP].dport == 53):
                if Raw in pkt:
                    raw_load = bytes(pkt[Raw].load)
                    # Simple DNS packet parser
                    if len(raw_load) > 12:
                        # Check if it's a query (bit 7 of byte 2 should be 0)
                        if (raw_load[2] & 0x80) == 0:
                            # Questions count at offset 4-5
                            qcount = int.from_bytes(raw_load[4:6], 'big')
                            if qcount > 0:
                                offset = 12
                                # Parse first question's domain name
                                name_parts = []
                                while offset < len(raw_load) and len(name_parts) < 10:
                                    length = raw_load[offset]
                                    if length == 0:
                                        break
                                    offset += 1
                                    if offset + length <= len(raw_load):
                                        name_parts.append(raw_load[offset:offset+length].decode('utf-8', errors='ignore'))
                                        offset += length
                                    else:
                                        break
                                if name_parts:
                                    domain = '.'.join(name_parts).lower()
                                    return domain
        except Exception:
            pass
        return None

    def stop(self):
        self.stop_event.set()