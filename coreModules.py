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
    SCAPY_AVAILABLE = True
except ImportError:
    sniff = None
    IP = IPv6 = TCP = UDP = ARP = Raw = None
    SCAPY_AVAILABLE = False
    print("[WARN] Scapy not installed or not available. Packet capture will be disabled.")

# ==========================================
# PART 2: FUNCTIONAL MODULES
# ==========================================

class FirewallManager:
    """Response Module: Interact with Windows Firewall"""
    @staticmethod
    def blockIp(ipAddress):
        ruleName = f"HIPS_BLOCK_{ipAddress}"
        command = (
            f"netsh advfirewall firewall add rule name=\"{ruleName}\" "
            f"dir=in action=block remoteip={ipAddress}"
        )
        try:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL)
            print(f"[FIREWALL] Blocked IP: {ipAddress}")
            return True
        except subprocess.CalledProcessError:
            print(f"[ERROR] Failed to block {ipAddress}. Run as Admin.")
            return False

    @staticmethod
    def unblockIp(ipAddress):
        ruleName = f"HIPS_BLOCK_{ipAddress}"
        command = f'netsh advfirewall firewall delete rule name="{ruleName}"'
        try:
            res = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(f"[FIREWALL] Unblocked IP: {ipAddress}")
            return True, res.stdout.strip()
        except subprocess.CalledProcessError as e:
            err = (e.stderr or str(e)).strip()
            print(f"[WARN] Unblock failed (non-elevated): {err}")
            try:
                psCmd = f"Start-Process netsh -ArgumentList 'advfirewall firewall delete rule name=\"{ruleName}\"' -Verb RunAs -Wait"
                subprocess.run(["powershell", "-Command", psCmd], check=True)
                print(f"[FIREWALL] Unblocked IP via elevation: {ipAddress}")
                return True, "Unblocked via elevation"
            except Exception as e2:
                err2 = str(e2)
                print(f"[ERROR] Elevated unblock failed: {err2}")
                return False, f"{err}; {err2}"

class Logger:
    """Alert System - Log File Entry with Rotation"""
    LOG_FILE = "hips_alerts.log"
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
    MAX_LOG_FILES = 5

    @staticmethod
    def rotateLogs():
        try:
            if os.path.isfile(Logger.LOG_FILE) and os.path.getsize(Logger.LOG_FILE) > Logger.MAX_LOG_SIZE:
                for i in range(Logger.MAX_LOG_FILES - 1, 0, -1):
                    oldFile = f"{Logger.LOG_FILE}.{i}"
                    newFile = f"{Logger.LOG_FILE}.{i+1}"
                    if os.path.isfile(oldFile):
                        if os.path.isfile(newFile):
                            os.remove(newFile)
                        os.rename(oldFile, newFile)
                if os.path.isfile(f"{Logger.LOG_FILE}.1"):
                    os.remove(f"{Logger.LOG_FILE}.1")
                os.rename(Logger.LOG_FILE, f"{Logger.LOG_FILE}.1")
        except Exception as e:
            print(f"[WARN] Log rotation failed: {e}")

    @staticmethod
    def logAlert(ip, reason, severity):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logEntry = f"[{timestamp}] [{severity.upper()}] IP: {ip} - {reason}\n"
        try:
            Logger.rotateLogs()
            with open(Logger.LOG_FILE, "a") as f:
                f.write(logEntry)
        except Exception as e:
            print(f"Logging Error: {e}")

class PacketCaptureThread(threading.Thread):
    """Multithreaded Sniffer"""
    def __init__(self, pktQueue, blockedIps=None, blockedLock=None):
        super().__init__()
        self.pktQueue = pktQueue
        self.stopEvent = threading.Event()
        self.daemon = True
        self.blockedIps = blockedIps
        self.blockedLock = blockedLock

    def run(self):
        print("[SNIFFER] Started...")
        if not SCAPY_AVAILABLE:
            return

        while not self.stopEvent.is_set():
            try:
                sniff(count=1, prn=self.processPacket, store=0, timeout=1)
            except Exception as e:
                time.sleep(2)

    def processPacket(self, packet):
        if IP in packet:
            try:
                srcIp = packet[IP].src
                if self.blockedIps:
                    if self.blockedLock:
                        with self.blockedLock:
                            if srcIp in self.blockedIps: return
                    elif srcIp in self.blockedIps: return
            except: pass

        if IP in packet or ARP in packet:
            self.pktQueue.put(packet)

    def stop(self):
        self.stopEvent.set()

class DetectionEngine(threading.Thread):
    """Signature Matching & Anomaly Detection Engine"""
    def __init__(self, pktQueue, guiCallback, blacklistBst, alertStack, analyzeLocal=False):
        super().__init__()
        self.pktQueue = pktQueue
        self.stopEvent = threading.Event()
        self.daemon = True
        self.guiCallback = guiCallback
        self.blacklist = blacklistBst
        self.alertStack = alertStack
        self.analyzeLocal = analyzeLocal
        
        self.pktCounts = {} 
        self.portMap = {} 
        self.synTrack = {} 
        self.blockedIps = set() 
        self.startTime = time.time()
        self.arpTable = {} 
        self.whitelist = {self.getLocalIp(), "127.0.0.1", "0.0.0.0"}
        self.maliciousDomains = set()
        
        self.THRESHOLD_PPS = 150 
        self.PORT_SCAN_THRESHOLD = 5 
        self.SYN_THRESHOLD = 20 
        self.dnsCache = {}
        self.blockedLock = threading.Lock()
        self.blockedStore = os.path.join(os.path.dirname(__file__), "blocked_ips.json")

        try:
            self.loadPersistedBlocks()
        except: pass

    def getLocalIp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
        except: return '127.0.0.1'
        finally: s.close()

    def getHostname(self, ip):
        if ip in self.dnsCache: return self.dnsCache[ip]
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            hostname = "Google Service" if "google" in hostname else hostname
        except: hostname = ip
        self.dnsCache[ip] = hostname
        return hostname

    def run(self):
        while not self.stopEvent.is_set():
            try:
                if not self.pktQueue.empty():
                    self.analyze(self.pktQueue.get())
                else: time.sleep(0.1)
            except: pass

    def analyze(self, pkt):
        if ARP in pkt and pkt[ARP].op == 2:
            ipSrc, macSrc = pkt[ARP].psrc, pkt[ARP].hwsrc
            if ipSrc in self.arpTable and self.arpTable[ipSrc] != macSrc:
                self.triggerAlert(ipSrc, "ARP Spoofing Detected", "High")
                return
            self.arpTable[ipSrc] = macSrc
            return

        if IP not in pkt: return
        srcIp, dstIp = pkt[IP].src, pkt[IP].dst
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
        length, sport, dport = len(pkt), 0, 0
        
        if TCP in pkt: sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt: sport, dport = pkt[UDP].sport, pkt[UDP].dport

        if srcIp != self.getLocalIp() and dstIp != self.getLocalIp(): return
        if srcIp in self.whitelist and not self.analyzeLocal: return

        with self.blockedLock:
            if srcIp in self.blockedIps: return

        # Reset thresholds every second
        currTime = time.time()
        if currTime - self.startTime > 1.0:
            self.pktCounts, self.portMap, self.synTrack, self.startTime = {}, {}, {}, currTime

        # Detection Logic
        threatDetected, reason, severity = False, "", "Low"

        if TCP in pkt and pkt[TCP].flags == 'S': 
            self.synTrack[srcIp] = self.synTrack.get(srcIp, 0) + 1
            if self.synTrack[srcIp] > self.SYN_THRESHOLD:
                threatDetected, reason, severity = True, "SYN Flood Attack", "High"

        if dport > 0:
            if srcIp not in self.portMap: self.portMap[srcIp] = set()
            self.portMap[srcIp].add(dport)
            if len(self.portMap[srcIp]) > self.PORT_SCAN_THRESHOLD:
                threatDetected, reason, severity = True, "Port Scanning", "Medium"

        if threatDetected:
            self.triggerAlert(srcIp, reason, severity)
        else:
            self.guiCallback("TRAFFIC", (srcIp, self.getHostname(srcIp), dstIp, proto, length, sport, dport))

    def triggerAlert(self, srcIp, reason, severity):
        with self.blockedLock: self.blockedIps.add(srcIp)
        self.blacklist.insert(srcIp)
        self.savePersistedBlocks()
        
        Logger.logAlert(srcIp, reason, severity)
        self.alertStack.push(f"[{severity.upper()}] BLOCKED {srcIp}: {reason}")
        self.guiCallback("ALERT", (srcIp, self.getHostname(srcIp), reason, severity))

        threading.Thread(target=FirewallManager.blockIp, args=(srcIp,), daemon=True).start()

    def savePersistedBlocks(self):
        try:
            with self.blockedLock: data = list(self.blockedIps)
            payload = json.dumps({'blocked': data})
            key = hashlib.sha256(self.getLocalIp().encode()).digest()
            sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
            with open(self.blockedStore, 'w') as f: json.dump({'blocked': data, 'signature': sig}, f)
        except: pass

    def loadPersistedBlocks(self):
        if not os.path.isfile(self.blockedStore): return
        try:
            with open(self.blockedStore, 'r') as f:
                j = json.load(f)
                key = hashlib.sha256(self.getLocalIp().encode()).digest()
                sig = hmac.new(key, json.dumps({'blocked': j['blocked']}).encode(), hashlib.sha256).hexdigest()
                if sig == j['signature']:
                    for ip in j['blocked']:
                        self.blockedIps.add(ip)
                        self.blacklist.insert(ip)
                        threading.Thread(target=FirewallManager.blockIp, args=(ip,), daemon=True).start()
        except: pass

    def stop(self):
        self.stopEvent.set()