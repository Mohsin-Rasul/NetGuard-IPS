# hostnameResolver.py - DNS Resolution Module for NetGuard-IPS

import socket
import threading
from threading import Thread
import queue
import time

class HostnameResolver:
    """
    Thread-safe hostname resolver using DNS reverse lookup
    with caching and TTL management to minimize network calls.
    """
    
    def __init__(self, maxCacheSize=1000, timeout=2.0):
        self.cache = {}  # { ipAddress: (hostname, timestamp) }
        self.maxCache = maxCacheSize
        self.timeout = timeout
        self.lock = threading.Lock()
        # FIX: Limit queue size to prevent memory exhaustion during heavy traffic
        self.resolveQueue = queue.Queue(maxsize=2000)
        self.resolverThread = None
        self.running = False
        # Cache TTL set to 1 hour (3600 seconds)
        self.cacheTTL = 3600 
    
    def start(self):
        """Start background resolver thread"""
        if self.running:
            return
        self.running = True
        self.resolverThread = Thread(target=self._resolverWorker, daemon=True)
        self.resolverThread.start()
    
    def stop(self):
        """Stop background resolver thread"""
        self.running = False
        if self.resolverThread:
            # Signal the worker to stop by joining
            self.resolverThread.join(timeout=2)
    
    def resolveAsync(self, ipAddress):
        """
        Non-blocking: Request async resolution if not already cached.
        """
        if ipAddress not in self.cache:
            try:
                # Use block=False to avoid hanging if the queue is full
                self.resolveQueue.put(ipAddress, block=False)
            except queue.Full:
                pass
    
    def getHostname(self, ipAddress, useCache=True):
        """
        Get hostname for IP (returns cached value if available and not expired).
        If not cached, returns IP and queues for background resolution.
        """
        with self.lock:
            if ipAddress in self.cache:
                hostname, timestamp = self.cache[ipAddress]
                # FIX: Check if the cache entry has expired based on TTL
                if (time.time() - timestamp) < self.cacheTTL:
                    return hostname
        
        if not useCache:
            return self._syncResolve(ipAddress)[0]
        else:
            self.resolveAsync(ipAddress)
            return ipAddress  # Return IP string until background resolution finishes
    
    def _syncResolve(self, ipAddress):
        """Synchronous DNS reverse lookup - BLOCKING"""
        try:
            socket.setdefaulttimeout(self.timeout)
            hostname, _, _ = socket.gethostbyaddr(ipAddress)
            # Extract just the hostname (without domain)
            hostname = hostname.split('.')[0]
            return (hostname, time.time())
        except (socket.herror, socket.timeout, socket.gaierror, OSError):
            # Return IP if resolution fails, but still mark timestamp to prevent constant retries
            return (ipAddress, time.time())
    
    def _resolverWorker(self):
        """Background worker thread for async resolution"""
        while self.running:
            try:
                # Get IPs from queue with a timeout to check if self.running changed
                ipAddress = self.resolveQueue.get(timeout=1)
                
                # Double-check cache validity before performing network I/O
                with self.lock:
                    if ipAddress in self.cache:
                        _, timestamp = self.cache[ipAddress]
                        if (time.time() - timestamp) < self.cacheTTL:
                            continue
                
                # Perform the blocking network resolution
                resolutionResult = self._syncResolve(ipAddress)
                
                # Store in cache with resource management
                with self.lock:
                    if len(self.cache) >= self.maxCache:
                        # Simple FIFO eviction: remove the oldest key
                        oldest = next(iter(self.cache))
                        del self.cache[oldest]
                    
                    self.cache[ipAddress] = resolutionResult
                    
            except queue.Empty:
                continue
            except Exception as e:
                # Basic error logging for the background thread
                print(f"[Resolver] Background Error: {e}")
    
    def clearCache(self):
        """Clear the hostname cache"""
        with self.lock:
            self.cache.clear()
    
    def getCacheStats(self):
        """Return real-time cache and queue metrics"""
        with self.lock:
            return {
                'cachedIps': len(self.cache),
                'maxSize': self.maxCache,
                'queueSize': self.resolveQueue.qsize(),
                'running': self.running
            }