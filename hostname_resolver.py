# hostname_resolver.py - DNS Resolution Module for NetGuard-IPS

import socket
import threading
from threading import Thread
import queue
import time

class HostnameResolver:
    """
    Thread-safe hostname resolver using DNS reverse lookup
    with caching to minimize network calls
    """
    
    def __init__(self, max_cache_size=1000, timeout=2.0):
        self.cache = {}  # { ip_address: hostname }
        self.max_cache = max_cache_size
        self.timeout = timeout
        self.lock = threading.Lock()
        self.resolve_queue = queue.Queue()
        self.resolver_thread = None
        self.running = False
    
    def start(self):
        """Start background resolver thread"""
        if self.running:
            return
        self.running = True
        self.resolver_thread = Thread(target=self._resolver_worker, daemon=True)
        self.resolver_thread.start()
    
    def stop(self):
        """Stop background resolver thread"""
        self.running = False
        if self.resolver_thread:
            self.resolver_thread.join(timeout=2)
    
    def resolve_async(self, ip_address):
        """
        Non-blocking: Request async resolution
        Returns immediately (check get_hostname for result)
        """
        if ip_address not in self.cache:
            self.resolve_queue.put(ip_address)
    
    def get_hostname(self, ip_address, use_cache=True):
        """
        Get hostname for IP (returns cached value if available)
        If not cached and use_cache=True, returns IP (and queues for background resolution)
        If use_cache=False, performs synchronous lookup (BLOCKS!)
        """
        with self.lock:
            if ip_address in self.cache:
                return self.cache[ip_address]
        
        if not use_cache:
            return self._sync_resolve(ip_address)
        else:
            # Queue for async resolution
            self.resolve_async(ip_address)
            return ip_address  # Return IP until resolved
    
    def _sync_resolve(self, ip_address):
        """Synchronous DNS reverse lookup - BLOCKING"""
        try:
            socket.setdefaulttimeout(self.timeout)
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            # Extract just the hostname (without domain)
            hostname = hostname.split('.')[0]
            return hostname
        except (socket.herror, socket.timeout, socket.gaierror, OSError):
            return ip_address  # Return IP if resolution fails
    
    def _resolver_worker(self):
        """Background worker thread for async resolution"""
        while self.running:
            try:
                # Get IPs from queue (with timeout to allow stopping)
                ip_address = self.resolve_queue.get(timeout=1)
                
                # Check cache again (might have been resolved)
                with self.lock:
                    if ip_address in self.cache:
                        continue
                
                # Perform resolution
                hostname = self._sync_resolve(ip_address)
                
                # Store in cache
                with self.lock:
                    if len(self.cache) >= self.max_cache:
                        # Simple FIFO eviction if cache is full
                        oldest = next(iter(self.cache))
                        del self.cache[oldest]
                    
                    self.cache[ip_address] = hostname
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[Resolver] Error: {e}")
    
    def clear_cache(self):
        """Clear the hostname cache"""
        with self.lock:
            self.cache.clear()
    
    def get_cache_stats(self):
        """Return cache statistics"""
        with self.lock:
            return {
                'cached_ips': len(self.cache),
                'max_size': self.max_cache,
                'queue_size': self.resolve_queue.qsize()
            }
