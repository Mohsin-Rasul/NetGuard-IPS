"""
Simplified data structures used by NetGuard-IPS.

This keeps the same public classes and methods used elsewhere but
implements them with simple, easy-to-read Python containers.
"""

from typing import Set, Dict


class BlacklistBST:
    """Simple blacklist container with the same API as the original BST.

    Internally this uses a set for O(1) insert/search while keeping
    the `insert(ip)` and `search(ip)` methods expected by the rest
    of the codebase.
    """

    def __init__(self):
        self._set: Set[str] = set()

    def insert(self, ip: str) -> None:
        self._set.add(ip)

    def search(self, ip: str) -> bool:
        return ip in self._set


class AlertStack:
    """A minimal stack for alerts (LIFO).

    Methods: `push(alert)`, `pop()` and `is_empty()` match the previous API.
    """

    def __init__(self):
        self._data = []

    def push(self, alert: str) -> None:
        self._data.append(alert)

    def pop(self):
        if not self._data:
            return None
        return self._data.pop()

    def is_empty(self) -> bool:
        return len(self._data) == 0


# NetworkGraph removed — visualization not required. Keep file minimal.
# ==========================================
# PART 1: DATA STRUCTURES (From Labs)
# ==========================================

# --- [Lab 8] Binary Search Tree (BST) ---
class BSTNode:
    def __init__(self, ip):
        self.ip = ip
        self.left = None# ==========================================
# PART 1: DATA STRUCTURES (From Labs)
# ==========================================

# --- [Lab 8] Binary Search Tree (BST) ---
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

    # [Lab 10] Binary Search Algorithm
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

# --- [Lab 4 & 6] Stack using Singly Linked List ---
class StackNode:
    def __init__(self, data):
        self.data = data
        self.next = None

class AlertStack:
    def __init__(self):
        self.top = None 
        self.size = 0

    def push(self, alert):
        new_node = StackNode(alert)
        new_node.next = self.top
        self.top = new_node
        self.size += 1

    def pop(self):
        if self.is_empty():
            return None
        data = self.top.data
        self.top = self.top.next
        self.size -= 1
        return data

    def is_empty(self):
        return self.top is None

# --- [Lab 9] Graph Data Structure ---
class NetworkGraph:
    def __init__(self):
        self.adj_list = {} 

    def add_connection(self, src, dst):
        if src not in self.adj_list:
            self.adj_list[src] = set()
        self.adj_list[src].add(dst)
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

    # [Lab 10] Binary Search Algorithm
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

# --- [Lab 4 & 6] Stack using Singly Linked List ---
class StackNode:
    def __init__(self, data):
        self.data = data
        self.next = None

class AlertStack:
    def __init__(self):
        self.top = None 
        self.size = 0

    def push(self, alert):
        new_node = StackNode(alert)
        new_node.next = self.top
        self.top = new_node
        self.size += 1

    def pop(self):
        if self.is_empty():
            return None
        data = self.top.data
        self.top = self.top.next
        self.size -= 1
        return data

    def is_empty(self):
        return self.top is None

# --- [Lab 9] Graph Data Structure ---
class NetworkGraph:
    def __init__(self):
        self.adj_list = {} 

    def add_connection(self, src, dst):
        if src not in self.adj_list:
            self.adj_list[src] = set()
        self.adj_list[src].add(dst)