# data_structures.py

# --- Binary Search Tree (for Blocked IPs) ---
class BSTNode:
    def __init__(self, ipaddress):
        self.ip = ipaddress
        self.left = None
        self.right = None

class BlacklistBST:
    def __init__(self):
        self.root = None

    def insert(self, ipaddress):
        if self.root is None:
            self.root = BSTNode(ipaddress)
        else:
            self.insertrecursive(self.root, ipaddress)

    def insertrecursive(self, node, ipaddress):
        if ipaddress < node.ip:
            if node.left is None:
                node.left = BSTNode(ipaddress)
            else:
                self.insertrecursive(node.left, ipaddress)
        elif ipaddress > node.ip:
            if node.right is None:
                node.right = BSTNode(ipaddress)
            else:
                self.insertrecursive(node.right, ipaddress)

    def search(self, ipaddress):
        return self.searchrecursive(self.root, ipaddress)

    def searchrecursive(self, node, ipaddress):
        if node is None:
            return False
        if ipaddress == node.ip:
            return True
        elif ipaddress < node.ip:
            return self.searchrecursive(node.left, ipaddress)
        else:
            return self.searchrecursive(node.right, ipaddress)

    def delete(self, ipaddress):
        self.root = self.deleterecursive(self.root, ipaddress)

    def deleterecursive(self, node, ipaddress):
        if node is None: return node
        if ipaddress < node.ip:
            node.left = self.deleterecursive(node.left, ipaddress)
        elif ipaddress > node.ip:
            node.right = self.deleterecursive(node.right, ipaddress)
        else:
            if node.left is None: return node.right
            elif node.right is None: return node.left
            temp = self.minvalue(node.right)
            node.ip = temp.ip
            node.right = self.deleterecursive(node.right, temp.ip)
        return node

    def minvalue(self, node):
        current = node
        while current.left is not None: current = current.left
        return current

# --- Stack (for Alerts) ---
class StackNode:
    def __init__(self, data):
        self.data = data
        self.next = None

class AlertStack:
    def __init__(self):
        self.top = None
        self.size = 0

    def push(self, alert):
        newnode = StackNode(alert)
        newnode.next = self.top
        self.top = newnode
        self.size += 1

    def pop(self):
        if self.isempty():
            return None
        data = self.top.data
        self.top = self.top.next
        self.size -= 1
        return data

    def isempty(self):
        return self.top is None

# --- Graph (for Network Map) ---
class NetworkGraph:
    def __init__(self):
        self.adjlist = {}

    def addconnection(self, src, dst):
        if src not in self.adjlist:
            self.adjlist[src] = set()
        self.adjlist[src].add(dst)