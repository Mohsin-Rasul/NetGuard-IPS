# dataStructures.py

# --- Binary Search Tree (for Blocked IPs) ---
class BSTNode:
    def __init__(self, ipAddress):
        self.ip = ipAddress
        self.left = None
        self.right = None

class BlacklistBST:
    def __init__(self):
        self.root = None

    def insert(self, ipAddress):
        if self.root is None:
            self.root = BSTNode(ipAddress)
        else:
            self.insertRecursive(self.root, ipAddress)

    def insertRecursive(self, node, ipAddress):
        if ipAddress < node.ip:
            if node.left is None:
                node.left = BSTNode(ipAddress)
            else:
                self.insertRecursive(node.left, ipAddress)
        elif ipAddress > node.ip:
            if node.right is None:
                node.right = BSTNode(ipAddress)
            else:
                self.insertRecursive(node.right, ipAddress)

    def search(self, ipAddress):
        return self.searchRecursive(self.root, ipAddress)

    def searchRecursive(self, node, ipAddress):
        if node is None:
            return False
        if ipAddress == node.ip:
            return True
        elif ipAddress < node.ip:
            return self.searchRecursive(node.left, ipAddress)
        else:
            return self.searchRecursive(node.right, ipAddress)

    def delete(self, ipAddress):
        self.root = self.deleteRecursive(self.root, ipAddress)

    def deleteRecursive(self, node, ipAddress):
        if node is None: 
            return node
        
        if ipAddress < node.ip:
            node.left = self.deleteRecursive(node.left, ipAddress)
        elif ipAddress > node.ip:
            node.right = self.deleteRecursive(node.right, ipAddress)
        else:
            # Node with only one child or no child
            if node.left is None: 
                return node.right
            elif node.right is None: 
                return node.left
            
            # Node with two children: Get the inorder successor
            temp = self.minValue(node.right)
            node.ip = temp.ip
            node.right = self.deleteRecursive(node.right, temp.ip)
            
        return node

    def minValue(self, node):
        current = node
        while current.left is not None: 
            current = current.left
        return current

    def getInorderList(self):
        """Helper for professional GUI to display all blocked IPs."""
        result = []
        self._inorderRecursive(self.root, result)
        return result

    def _inorderRecursive(self, node, result):
        if node:
            self._inorderRecursive(node.left, result)
            result.append(node.ip)
            self._inorderRecursive(node.right, result)

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
        # Create alert string with timestamp for professional logging
        newNode = StackNode(alert)
        newNode.next = self.top
        self.top = newNode
        self.size += 1

    def pop(self):
        if self.isEmpty():
            return None
        data = self.top.data
        self.top = self.top.next
        self.size -= 1
        return data

    def isEmpty(self):
        return self.top is None

# --- Graph (for Network Map) ---
class NetworkGraph:
    def __init__(self):
        self.adjList = {}

    def addConnection(self, src, dst):
        if src not in self.adjList:
            self.adjList[src] = set()
        self.adjList[src].add(dst)

    def getConnections(self, src):
        return self.adjList.get(src, set())