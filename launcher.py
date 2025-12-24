"""
NetGuard-IPS - Main Launcher
Choose between Modern GUI or Classic GUI
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
import os

class LauncherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetGuard-IPS - Launcher")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        
        # Center window
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup launcher UI"""
        # Header
        header = tk.Frame(self.root, bg='#1e3a5f', height=80)
        header.pack(fill='x')
        header.pack_propagate(False)
        
        title = tk.Label(header, text="🛡️ NetGuard-IPS Launcher",
                        font=('Segoe UI', 18, 'bold'), bg='#1e3a5f', fg='white')
        title.pack(pady=20)
        
        # Content
        content = tk.Frame(self.root, bg='white', padx=20, pady=20)
        content.pack(fill='both', expand=True)
        
        ttk.Label(content, text="Select a GUI Version:", font=('Segoe UI', 12, 'bold')).pack(pady=(0, 20))
        
        # Modern GUI option
        modern_frame = tk.LabelFrame(content, text="🚀 MODERN GUI (Recommended)",
                                     font=('Segoe UI', 11, 'bold'), padx=15, pady=15,
                                     bg='#e3f2fd', fg='#1565c0')
        modern_frame.pack(fill='x', pady=10)
        
        modern_desc = """Beautiful, user-friendly interface with:
• Tabbed dashboard
• Real-time statistics
• Easy-to-use controls
• Modern design"""
        
        ttk.Label(modern_frame, text=modern_desc, justify='left',
                 font=('Segoe UI', 9)).pack(anchor='w')
        ttk.Button(modern_frame, text="🚀 Launch Modern GUI",
                  command=self.launch_modern).pack(pady=10)
        
        # Classic GUI option
        classic_frame = tk.LabelFrame(content, text="📋 CLASSIC GUI (Advanced)",
                                      font=('Segoe UI', 11, 'bold'), padx=15, pady=15,
                                      bg='#f3e5f5', fg='#4a148c')
        classic_frame.pack(fill='x', pady=10)
        
        classic_desc = """Traditional interface with:
• Detailed traffic view
• Advanced monitoring
• Network mapping
• Expert controls"""
        
        ttk.Label(classic_frame, text=classic_desc, justify='left',
                 font=('Segoe UI', 9)).pack(anchor='w')
        ttk.Button(classic_frame, text="📋 Launch Classic GUI",
                  command=self.launch_classic).pack(pady=10)
        
        # Footer
        footer = tk.Frame(self.root, bg='#f0f0f0')
        footer.pack(fill='x', side='bottom')
        ttk.Label(footer, text="⚠️ Administrator privileges required",
                 font=('Segoe UI', 9), foreground='#ff6f00').pack(pady=10)
    
    def launch_modern(self):
        """Launch modern GUI"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            subprocess.Popen([sys.executable, os.path.join(script_dir, 'gui_modern.py')])
            self.root.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch: {str(e)}")
    
    def launch_classic(self):
        """Launch classic GUI"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            subprocess.Popen([sys.executable, os.path.join(script_dir, 'main.py')])
            self.root.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = LauncherGUI(root)
    root.mainloop()
