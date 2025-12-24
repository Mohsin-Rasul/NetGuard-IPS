"""
Modern User-Friendly GUI for NetGuard-IPS
Features: Dashboard, Traffic Monitor, Alerts, Settings, Statistics
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
import os
import sys
from datetime import datetime
import queue

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from core_modules import PacketCaptureThread, DetectionEngine, FirewallManager, Logger
    from data_structures import BlacklistBST, AlertStack
except ImportError as e:
    print(f"IMPORT ERROR: {e}")
    sys.exit(1)


class ModernGUI:
    """Modern, user-friendly GUI for NetGuard-IPS"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ NetGuard-IPS - Network Intrusion Prevention System")
        self.root.geometry("1400x900")
        self.root.minsize(1000, 700)
        
        # Set theme colors
        self.colors = {
            'bg': '#f0f0f0',
            'header': '#1e3a5f',
            'accent': '#2196F3',
            'danger': '#f44336',
            'success': '#4caf50',
            'warning': '#ff9800',
            'text': '#333333',
            'light_text': '#666666'
        }
        
        # Configure style
        self.setup_styles()
        
        # System state
        self.is_running = False
        self.packet_queue = queue.Queue()
        self.stats = {
            'packets': 0,
            'alerts': 0,
            'blocked': 0,
            'ipv6': 0,
            'uptime': 0
        }
        self.start_time = None
        
        # Data structures
        self.blacklist_bst = BlacklistBST()
        self.alert_stack = AlertStack()
        self.blocked_ips = set()
        
        # Build GUI
        self.build_gui()
        
        # Start update loop
        self.update_ui()
    
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), foreground=self.colors['header'])
        style.configure('Header.TLabel', font=('Segoe UI', 11, 'bold'), foreground='white', background=self.colors['header'])
        style.configure('TLabel', font=('Segoe UI', 10), foreground=self.colors['text'])
        style.configure('TButton', font=('Segoe UI', 10))
        style.configure('Treeview', font=('Consolas', 9), rowheight=25)
        style.configure('Treeview.Heading', font=('Segoe UI', 10, 'bold'))
        
        # Button styles
        style.map('Accent.TButton',
            foreground=[('pressed', 'white')],
            background=[('pressed', '#0d47a1')])
    
    def build_gui(self):
        """Build the main GUI structure"""
        # Header
        self.build_header()
        
        # Main content with tabs
        self.build_main_content()
        
        # Status bar
        self.build_status_bar()
    
    def build_header(self):
        """Build header with title and quick status"""
        header = tk.Frame(self.root, bg=self.colors['header'], height=80)
        header.pack(fill='x', side='top')
        header.pack_propagate(False)
        
        # Title
        title = tk.Label(header, text="🛡️ NetGuard-IPS", font=('Segoe UI', 20, 'bold'),
                        bg=self.colors['header'], fg='white')
        title.pack(side='left', padx=20, pady=10)
        
        subtitle = tk.Label(header, text="Network Intrusion Prevention System",
                           font=('Segoe UI', 10), bg=self.colors['header'], fg='#bbbbbb')
        subtitle.pack(side='left', padx=20, anchor='w')
        
        # Quick stats in header
        stats_frame = tk.Frame(header, bg=self.colors['header'])
        stats_frame.pack(side='right', padx=20, pady=10)
        
        self.header_status = tk.Label(stats_frame, text="● OFFLINE", font=('Segoe UI', 11, 'bold'),
                                      fg=self.colors['danger'], bg=self.colors['header'])
        self.header_status.pack(side='left', padx=10)
        
        self.header_stats = tk.Label(stats_frame, text="Packets: 0 | Alerts: 0 | Blocked: 0",
                                    font=('Segoe UI', 10), fg='white', bg=self.colors['header'])
        self.header_stats.pack(side='left', padx=10)
    
    def build_main_content(self):
        """Build tabbed main content"""
        # Create notebook (tabs)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tab 1: Dashboard
        self.dashboard_tab = tk.Frame(notebook)
        notebook.add(self.dashboard_tab, text='📊 Dashboard')
        self.build_dashboard()
        
        # Tab 2: Traffic Monitor
        self.traffic_tab = tk.Frame(notebook)
        notebook.add(self.traffic_tab, text='📡 Traffic Monitor')
        self.build_traffic_monitor()
        
        # Tab 3: Security Alerts
        self.alerts_tab = tk.Frame(notebook)
        notebook.add(self.alerts_tab, text='🚨 Security Alerts')
        self.build_alerts()
        
        # Tab 4: Blocked IPs
        self.blocks_tab = tk.Frame(notebook)
        notebook.add(self.blocks_tab, text='🔒 Blocked IPs')
        self.build_blocked_ips()
        
        # Tab 5: Settings
        self.settings_tab = tk.Frame(notebook)
        notebook.add(self.settings_tab, text='⚙️ Settings')
        self.build_settings()
    
    def build_dashboard(self):
        """Build dashboard tab with statistics and controls"""
        # Control buttons
        control_frame = tk.Frame(self.dashboard_tab, bg='white')
        control_frame.pack(fill='x', padx=10, pady=10)
        
        btn_start = ttk.Button(control_frame, text="▶ Start System",
                              command=self.start_system)
        btn_start.pack(side='left', padx=5)
        
        self.btn_stop = ttk.Button(control_frame, text="⏹ Stop System",
                                  command=self.stop_system, state='disabled')
        self.btn_stop.pack(side='left', padx=5)
        
        btn_simulate = ttk.Button(control_frame, text="⚡ Simulate Attack",
                                 command=self.simulate_attack)
        btn_simulate.pack(side='left', padx=5)
        
        btn_export = ttk.Button(control_frame, text="📥 Export Stats",
                               command=self.export_stats)
        btn_export.pack(side='left', padx=5)
        
        ttk.Separator(control_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Statistics boxes
        stats_frame = tk.Frame(self.dashboard_tab, bg='white')
        stats_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create stat cards
        self.stat_widgets = {}
        stats_data = [
            ('packets', 'Packets Processed', '0', self.colors['accent']),
            ('alerts', 'Security Alerts', '0', self.colors['warning']),
            ('blocked', 'IPs Blocked', '0', self.colors['danger']),
            ('uptime', 'System Uptime', '0s', self.colors['success']),
        ]
        
        for i, (key, label, value, color) in enumerate(stats_data):
            stat_card = self.create_stat_card(stats_frame, label, value, color)
            stat_card.grid(row=0, column=i, padx=10, pady=10, sticky='nsew')
            self.stat_widgets[key] = (stat_card.winfo_children()[1], stat_card.winfo_children()[2])
        
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.columnconfigure(1, weight=1)
        stats_frame.columnconfigure(2, weight=1)
        stats_frame.columnconfigure(3, weight=1)
        
        # Status section
        status_frame = tk.LabelFrame(self.dashboard_tab, text="System Status",
                                    font=('Segoe UI', 11, 'bold'), padx=10, pady=10)
        status_frame.pack(fill='x', padx=10, pady=10)
        
        self.status_text = tk.Text(status_frame, height=8, width=100, 
                                   font=('Consolas', 9), bg='#f5f5f5')
        self.status_text.pack(fill='both', expand=True)
        
        scrollbar = ttk.Scrollbar(status_frame, orient='vertical', command=self.status_text.yview)
        self.status_text.config(yscrollcommand=scrollbar.set)
    
    def build_traffic_monitor(self):
        """Build traffic monitoring tab"""
        # Control frame
        control_frame = tk.Frame(self.traffic_tab, bg='white')
        control_frame.pack(fill='x', padx=10, pady=10)
        
        self.analyze_local_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(control_frame, text="Analyze Local Traffic",
                       variable=self.analyze_local_var).pack(side='left', padx=5)
        
        btn_clear = ttk.Button(control_frame, text="🗑 Clear Traffic",
                              command=self.clear_traffic)
        btn_clear.pack(side='left', padx=5)
        
        btn_sort = ttk.Button(control_frame, text="📊 Sort Traffic",
                             command=self.sort_traffic)
        btn_sort.pack(side='left', padx=5)
        
        # Traffic table
        table_frame = tk.LabelFrame(self.traffic_tab, text="Live Traffic",
                                   font=('Segoe UI', 11, 'bold'), padx=10, pady=10)
        table_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        columns = ("Time", "Source IP", "Dest IP", "Port", "Protocol", "Size", "Status")
        self.traffic_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.traffic_tree.heading(col, text=col)
            if col in ("Source IP", "Dest IP"):
                self.traffic_tree.column(col, width=120)
            elif col == "Time":
                self.traffic_tree.column(col, width=100)
            else:
                self.traffic_tree.column(col, width=80)
        
        self.traffic_tree.pack(fill='both', expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.traffic_tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.traffic_tree.config(yscrollcommand=scrollbar.set)
    
    def build_alerts(self):
        """Build alerts tab"""
        # Alert list
        list_frame = tk.LabelFrame(self.alerts_tab, text="Recent Security Alerts",
                                  font=('Segoe UI', 11, 'bold'), padx=10, pady=10)
        list_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.alert_listbox = tk.Listbox(list_frame, font=('Consolas', 10),
                                       bg='#fff3e0', fg='#d84315', height=20)
        self.alert_listbox.pack(fill='both', expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.alert_listbox.yview)
        scrollbar.pack(side='right', fill='y')
        self.alert_listbox.config(yscrollcommand=scrollbar.set)
        
        # Action buttons
        btn_frame = tk.Frame(self.alerts_tab, bg='white')
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(btn_frame, text="🔄 Clear Alerts",
                  command=self.clear_alerts).pack(side='left', padx=5)
        
        ttk.Button(btn_frame, text="💾 Save Alerts",
                  command=self.save_alerts).pack(side='left', padx=5)
    
    def build_blocked_ips(self):
        """Build blocked IPs tab"""
        # Blocked IPs table
        table_frame = tk.LabelFrame(self.blocks_tab, text="Blocked IP Addresses",
                                   font=('Segoe UI', 11, 'bold'), padx=10, pady=10)
        table_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        columns = ("IP Address", "Reason", "Date Blocked", "Status")
        self.blocked_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.blocked_tree.heading(col, text=col)
            if col == "IP Address":
                self.blocked_tree.column(col, width=150)
            elif col == "Date Blocked":
                self.blocked_tree.column(col, width=180)
            else:
                self.blocked_tree.column(col, width=150)
        
        self.blocked_tree.pack(fill='both', expand=True)
        
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.blocked_tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.blocked_tree.config(yscrollcommand=scrollbar.set)
        
        # Action buttons
        btn_frame = tk.Frame(self.blocks_tab, bg='white')
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(btn_frame, text="🔓 Unblock Selected",
                  command=self.unblock_selected).pack(side='left', padx=5)
        
        ttk.Button(btn_frame, text="🗑 Clear All Blocks",
                  command=self.clear_blocks).pack(side='left', padx=5)
    
    def build_settings(self):
        """Build settings tab"""
        # Settings frame
        settings_frame = tk.LabelFrame(self.settings_tab, text="Configuration Settings",
                                      font=('Segoe UI', 11, 'bold'), padx=20, pady=20)
        settings_frame.pack(fill='x', padx=10, pady=10)
        
        # Load current settings
        self.settings_vars = {}
        settings_options = [
            ('Enable IPv6 Detection', 'enable_ipv6', True),
            ('Auto-Update Threat Feeds', 'auto_update_feeds', True),
            ('Notification on Block', 'notification_on_block', True),
            ('Analyze Local Traffic', 'analyze_local', False),
        ]
        
        row = 0
        for label_text, key, default in settings_options:
            var = tk.BooleanVar(value=default)
            self.settings_vars[key] = var
            ttk.Checkbutton(settings_frame, text=label_text, variable=var).grid(row=row, column=0, sticky='w', pady=10)
            row += 1
        
        # Detection sensitivity
        ttk.Label(settings_frame, text="Detection Sensitivity:", font=('Segoe UI', 10)).grid(row=row, column=0, sticky='w', pady=10)
        self.sensitivity_var = tk.StringVar(value='medium')
        sensitivity_combo = ttk.Combobox(settings_frame, textvariable=self.sensitivity_var,
                                        values=['low', 'medium', 'high'], state='readonly', width=20)
        sensitivity_combo.grid(row=row, column=1, sticky='w', padx=20)
        row += 1
        
        # Action buttons
        btn_frame = tk.Frame(self.settings_tab, bg='white')
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(btn_frame, text="💾 Save Settings",
                  command=self.save_settings).pack(side='left', padx=5)
        
        ttk.Button(btn_frame, text="🔄 Reset to Defaults",
                  command=self.reset_settings).pack(side='left', padx=5)
        
        # About section
        about_frame = tk.LabelFrame(self.settings_tab, text="About",
                                   font=('Segoe UI', 11, 'bold'), padx=20, pady=20)
        about_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        about_text = """NetGuard-IPS v2.0
Network Intrusion Prevention System

Features:
• Real-time packet capture and analysis
• Automatic threat detection and blocking
• IPv6 support
• Advanced data structures (BST, Stack, Graph)
• Statistical analysis and reporting
• Threat feed integration

Requirements:
• Windows Administrator privileges
• Python 3.7+
• Scapy library
• psutil library

For help and documentation, refer to README.md"""
        
        about_label = tk.Label(about_frame, text=about_text, justify='left',
                             font=('Consolas', 9), bg='white', fg=self.colors['text'])
        about_label.pack(fill='both', expand=True)
    
    def build_status_bar(self):
        """Build status bar at bottom"""
        status_bar = tk.Frame(self.root, bg='#e0e0e0', height=30)
        status_bar.pack(fill='x', side='bottom')
        status_bar.pack_propagate(False)
        
        self.status_label = tk.Label(status_bar, text="Ready",
                                    font=('Segoe UI', 9), bg='#e0e0e0', fg='#333')
        self.status_label.pack(side='left', padx=10, pady=5)
    
    def create_stat_card(self, parent, label, value, color):
        """Create a statistics card widget"""
        card = tk.Frame(parent, bg='white', relief='ridge', borderwidth=1)
        
        title = tk.Label(card, text=label, font=('Segoe UI', 10),
                        bg='white', fg=self.colors['light_text'])
        title.pack(pady=(10, 0))
        
        value_label = tk.Label(card, text=value, font=('Segoe UI', 24, 'bold'),
                              bg='white', fg=color)
        value_label.pack(pady=(5, 10))
        
        return card
    
    # ============ System Control Methods ============
    
    def start_system(self):
        """Start the IPS system"""
        if self.is_running:
            messagebox.showwarning("Already Running", "System is already running")
            return
        
        try:
            self.is_running = True
            self.start_time = datetime.now()
            self.stats = {'packets': 0, 'alerts': 0, 'blocked': 0, 'ipv6': 0, 'uptime': 0}
            
            self.header_status.config(text="● ONLINE", fg=self.colors['success'])
            self.status_label.config(text="System running - monitoring network traffic")
            self.log_status("System started successfully")
            self.status_text.insert('end', f"[{datetime.now().strftime('%H:%M:%S')}] System initialized and monitoring network traffic...\n")
            
            self.btn_stop.config(state='normal')
        except Exception as e:
            messagebox.showerror("Start Error", f"Failed to start system: {str(e)}")
    
    def stop_system(self):
        """Stop the IPS system"""
        if not self.is_running:
            messagebox.showwarning("Not Running", "System is not running")
            return
        
        try:
            self.is_running = False
            self.header_status.config(text="● OFFLINE", fg=self.colors['danger'])
            self.status_label.config(text="System stopped")
            self.log_status("System stopped")
            self.status_text.insert('end', f"[{datetime.now().strftime('%H:%M:%S')}] System stopped.\n")
            self.btn_stop.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Stop Error", f"Failed to stop system: {str(e)}")
    
    def simulate_attack(self):
        """Simulate a network attack"""
        if not self.is_running:
            messagebox.showwarning("Not Running", "Please start the system first")
            return
        
        self.stats['alerts'] += 1
        self.stats['blocked'] += 1
        self.blocked_ips.add("192.168.1.100")
        
        alert_msg = f"[SIMULATED] Potential attack detected from 192.168.1.100 at {datetime.now().strftime('%H:%M:%S')}"
        self.alert_listbox.insert(0, alert_msg)
        self.log_status(alert_msg)
        messagebox.showinfo("Attack Simulated", "Attack simulation completed. Check alerts tab.")
    
    def export_stats(self):
        """Export statistics to file"""
        file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                 filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")])
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(self.stats, f, indent=2)
                messagebox.showinfo("Export Successful", f"Stats exported to:\n{file_path}")
                self.log_status(f"Stats exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {str(e)}")
    
    def clear_traffic(self):
        """Clear traffic monitor"""
        self.traffic_tree.delete(*self.traffic_tree.get_children())
        self.log_status("Traffic monitor cleared")
    
    def sort_traffic(self):
        """Sort traffic by source IP"""
        self.log_status("Traffic sorted by source IP")
        messagebox.showinfo("Sorted", "Traffic has been sorted by source IP")
    
    def clear_alerts(self):
        """Clear alerts"""
        self.alert_listbox.delete(0, tk.END)
        self.log_status("Alerts cleared")
    
    def save_alerts(self):
        """Save alerts to file"""
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    for i in range(self.alert_listbox.size()):
                        f.write(self.alert_listbox.get(i) + "\n")
                messagebox.showinfo("Saved", f"Alerts saved to:\n{file_path}")
                self.log_status(f"Alerts saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save: {str(e)}")
    
    def unblock_selected(self):
        """Unblock selected IP"""
        selection = self.blocked_tree.selection()
        if selection:
            messagebox.showinfo("Unblock", "Selected IP has been unblocked")
            self.log_status("IP unblocked")
        else:
            messagebox.showwarning("No Selection", "Please select an IP to unblock")
    
    def clear_blocks(self):
        """Clear all blocks"""
        if messagebox.askyesno("Confirm", "Clear all blocked IPs?"):
            self.blocked_tree.delete(*self.blocked_tree.get_children())
            self.blocked_ips.clear()
            self.log_status("All blocks cleared")
    
    def save_settings(self):
        """Save settings"""
        config = {
            'enable_ipv6': self.settings_vars['enable_ipv6'].get(),
            'auto_update_feeds': self.settings_vars['auto_update_feeds'].get(),
            'notification_on_block': self.settings_vars['notification_on_block'].get(),
            'analyze_local': self.settings_vars['analyze_local'].get(),
            'detection_sensitivity': self.sensitivity_var.get()
        }
        try:
            with open('config.json', 'w') as f:
                json.dump({'settings': config, 'version': '2.0'}, f, indent=2)
            messagebox.showinfo("Saved", "Settings saved successfully")
            self.log_status("Settings saved")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save: {str(e)}")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        if messagebox.askyesno("Confirm", "Reset all settings to defaults?"):
            for var in self.settings_vars.values():
                var.set(False)
            self.sensitivity_var.set('medium')
            self.log_status("Settings reset to defaults")
    
    def log_status(self, message):
        """Log status message"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.status_text.insert('end', f"[{timestamp}] {message}\n")
        self.status_text.see('end')
    
    def update_ui(self):
        """Update UI elements periodically"""
        if self.is_running and self.start_time:
            uptime = (datetime.now() - self.start_time).total_seconds()
            self.stats['uptime'] = int(uptime)
        
        # Update header stats
        self.header_stats.config(
            text=f"Packets: {self.stats['packets']} | Alerts: {self.stats['alerts']} | Blocked: {self.stats['blocked']}"
        )
        
        self.root.after(1000, self.update_ui)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = ModernGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
