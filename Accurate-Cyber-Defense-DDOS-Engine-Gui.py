import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import socket
import subprocess
import os
import json
import random
import requests
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import numpy as np
from collections import deque
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
from scapy.sendrecv import send, sr1, sr
import psutil
import threading
import time

class CyberSecurityTool:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Accurate Cyber Defense DDOS Engine Gui")
        self.root.geometry("1200x800")
        
        # Initialize variables
        self.monitored_ips = []
        self.command_history = []
        self.config = {
            'telegram_token': '',
            'telegram_chat_id': ''
        }
        self.traffic_data = deque(maxlen=100)
        self.scan_results = {}
        self.theme = "black"
        
        # Load config if exists
        self.load_config()
        
        # Setup GUI
        self.setup_gui()
        
        # Apply initial theme
        self.apply_theme()
        
    def setup_gui(self):
        # Create menu bar
        self.menu_bar = tk.Menu(self.root)
        
        # File menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="New", command=self.new_file)
        self.file_menu.add_command(label="Open", command=self.open_file)
        self.file_menu.add_command(label="Save", command=self.save_file)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.exit_app)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        
        # View menu
        self.view_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.view_menu.add_command(label="Dashboard", command=self.show_dashboard)
        self.view_menu.add_command(label="CLI", command=self.show_cli)
        self.view_menu.add_separator()
        self.view_menu.add_command(label="Switch Theme", command=self.switch_theme)
        self.menu_bar.add_cascade(label="View", menu=self.view_menu)
        
        # Tools menu
        self.tools_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.tools_menu.add_command(label="Network Scanner", command=self.show_scanner)
        self.tools_menu.add_command(label="Traffic Generator", command=self.show_traffic_gen)
        self.tools_menu.add_command(label="Connection Test", command=self.test_connection)
        self.menu_bar.add_cascade(label="Tools", menu=self.tools_menu)
        
        # Settings menu
        self.settings_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.settings_menu.add_command(label="Telegram Config", command=self.telegram_config)
        self.settings_menu.add_command(label="Appearance", command=self.appearance_settings)
        self.menu_bar.add_cascade(label="Settings", menu=self.settings_menu)
        
        self.root.config(menu=self.menu_bar)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Dashboard tab
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.setup_dashboard()
        
        # CLI tab
        self.cli_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.cli_frame, text="Command Line")
        self.setup_cli()
        
        # Scanner tab
        self.scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_frame, text="Network Scanner")
        self.setup_scanner()
        
        # Traffic Generator tab
        self.traffic_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.traffic_frame, text="Traffic Generator")
        self.setup_traffic_generator()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_dashboard(self):
        # Create frames for dashboard
        left_frame = ttk.Frame(self.dashboard_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        right_frame = ttk.Frame(self.dashboard_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Traffic chart
        traffic_label = ttk.Label(left_frame, text="Network Traffic Overview")
        traffic_label.pack(pady=5)
        
        self.traffic_fig, self.traffic_ax = plt.subplots(figsize=(6, 4))
        self.traffic_canvas = FigureCanvasTkAgg(self.traffic_fig, left_frame)
        self.traffic_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.update_traffic_chart()
        
        # Scan results chart
        scan_label = ttk.Label(right_frame, text="Port Scan Results")
        scan_label.pack(pady=5)
        
        self.scan_fig, self.scan_ax = plt.subplots(figsize=(6, 4))
        self.scan_canvas = FigureCanvasTkAgg(self.scan_fig, right_frame)
        self.scan_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # System info
        sys_frame = ttk.LabelFrame(self.dashboard_frame, text="System Information")
        sys_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.cpu_var = tk.StringVar()
        self.memory_var = tk.StringVar()
        self.network_var = tk.StringVar()
        
        ttk.Label(sys_frame, text="CPU Usage:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(sys_frame, textvariable=self.cpu_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(sys_frame, text="Memory Usage:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(sys_frame, textvariable=self.memory_var).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(sys_frame, text="Network Activity:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(sys_frame, textvariable=self.network_var).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Update system info periodically
        self.update_system_info()
    
    def setup_cli(self):
        # Command input
        input_frame = ttk.Frame(self.cli_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Command:").pack(side=tk.LEFT)
        self.cmd_entry = ttk.Entry(input_frame, width=50)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.cmd_entry.bind("<Return>", self.execute_command)
        
        ttk.Button(input_frame, text="Execute", command=self.execute_command).pack(side=tk.RIGHT)
        
        # Output area
        output_frame = ttk.LabelFrame(self.cli_frame, text="Output")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, width=80, height=25)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Help command list
        help_frame = ttk.LabelFrame(self.cli_frame, text="Available Commands")
        help_frame.pack(fill=tk.X, padx=5, pady=5)
        
        help_text = """
        help - Show this help message
        ping <ip> - Ping an IP address
        start monitoring <ip> - Start monitoring an IP address
        config telegram token <token> - Set Telegram bot token
        config telegram chat_id <id> - Set Telegram chat ID
        scan <ip> - Scan an IP address for open ports
        deep scan <ip> - Perform a deep scan of all ports
        add ip <ip> - Add an IP to monitoring list
        remove ip <ip> - Remove an IP from monitoring list
        exit - Exit the application
        clear - Clear the output screen
        history - Show command history
        view - View monitored IPs
        status - Show current monitoring status
        traceroute <ip> - Perform traceroute to IP
        udptraceroute <ip> - Perform UDP traceroute
        tcptraceroute <ip> - Perform TCP traceroute
        export data - Export data to Telegram
        test connection - Test network connection
        generate traffic <ip> <type> <duration> - Generate network traffic
        """
        
        help_label = ttk.Label(help_frame, text=help_text, justify=tk.LEFT)
        help_label.pack(fill=tk.X, padx=5, pady=5)
    
    def setup_scanner(self):
        # Scanner input
        scan_input_frame = ttk.Frame(self.scanner_frame)
        scan_input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(scan_input_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5)
        self.scan_ip_entry = ttk.Entry(scan_input_frame, width=20)
        self.scan_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(scan_input_frame, text="Quick Scan", 
                  command=lambda: self.start_scan(self.scan_ip_entry.get(), False)).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Button(scan_input_frame, text="Deep Scan", 
                  command=lambda: self.start_scan(self.scan_ip_entry.get(), True)).grid(row=0, column=3, padx=5, pady=5)
        
        # Port range selection
        port_frame = ttk.Frame(self.scanner_frame)
        port_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(port_frame, text="Port Range:").grid(row=0, column=0, padx=5, pady=5)
        self.port_start = ttk.Entry(port_frame, width=8)
        self.port_start.grid(row=0, column=1, padx=5, pady=5)
        self.port_start.insert(0, "1")
        
        ttk.Label(port_frame, text="to").grid(row=0, column=2, padx=5, pady=5)
        self.port_end = ttk.Entry(port_frame, width=8)
        self.port_end.grid(row=0, column=3, padx=5, pady=5)
        self.port_end.insert(0, "1024")
        
        ttk.Button(port_frame, text="Custom Scan", 
                  command=self.custom_scan).grid(row=0, column=4, padx=5, pady=5)
        
        # Scan results
        result_frame = ttk.LabelFrame(self.scanner_frame, text="Scan Results")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.scan_result_text = scrolledtext.ScrolledText(result_frame, width=80, height=20)
        self.scan_result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_traffic_generator(self):
        # Traffic generator input
        traffic_input_frame = ttk.Frame(self.traffic_frame)
        traffic_input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(traffic_input_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5)
        self.traffic_ip_entry = ttk.Entry(traffic_input_frame, width=20)
        self.traffic_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(traffic_input_frame, text="Protocol:").grid(row=0, column=2, padx=5, pady=5)
        self.protocol_var = tk.StringVar(value="TCP")
        protocol_combo = ttk.Combobox(traffic_input_frame, textvariable=self.protocol_var, 
                                     values=["TCP", "UDP", "HTTP", "HTTPS"], width=10)
        protocol_combo.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Label(traffic_input_frame, text="Duration (s):").grid(row=0, column=4, padx=5, pady=5)
        self.duration_entry = ttk.Entry(traffic_input_frame, width=10)
        self.duration_entry.grid(row=0, column=5, padx=5, pady=5)
        self.duration_entry.insert(0, "10")
        
        ttk.Button(traffic_input_frame, text="Generate Traffic", 
                  command=self.generate_traffic).grid(row=0, column=6, padx=5, pady=5)
        
        # Traffic stats
        stats_frame = ttk.LabelFrame(self.traffic_frame, text="Traffic Statistics")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.packets_sent_var = tk.StringVar(value="Packets Sent: 0")
        self.bytes_sent_var = tk.StringVar(value="Bytes Sent: 0")
        self.current_rate_var = tk.StringVar(value="Current Rate: 0 packets/s")
        
        ttk.Label(stats_frame, textvariable=self.packets_sent_var).grid(row=0, column=0, padx=10, pady=5)
        ttk.Label(stats_frame, textvariable=self.bytes_sent_var).grid(row=0, column=1, padx=10, pady=5)
        ttk.Label(stats_frame, textvariable=self.current_rate_var).grid(row=0, column=2, padx=10, pady=5)
        
        # Traffic log
        log_frame = ttk.LabelFrame(self.traffic_frame, text="Traffic Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.traffic_log_text = scrolledtext.ScrolledText(log_frame, width=80, height=15)
        self.traffic_log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def execute_command(self, event=None):
        command = self.cmd_entry.get()
        self.cmd_entry.delete(0, tk.END)
        
        if not command:
            return
        
        self.command_history.append(command)
        self.output_text.insert(tk.END, f"> {command}\n")
        
        parts = command.split()
        cmd = parts[0].lower()
        
        try:
            if cmd == "help":
                self.show_help()
            elif cmd == "ping" and len(parts) > 1:
                self.ping_ip(parts[1])
            elif cmd == "start" and len(parts) > 2 and parts[1].lower() == "monitoring":
                self.start_monitoring(parts[2])
            elif cmd == "config" and len(parts) > 3:
                if parts[1].lower() == "telegram":
                    if parts[2].lower() == "token":
                        self.config_telegram_token(parts[3])
                    elif parts[2].lower() == "chat_id":
                        self.config_telegram_chat_id(parts[3])
            elif cmd == "scan" and len(parts) > 1:
                self.scan_ip(parts[1], False)
            elif cmd == "deep" and len(parts) > 2 and parts[1].lower() == "scan":
                self.scan_ip(parts[2], True)
            elif cmd == "add" and len(parts) > 2 and parts[1].lower() == "ip":
                self.add_ip(parts[2])
            elif cmd == "remove" and len(parts) > 2 and parts[1].lower() == "ip":
                self.remove_ip(parts[2])
            elif cmd == "exit":
                self.exit_app()
            elif cmd == "clear":
                self.output_text.delete(1.0, tk.END)
            elif cmd == "history":
                self.show_history()
            elif cmd == "view":
                self.view_ips()
            elif cmd == "status":
                self.show_status()
            elif cmd == "traceroute" and len(parts) > 1:
                self.traceroute(parts[1], "icmp")
            elif cmd == "udptraceroute" and len(parts) > 1:
                self.traceroute(parts[1], "udp")
            elif cmd == "tcptraceroute" and len(parts) > 1:
                self.traceroute(parts[1], "tcp")
            elif cmd == "export" and len(parts) > 1 and parts[1].lower() == "data":
                self.export_data()
            elif cmd == "test" and len(parts) > 1 and parts[1].lower() == "connection":
                self.test_connection()
            elif cmd == "generate" and len(parts) > 4 and parts[1].lower() == "traffic":
                self.generate_traffic_cli(parts[2], parts[3], parts[4])
            else:
                self.output_text.insert(tk.END, f"Unknown command: {command}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error executing command: {str(e)}\n")
        
        self.output_text.see(tk.END)
    
    def show_help(self):
        help_text = """
Available commands:
- help: Show this help message
- ping <ip>: Ping an IP address
- start monitoring <ip>: Start monitoring an IP address
- config telegram token <token>: Set Telegram bot token
- config telegram chat_id <id>: Set Telegram chat ID
- scan <ip>: Scan an IP address for open ports
- deep scan <ip>: Perform a deep scan of all ports
- add ip <ip>: Add an IP to monitoring list
- remove ip <ip>: Remove an IP from monitoring list
- exit: Exit the application
- clear: Clear the output screen
- history: Show command history
- view: View monitored IPs
- status: Show current monitoring status
- traceroute <ip>: Perform traceroute to IP
- udptraceroute <ip>: Perform UDP traceroute
- tcptraceroute <ip>: Perform TCP traceroute
- export data: Export data to Telegram
- test connection: Test network connection
- generate traffic <ip> <type> <duration>: Generate network traffic
        """
        self.output_text.insert(tk.END, help_text)
    
    def ping_ip(self, ip):
        try:
            self.output_text.insert(tk.END, f"Pinging {ip}...\n")
            result = subprocess.run(['ping', '-c', '4', ip], capture_output=True, text=True)
            self.output_text.insert(tk.END, result.stdout)
            if result.returncode != 0:
                self.output_text.insert(tk.END, f"Ping failed with return code {result.returncode}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error pinging {ip}: {str(e)}\n")
    
    def start_monitoring(self, ip):
        if ip not in self.monitored_ips:
            self.monitored_ips.append(ip)
            self.output_text.insert(tk.END, f"Started monitoring {ip}\n")
        else:
            self.output_text.insert(tk.END, f"Already monitoring {ip}\n")
    
    def config_telegram_token(self, token):
        self.config['telegram_token'] = token
        self.output_text.insert(tk.END, "Telegram token configured\n")
        self.save_config()
    
    def config_telegram_chat_id(self, chat_id):
        self.config['telegram_chat_id'] = chat_id
        self.output_text.insert(tk.END, "Telegram chat ID configured\n")
        self.save_config()
    
    def scan_ip(self, ip, deep_scan=False):
        self.output_text.insert(tk.END, f"Scanning {ip}...\n")
        
        # Determine port range
        if deep_scan:
            port_range = range(1, 65536)
            self.output_text.insert(tk.END, "Performing deep scan (all ports)\n")
        else:
            port_range = range(1, 1025)  # Well-known ports
            self.output_text.insert(tk.END, "Performing standard scan (well-known ports)\n")
        
        # Run scan in background thread
        threading.Thread(target=self.run_scan, args=(ip, port_range), daemon=True).start()
    
    def run_scan(self, ip, port_range):
        open_ports = []
        start_time = time.time()
        
        for port in port_range:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                        self.output_text.insert(tk.END, f"Port {port} is open\n")
            except:
                pass
        
        end_time = time.time()
        self.output_text.insert(tk.END, f"Scan completed in {end_time - start_time:.2f} seconds\n")
        self.output_text.insert(tk.END, f"Found {len(open_ports)} open ports: {open_ports}\n")
        
        # Update scan results for dashboard
        self.scan_results[ip] = {
            'open_ports': open_ports,
            'total_ports': len(port_range),
            'scan_time': end_time - start_time
        }
        
        # Update scan chart
        self.update_scan_chart(ip)
    
    def add_ip(self, ip):
        if ip not in self.monitored_ips:
            self.monitored_ips.append(ip)
            self.output_text.insert(tk.END, f"Added {ip} to monitoring list\n")
        else:
            self.output_text.insert(tk.END, f"{ip} is already in monitoring list\n")
    
    def remove_ip(self, ip):
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            self.output_text.insert(tk.END, f"Removed {ip} from monitoring list\n")
        else:
            self.output_text.insert(tk.END, f"{ip} is not in monitoring list\n")
    
    def show_history(self):
        self.output_text.insert(tk.END, "Command history:\n")
        for i, cmd in enumerate(self.command_history, 1):
            self.output_text.insert(tk.END, f"{i}. {cmd}\n")
    
    def view_ips(self):
        self.output_text.insert(tk.END, "Monitored IPs:\n")
        for ip in self.monitored_ips:
            self.output_text.insert(tk.END, f"- {ip}\n")
    
    def show_status(self):
        self.output_text.insert(tk.END, "Monitoring status:\n")
        self.output_text.insert(tk.END, f"Monitoring {len(self.monitored_ips)} IPs\n")
        for ip in self.monitored_ips:
            self.output_text.insert(tk.END, f"- {ip}\n")
        
        if self.config['telegram_token']:
            self.output_text.insert(tk.END, "Telegram token: Configured\n")
        else:
            self.output_text.insert(tk.END, "Telegram token: Not configured\n")
            
        if self.config['telegram_chat_id']:
            self.output_text.insert(tk.END, "Telegram chat ID: Configured\n")
        else:
            self.output_text.insert(tk.END, "Telegram chat ID: Not configured\n")
    
    def traceroute(self, ip, protocol="icmp"):
        self.output_text.insert(tk.END, f"Performing {protocol.upper()} traceroute to {ip}...\n")
        
        # Run traceroute in background thread
        threading.Thread(target=self.run_traceroute, args=(ip, protocol), daemon=True).start()
    
    def run_traceroute(self, ip, protocol):
        try:
            if protocol == "icmp":
                result = subprocess.run(['traceroute', ip], capture_output=True, text=True)
            elif protocol == "udp":
                result = subprocess.run(['traceroute', '-U', ip], capture_output=True, text=True)
            elif protocol == "tcp":
                result = subprocess.run(['traceroute', '-T', ip], capture_output=True, text=True)
            
            self.output_text.insert(tk.END, result.stdout)
            if result.returncode != 0:
                self.output_text.insert(tk.END, f"Traceroute failed with return code {result.returncode}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error performing traceroute: {str(e)}\n")
    
    def export_data(self):
        if not self.config['telegram_token'] or not self.config['telegram_chat_id']:
            self.output_text.insert(tk.END, "Telegram not configured. Please set token and chat ID first.\n")
            return
        
        self.output_text.insert(tk.END, "Exporting data to Telegram...\n")
        
        # Prepare data for export
        data = {
            'monitored_ips': self.monitored_ips,
            'scan_results': self.scan_results,
            'export_time': datetime.now().isoformat()
        }
        
        # Send data to Telegram
        threading.Thread(target=self.send_to_telegram, args=(data,), daemon=True).start()
    
    def send_to_telegram(self, data):
        try:
            url = f"https://api.telegram.org/bot{self.config['telegram_token']}/sendMessage"
            message = f"Cyber Security Tool Export\n\nMonitored IPs: {', '.join(self.monitored_ips)}\n\nScan Results:\n"
            
            for ip, results in self.scan_results.items():
                message += f"{ip}: {len(results['open_ports'])} open ports\n"
            
            payload = {
                'chat_id': self.config['telegram_chat_id'],
                'text': message
            }
            
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                self.output_text.insert(tk.END, "Data exported to Telegram successfully\n")
            else:
                self.output_text.insert(tk.END, f"Failed to export data to Telegram: {response.text}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error exporting to Telegram: {str(e)}\n")
    
    def test_connection(self):
        self.output_text.insert(tk.END, "Testing network connection...\n")
        
        # Test internet connectivity
        try:
            response = requests.get("https://www.google.com", timeout=5)
            if response.status_code == 200:
                self.output_text.insert(tk.END, "Internet connection: OK\n")
            else:
                self.output_text.insert(tk.END, "Internet connection: Limited\n")
        except:
            self.output_text.insert(tk.END, "Internet connection: Failed\n")
        
        # Test local network
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            self.output_text.insert(tk.END, f"Local hostname: {hostname}\n")
            self.output_text.insert(tk.END, f"Local IP: {local_ip}\n")
        except:
            self.output_text.insert(tk.END, "Local network: Failed\n")
    
    def generate_traffic_cli(self, ip, protocol, duration):
        try:
            duration = int(duration)
            self.output_text.insert(tk.END, f"Generating {protocol} traffic to {ip} for {duration} seconds...\n")
            
            # Start traffic generation in background thread
            threading.Thread(target=self.run_traffic_generation, 
                            args=(ip, protocol.lower(), duration), daemon=True).start()
        except ValueError:
            self.output_text.insert(tk.END, "Invalid duration. Please provide a number.\n")
    
    def generate_traffic(self):
        ip = self.traffic_ip_entry.get()
        protocol = self.protocol_var.get()
        
        try:
            duration = int(self.duration_entry.get())
            self.traffic_log_text.insert(tk.END, f"Generating {protocol} traffic to {ip} for {duration} seconds...\n")
            
            # Start traffic generation in background thread
            threading.Thread(target=self.run_traffic_generation, 
                            args=(ip, protocol.lower(), duration, True), daemon=True).start()
        except ValueError:
            self.traffic_log_text.insert(tk.END, "Invalid duration. Please provide a number.\n")
    
    def run_traffic_generation(self, ip, protocol, duration, gui=False):
        start_time = time.time()
        packets_sent = 0
        bytes_sent = 0
        
        # Reset stats
        if gui:
            self.packets_sent_var.set("Packets Sent: 0")
            self.bytes_sent_var.set("Bytes Sent: 0")
            self.current_rate_var.set("Current Rate: 0 packets/s")
        
        while time.time() - start_time < duration:
            try:
                if protocol == "tcp":
                    # Send TCP packet
                    packet = IP(dst=ip)/TCP(dport=random.randint(1, 65535))
                    send(packet, verbose=0)
                    packets_sent += 1
                    bytes_sent += len(packet)
                
                elif protocol == "udp":
                    # Send UDP packet
                    packet = IP(dst=ip)/UDP(dport=random.randint(1, 65535))
                    send(packet, verbose=0)
                    packets_sent += 1
                    bytes_sent += len(packet)
                
                elif protocol == "http":
                    # Send HTTP request
                    try:
                        response = requests.get(f"http://{ip}", timeout=1)
                        packets_sent += 1
                        bytes_sent += len(response.content)
                    except:
                        pass
                
                elif protocol == "https":
                    # Send HTTPS request
                    try:
                        response = requests.get(f"https://{ip}", timeout=1, verify=False)
                        packets_sent += 1
                        bytes_sent += len(response.content)
                    except:
                        pass
                
                # Update stats
                if gui:
                    current_rate = packets_sent / (time.time() - start_time)
                    self.packets_sent_var.set(f"Packets Sent: {packets_sent}")
                    self.bytes_sent_var.set(f"Bytes Sent: {bytes_sent}")
                    self.current_rate_var.set(f"Current Rate: {current_rate:.2f} packets/s")
                
                # Small delay to avoid overwhelming the system
                time.sleep(0.01)
                
            except Exception as e:
                if gui:
                    self.traffic_log_text.insert(tk.END, f"Error generating traffic: {str(e)}\n")
                else:
                    self.output_text.insert(tk.END, f"Error generating traffic: {str(e)}\n")
                break
        
        # Final update
        if gui:
            self.packets_sent_var.set(f"Packets Sent: {packets_sent}")
            self.bytes_sent_var.set(f"Bytes Sent: {bytes_sent}")
            self.current_rate_var.set("Traffic generation completed")
            self.traffic_log_text.insert(tk.END, 
                f"Traffic generation completed. Sent {packets_sent} packets, {bytes_sent} bytes\n")
        else:
            self.output_text.insert(tk.END, 
                f"Traffic generation completed. Sent {packets_sent} packets, {bytes_sent} bytes\n")
    
    def start_scan(self, ip, deep_scan):
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address to scan")
            return
        
        self.scan_result_text.delete(1.0, tk.END)
        self.scan_result_text.insert(tk.END, f"Starting {'deep' if deep_scan else 'quick'} scan of {ip}...\n")
        
        # Run scan in background thread
        threading.Thread(target=self.run_gui_scan, args=(ip, deep_scan), daemon=True).start()
    
    def run_gui_scan(self, ip, deep_scan):
        # Determine port range
        if deep_scan:
            port_range = range(1, 65536)
        else:
            port_range = range(1, 1025)  # Well-known ports
        
        open_ports = []
        start_time = time.time()
        
        for port in port_range:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                        self.scan_result_text.insert(tk.END, f"Port {port} is open\n")
                        self.scan_result_text.see(tk.END)
            except:
                pass
        
        end_time = time.time()
        self.scan_result_text.insert(tk.END, f"Scan completed in {end_time - start_time:.2f} seconds\n")
        self.scan_result_text.insert(tk.END, f"Found {len(open_ports)} open ports: {open_ports}\n")
        
        # Update scan results for dashboard
        self.scan_results[ip] = {
            'open_ports': open_ports,
            'total_ports': len(port_range),
            'scan_time': end_time - start_time
        }
        
        # Update scan chart
        self.update_scan_chart(ip)
    
    def custom_scan(self):
        ip = self.scan_ip_entry.get()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address to scan")
            return
        
        try:
            start_port = int(self.port_start.get())
            end_port = int(self.port_end.get()) + 1  # Include the end port
        except ValueError:
            messagebox.showerror("Error", "Please enter valid port numbers")
            return
        
        self.scan_result_text.delete(1.0, tk.END)
        self.scan_result_text.insert(tk.END, f"Starting custom scan of {ip} (ports {start_port}-{end_port-1})...\n")
        
        # Run scan in background thread
        threading.Thread(target=self.run_custom_scan, args=(ip, start_port, end_port), daemon=True).start()
    
    def run_custom_scan(self, ip, start_port, end_port):
        port_range = range(start_port, end_port)
        open_ports = []
        start_time = time.time()
        
        for port in port_range:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                        self.scan_result_text.insert(tk.END, f"Port {port} is open\n")
                        self.scan_result_text.see(tk.END)
            except:
                pass
        
        end_time = time.time()
        self.scan_result_text.insert(tk.END, f"Scan completed in {end_time - start_time:.2f} seconds\n")
        self.scan_result_text.insert(tk.END, f"Found {len(open_ports)} open ports: {open_ports}\n")
        
        # Update scan results for dashboard
        self.scan_results[ip] = {
            'open_ports': open_ports,
            'total_ports': len(port_range),
            'scan_time': end_time - start_time
        }
        
        # Update scan chart
        self.update_scan_chart(ip)
    
    def update_traffic_chart(self):
        # Simulate network traffic data
        if not hasattr(self, 'traffic_data'):
            self.traffic_data = deque(maxlen=100)
        
        # Add new data point
        current_time = datetime.now().strftime("%H:%M:%S")
        traffic_value = random.randint(100, 1000)  # Simulated traffic value
        self.traffic_data.append((current_time, traffic_value))
        
        # Update chart
        self.traffic_ax.clear()
        
        if self.traffic_data:
            times, values = zip(*self.traffic_data)
            self.traffic_ax.plot(times, values, 'g-')
            self.traffic_ax.set_title('Network Traffic Over Time')
            self.traffic_ax.set_xlabel('Time')
            self.traffic_ax.set_ylabel('Traffic (KB/s)')
            self.traffic_ax.tick_params(axis='x', rotation=45)
        
        self.traffic_canvas.draw()
        
        # Schedule next update
        self.root.after(2000, self.update_traffic_chart)
    
    def update_scan_chart(self, ip):
        if ip not in self.scan_results:
            return
        
        results = self.scan_results[ip]
        open_ports = len(results['open_ports'])
        closed_ports = results['total_ports'] - open_ports
        
        self.scan_ax.clear()
        
        # Create pie chart
        labels = ['Open Ports', 'Closed Ports']
        sizes = [open_ports, closed_ports]
        colors = ['#ff9999', '#66b3ff']
        
        self.scan_ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        self.scan_ax.axis('equal')
        self.scan_ax.set_title(f'Port Scan Results for {ip}')
        
        self.scan_canvas.draw()
    
    def update_system_info(self):
        # Get CPU usage
        cpu_percent = psutil.cpu_percent()
        self.cpu_var.set(f"{cpu_percent}%")
        
        # Get memory usage
        memory = psutil.virtual_memory()
        self.memory_var.set(f"{memory.percent}% ({memory.used//1024//1024}MB/{memory.total//1024//1024}MB)")
        
        # Get network activity
        net_io = psutil.net_io_counters()
        self.network_var.set(f"Sent: {net_io.bytes_sent//1024}KB, Recv: {net_io.bytes_recv//1024}KB")
        
        # Schedule next update
        self.root.after(1000, self.update_system_info)
    
    def new_file(self):
        self.monitored_ips = []
        self.command_history = []
        self.output_text.delete(1.0, tk.END)
        self.scan_result_text.delete(1.0, tk.END)
        self.traffic_log_text.delete(1.0, tk.END)
        self.status_var.set("New session started")
    
    def open_file(self):
        file_path = filedialog.askopenfilename(
            title="Open Configuration",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                if 'monitored_ips' in data:
                    self.monitored_ips = data['monitored_ips']
                
                if 'config' in data:
                    self.config = data['config']
                
                self.output_text.insert(tk.END, f"Loaded configuration from {file_path}\n")
                self.status_var.set(f"Loaded configuration from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def save_file(self):
        file_path = filedialog.asksaveasfilename(
            title="Save Configuration",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                data = {
                    'monitored_ips': self.monitored_ips,
                    'config': self.config,
                    'export_time': datetime.now().isoformat()
                }
                
                with open(file_path, 'w') as f:
                    json.dump(data, f, indent=4)
                
                self.output_text.insert(tk.END, f"Saved configuration to {file_path}\n")
                self.status_var.set(f"Saved configuration to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def exit_app(self):
        self.save_config()
        self.root.quit()
    
    def show_dashboard(self):
        self.notebook.select(0)
    
    def show_cli(self):
        self.notebook.select(1)
    
    def show_scanner(self):
        self.notebook.select(2)
    
    def show_traffic_gen(self):
        self.notebook.select(3)
    
    def switch_theme(self):
        if self.theme == "black":
            self.theme = "green"
        else:
            self.theme = "black"
        
        self.apply_theme()
    
    def apply_theme(self):
        if self.theme == "black":
            # Black theme
            bg_color = "#000000"
            fg_color = "#00FF00"
            accent_color = "#008800"
        else:
            # Green theme
            bg_color = "#001100"
            fg_color = "#00FF00"
            accent_color = "#004400"
        
        # Apply colors to widgets
        self.root.configure(background=bg_color)
        
        # Apply to text widgets
        self.output_text.configure(bg=bg_color, fg=fg_color, insertbackground=fg_color)
        self.scan_result_text.configure(bg=bg_color, fg=fg_color, insertbackground=fg_color)
        self.traffic_log_text.configure(bg=bg_color, fg=fg_color, insertbackground=fg_color)
        
        # Update status
        self.status_var.set(f"Theme changed to {self.theme}")
    
    def telegram_config(self):
        # Create configuration dialog
        config_dialog = tk.Toplevel(self.root)
        config_dialog.title("Telegram Configuration")
        config_dialog.geometry("400x200")
        config_dialog.resizable(False, False)
        
        ttk.Label(config_dialog, text="Telegram Bot Token:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        token_entry = ttk.Entry(config_dialog, width=40)
        token_entry.grid(row=0, column=1, padx=10, pady=10)
        token_entry.insert(0, self.config['telegram_token'])
        
        ttk.Label(config_dialog, text="Chat ID:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        chat_id_entry = ttk.Entry(config_dialog, width=40)
        chat_id_entry.grid(row=1, column=1, padx=10, pady=10)
        chat_id_entry.insert(0, self.config['telegram_chat_id'])
        
        def save_config():
            self.config['telegram_token'] = token_entry.get()
            self.config['telegram_chat_id'] = chat_id_entry.get()
            self.save_config()
            config_dialog.destroy()
            self.status_var.set("Telegram configuration updated")
        
        ttk.Button(config_dialog, text="Save", command=save_config).grid(row=2, column=1, padx=10, pady=10, sticky=tk.E)
    
    def appearance_settings(self):
        # Create appearance settings dialog
        appearance_dialog = tk.Toplevel(self.root)
        appearance_dialog.title("Appearance Settings")
        appearance_dialog.geometry("300x150")
        appearance_dialog.resizable(False, False)
        
        ttk.Label(appearance_dialog, text="Theme:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        theme_var = tk.StringVar(value=self.theme)
        theme_combo = ttk.Combobox(appearance_dialog, textvariable=theme_var, values=["black", "green"], width=15)
        theme_combo.grid(row=0, column=1, padx=10, pady=10)
        
        def apply_settings():
            self.theme = theme_var.get()
            self.apply_theme()
            appearance_dialog.destroy()
        
        ttk.Button(appearance_dialog, text="Apply", command=apply_settings).grid(row=1, column=1, padx=10, pady=10, sticky=tk.E)
    
    def load_config(self):
        config_path = os.path.expanduser("~/.cyber_tool_config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    self.config = json.load(f)
            except:
                # If config file is corrupted, use defaults
                self.config = {
                    'telegram_token': '',
                    'telegram_chat_id': ''
                }
    
    def save_config(self):
        config_path = os.path.expanduser("~/.cyber_tool_config.json")
        with open(config_path, 'w') as f:
            json.dump(self.config, f)
    
    def run(self):
        self.root.mainloop()

# Main entry point
if __name__ == "__main__":
    app = CyberSecurityTool()
    app.run()