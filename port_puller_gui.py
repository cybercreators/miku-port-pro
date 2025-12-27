#!/usr/bin/env python3
"""
Port Puller GUI - Hatsune Miku Themed Port Scanner
A cute anime-themed GUI for scanning network ports
"""

import socket
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox
    from PIL import Image, ImageTk
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False
    print("Note: tkinter not available. Install with: sudo apt-get install python3-tk")
    print("Note: PIL not available. Install with: pip3 install Pillow")

# Miku Color Palette
MIKU_COLORS = {
    'primary_teal': '#00ddc0',
    'dark_teal': '#137a7f',
    'cyan': '#47dfd3',
    'pink': '#e12885',
    'light_cyan': '#86cecb',
    'dark_gray': '#373b3e',
    'light_gray': '#bec8d1',
    'bg_dark': '#1a2332',
    'bg_medium': '#2a3f5f',
}

# Common ports and their services
COMMON_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP Proxy",
    8443: "HTTPS Alt", 27017: "MongoDB",
}


class PortScanner:
    """Port scanning functionality"""
    
    def __init__(self):
        self.is_scanning = False
        self.open_ports = []
    
    def scan_port(self, ip, port, timeout=1):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                return (port, True, service)
            else:
                return (port, False, None)
        except:
            return (port, False, None)
    
    def scan_ports(self, ip, start_port, end_port, timeout, threads, callback):
        """Scan a range of ports with progress callback"""
        self.is_scanning = True
        self.open_ports = []
        total_ports = end_port - start_port + 1
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self.scan_port, ip, port, timeout): port 
                for port in range(start_port, end_port + 1)
            }
            
            completed = 0
            for future in as_completed(futures):
                if not self.is_scanning:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                    
                port, is_open, service = future.result()
                completed += 1
                
                if is_open:
                    self.open_ports.append((port, service))
                
                progress = (completed / total_ports) * 100
                callback(progress, port, is_open, service, completed, total_ports)
        
        self.is_scanning = False
        return sorted(self.open_ports)
    
    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False


class MikuPortScannerGUI:
    """Hatsune Miku themed port scanner GUI"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🎵 Miku Port Puller 🎵")
        self.root.geometry("900x700")
        self.root.configure(bg=MIKU_COLORS['bg_dark'])
        
        self.scanner = PortScanner()
        self.scan_thread = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        
        # Title Frame
        title_frame = tk.Frame(self.root, bg=MIKU_COLORS['primary_teal'], height=80)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame,
            text="🎤 Miku Port Puller 🎤",
            font=("Arial", 24, "bold"),
            bg=MIKU_COLORS['primary_teal'],
            fg='white'
        )
        title_label.pack(expand=True)
        
        subtitle_label = tk.Label(
            title_frame,
            text="♪ Scan ports with the power of music! ♪",
            font=("Arial", 10),
            bg=MIKU_COLORS['primary_teal'],
            fg=MIKU_COLORS['bg_dark']
        )
        subtitle_label.pack()
        
        # Main Content Frame
        content_frame = tk.Frame(self.root, bg=MIKU_COLORS['bg_dark'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Input Section
        input_frame = tk.LabelFrame(
            content_frame,
            text="🎵 Scan Configuration",
            font=("Arial", 12, "bold"),
            bg=MIKU_COLORS['bg_medium'],
            fg=MIKU_COLORS['primary_teal'],
            relief=tk.GROOVE,
            borderwidth=2
        )
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        # IP Address
        ip_frame = tk.Frame(input_frame, bg=MIKU_COLORS['bg_medium'])
        ip_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(
            ip_frame,
            text="Target IP/Host:",
            font=("Arial", 10, "bold"),
            bg=MIKU_COLORS['bg_medium'],
            fg=MIKU_COLORS['cyan'],
            width=15,
            anchor='w'
        ).pack(side=tk.LEFT)
        
        self.ip_entry = tk.Entry(
            ip_frame,
            font=("Arial", 10),
            bg='white',
            fg=MIKU_COLORS['dark_gray'],
            relief=tk.FLAT,
            insertbackground=MIKU_COLORS['pink']
        )
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.ip_entry.insert(0, "127.0.0.1")
        
        # Port Range
        port_frame = tk.Frame(input_frame, bg=MIKU_COLORS['bg_medium'])
        port_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(
            port_frame,
            text="Port Range:",
            font=("Arial", 10, "bold"),
            bg=MIKU_COLORS['bg_medium'],
            fg=MIKU_COLORS['cyan'],
            width=15,
            anchor='w'
        ).pack(side=tk.LEFT)
        
        self.start_port = tk.Entry(
            port_frame,
            font=("Arial", 10),
            bg='white',
            fg=MIKU_COLORS['dark_gray'],
            width=8,
            relief=tk.FLAT
        )
        self.start_port.pack(side=tk.LEFT, padx=5)
        self.start_port.insert(0, "1")
        
        tk.Label(
            port_frame,
            text="to",
            font=("Arial", 10),
            bg=MIKU_COLORS['bg_medium'],
            fg=MIKU_COLORS['light_gray']
        ).pack(side=tk.LEFT, padx=5)
        
        self.end_port = tk.Entry(
            port_frame,
            font=("Arial", 10),
            bg='white',
            fg=MIKU_COLORS['dark_gray'],
            width=8,
            relief=tk.FLAT
        )
        self.end_port.pack(side=tk.LEFT, padx=5)
        self.end_port.insert(0, "1024")
        
        # Timeout and Threads
        options_frame = tk.Frame(input_frame, bg=MIKU_COLORS['bg_medium'])
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(
            options_frame,
            text="Timeout (s):",
            font=("Arial", 10, "bold"),
            bg=MIKU_COLORS['bg_medium'],
            fg=MIKU_COLORS['cyan'],
            width=15,
            anchor='w'
        ).pack(side=tk.LEFT)
        
        self.timeout_entry = tk.Entry(
            options_frame,
            font=("Arial", 10),
            bg='white',
            fg=MIKU_COLORS['dark_gray'],
            width=8,
            relief=tk.FLAT
        )
        self.timeout_entry.pack(side=tk.LEFT, padx=5)
        self.timeout_entry.insert(0, "1.0")
        
        tk.Label(
            options_frame,
            text="Threads:",
            font=("Arial", 10, "bold"),
            bg=MIKU_COLORS['bg_medium'],
            fg=MIKU_COLORS['cyan'],
            width=10,
            anchor='w'
        ).pack(side=tk.LEFT, padx=(20, 0))
        
        self.threads_entry = tk.Entry(
            options_frame,
            font=("Arial", 10),
            bg='white',
            fg=MIKU_COLORS['dark_gray'],
            width=8,
            relief=tk.FLAT
        )
        self.threads_entry.pack(side=tk.LEFT, padx=5)
        self.threads_entry.insert(0, "100")
        
        # Buttons
        button_frame = tk.Frame(input_frame, bg=MIKU_COLORS['bg_medium'])
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.scan_button = tk.Button(
            button_frame,
            text="🎵 Start Scan",
            font=("Arial", 12, "bold"),
            bg=MIKU_COLORS['primary_teal'],
            fg='white',
            activebackground=MIKU_COLORS['cyan'],
            activeforeground='white',
            relief=tk.FLAT,
            cursor='hand2',
            command=self.start_scan,
            padx=20,
            pady=10
        )
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(
            button_frame,
            text="⏹ Stop Scan",
            font=("Arial", 12, "bold"),
            bg=MIKU_COLORS['pink'],
            fg='white',
            activebackground='#ff1a9e',
            activeforeground='white',
            relief=tk.FLAT,
            cursor='hand2',
            command=self.stop_scan,
            padx=20,
            pady=10,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = tk.Button(
            button_frame,
            text="🗑 Clear Results",
            font=("Arial", 12, "bold"),
            bg=MIKU_COLORS['dark_gray'],
            fg='white',
            activebackground='#4a5a6e',
            activeforeground='white',
            relief=tk.FLAT,
            cursor='hand2',
            command=self.clear_results,
            padx=20,
            pady=10
        )
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Progress Section
        progress_frame = tk.LabelFrame(
            content_frame,
            text="🎶 Scan Progress",
            font=("Arial", 12, "bold"),
            bg=MIKU_COLORS['bg_medium'],
            fg=MIKU_COLORS['primary_teal'],
            relief=tk.GROOVE,
            borderwidth=2
        )
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.progress_label = tk.Label(
            progress_frame,
            text="Ready to scan! ♪",
            font=("Arial", 10),
            bg=MIKU_COLORS['bg_medium'],
            fg=MIKU_COLORS['cyan'],
            anchor='w'
        )
        self.progress_label.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode='determinate',
            length=100
        )
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
        
        # Configure progress bar style
        style = ttk.Style()
        style.theme_use('default')
        style.configure(
            "TProgressbar",
            thickness=20,
            troughcolor=MIKU_COLORS['bg_dark'],
            background=MIKU_COLORS['primary_teal']
        )
        
        # Results Section
        results_frame = tk.LabelFrame(
            content_frame,
            text="🎤 Scan Results",
            font=("Arial", 12, "bold"),
            bg=MIKU_COLORS['bg_medium'],
            fg=MIKU_COLORS['primary_teal'],
            relief=tk.GROOVE,
            borderwidth=2
        )
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            font=("Courier", 10),
            bg=MIKU_COLORS['bg_dark'],
            fg=MIKU_COLORS['cyan'],
            insertbackground=MIKU_COLORS['pink'],
            relief=tk.FLAT,
            wrap=tk.WORD
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configure text tags for colored output
        self.results_text.tag_config('header', foreground=MIKU_COLORS['primary_teal'], font=("Courier", 10, "bold"))
        self.results_text.tag_config('open', foreground='#00ff88', font=("Courier", 10, "bold"))
        self.results_text.tag_config('info', foreground=MIKU_COLORS['cyan'])
        self.results_text.tag_config('pink', foreground=MIKU_COLORS['pink'], font=("Courier", 10, "bold"))
        
        self.log("🎵 Welcome to Miku Port Puller! 🎵\n", 'header')
        self.log("Ready to scan ports with the power of music! ♪\n\n", 'info')
    
    def log(self, message, tag='info'):
        """Add message to results text"""
        self.results_text.insert(tk.END, message, tag)
        self.results_text.see(tk.END)
        self.results_text.update()
    
    def clear_results(self):
        """Clear the results text"""
        self.results_text.delete(1.0, tk.END)
        self.log("🎵 Results cleared! Ready for a new scan! 🎵\n\n", 'header')
    
    def validate_inputs(self):
        """Validate user inputs"""
        try:
            ip = self.ip_entry.get().strip()
            if not ip:
                raise ValueError("Please enter an IP address or hostname")
            
            start = int(self.start_port.get())
            end = int(self.end_port.get())
            
            if start < 1 or end > 65535 or start > end:
                raise ValueError("Invalid port range (1-65535)")
            
            timeout = float(self.timeout_entry.get())
            if timeout <= 0:
                raise ValueError("Timeout must be positive")
            
            threads = int(self.threads_entry.get())
            if threads < 1 or threads > 1000:
                raise ValueError("Threads must be between 1 and 1000")
            
            return ip, start, end, timeout, threads
            
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return None
    
    def update_progress(self, progress, port, is_open, service, completed, total):
        """Update progress bar and log"""
        self.progress_bar['value'] = progress
        self.progress_label.config(
            text=f"Scanning... {completed}/{total} ports checked ({progress:.1f}%) ♪"
        )
        
        if is_open:
            self.log(f"[+] Port {port:5d} - OPEN  - {service}\n", 'open')
    
    def scan_worker(self, ip, start, end, timeout, threads):
        """Worker thread for scanning"""
        try:
            # Resolve hostname
            resolved_ip = socket.gethostbyname(ip)
            if resolved_ip != ip:
                self.log(f"[*] Resolved {ip} to {resolved_ip}\n", 'info')
            
            self.log(f"\n{'='*60}\n", 'header')
            self.log(f"[*] Starting port scan on {ip}\n", 'header')
            self.log(f"[*] Port range: {start}-{end}\n", 'info')
            self.log(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", 'info')
            self.log(f"[*] Using {threads} threads with {timeout}s timeout\n", 'info')
            self.log(f"{'='*60}\n\n", 'header')
            
            # Perform scan
            open_ports = self.scanner.scan_ports(
                resolved_ip, start, end, timeout, threads,
                lambda p, port, is_open, svc, c, t: self.root.after(
                    0, self.update_progress, p, port, is_open, svc, c, t
                )
            )
            
            # Display results
            self.root.after(0, self.display_results, ip, open_ports)
            
        except socket.gaierror:
            self.root.after(0, messagebox.showerror, "Error", f"Could not resolve hostname '{ip}'")
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", f"Scan error: {e}")
        finally:
            self.root.after(0, self.scan_complete)
    
    def display_results(self, ip, open_ports):
        """Display scan results"""
        self.log(f"\n{'='*60}\n", 'header')
        self.log(f"[*] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", 'header')
        self.log(f"{'='*60}\n\n", 'header')
        
        if open_ports:
            self.log(f"[+] Found {len(open_ports)} open port(s) on {ip}! 🎉\n\n", 'pink')
            self.log(f"{'PORT':<10} {'SERVICE':<20}\n", 'header')
            self.log(f"{'-'*30}\n", 'header')
            for port, service in open_ports:
                self.log(f"{port:<10} {service:<20}\n", 'open')
        else:
            self.log(f"[-] No open ports found on {ip}\n", 'info')
        
        self.log(f"\n🎵 Scan complete! ♪\n", 'pink')
    
    def start_scan(self):
        """Start the port scan"""
        inputs = self.validate_inputs()
        if not inputs:
            return
        
        ip, start, end, timeout, threads = inputs
        
        # Update UI state
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_bar['value'] = 0
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.scan_worker,
            args=(ip, start, end, timeout, threads),
            daemon=True
        )
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop the current scan"""
        self.scanner.stop_scan()
        self.log("\n[!] Scan stopped by user\n", 'pink')
        self.scan_complete()
    
    def scan_complete(self):
        """Reset UI after scan completion"""
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_label.config(text="Scan complete! Ready for next scan ♪")


def main():
    """Main entry point"""
    if not HAS_TKINTER:
        print("\n" + "="*60)
        print("ERROR: tkinter is not installed!")
        print("="*60)
        print("\nTo install tkinter, run:")
        print("  sudo apt-get install python3-tk")
        print("\nTo install Pillow (optional, for images), run:")
        print("  pip3 install Pillow")
        print("\nThen run this script again.")
        print("="*60 + "\n")
        return
    
    root = tk.Tk()
    app = MikuPortScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
