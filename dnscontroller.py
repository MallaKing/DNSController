import socket
import threading
import queue
import time
import os
import sys
import subprocess
import urllib.request
import ssl
import tkinter as tk
from tkinter import ttk, messagebox, Menu
from dnslib import DNSRecord, QTYPE, RR, A

# --- Configuration Constants ---
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 53
UPSTREAM_DNS = ("8.8.8.8", 53)
BUFFER_SIZE = 65535
CACHE_TTL = 300  # 5 Minutes (Set to 0 to disable cache)
BLOCKLIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
USER_RULES_FILE = "user_rules.txt"
WHITELIST_FILE = "whitelist.txt"
ACTIVE_INTERFACE = "Wi-Fi" 

# --- SAFE SEARCH VIP IPs ---
SAFE_GOOGLE_IP = "216.239.38.120" # forcesafesearch.google.com
SAFE_BING_IP   = "204.79.197.220" # strict.bing.com
SAFE_YOUTUBE_IP= "216.239.38.120" # restrict.youtube.com

class DNSFirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python DNS Firewall (Pro + SafeSearch)")
        self.root.geometry("1100x650")
        
        self.running = True
        self.dns_cache = {} 
        self.global_blocklist = set()
        self.user_blocklist = set()
        self.whitelist = set()
        self.log_queue = queue.Queue()
        
        # Safe Search Toggle Variable
        self.safe_search_enabled = tk.BooleanVar(value=True) 

        self._setup_ui()
        self._load_rules()
        
        threading.Thread(target=self._download_blocklist, daemon=True).start()
        threading.Thread(target=self._start_dns_server, daemon=True).start()
        
        self.root.after(100, self._process_logs)

    def _setup_ui(self):
        # Top Control Bar
        control_frame = tk.Frame(self.root, padx=10, pady=10, bg="#f0f0f0")
        control_frame.pack(fill=tk.X)
        
        # Status Label
        self.status_label = tk.Label(control_frame, text="Initializing...", font=("Segoe UI", 10, "bold"), bg="#f0f0f0")
        self.status_label.pack(side=tk.LEFT)
        
        # Right Side Buttons
        btn_frame = tk.Frame(control_frame, bg="#f0f0f0")
        btn_frame.pack(side=tk.RIGHT)
        
        # Safe Search Checkbox
        cb_safe = tk.Checkbutton(btn_frame, text="Safe Search Mode", variable=self.safe_search_enabled, bg="#f0f0f0", font=("Segoe UI", 9))
        cb_safe.pack(side=tk.LEFT, padx=15)

        tk.Button(btn_frame, text="Clear Logs", command=self._clear_logs).pack(side=tk.LEFT, padx=5)

        # Log Table
        self.tree = ttk.Treeview(self.root, columns=("Time", "Type", "Domain", "Action", "Details"), show="headings", selectmode="browse")
        self.tree.heading("Time", text="Time"); self.tree.column("Time", width=80, anchor="center")
        self.tree.heading("Type", text="Type"); self.tree.column("Type", width=60, anchor="center")
        self.tree.heading("Domain", text="Domain"); self.tree.column("Domain", width=450, anchor="w")
        self.tree.heading("Action", text="Status"); self.tree.column("Action", width=100, anchor="center")
        self.tree.heading("Details", text="Reason"); self.tree.column("Details", width=150, anchor="w")
        
        scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Tags for coloring
        self.tree.tag_configure("blocked", foreground="#d9534f")   # Red
        self.tree.tag_configure("allowed", foreground="#5cb85c")   # Green
        self.tree.tag_configure("whitelisted", foreground="#5bc0de") # Light Blue
        self.tree.tag_configure("safesearch", foreground="#f0ad4e") # Orange
        self.tree.tag_configure("cached", foreground="#0275d8")    # Blue

        # Context Menu
        self.context_menu = Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Block This Domain", command=self._block_selected_domain)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Unblock / Whitelist", command=self._unblock_selected_domain)
        self.tree.bind("<Button-3>", self._show_context_menu)

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _block_selected_domain(self):
        selected_item = self.tree.selection()
        if not selected_item: return
        domain = self.tree.item(selected_item)['values'][2]
        
        if domain in self.whitelist:
            self.whitelist.remove(domain)
            self._save_rules()

        if domain not in self.user_blocklist:
            self.user_blocklist.add(domain)
            self._save_rules()
            self._clear_cache_for_domain(domain)
            self.log_queue.put(("BLOCKED", domain, "User Rule", "Added to Blocklist"))
            messagebox.showinfo("Success", f"Blocked: {domain}")

    def _unblock_selected_domain(self):
        selected_item = self.tree.selection()
        if not selected_item: return
        domain = self.tree.item(selected_item)['values'][2]

        if domain in self.user_blocklist:
            self.user_blocklist.remove(domain)
            self._save_rules()
            self._clear_cache_for_domain(domain)
            self.log_queue.put(("ALLOWED", domain, "User Unblocked", "Removed from Blocklist"))
            messagebox.showinfo("Success", f"Unblocked: {domain}")
            return

        if domain not in self.whitelist:
            if messagebox.askyesno("Whitelist?", f"'{domain}' is blocked by the Global List.\n\nDo you want to Whitelist it?"):
                self.whitelist.add(domain)
                self._save_rules()
                self._clear_cache_for_domain(domain)
                self.log_queue.put(("ALLOWED", domain, "Whitelisted", "Added to Whitelist"))
        else:
            messagebox.showinfo("Info", "Domain is already whitelisted.")

    def _clear_cache_for_domain(self, domain):
        self.dns_cache = {k:v for k,v in self.dns_cache.items() if k[0] != domain}

    # --- MAIN DNS LOGIC ---
    def _start_dns_server(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((LISTEN_IP, LISTEN_PORT))
            try: sock.ioctl(socket.SIO_UDP_CONNRESET, False)
            except AttributeError: pass

            self._set_system_dns(LISTEN_IP)
            self.root.after(0, lambda: self.status_label.config(text=f"Active | {LISTEN_IP}", fg="green"))

            while self.running:
                try:
                    data, addr = sock.recvfrom(BUFFER_SIZE)
                    threading.Thread(target=self._handle_query, args=(sock, data, addr), daemon=True).start()
                except ConnectionResetError: continue
                except Exception as e: print(f"Socket: {e}")
        except Exception as e:
            self.log_queue.put(("SYSTEM", "Error", str(e), ""))
        finally:
            self._reset_system_dns()

    def _handle_query(self, sock, data, addr):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip('.')
            qtype = request.q.qtype 
            cache_key = (qname, qtype)

            # 1. SAFE SEARCH CHECK (Fixed for Speed)
            if self.safe_search_enabled.get():
                safe_ip = self._get_safesearch_ip(qname)
                if safe_ip:
                    reply = request.reply()
                    
                    if qtype == QTYPE.AAAA:
                        # FIX: If browser asks for IPv6, send EMPTY response (NOERROR).
                        # This forces the browser to immediately use the IPv4 address below.
                        reply.header.rcode = 0 # No Error
                        # We add NO answers. Just return empty.
                        sock.sendto(reply.pack(), addr)
                        return

                    elif qtype == QTYPE.A:
                        # If browser asks for IPv4, send the VIP Safe IP.
                        reply.add_answer(RR(str(request.q.qname), QTYPE.A, rdata=A(safe_ip), ttl=60))
                        sock.sendto(reply.pack(), addr)
                        self.log_queue.put(("SAFE", qname, "Enforced", "Safe Search On"))
                        return

            # 2. BLOCK CHECK
            blocked, reason = self._check_status(qname)
            if blocked:
                self.log_queue.put(("BLOCKED", qname, reason, "Blocked IP 0.0.0.0"))
                reply = request.reply()
                reply.add_answer(RR(str(request.q.qname), QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
                sock.sendto(reply.pack(), addr)
                return

            # 3. CACHE CHECK
            if cache_key in self.dns_cache:
                resp, ts = self.dns_cache[cache_key]
                if time.time() - ts < CACHE_TTL:
                    reply = DNSRecord.parse(resp)
                    reply.header.id = request.header.id
                    sock.sendto(reply.pack(), addr)
                    self.log_queue.put(("CACHED", qname, "Memory", "Served from Cache"))
                    return
                else:
                    del self.dns_cache[cache_key]

            # 4. FORWARD
            resp = self._forward(data)
            if resp:
                sock.sendto(resp, addr)
                self.dns_cache[cache_key] = (resp, time.time())
                tag = "Whitelisted" if reason == "Whitelist" else "Forwarded"
                self.log_queue.put(("ALLOWED", qname, tag, "Sent to 8.8.8.8"))

        except Exception as e:
            print(f"Query Error: {e}")

    def _get_safesearch_ip(self, domain):
        d = domain.lower()
        
        # 1. Google Safe Search (Strict)
        if "google.com" in d or "google.co" in d:
             # Skip technical domains that break if redirected
             if not any(x in d for x in ["mtalk", "accounts", "admin", "mail", "drive"]):
                 return SAFE_GOOGLE_IP
        
        # 2. Bing Safe Search (Strict)
        if "bing.com" in d:
            return SAFE_BING_IP
            
        # 3. YouTube Restricted Mode (STRICT + COMPREHENSIVE)
        # We must redirect ALL these to the Safe IP to force Strict Mode.
        youtube_restricted_domains = [
            "www.youtube.com",
            "m.youtube.com",
            "youtube.com",
            "youtu.be",
            "youtubei.googleapis.com", # Used by mobile apps/Smart TVs
            "youtube.googleapis.com",  # Used by embedded players
            "www.youtube-nocookie.com"
        ]
        
        if any(sub in d for sub in youtube_restricted_domains):
            return SAFE_YOUTUBE_IP
            
        return None
    def _forward(self, data):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5.0)
        try:
            s.sendto(data, UPSTREAM_DNS)
            return s.recvfrom(BUFFER_SIZE)[0]
        except: return None
        finally: s.close()

    def _check_status(self, domain):
        # Returns (IsBlocked, Reason)
        d = domain.lower()

        # --- 1. YOUTUBE KIDS MODE (The Nuclear Option) ---
        # If this logic is active, we block regular YouTube entirely.
        
        # A. ALWAYS ALLOW Infrastructure (Needed for Kids videos to play)
        if any(x in d for x in ["googlevideo.com", "ytimg.com", "ggpht.com", "youtubei.googleapis.com"]):
            return False, "Allowed Infra"

        # B. ALWAYS ALLOW YouTube Kids
        if "youtubekids.com" in d:
            return False, "Allowed Kids"

        # C. HARD BLOCK Regular YouTube
        if "youtube.com" in d or "youtu.be" in d:
            return True, "Blocked: Main YouTube"

        # --- 2. STANDARD CHECKS ---
        if domain in self.whitelist:
            return False, "Whitelist"

        if domain in self.user_blocklist: 
            return True, "User Block"
        
        for rule in self.user_blocklist:
            if domain.endswith("." + rule):
                return True, "User Wildcard"

        if domain in self.global_blocklist: 
            return True, "Global List"
            
        return False, "Allowed"

    # --- DATA UTILS ---
    def _download_blocklist(self):
        self.log_queue.put(("SYSTEM", "Blocklist", "Downloading...", ""))
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            req = urllib.request.Request(BLOCKLIST_URL, headers=headers)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, context=ctx) as r:
                data = r.read().decode('utf-8')
            
            count = 0
            for line in data.splitlines():
                if line.startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) >= 2:
                        self.global_blocklist.add(parts[1])
                        count += 1
            self.log_queue.put(("SYSTEM", "Blocklist", f"Loaded {count} rules", "Ready"))
        except Exception:
            self.log_queue.put(("SYSTEM", "Error", "Download Failed", ""))

    def _load_rules(self):
        if os.path.exists(USER_RULES_FILE):
            with open(USER_RULES_FILE, "r") as f:
                for l in f: self.user_blocklist.add(l.strip())
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, "r") as f:
                for l in f: self.whitelist.add(l.strip())

    def _save_rules(self):
        with open(USER_RULES_FILE, "w") as f:
            for r in self.user_blocklist: f.write(r+"\n")
        with open(WHITELIST_FILE, "w") as f:
            for r in self.whitelist: f.write(r+"\n")

    def _process_logs(self):
        try:
            while True:
                m = self.log_queue.get_nowait()
                tag = "allowed"
                if m[0] == "BLOCKED": tag = "blocked"
                elif m[0] == "SAFE": tag = "safesearch"
                elif m[0] == "CACHED": tag = "cached"
                elif "Whitelisted" in m[2]: tag = "whitelisted"
                
                # m contains (Status, Domain, Action, Details)
                self.tree.insert("", 0, values=(time.strftime("%H:%M:%S"), m[1], m[0], m[2], m[3] if len(m)>3 else ""), tags=(tag,))
                if len(self.tree.get_children()) > 1000:
                    self.tree.delete(self.tree.get_children()[-1])
        except queue.Empty: pass
        self.root.after(100, self._process_logs)
    
    def _clear_logs(self):
        for i in self.tree.get_children(): self.tree.delete(i)

    def _set_system_dns(self, ip):
        subprocess.run(f'netsh interface ip set dns name="{ACTIVE_INTERFACE}" static {ip}', shell=True, stdout=subprocess.DEVNULL)
        subprocess.run("ipconfig /flushdns", shell=True, stdout=subprocess.DEVNULL)

    def _reset_system_dns(self):
        subprocess.run(f'netsh interface ip set dns name="{ACTIVE_INTERFACE}" dhcp', shell=True, stdout=subprocess.DEVNULL)

    def on_close(self):
        if messagebox.askokcancel("Quit", "Stop DNS Server?"):
            self.running = False
            self._reset_system_dns()
            self.root.destroy()
            sys.exit()

if __name__ == "__main__":
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Run as Administrator.")
            input()
            sys.exit()
        root = tk.Tk()
        app = DNSFirewallApp(root)
        root.protocol("WM_DELETE_WINDOW", app.on_close)
        root.mainloop()
    except Exception as e:
        print(f"Startup Error: {e}")
        input()