#!/usr/bin/env python3
"""
RedCore - Attack Simulator for A.T.I.C.E
Sends attack data to the dashboard
"""

import sys
import time
import random
import threading
import requests
import re
from datetime import datetime

# ==================== COLORS ====================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ==================== CONFIGURATION ====================
DASHBOARD_URL = "http://127.0.0.1:5001/api/attack"

# ==================== IP POOL (50 unique IPs) ====================
def generate_ip_pool(size=50):
    base_ranges = [
        ('203.0.113', 1, 254),   # Russia
        ('198.51.100', 1, 254),  # China
        ('192.0.2', 1, 254),     # Brazil
        ('203.0.114', 1, 254),   # Iran
        ('198.51.101', 1, 254),  # North Korea
        ('192.0.3', 1, 254),     # Netherlands
    ]
    pool = []
    while len(pool) < size:
        prefix, start, end = random.choice(base_ranges)
        ip = f"{prefix}.{random.randint(start, end)}"
        if ip not in pool:
            pool.append(ip)
    return pool

IP_POOL = generate_ip_pool(50)

def get_country(ip):
    if ip.startswith('203.0.113'): return 'Russia'
    elif ip.startswith('198.51.100'): return 'China'
    elif ip.startswith('192.0.2'): return 'Brazil'
    elif ip.startswith('203.0.114'): return 'Iran'
    elif ip.startswith('198.51.101'): return 'North Korea'
    elif ip.startswith('192.0.3'): return 'Netherlands'
    else: return 'Unknown'

# ==================== ATTACK TEMPLATES ====================
ATTACK_TYPES = [
    {"type": "Brute Force", "risk": 94, "port": 443, "protocol": "HTTPS", "actor": "APT28"},
    {"type": "DDoS", "risk": 98, "port": 80, "protocol": "TCP", "actor": "Lazarus"},
    {"type": "SQL Injection", "risk": 96, "port": 3306, "protocol": "MySQL", "actor": "APT41"},
    {"type": "Directory Enumeration", "risk": 75, "port": 80, "protocol": "HTTP", "actor": "APT33"},
    {"type": "XSS", "risk": 88, "port": 443, "protocol": "HTTPS", "actor": "APT28"},
    {"type": "Ransomware", "risk": 99, "port": 445, "protocol": "SMB", "actor": "Ryuk"},
    {"type": "Port Scan", "risk": 65, "port": 22, "protocol": "SSH", "actor": "Unknown"},
    {"type": "Credential Dumping", "risk": 92, "port": 3389, "protocol": "RDP", "actor": "Mimikatz"},
]

def generate_attack(ip=None):
    """Generate a single attack event"""
    if ip is None:
        ip = random.choice(IP_POOL)
    template = random.choice(ATTACK_TYPES)
    return {
        "ip": ip,
        "type": template["type"],
        "risk": template["risk"],
        "country": get_country(ip),
        "port": template["port"],
        "protocol": template["protocol"],
        "threat_actor": template["actor"]
    }

# ==================== IP VALIDATION ====================
def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    for part in parts:
        if int(part) > 255:
            return False
    return True

# ==================== REDCORE CLASS ====================
class RedCore:
    def __init__(self):
        self.continuous_thread = None
        self.continuous_running = False
        self.attack_count = 0

    def print_banner(self):
        banner = f"""
{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════════╗
║     ██████╗ ███████╗██████╗  ██████╗ ██████╗    ║
║     ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗   ║
║     ██████╔╝█████╗  ██║  ██║██║   ██║██████╔╝   ║
║     ██╔══██╗██╔══╝  ██║  ██║██║   ██║██╔══██╗   ║
║     ██║  ██║███████╗██████╔╝╚██████╔╝██║  ██║   ║
║     ╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ║
║                                                  ║
║         {Colors.WHITE}ATTACK SIMULATOR FOR A.T.I.C.E{Colors.RED}          ║
║         {Colors.GREEN}🔥 50 IPs • Bursts • Custom{Colors.RED}             ║
╚══════════════════════════════════════════════════╝
{Colors.END}
"""
        print(banner)
        print(f"{Colors.CYAN}[*] Loaded {len(IP_POOL)} attack IPs{Colors.END}")
        print(f"{Colors.YELLOW}[!] Target: {DASHBOARD_URL}{Colors.END}")

    def show_menu(self):
        print(f"\n{Colors.BOLD}{Colors.YELLOW}╔════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}║         REDCORE MENU              ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}╠════════════════════════════════════╣{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}║  {Colors.GREEN}[1]{Colors.YELLOW} Single Attack              ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}║  {Colors.GREEN}[2]{Colors.YELLOW} Burst (5 same IP)          ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}║  {Colors.GREEN}[3]{Colors.YELLOW} 🔥 CONTINUOUS MODE         ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}║  {Colors.GREEN}[4]{Colors.YELLOW} Stop Continuous           ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}║  {Colors.GREEN}[5]{Colors.YELLOW} Custom IP Attack          ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}║  {Colors.GREEN}[0]{Colors.YELLOW} Exit                      ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}╚════════════════════════════════════╝{Colors.END}")

    def send_attack(self, attack):
        """Send attack to dashboard"""
        try:
            r = requests.post(DASHBOARD_URL, json=attack, timeout=2)
            if r.status_code == 200:
                self.attack_count += 1
                print(f"{Colors.GREEN}[{self.attack_count}] 🔥 {attack['type']} from {attack['ip']} ({attack['country']}){Colors.END}")
            else:
                print(f"{Colors.YELLOW}[!] Dashboard returned {r.status_code}{Colors.END}")
        except requests.exceptions.ConnectionError:
            print(f"{Colors.RED}[-] Dashboard not reachable! Is it running?{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] Error: {e}{Colors.END}")

    def single_attack(self):
        attack = generate_attack()
        self.send_attack(attack)

    def burst_attack(self, count=5):
        ip = random.choice(IP_POOL)
        print(f"{Colors.CYAN}[*] Burst: {count} attacks from {ip}{Colors.END}")
        for _ in range(count):
            attack = generate_attack(ip)
            self.send_attack(attack)
            time.sleep(random.uniform(0.3, 0.8))

    def custom_ip_attack(self):
        ip = input(f"{Colors.CYAN}[?] Enter target IP: {Colors.END}").strip()
        if not is_valid_ip(ip):
            print(f"{Colors.RED}[-] Invalid IP format{Colors.END}")
            return
        attack = generate_attack(ip)
        self.send_attack(attack)

    def continuous_worker(self):
        while self.continuous_running:
            if random.random() < 0.7:
                attack = generate_attack()
                self.send_attack(attack)
                delay = random.uniform(0.5, 1.5)
            else:
                ip = random.choice(IP_POOL)
                burst_size = random.randint(2, 4)
                print(f"{Colors.YELLOW}[*] Burst: {burst_size} from {ip}{Colors.END}")
                for _ in range(burst_size):
                    attack = generate_attack(ip)
                    self.send_attack(attack)
                    time.sleep(random.uniform(0.2, 0.5))
                delay = random.uniform(0.8, 2.0)
            time.sleep(delay)

    def start_continuous(self):
        if self.continuous_running:
            print(f"{Colors.YELLOW}[!] Already running{Colors.END}")
            return
        self.continuous_running = True
        self.attack_count = 0
        self.continuous_thread = threading.Thread(target=self.continuous_worker, daemon=True)
        self.continuous_thread.start()
        print(f"{Colors.GREEN}[+] Continuous mode started{Colors.END}")

    def stop_continuous(self):
        self.continuous_running = False
        print(f"{Colors.RED}[-] Stopped. Total: {self.attack_count}{Colors.END}")

    def main_loop(self):
        self.print_banner()
        while True:
            self.show_menu()
            try:
                choice = int(input(f"{Colors.CYAN}[?] Choose: {Colors.END}").strip())
                if choice == 0:
                    self.stop_continuous()
                    print(f"{Colors.GREEN}[*] Goodbye!{Colors.END}")
                    sys.exit(0)
                elif choice == 1:
                    self.single_attack()
                elif choice == 2:
                    self.burst_attack(5)
                elif choice == 3:
                    self.start_continuous()
                elif choice == 4:
                    self.stop_continuous()
                elif choice == 5:
                    self.custom_ip_attack()
                else:
                    print(f"{Colors.RED}[-] Invalid{Colors.END}")
            except ValueError:
                print(f"{Colors.RED}[-] Enter a number{Colors.END}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Interrupted{Colors.END}")
                self.stop_continuous()
                sys.exit(0)

if __name__ == "__main__":
    tool = RedCore()
    tool.main_loop()
