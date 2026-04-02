#!/usr/bin/env python3
"""
REDCORE PROFESSIONAL - Attack Simulator
Now with REAL targeting + Terminal Animations
FOR EDUCATIONAL USE ONLY - Test on your own systems!
"""

import sys
import time
import random
import threading
import requests
from datetime import datetime
import os

# ==================== PROFESSIONAL COLOR CODES ====================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'

# ==================== ASCII BANNER WITH ANIMATION ====================
BANNER = f"""
{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ██████╗ ███████╗██████╗  ██████╗ ██████╗ ██████╗ ███████╗          ║ 
║   ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔════╝          ║
║   ██████╔╝█████╗  ██║  ██║██║   ██║██████╔╝██████╔╝█████╗            ║
║   ██╔══██╗██╔══╝  ██║  ██║██║   ██║██╔══██╗██╔══██╗██╔══╝            ║
║   ██║  ██║███████╗██████╔╝╚██████╔╝██║  ██║██║  ██║███████╗          ║
║   ╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝          ║
║                                                                      ║
║            {Colors.WHITE}PROFESSIONAL ATTACK SIMULATION FRAMEWORK{Colors.RED}            
║            {Colors.CYAN}● Target Any IP/Website ● Live Animations ●{Colors.RED}          
╚══════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""

# ==================== TARGET INPUT WITH VALIDATION ====================
def get_target():
    print(f"\n{Colors.CYAN}{Colors.BOLD}🎯 TARGET CONFIGURATION{Colors.END}")
    print(f"{Colors.YELLOW}─" * 50 + f"{Colors.END}")
    
    while True:
        target = input(f"{Colors.GREEN}Enter target URL/IP (e.g., http://192.168.1.100:5000 or https://example.com): {Colors.END}").strip()
        
        # Add http:// if missing
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
            
        # Validate basic format
        if '.' in target or 'localhost' in target:
            print(f"{Colors.GREEN}✅ Target set to: {target}{Colors.END}")
            return target
        else:
            print(f"{Colors.RED}❌ Invalid target! Please try again.{Colors.END}")

# ==================== ANIMATED LOADING ====================
def loading_animation(message, duration=2):
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        print(f"\r{Colors.CYAN}{frames[i % len(frames)]} {message}{Colors.END}", end="", flush=True)
        i += 1
        time.sleep(0.1)
    print(f"\r{Colors.GREEN}✅ {message} - Done!{Colors.END}   ")

# ==================== ATTACK TEMPLATES ====================
ATTACKS = [
    {"type": "Brute Force", "risk": 94, "port": 443, "protocol": "HTTPS", "actor": "APT28", "country": "Russia", "color": Colors.RED},
    {"type": "DDoS", "risk": 98, "port": 80, "protocol": "TCP", "actor": "Lazarus", "country": "North Korea", "color": Colors.RED},
    {"type": "SQL Injection", "risk": 96, "port": 3306, "protocol": "MySQL", "actor": "APT41", "country": "China", "color": Colors.RED},
    {"type": "Ransomware", "risk": 99, "port": 445, "protocol": "SMB", "actor": "Ryuk", "country": "Russia", "color": Colors.RED},
    {"type": "Port Scan", "risk": 65, "port": 22, "protocol": "SSH", "actor": "Unknown", "country": "Brazil", "color": Colors.YELLOW},
    {"type": "Credential Dumping", "risk": 92, "port": 3389, "protocol": "RDP", "actor": "Mimikatz", "country": "China", "color": Colors.RED},
    {"type": "Zero Day Exploit", "risk": 100, "port": 443, "protocol": "HTTPS", "actor": "APT32", "country": "Vietnam", "color": Colors.RED},
    {"type": "Man in the Middle", "risk": 87, "port": 8080, "protocol": "HTTP", "actor": "Fancy Bear", "country": "Russia", "color": Colors.YELLOW},
    {"type": "DNS Poisoning", "risk": 82, "port": 53, "protocol": "UDP", "actor": "Equation Group", "country": "USA", "color": Colors.YELLOW},
    {"type": "Buffer Overflow", "risk": 91, "port": 9999, "protocol": "TCP", "actor": "Shadow Brokers", "country": "Unknown", "color": Colors.RED},
]

# ==================== ATTACK GENERATOR ====================
def generate_attack(target, ip=None):
    """Generate a professional attack with random IP"""
    if ip is None:
        # Generate random IP for source
        ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    
    attack = random.choice(ATTACKS)
    
    return {
        "target": target,
        "source_ip": ip,
        "type": attack["type"],
        "risk": attack["risk"],
        "country": attack["country"],
        "port": attack["port"],
        "protocol": attack["protocol"],
        "threat_actor": attack["actor"],
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "color": attack["color"]
    }

# ==================== ANIMATED ATTACK DISPLAY ====================
def display_attack(attack, attack_count):
    """Show attack with professional animation"""
    
    # Determine risk level
    if attack["risk"] >= 90:
        risk_color = Colors.RED
        risk_text = "CRITICAL"
    elif attack["risk"] >= 70:
        risk_color = Colors.YELLOW
        risk_text = "HIGH"
    else:
        risk_color = Colors.GREEN
        risk_text = "MEDIUM"
    
    # Attack visualization
    print(f"\n{Colors.WHITE}{Colors.BOLD}{'═' * 60}{Colors.END}")
    
    # Attack header with counter
    print(f"{Colors.BOLD}🔥 ATTACK #{attack_count} {Colors.END}{risk_color}{Colors.BOLD}[{risk_text}]{Colors.END}")
    
    # Attack details in columns
    print(f"""
{Colors.CYAN}  ╭─ Target{Colors.END}       {Colors.WHITE}→{Colors.END} {Colors.BOLD}{attack['target']}{Colors.END}
{Colors.CYAN}  ├─ Source IP{Colors.END}    {Colors.WHITE}→{Colors.END} {attack['source_ip']} ({attack['country']})
{Colors.CYAN}  ├─ Attack Type{Colors.END}  {Colors.WHITE}→{Colors.END} {attack['color']}{attack['type']}{Colors.END}
{Colors.CYAN}  ├─ Risk Score{Colors.END}   {Colors.WHITE}→{Colors.END} {risk_color}{attack['risk']}%{Colors.END}
{Colors.CYAN}  ├─ Threat Actor{Colors.END} {Colors.WHITE}→{Colors.END} {attack['threat_actor']}
{Colors.CYAN}  ├─ Port/Proto{Colors.END}   {Colors.WHITE}→{Colors.END} {attack['port']}/{attack['protocol']}
{Colors.CYAN}  ╰─ Timestamp{Colors.END}    {Colors.WHITE}→{Colors.END} {attack['timestamp']}
    """)

# ==================== SEND TO DASHBOARD ====================
def send_to_dashboard(attack, dashboard_url):
    """Send attack to dashboard"""
    try:
        payload = {
            "ip": attack['source_ip'],
            "type": attack['type'],
            "risk": attack['risk'],
            "country": attack['country'],
            "port": attack['port'],
            "protocol": attack['protocol'],
            "threat_actor": attack['threat_actor']
        }
        
        response = requests.post(dashboard_url, json=payload, timeout=2)
        return response.status_code == 200
    except:
        return False

# ==================== ANIMATED MENU ====================
def show_menu():
    os.system('clear')  # Clear screen for clean menu
    print(BANNER)
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}📋 MAIN MENU{Colors.END}")
    print(f"{Colors.YELLOW}─" * 40 + f"{Colors.END}")
    
    menu_items = [
        ("1", "Single Attack", "Send one attack to target"),
        ("2", "Burst Attack", "5 attacks from same source IP"),
        ("3", "🔥 CONTINUOUS MODE", "Non-stop attacks with random IPs"),
        ("4", "Custom Attack", "Create your own attack"),
        ("5", "Stop Continuous", "Stop ongoing attacks"),
        ("0", "Exit", "Close RedCore")
    ]
    
    for num, name, desc in menu_items:
        color = Colors.GREEN if "🔥" in name else Colors.YELLOW
        print(f"  {color}{num}.{Colors.END} {Colors.BOLD}{name}{Colors.END}")
        print(f"     {Colors.WHITE}{desc}{Colors.END}\n")

# ==================== MAIN APPLICATION ====================
class RedCorePro:
    def __init__(self):
        self.target = None
        self.dashboard_url = "http://127.0.0.1:5001/api/attack"
        self.continuous_running = False
        self.attack_count = 0

    def run(self):
        os.system('clear')
        print(BANNER)
        
        # Professional intro
        loading_animation("Initializing RedCore Professional", 2)
        
        # Get target
        self.target = get_target()
        
        # Ask for dashboard URL
        print(f"\n{Colors.YELLOW}Dashboard is running at: {self.dashboard_url}{Colors.END}")
        change = input(f"{Colors.CYAN}Change dashboard URL? (y/N): {Colors.END}").lower()
        if change == 'y':
            self.dashboard_url = input(f"{Colors.GREEN}New dashboard URL: {Colors.END}").strip()
        
        # Main loop
        while True:
            show_menu()
            
            try:
                choice = input(f"{Colors.CYAN}Select option: {Colors.END}").strip()
                
                if choice == "1":
                    self.single_attack()
                elif choice == "2":
                    self.burst_attack()
                elif choice == "3":
                    self.start_continuous()
                elif choice == "4":
                    self.custom_attack()
                elif choice == "5":
                    self.stop_continuous()
                elif choice == "0":
                    self.clean_exit()
                    break
                else:
                    print(f"{Colors.RED}❌ Invalid option{Colors.END}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                self.clean_exit()
                break

    def single_attack(self):
        attack = generate_attack(self.target)
        self.attack_count += 1
        display_attack(attack, self.attack_count)
        
        if send_to_dashboard(attack, self.dashboard_url):
            print(f"{Colors.GREEN}✅ Attack sent to dashboard{Colors.END}")
        else:
            print(f"{Colors.YELLOW}⚠️ Dashboard not reachable{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

    def burst_attack(self, count=5):
        source_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        print(f"\n{Colors.YELLOW}🎯 BURST MODE: {count} attacks from {source_ip}{Colors.END}")
        
        for i in range(count):
            attack = generate_attack(self.target, source_ip)
            self.attack_count += 1
            display_attack(attack, self.attack_count)
            send_to_dashboard(attack, self.dashboard_url)
            time.sleep(0.5)
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

    def start_continuous(self):
        if self.continuous_running:
            print(f"{Colors.YELLOW}⚠️ Continuous mode already running{Colors.END}")
            return
            
        self.continuous_running = True
        self.attack_count = 0
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}🔥 CONTINUOUS MODE STARTED{Colors.END}")
        print(f"{Colors.YELLOW}Press Ctrl+C to stop{Colors.END}\n")
        
        try:
            while self.continuous_running:
                attack = generate_attack(self.target)
                self.attack_count += 1
                display_attack(attack, self.attack_count)
                send_to_dashboard(attack, self.dashboard_url)
                time.sleep(random.uniform(1, 3))
        except KeyboardInterrupt:
            self.stop_continuous()

    def stop_continuous(self):
        self.continuous_running = False
        print(f"\n{Colors.YELLOW}🛑 Continuous mode stopped{Colors.END}")
        print(f"{Colors.GREEN}Total attacks: {self.attack_count}{Colors.END}")
        time.sleep(2)

    def custom_attack(self):
        print(f"\n{Colors.BOLD}⚙️ CUSTOM ATTACK BUILDER{Colors.END}")
        
        source_ip = input(f"{Colors.CYAN}Source IP: {Colors.END}").strip()
        if not source_ip:
            source_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        
        attack_type = input(f"{Colors.CYAN}Attack type: {Colors.END}").strip() or "Custom Attack"
        risk = input(f"{Colors.CYAN}Risk (0-100): {Colors.END}").strip() or "85"
        
        attack = {
            "target": self.target,
            "source_ip": source_ip,
            "type": attack_type,
            "risk": int(risk),
            "country": "Unknown",
            "port": 443,
            "protocol": "HTTPS",
            "threat_actor": "Unknown",
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "color": Colors.RED
        }
        
        self.attack_count += 1
        display_attack(attack, self.attack_count)
        send_to_dashboard(attack, self.dashboard_url)
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

    def clean_exit(self):
        self.continuous_running = False
        print(f"\n{Colors.GREEN}{Colors.BOLD}")
        print("╔════════════════════════════════════════╗")
        print("║     THANK YOU FOR USING REDCORE!       ║")
        print("║     Total Attacks Sent: " + str(self.attack_count).ljust(10) + "       ║")
        print("╚════════════════════════════════════════╝")
        print(f"{Colors.END}")

# ==================== ENTRY POINT ====================
if __name__ == "__main__":
    tool = RedCorePro()
    tool.run()
