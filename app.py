#!/usr/bin/env python3
"""
A.T.I.C.E - Automated Threat Intelligence Correlation Engine
PROFESSIONAL EDITION v2.5 - Full Graphics + Auto‑Block Toggle
"""

from flask import Flask, jsonify, render_template_string, request
from datetime import datetime, timedelta
import random
from collections import defaultdict

app = Flask(__name__)

MAX_ALERTS = 1000
REFRESH_INTERVAL = 2000

alerts = []
alert_id = 0

# Correlation storage
correlations = defaultdict(lambda: {
    'alerts': [], 'first_seen': None, 'last_seen': None, 'type': '', 'count': 0
})

def correlate_alert(alert):
    now = datetime.strptime(alert['timestamp'], "%Y-%m-%d %H:%M:%S")
    # Same source IP
    ip_key = f"ip:{alert['source_ip']}"
    if ip_key not in correlations:
        correlations[ip_key] = {'alerts': [], 'first_seen': alert['timestamp'], 'last_seen': alert['timestamp'], 'type': 'Same Source IP', 'count': 0}
    correlations[ip_key]['alerts'].append(alert['id'])
    correlations[ip_key]['last_seen'] = alert['timestamp']
    correlations[ip_key]['count'] += 1
    correlations[ip_key]['alerts'] = correlations[ip_key]['alerts'][-20:]

    # Same threat actor
    if alert['threat_actor'] not in ['Unknown', 'Unattributed', 'Cyber Criminal']:
        actor_key = f"actor:{alert['threat_actor']}"
        if actor_key not in correlations:
            correlations[actor_key] = {'alerts': [], 'first_seen': alert['timestamp'], 'last_seen': alert['timestamp'], 'type': 'Same Threat Actor', 'count': 0}
        correlations[actor_key]['alerts'].append(alert['id'])
        correlations[actor_key]['last_seen'] = alert['timestamp']
        correlations[actor_key]['count'] += 1
        correlations[actor_key]['alerts'] = correlations[actor_key]['alerts'][-20:]

    # Same country
    country_key = f"country:{alert['country']}"
    if country_key not in correlations:
        correlations[country_key] = {'alerts': [], 'first_seen': alert['timestamp'], 'last_seen': alert['timestamp'], 'type': 'Same Country', 'count': 0}
    correlations[country_key]['alerts'].append(alert['id'])
    correlations[country_key]['last_seen'] = alert['timestamp']
    correlations[country_key]['count'] += 1
    correlations[country_key]['alerts'] = correlations[country_key]['alerts'][-20:]

    # Same attack type
    type_key = f"type:{alert['type']}"
    if type_key not in correlations:
        correlations[type_key] = {'alerts': [], 'first_seen': alert['timestamp'], 'last_seen': alert['timestamp'], 'type': 'Same Attack Type', 'count': 0}
    correlations[type_key]['alerts'].append(alert['id'])
    correlations[type_key]['last_seen'] = alert['timestamp']
    correlations[type_key]['count'] += 1
    correlations[type_key]['alerts'] = correlations[type_key]['alerts'][-20:]

# MITRE ATT&CK mapping (full)
mitre_attack = {
    'Brute Force': {'tactic': 'Credential Access', 'technique': 'T1110', 'name': 'Brute Force', 'description': 'Password guessing attack'},
    'Port Scan': {'tactic': 'Discovery', 'technique': 'T1046', 'name': 'Network Service Scanning', 'description': 'Port scanning activity'},
    'SQL Injection': {'tactic': 'Initial Access', 'technique': 'T1190', 'name': 'SQL Injection', 'description': 'SQL database attack'},
    'Ransomware': {'tactic': 'Impact', 'technique': 'T1486', 'name': 'Ransomware', 'description': 'Ransomware encryption'},
    'DDoS': {'tactic': 'Impact', 'technique': 'T1498', 'name': 'DDoS', 'description': 'DDoS attack'},
    'C2 Beacon': {'tactic': 'Command and Control', 'technique': 'T1071', 'name': 'C2 Beacon', 'description': 'C2 communication'},
    'XSS': {'tactic': 'Initial Access', 'technique': 'T1189', 'name': 'XSS', 'description': 'Cross-site scripting'},
    'Directory Enumeration': {'tactic': 'Discovery', 'technique': 'T1046', 'name': 'Directory Enumeration', 'description': 'Web directory scanning'},
    'Credential Dumping': {'tactic': 'Credential Access', 'technique': 'T1003', 'name': 'Credential Dumping', 'description': 'Password hash extraction'},
    'APT Attack': {'tactic': 'Command and Control', 'technique': 'T1071', 'name': 'APT Attack', 'description': 'Multi-stage attack'},
    'Spear Phishing': {'tactic': 'Initial Access', 'technique': 'T1566', 'name': 'Spearphishing', 'description': 'Targeted phishing'},
    'Drive-by Compromise': {'tactic': 'Initial Access', 'technique': 'T1189', 'name': 'Drive-by', 'description': 'Web exploit'},
    'Exploit Public App': {'tactic': 'Initial Access', 'technique': 'T1190', 'name': 'Public App Exploit', 'description': 'Web app exploit'},
    'Command Execution': {'tactic': 'Execution', 'technique': 'T1059', 'name': 'Command Execution', 'description': 'Shell command'},
    'Powershell Attack': {'tactic': 'Execution', 'technique': 'T1059.001', 'name': 'PowerShell', 'description': 'Malicious PowerShell'},
    'Registry Modification': {'tactic': 'Persistence', 'technique': 'T1547.001', 'name': 'Registry Run Keys', 'description': 'Registry persistence'},
    'Scheduled Task': {'tactic': 'Persistence', 'technique': 'T1053.005', 'name': 'Scheduled Task', 'description': 'Malicious scheduled task'},
    'UAC Bypass': {'tactic': 'Privilege Escalation', 'technique': 'T1548.002', 'name': 'UAC Bypass', 'description': 'UAC bypass'},
    'Token Impersonation': {'tactic': 'Privilege Escalation', 'technique': 'T1134', 'name': 'Token Theft', 'description': 'Token impersonation'},
    'Process Injection': {'tactic': 'Defense Evasion', 'technique': 'T1055', 'name': 'Process Injection', 'description': 'Code injection'},
    'Obfuscation': {'tactic': 'Defense Evasion', 'technique': 'T1027', 'name': 'Obfuscation', 'description': 'Malware obfuscation'},
    'Keylogging': {'tactic': 'Credential Access', 'technique': 'T1056.001', 'name': 'Keylogging', 'description': 'Keystroke capture'},
    'Network Scanning': {'tactic': 'Discovery', 'technique': 'T1046', 'name': 'Network Scan', 'description': 'Network recon'},
    'RDP Attack': {'tactic': 'Lateral Movement', 'technique': 'T1021.001', 'name': 'RDP Brute', 'description': 'RDP brute force'},
    'SMB Exploit': {'tactic': 'Lateral Movement', 'technique': 'T1021.002', 'name': 'SMB Attack', 'description': 'SMB lateral movement'},
    'Screen Capture': {'tactic': 'Collection', 'technique': 'T1113', 'name': 'Screen Capture', 'description': 'Screen scraping'},
    'Clipboard Data': {'tactic': 'Collection', 'technique': 'T1115', 'name': 'Clipboard Theft', 'description': 'Clipboard data'},
    'DNS Tunneling': {'tactic': 'Command and Control', 'technique': 'T1572', 'name': 'DNS Tunneling', 'description': 'DNS covert channel'},
    'Data Exfiltration': {'tactic': 'Exfiltration', 'technique': 'T1048', 'name': 'Data Exfil', 'description': 'Data theft'},
    'Data Destruction': {'tactic': 'Impact', 'technique': 'T1485', 'name': 'Data Destruction', 'description': 'Data deletion'},
    'CSRF': {'tactic': 'Initial Access', 'technique': 'T1190', 'name': 'CSRF', 'description': 'Cross-site request forgery'},
    'Zero Day': {'tactic': 'Initial Access', 'technique': 'T1190', 'name': 'Zero Day', 'description': 'Unknown vulnerability'},
    'Fileless Malware': {'tactic': 'Defense Evasion', 'technique': 'T1027', 'name': 'Fileless', 'description': 'Memory-only malware'},
}

threat_actors = {
    'Russia': ['APT28', 'APT29', 'Fancy Bear', 'Sandworm', 'Turla', 'Gamaredon'],
    'China': ['APT41', 'APT40', 'APT17', 'Winnti', 'Mustang Panda', 'Tickle'],
    'North Korea': ['Lazarus', 'Kimsuky', 'APT37', 'APT38', 'Andariel'],
    'Iran': ['APT33', 'APT34', 'APT39', 'MuddyWater', 'OilRig', 'Fox Kitten'],
    'USA': ['Equation Group', 'TAO', 'CIA', 'NSA'],
    'Israel': ['Unit 8200', 'NSO Group'],
    'Vietnam': ['APT32', 'OceanLotus'],
    'India': ['Patchwork', 'SideWinder'],
    'Brazil': ['APT-C-01', 'Grandoreiro'],
    'Unknown': ['Anonymous', 'KillNet', 'REvil', 'DarkSide', 'BlackCat', 'LockBit']
}

malicious_ranges = [
    ('203.0.113', 1, 254), ('198.51.100', 1, 254), ('192.0.2', 1, 254),
    ('203.0.114', 1, 254), ('198.51.101', 1, 254), ('192.0.3', 1, 254),
    ('185.130.5', 1, 255), ('45.155', 1, 255),
]

def get_random_ip(from_malicious=True):
    if from_malicious and random.random() > 0.3:
        prefix, start, end = random.choice(malicious_ranges)
        return f"{prefix}.{random.randint(start, end)}"
    else:
        return f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

def get_country_from_ip(ip):
    if ip.startswith('203.0.113'): return 'Russia'
    elif ip.startswith('198.51.100'): return 'China'
    elif ip.startswith('192.0.2'): return 'Brazil'
    elif ip.startswith('203.0.114'): return 'Iran'
    elif ip.startswith('198.51.101'): return 'North Korea'
    elif ip.startswith('192.0.3'): return 'Netherlands'
    elif ip.startswith('185.130'): return 'Ukraine'
    elif ip.startswith('45.155'): return 'Netherlands'
    else: return random.choice(['USA', 'Germany', 'UK', 'Canada', 'France', 'Japan', 'Australia'])

def get_threat_actor(country):
    if country in threat_actors:
        return random.choice(threat_actors[country])
    return random.choice(['Unknown', 'Unattributed', 'Cyber Criminal'])

def get_reputation(ip):
    malicious_score = 0
    for prefix, start, end in malicious_ranges:
        if ip.startswith(prefix):
            malicious_score = random.randint(70, 100)
            break
    if malicious_score > 85:
        rep = 'Critical'
        conf = random.randint(90, 99)
        tags = ['apt', 'c2', 'malware', 'botnet', 'ransomware']
    elif malicious_score > 60:
        rep = 'Malicious'
        conf = random.randint(75, 90)
        tags = ['malware', 'scanner', 'suspicious']
    elif malicious_score > 30:
        rep = 'Suspicious'
        conf = random.randint(50, 75)
        tags = ['unverified', 'new', 'scanner']
    else:
        rep = random.choice(['Benign', 'Unknown'])
        conf = random.randint(20, 50)
        tags = ['clean', 'legitimate']
    extra_tags = ['phishing', 'ddos', 'exploit', 'bruteforce', 'backdoor']
    if random.random() > 0.7:
        tags.append(random.choice(extra_tags))
    return {
        'reputation': rep,
        'confidence': conf,
        'score': malicious_score,
        'source': random.choice(['VirusTotal', 'AlienVault OTX', 'Recorded Future', 'IBM X-Force', 'CrowdStrike']),
        'last_seen': (datetime.now() - timedelta(days=random.randint(0,30))).strftime("%Y-%m-%d"),
        'tags': list(set(tags[:4]))
    }

def generate_attack():
    global alert_id
    alert_id += 1
    attack_name = random.choice(list(mitre_attack.keys()))
    mitre_info = mitre_attack[attack_name]
    source_ip = get_random_ip()
    country = get_country_from_ip(source_ip)
    threat_actor = get_threat_actor(country)
    reputation = get_reputation(source_ip)
    base_risk = mitre_info.get('base_risk', random.randint(40,95))
    rep_boost = reputation['score']
    risk = min(99, max(1, (base_risk + rep_boost) // 2))
    target = f"{random.randint(10,192)}.{random.randint(0,168)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return {
        'id': alert_id,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'time': datetime.now().strftime("%H:%M:%S"),
        'source_ip': source_ip,
        'target_ip': target,
        'type': attack_name,
        'risk': risk,
        'country': country,
        'threat_actor': threat_actor,
        'mitre': mitre_info,
        'reputation': reputation,
        'port': random.choice([22,80,443,445,3389,8080,3306,5432]),
        'protocol': random.choice(['TCP','UDP','HTTP','HTTPS','SMB','RDP','SSH','MySQL']),
        'status': random.choice(['active','investigating','contained']),
        'confidence': reputation['confidence'],
        'severity': 'critical' if risk>85 else 'high' if risk>70 else 'medium' if risk>40 else 'low',
        'tags': reputation['tags'],
        'notes': f"{mitre_info['description']} from {country}"
    }

@app.route('/api/attack', methods=['POST'])
def receive_attack():
    global alerts
    data = request.json
    attack = generate_attack()
    if data:
        for key, value in data.items():
            if key in attack:
                attack[key] = value
    alerts.append(attack)
    correlate_alert(attack)
    if len(alerts) > MAX_ALERTS:
        alerts = alerts[-MAX_ALERTS:]
    print(f"\n🔥 ALERT #{attack['id']}: {attack['type']} from {attack['source_ip']} ({attack['country']})")
    return jsonify({"status": "success", "alert_id": attack['id']})

@app.route('/api/alerts')
def get_alerts():
    return jsonify(alerts)

@app.route('/api/alert/<int:alert_id>')
def get_alert(alert_id):
    for alert in alerts:
        if alert['id'] == alert_id:
            return jsonify(alert)
    return jsonify({"error": "Alert not found"}), 404

@app.route('/api/correlations')
def get_correlations():
    return jsonify({k: dict(v) for k, v in correlations.items()})

@app.route('/api/stats')
def get_stats():
    total = len(alerts)
    critical = len([a for a in alerts if a['risk'] >= 90])
    high = len([a for a in alerts if 70 <= a['risk'] < 90])
    medium = len([a for a in alerts if 40 <= a['risk'] < 70])
    low = len([a for a in alerts if a['risk'] < 40])
    attack_types = {}
    for alert in alerts[-100:]:
        attack_types[alert['type']] = attack_types.get(alert['type'], 0) + 1
    top_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:5]
    countries = {}
    for alert in alerts[-100:]:
        countries[alert['country']] = countries.get(alert['country'], 0) + 1
    top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]
    return jsonify({
        'total': total, 'critical': critical, 'high': high, 'medium': medium, 'low': low,
        'top_attacks': top_attacks, 'top_countries': top_countries
    })

@app.route('/')
def home():
    return render_template_string(DASHBOARD_HTML)

# ==================== PROFESSIONAL DASHBOARD HTML ====================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>A.T.I.C.E Professional - Threat Intelligence</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/animejs/3.2.1/anime.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #0a0c10; --bg-secondary: #0f1217; --bg-tertiary: #161b22;
            --bg-card: #1a1f2b; --bg-hover: #2d3748;
            --text-primary: #e6edf3; --text-secondary: #9ca3af; --text-muted: #6b7280;
            --accent-primary: #00ff9d; --accent-secondary: #3b82f6; --accent-tertiary: #a855f7;
            --danger: #ef4444; --warning: #f59e0b; --success: #10b981; --info: #3b82f6;
            --border: #2d3748; --border-light: #374151;
            --shadow-sm: 0 2px 4px rgba(0,0,0,0.3); --shadow-md: 0 4px 8px rgba(0,0,0,0.4);
            --shadow-lg: 0 8px 16px rgba(0,0,0,0.5); --shadow-xl: 0 12px 24px rgba(0,0,0,0.6);
            --glow-primary: 0 0 20px rgba(0,255,157,0.3); --glow-danger: 0 0 20px rgba(239,68,68,0.3);
            --glow-warning: 0 0 20px rgba(245,158,11,0.3);
            --transition-fast: 0.2s ease; --transition-normal: 0.3s ease; --transition-slow: 0.5s ease;
        }
        body {
            font-family: 'Inter', sans-serif; background: var(--bg-primary); color: var(--text-primary);
            overflow: hidden; line-height: 1.6;
        }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-secondary); }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--accent-primary); }
        .matrix-bg {
            position: fixed; top:0; left:0; width:100%; height:100%;
            background: radial-gradient(circle at 50% 50%, rgba(0,255,157,0.03) 0%, transparent 50%);
            pointer-events: none; z-index:0; animation: matrixPulse 8s infinite;
        }
        @keyframes matrixPulse { 0%,100% { opacity:0.3; } 50% { opacity:0.6; } }
        .app { display: flex; height: 100vh; position: relative; z-index: 1; }
        .sidebar {
            width: 280px; background: var(--bg-secondary); border-right: 1px solid var(--border);
            padding: 24px 16px; overflow-y: auto; backdrop-filter: blur(10px);
            animation: slideIn 0.5s var(--transition-normal);
        }
        @keyframes slideIn { from { transform: translateX(-100%); } to { transform: translateX(0); } }
        .logo {
            font-size: 24px; font-weight: 800; color: var(--accent-primary);
            margin-bottom: 32px; display: flex; align-items: center; gap: 12px;
            padding: 12px; border-bottom: 1px solid var(--border);
            text-shadow: var(--glow-primary); animation: logoGlow 3s infinite;
        }
        @keyframes logoGlow { 0%,100% { text-shadow:0 0 20px rgba(0,255,157,0.5); } 50% { text-shadow:0 0 40px rgba(0,255,157,0.8); } }
        .nav-item {
            padding: 14px 20px; color: var(--text-secondary); border-radius: 12px;
            margin-bottom: 8px; cursor: pointer; transition: all var(--transition-normal);
            display: flex; align-items: center; gap: 14px; font-weight: 500;
            position: relative; overflow: hidden;
        }
        .nav-item::before {
            content: ''; position: absolute; left: 0; top: 0; height: 100%; width: 4px;
            background: var(--accent-primary); transform: scaleY(0);
            transition: transform var(--transition-normal);
        }
        .nav-item:hover { background: var(--bg-tertiary); color: var(--text-primary); transform: translateX(5px); }
        .nav-item:hover::before { transform: scaleY(1); }
        .nav-item.active { background: var(--bg-tertiary); color: var(--accent-primary); box-shadow: var(--shadow-md); }
        .nav-item.active::before { transform: scaleY(1); }
        .nav-item i { font-size: 20px; width: 24px; text-align: center; }
        .main {
            flex: 1; padding: 24px 32px; overflow-y: auto;
            background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 100%);
            animation: fadeIn 0.5s var(--transition-normal);
        }
        @keyframes fadeIn { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }
        .header {
            display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px;
            animation: slideDown 0.5s var(--transition-normal);
        }
        @keyframes slideDown { from { transform:translateY(-20px); opacity:0; } to { transform:translateY(0); opacity:1; } }
        .title {
            font-size: 28px; font-weight: 700;
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
        }
        .status {
            background: var(--bg-tertiary); padding: 8px 20px; border-radius: 30px;
            display: flex; align-items: center; gap: 12px; border: 1px solid var(--border);
            box-shadow: var(--shadow-md);
        }
        .status-dot {
            width: 12px; height: 12px; background: var(--success); border-radius: 50%;
            animation: pulse 2s infinite; box-shadow: 0 0 10px var(--success);
        }
        @keyframes pulse { 0%,100% { opacity:1; transform:scale(1); } 50% { opacity:0.5; transform:scale(1.2); } }
        .last-updated { font-size: 12px; color: var(--text-secondary); }
        .stats-grid {
            display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px; margin-bottom: 32px;
        }
        .stat-card {
            background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 20px;
            padding: 24px; position: relative; overflow: hidden; transition: all var(--transition-normal);
            animation: cardFloat 0.5s ease; box-shadow: var(--shadow-md);
        }
        @keyframes cardFloat { from { transform:translateY(20px); opacity:0; } to { transform:translateY(0); opacity:1; } }
        .stat-card:hover { transform: translateY(-5px); box-shadow: var(--shadow-xl); border-color: var(--accent-primary); }
        .stat-card::before {
            content: ''; position: absolute; top:0; left:0; right:0; height:4px;
            background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
            animation: shimmer 2s infinite;
        }
        @keyframes shimmer { 0% { transform:translateX(-100%); } 100% { transform:translateX(100%); } }
        .stat-icon { font-size: 24px; margin-bottom: 16px; color: var(--accent-primary); }
        .stat-label { font-size: 14px; color: var(--text-secondary); margin-bottom: 8px; text-transform: uppercase; letter-spacing:0.5px; }
        .stat-value { font-size: 42px; font-weight: 700; line-height:1; margin-bottom:8px; }
        .stat-total .stat-value { color: var(--accent-primary); }
        .stat-critical .stat-value { color: var(--danger); }
        .stat-high .stat-value { color: var(--warning); }
        .stat-medium .stat-value { color: var(--accent-secondary); }
        .stat-trend { font-size: 12px; display: flex; align-items: center; gap: 4px; }
        .trend-up { color: var(--success); }
        .trend-down { color: var(--danger); }
        .charts-grid {
            display: grid; grid-template-columns: 2fr 1fr; gap: 24px; margin-bottom: 32px;
        }
        .chart-card {
            background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 20px;
            padding: 20px; box-shadow: var(--shadow-md);
        }
        .chart-header { display: flex; justify-content: space-between; align-items: center; margin-bottom:16px; }
        .chart-title { font-size:16px; font-weight:600; color:var(--text-primary); }
        .chart-container { height:250px; position: relative; }
        .table-container {
            background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 20px;
            overflow: hidden; margin-top: 24px; animation: fadeIn 0.5s ease; box-shadow: var(--shadow-md);
        }
        .table-header {
            padding: 20px; border-bottom: 1px solid var(--border);
            display: flex; justify-content: space-between; align-items: center;
        }
        .table-title { font-size:18px; font-weight:600; display: flex; align-items: center; gap:8px; }
        .table-actions { display: flex; gap: 8px; }
        table { width: 100%; border-collapse: collapse; }
        th {
            background: var(--bg-secondary); padding: 16px 20px; text-align: left;
            color: var(--text-secondary); font-weight:600; font-size:12px;
            text-transform: uppercase; letter-spacing:0.5px; border-bottom:1px solid var(--border);
        }
        td { padding: 16px 20px; border-bottom: 1px solid var(--border); font-size:14px; transition: background var(--transition-fast); }
        tr { transition: all var(--transition-fast); animation: rowAppear 0.3s ease; }
        @keyframes rowAppear { from { opacity:0; transform:translateX(-10px); } to { opacity:1; transform:translateX(0); } }
        tr:hover td { background: var(--bg-hover); }
        tr.new-row { animation: highlightNew 1s ease; }
        @keyframes highlightNew { 0% { background: rgba(0,255,157,0.2); } 100% { background: transparent; } }
        .badge {
            display: inline-block; padding: 4px 12px; border-radius: 30px; font-size:11px;
            font-weight:600; text-transform: uppercase; letter-spacing:0.3px; transition: all var(--transition-fast);
        }
        .badge-critical { background: rgba(239,68,68,0.15); color: var(--danger); border:1px solid rgba(239,68,68,0.3); }
        .badge-high { background: rgba(245,158,11,0.15); color: var(--warning); border:1px solid rgba(245,158,11,0.3); }
        .badge-medium { background: rgba(59,130,246,0.15); color: var(--info); border:1px solid rgba(59,130,246,0.3); }
        .badge-low { background: rgba(16,185,129,0.15); color: var(--success); border:1px solid rgba(16,185,129,0.3); }
        .badge-mitre { background: rgba(168,85,247,0.15); color: var(--accent-tertiary); border:1px solid rgba(168,85,247,0.3); }
        .badge-Critical, .badge-Malicious { background: rgba(239,68,68,0.15); color: var(--danger); border:1px solid rgba(239,68,68,0.3); }
        .badge-High, .badge-Suspicious { background: rgba(245,158,11,0.15); color: var(--warning); border:1px solid rgba(245,158,11,0.3); }
        .badge-Medium { background: rgba(59,130,246,0.15); color: var(--info); border:1px solid rgba(59,130,246,0.3); }
        .badge-Low, .badge-Benign { background: rgba(16,185,129,0.15); color: var(--success); border:1px solid rgba(16,185,129,0.3); }
        .badge-Unknown { background: rgba(107,114,128,0.15); color: var(--text-secondary); border:1px solid var(--border); }
        .blocked-badge { background: var(--danger); color:white; font-size:10px; padding:2px 8px; border-radius:12px; margin-left:8px; animation:pulse 2s infinite; }
        .btn {
            padding: 8px 16px; border-radius: 8px; border: none; font-weight:500; font-size:12px;
            cursor: pointer; transition: all var(--transition-fast); display: inline-flex; align-items: center; gap:6px;
        }
        .btn-primary { background: var(--accent-primary); color: var(--bg-primary); }
        .btn-primary:hover { background: var(--accent-secondary); transform: translateY(-2px); box-shadow: var(--glow-primary); }
        .btn-secondary { background: var(--bg-tertiary); color: var(--text-primary); border:1px solid var(--border); }
        .btn-secondary:hover { border-color: var(--accent-primary); transform: translateY(-2px); }
        .btn-danger { background: rgba(239,68,68,0.1); color: var(--danger); border:1px solid var(--danger); }
        .btn-danger:hover { background: var(--danger); color:white; transform: translateY(-2px); box-shadow: var(--glow-danger); }
        .btn-success { background: rgba(16,185,129,0.1); color: var(--success); border:1px solid var(--success); }
        .btn-success:hover { background: var(--success); color:white; }
        .btn-warning { background: rgba(245,158,11,0.1); color: var(--warning); border:1px solid var(--warning); }
        .btn-warning:hover { background: var(--warning); color:white; }
        .modal {
            display: none; position: fixed; top:0; left:0; width:100%; height:100%;
            background: rgba(0,0,0,0.8); backdrop-filter: blur(5px); z-index:1000;
            align-items: center; justify-content: center; animation: modalFade 0.3s ease;
        }
        @keyframes modalFade { from { opacity:0; } to { opacity:1; } }
        .modal.active { display: flex; }
        .modal-content {
            background: var(--bg-tertiary); border:1px solid var(--border); border-radius:24px;
            padding: 32px; max-width: 800px; width:90%; max-height:90vh; overflow-y:auto;
            animation: modalSlide 0.3s ease; box-shadow: var(--shadow-xl);
        }
        @keyframes modalSlide { from { transform:translateY(-50px); opacity:0; } to { transform:translateY(0); opacity:1; } }
        .modal-header {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 24px; padding-bottom:16px; border-bottom:1px solid var(--border);
        }
        .modal-header h2 { color: var(--accent-primary); font-size:24px; font-weight:600; }
        .modal-close { cursor: pointer; font-size:28px; color: var(--text-secondary); transition: all var(--transition-fast); }
        .modal-close:hover { color: var(--danger); transform: rotate(90deg); }
        .detail-grid { display: grid; grid-template-columns: repeat(2,1fr); gap:16px; margin-bottom:24px; }
        .detail-item { background: var(--bg-secondary); padding:16px; border-radius:12px; border:1px solid var(--border); }
        .detail-label { font-size:11px; color: var(--text-secondary); margin-bottom:4px; text-transform:uppercase; letter-spacing:0.3px; }
        .detail-value { font-size:16px; font-weight:600; }
        .tags { display: flex; flex-wrap: wrap; gap:8px; margin-top:8px; }
        .tag { background: var(--bg-tertiary); padding:4px 12px; border-radius:20px; font-size:11px; border:1px solid var(--border); }
        .search-bar {
            background: var(--bg-tertiary); border:1px solid var(--border); border-radius:40px;
            padding: 8px 8px 8px 20px; display: flex; align-items: center; gap:10px;
            margin-bottom:24px; transition: all var(--transition-fast);
        }
        .search-bar:focus-within { border-color: var(--accent-primary); box-shadow: var(--glow-primary); }
        .search-input { flex:1; background:transparent; border:none; color:var(--text-primary); font-size:14px; outline:none; }
        .search-input::placeholder { color: var(--text-muted); }
        .search-btn { background: var(--accent-primary); color: var(--bg-primary); border:none; padding:10px 24px; border-radius:30px; font-weight:600; cursor:pointer; transition: all var(--transition-fast); }
        .search-btn:hover { background: var(--accent-secondary); transform:scale(1.05); }
        .page { display: none; animation: pageFade 0.3s ease; }
        @keyframes pageFade { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:translateY(0); } }
        .page.active { display: block; }
        .loading-spinner { width:40px; height:40px; border:3px solid var(--bg-tertiary); border-top-color:var(--accent-primary); border-radius:50%; animation:spin 1s infinite linear; margin:20px auto; }
        @keyframes spin { to { transform:rotate(360deg); } }
        .skeleton { background: linear-gradient(90deg,var(--bg-tertiary) 25%,var(--bg-hover) 50%,var(--bg-tertiary) 75%); background-size:200% 100%; animation:skeleton 1.5s infinite; border-radius:4px; }
        @keyframes skeleton { 0% { background-position:200% 0; } 100% { background-position:-200% 0; } }
        .text-primary { color: var(--accent-primary); } .text-danger { color: var(--danger); } .text-warning { color: var(--warning); }
        .text-success { color: var(--success); } .text-info { color: var(--info); }
        .flex { display: flex; } .items-center { align-items: center; } .justify-between { justify-content: space-between; }
        .gap-2 { gap: 8px; } .gap-4 { gap: 16px; }
        .mt-2 { margin-top: 8px; } .mt-4 { margin-top: 16px; } .mb-2 { margin-bottom: 8px; } .mb-4 { margin-bottom: 16px; }
        .p-2 { padding: 8px; } .p-4 { padding: 16px; }
        .rounded { border-radius: 8px; } .rounded-lg { border-radius: 12px; } .rounded-xl { border-radius: 16px; }
        @media (max-width:1200px) { .stats-grid { grid-template-columns:repeat(2,1fr); } .charts-grid { grid-template-columns:1fr; } }
        @media (max-width:768px) {
            .app { flex-direction:column; }
            .sidebar { width:100%; height:auto; max-height:200px; }
            .stats-grid { grid-template-columns:1fr; }
            .detail-grid { grid-template-columns:1fr; }
            .header { flex-direction:column; gap:16px; align-items:flex-start; }
        }
        .glow-text { animation: glowText 2s infinite; }
        @keyframes glowText { 0%,100% { text-shadow:0 0 10px currentColor; } 50% { text-shadow:0 0 20px currentColor; } }
        .float { animation: float 3s infinite ease-in-out; }
        @keyframes float { 0%,100% { transform:translateY(0); } 50% { transform:translateY(-10px); } }
        .pulse-slow { animation: pulseSlow 3s infinite; }
        @keyframes pulseSlow { 0%,100% { opacity:1; } 50% { opacity:0.6; } }
        .rotate { animation: rotate 10s infinite linear; }
        @keyframes rotate { from { transform:rotate(0deg); } to { transform:rotate(360deg); } }
        /* Toggle switch */
        .toggle-switch {
            position: relative; display: inline-block; width: 60px; height: 30px;
            margin-left: 15px;
        }
        .toggle-switch input { opacity: 0; width: 0; height: 0; }
        .slider {
            position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0;
            background-color: #2d3748; transition: .4s; border-radius: 30px;
        }
        .slider:before {
            position: absolute; content: ""; height: 24px; width: 24px; left: 3px; bottom: 3px;
            background-color: white; transition: .4s; border-radius: 50%;
        }
        input:checked + .slider { background-color: var(--accent-primary); }
        input:checked + .slider:before { transform: translateX(30px); }
        .auto-block-label {
            display: flex; align-items: center; gap: 10px; margin-right: 20px;
        }
    </style>
</head>
<body>
    <div class="matrix-bg"></div>
    <div class="app">
        <!-- Sidebar Navigation -->
        <div class="sidebar">
            <div class="logo"><i class="fas fa-shield-halos"></i> A.T.I.C.E</div>
            <div class="nav-item active" data-page="dashboard"><i class="fas fa-chart-pie"></i> Dashboard <span class="badge badge-mitre" style="margin-left:auto;" id="totalAlertsBadge">0</span></div>
            <div class="nav-item" data-page="alerts"><i class="fas fa-exclamation-triangle"></i> Alerts <span class="badge badge-critical" style="margin-left:auto;" id="criticalAlertsBadge">0</span></div>
            <div class="nav-item" data-page="threatfeed"><i class="fas fa-stream"></i> Threat Feed</div>
            <div class="nav-item" data-page="mitre"><i class="fas fa-dragon"></i> MITRE ATT&CK</div>
            <div class="nav-item" data-page="reputation"><i class="fas fa-search"></i> Reputation</div>
            <div class="nav-item" data-page="blocked"><i class="fas fa-ban"></i> Blocked IPs</div>
            <div class="nav-item" data-page="analytics"><i class="fas fa-chart-line"></i> Analytics</div>
            <div class="nav-item" data-page="correlations"><i class="fas fa-link"></i> Correlations <span class="badge badge-info" style="margin-left:auto;" id="correlationCountBadge">0</span></div>
        </div>
        <!-- Main Content -->
        <div class="main">
            <div class="header">
                <div class="title"><i class="fas fa-shield-halos"></i> Security Operations Center</div>
                <div class="status">
                    <span class="status-dot"></span>
                    <span>Live Feed: Connected</span>
                    <span class="last-updated" id="lastUpdated"></span>
                </div>
            </div>
            <!-- Global Search -->
            <div class="search-bar">
                <i class="fas fa-search" style="color: var(--text-secondary);"></i>
                <input type="text" class="search-input" id="globalSearch" placeholder="Search IP, domain, hash, threat actor, or MITRE technique...">
                <button class="search-btn" onclick="searchIOC()">Search</button>
            </div>
            <!-- Dashboard Page -->
            <div id="page-dashboard" class="page active">
                <div class="stats-grid">
                    <div class="stat-card stat-total"><div class="stat-icon"><i class="fas fa-database"></i></div><div class="stat-label">Total Alerts</div><div class="stat-value" id="totalAlerts">0</div><div class="stat-trend" id="totalTrend"></div></div>
                    <div class="stat-card stat-critical"><div class="stat-icon"><i class="fas fa-skull-crossbones"></i></div><div class="stat-label">Critical (90%+)</div><div class="stat-value" id="criticalAlerts">0</div><div class="stat-trend" id="criticalTrend"></div></div>
                    <div class="stat-card stat-high"><div class="stat-icon"><i class="fas fa-exclamation"></i></div><div class="stat-label">High (70-89%)</div><div class="stat-value" id="highAlerts">0</div><div class="stat-trend" id="highTrend"></div></div>
                    <div class="stat-card stat-medium"><div class="stat-icon"><i class="fas fa-chart-line"></i></div><div class="stat-label">Medium (40-69%)</div><div class="stat-value" id="mediumAlerts">0</div><div class="stat-trend" id="mediumTrend"></div></div>
                </div>
                <div class="charts-grid">
                    <div class="chart-card"><div class="chart-header"><span class="chart-title"><i class="fas fa-chart-line" style="color:var(--accent-primary);"></i> Attack Timeline (Last 20)</span><span class="badge badge-mitre">Real-time</span></div><div class="chart-container"><canvas id="attackChart"></canvas></div></div>
                    <div class="chart-card"><div class="chart-header"><span class="chart-title"><i class="fas fa-chart-pie" style="color:var(--accent-primary);"></i> Attack Distribution</span><span class="badge badge-mitre">Last 100</span></div><div class="chart-container"><canvas id="distributionChart"></canvas></div></div>
                </div>
                <div class="table-container">
                    <div class="table-header"><div class="table-title"><i class="fas fa-bolt" style="color:var(--accent-primary);"></i> Recent Alerts</div><div class="table-actions"><button class="btn btn-secondary" onclick="refreshAlerts()"><i class="fas fa-sync-alt"></i> Refresh</button><button class="btn btn-secondary" onclick="exportAlerts()"><i class="fas fa-download"></i> Export</button></div></div>
                    <table><thead><tr><th>Time</th><th>Source IP</th><th>Target IP</th><th>Attack Type</th><th>Risk</th><th>MITRE</th><th>Reputation</th><th>Country</th><th>Actor</th><th>Actions</th></tr></thead><tbody id="recentAlerts"></tbody></table>
                </div>
            </div>
            <!-- Alerts Page -->
            <div id="page-alerts" class="page">
                <h2 style="margin-bottom:20px;"><i class="fas fa-exclamation-triangle" style="color:var(--warning);"></i> All Alerts</h2>
                <div class="table-container">
                    <div class="table-header"><div class="table-title">Complete Alert History</div><div class="table-actions"><button class="btn btn-secondary" onclick="filterAlerts()"><i class="fas fa-filter"></i> Filter</button><button class="btn btn-secondary" onclick="exportAllAlerts()"><i class="fas fa-download"></i> Export CSV</button></div></div>
                    <table><thead><tr><th>Time</th><th>Source IP</th><th>Target IP</th><th>Type</th><th>Risk</th><th>MITRE</th><th>Reputation</th><th>Country</th><th>Actor</th><th>Status</th><th>Actions</th></tr></thead><tbody id="allAlerts"></tbody></table>
                </div>
            </div>
            <!-- Threat Feed Page -->
            <div id="page-threatfeed" class="page">
                <h2 style="margin-bottom:20px;"><i class="fas fa-stream" style="color:var(--accent-primary);"></i> Live Threat Intelligence Feed</h2>
                <div class="table-container" id="threatFeed"></div>
            </div>
            <!-- MITRE Page -->
            <div id="page-mitre" class="page">
                <h2 style="margin-bottom:20px;"><i class="fas fa-dragon" style="color:var(--accent-tertiary);"></i> MITRE ATT&CK Framework Mapping</h2>
                <div class="table-container">
                    <table><thead><tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Count</th><th>Trend</th><th>Actions</th></tr></thead><tbody id="mitreTable"></tbody></table>
                </div>
            </div>
            <!-- Reputation Page -->
            <div id="page-reputation" class="page">
                <h2 style="margin-bottom:20px;"><i class="fas fa-search" style="color:var(--accent-primary);"></i> Threat Intelligence Lookup</h2>
                <div class="search-bar" style="margin-bottom:30px;"><i class="fas fa-search"></i><input type="text" class="search-input" id="reputationSearch" placeholder="Enter IP address, domain, or hash to check reputation..."><button class="search-btn" onclick="checkReputation()">Check Reputation</button></div>
                <div id="reputationResult" style="margin-bottom:30px;"></div>
                <h3 style="margin-bottom:20px;">Recent Reputation Scores</h3>
                <div class="table-container"><table><thead><tr><th>IP</th><th>Reputation</th><th>Confidence</th><th>Score</th><th>Source</th><th>Last Seen</th><th>Tags</th></tr></thead><tbody id="reputationTable"></tbody></table></div>
            </div>
            <!-- Blocked IPs Page with Auto-Block Toggle -->
            <div id="page-blocked" class="page">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
                    <h2><i class="fas fa-ban" style="color:var(--danger);"></i> Blocked IP Addresses</h2>
                    <div style="display:flex; align-items:center;">
                        <div class="auto-block-label">
                            <span>Auto‑block suspicious IPs</span>
                            <label class="toggle-switch">
                                <input type="checkbox" id="autoBlockToggle">
                                <span class="slider"></span>
                            </label>
                        </div>
                        <button class="btn btn-warning" onclick="blockAllSuspicious()" style="margin-right:10px;"><i class="fas fa-shield"></i> Block All Suspicious</button>
                        <button class="btn btn-danger" onclick="clearAllBlocked()"><i class="fas fa-trash"></i> Clear All</button>
                    </div>
                </div>
                <div class="table-container" id="blockedList"></div>
            </div>
            <!-- Analytics Page -->
            <div id="page-analytics" class="page">
                <h2 style="margin-bottom:20px;"><i class="fas fa-chart-line" style="color:var(--accent-primary);"></i> Advanced Analytics</h2>
                <div class="charts-grid">
                    <div class="chart-card"><div class="chart-header"><span class="chart-title">Attacks by Country</span></div><div class="chart-container"><canvas id="countryChart"></canvas></div></div>
                    <div class="chart-card"><div class="chart-header"><span class="chart-title">Top Threat Actors</span></div><div class="chart-container"><canvas id="actorChart"></canvas></div></div>
                </div>
                <div class="charts-grid">
                    <div class="chart-card"><div class="chart-header"><span class="chart-title">Risk Distribution</span></div><div class="chart-container"><canvas id="riskChart"></canvas></div></div>
                    <div class="chart-card"><div class="chart-header"><span class="chart-title">Attack Trends</span></div><div class="chart-container"><canvas id="trendChart"></canvas></div></div>
                </div>
            </div>
            <!-- Correlations Page -->
            <div id="page-correlations" class="page">
                <h2 style="margin-bottom:20px;"><i class="fas fa-link" style="color:var(--accent-tertiary);"></i> Correlation Insights</h2>
                <div class="table-container" id="correlationsTable"><div style="padding:20px; text-align:center;">Loading correlations...</div></div>
            </div>
        </div>
    </div>
    <!-- Modals -->
    <div class="modal" id="alertModal"><div class="modal-content"><div class="modal-header"><h2><i class="fas fa-info-circle"></i> Alert Details</h2><span class="modal-close" onclick="closeModal('alertModal')">&times;</span></div><div id="modalContent"></div></div></div>
    <div class="modal" id="investigationModal"><div class="modal-content"><div class="modal-header"><h2><i class="fas fa-microscope"></i> Investigation Report</h2><span class="modal-close" onclick="closeModal('investigationModal')">&times;</span></div><div id="investigationContent"></div></div></div>

    <script>
        // ==================== GLOBAL VARIABLES ====================
        let alerts = [];
        let previousCounts = { total:0, critical:0, high:0, medium:0 };
        let attackChart, distributionChart, countryChart, actorChart, riskChart, trendChart;
        let autoBlockEnabled = localStorage.getItem('autoBlock') === 'true'; // default false

        // ==================== INITIALIZATION ====================
        document.addEventListener('DOMContentLoaded', function() {
            initCharts();
            setupNavigation();
            startAutoRefresh();
            animateElements();
            // Set toggle state
            const toggle = document.getElementById('autoBlockToggle');
            if (toggle) {
                toggle.checked = autoBlockEnabled;
                toggle.addEventListener('change', function() {
                    autoBlockEnabled = this.checked;
                    localStorage.setItem('autoBlock', autoBlockEnabled);
                    showNotification(`Auto‑block ${autoBlockEnabled ? 'enabled' : 'disabled'}`, 'info');
                });
            }
            showNotification('A.T.I.C.E Professional Ready', 'success');
        });

        function initCharts() {
            // Attack Timeline Chart
            const ctx1 = document.getElementById('attackChart')?.getContext('2d');
            if (ctx1) {
                attackChart = new Chart(ctx1, {
                    type: 'line',
                    data: { labels: [], datasets: [
                        { label: 'Critical', data: [], borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)', tension:0.4, fill:true },
                        { label: 'High', data: [], borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.1)', tension:0.4, fill:true }
                    ]},
                    options: { responsive:true, maintainAspectRatio:false, scales: { y: { beginAtZero:true, grid: { color:'rgba(255,255,255,0.1)' } }, x: { grid:{ display:false } } }, plugins: { legend: { labels: { color:'#9ca3af' } } } }
                });
            }
            const ctx2 = document.getElementById('distributionChart')?.getContext('2d');
            if (ctx2) {
                distributionChart = new Chart(ctx2, {
                    type: 'doughnut',
                    data: { labels: ['Critical','High','Medium','Low'], datasets: [{ data:[0,0,0,0], backgroundColor:['#ef4444','#f59e0b','#3b82f6','#10b981'], borderWidth:0 }] },
                    options: { responsive:true, maintainAspectRatio:false, plugins: { legend: { position:'bottom', labels:{ color:'#9ca3af' } } } }
                });
            }
            const ctx3 = document.getElementById('countryChart')?.getContext('2d');
            if (ctx3) {
                countryChart = new Chart(ctx3, {
                    type: 'bar',
                    data: { labels:[], datasets:[{ label:'Attacks by Country', data:[], backgroundColor:'#3b82f6' }] },
                    options: { responsive:true, maintainAspectRatio:false, scales: { y: { beginAtZero:true, grid: { color:'rgba(255,255,255,0.1)' } }, x: { grid:{ display:false } } } }
                });
            }
            const ctx4 = document.getElementById('actorChart')?.getContext('2d');
            if (ctx4) {
                actorChart = new Chart(ctx4, {
                    type: 'bar',
                    data: { labels:[], datasets:[{ label:'Top Threat Actors', data:[], backgroundColor:'#ef4444' }] },
                    options: { responsive:true, maintainAspectRatio:false, scales: { y: { beginAtZero:true, grid: { color:'rgba(255,255,255,0.1)' } }, x: { grid:{ display:false } } } }
                });
            }
            const ctx5 = document.getElementById('riskChart')?.getContext('2d');
            if (ctx5) {
                riskChart = new Chart(ctx5, {
                    type: 'pie',
                    data: { labels: ['Critical','High','Medium','Low'], datasets:[{ data:[0,0,0,0], backgroundColor:['#ef4444','#f59e0b','#3b82f6','#10b981'] }] },
                    options: { responsive:true, maintainAspectRatio:false, plugins: { legend: { position:'bottom', labels:{ color:'#9ca3af' } } } }
                });
            }
            const ctx6 = document.getElementById('trendChart')?.getContext('2d');
            if (ctx6) {
                trendChart = new Chart(ctx6, {
                    type: 'line',
                    data: { labels:[], datasets:[{ label:'Attack Trend', data:[], borderColor:'#00ff9d', backgroundColor:'rgba(0,255,157,0.1)', tension:0.4, fill:true }] },
                    options: { responsive:true, maintainAspectRatio:false, scales: { y: { beginAtZero:true, grid: { color:'rgba(255,255,255,0.1)' } }, x: { grid:{ display:false } } } }
                });
            }
        }

        // ==================== NAVIGATION ====================
        function setupNavigation() {
            document.querySelectorAll('.nav-item').forEach(item => {
                item.addEventListener('click', function() {
                    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
                    this.classList.add('active');
                    const page = this.dataset.page;
                    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
                    document.getElementById('page-' + page).classList.add('active');
                    if (page === 'dashboard') updateCharts();
                    else if (page === 'analytics') updateAnalyticsCharts();
                    else if (page === 'blocked') showBlockedList();
                    else if (page === 'correlations') fetchCorrelations();
                });
            });
        }

        // ==================== AUTO REFRESH ====================
        function startAutoRefresh() {
            setInterval(fetchAlerts, 2000);
        }

        // ==================== FETCH ALERTS ====================
        function fetchAlerts() {
            fetch('/api/alerts')
                .then(res => res.json())
                .then(data => {
                    const oldLen = alerts.length;
                    alerts = data;
                    if (data.length > oldLen) {
                        const newAlerts = data.slice(oldLen);
                        newAlerts.forEach(alert => {
                            if (autoBlockEnabled && ['Suspicious','Malicious','Critical'].includes(alert.reputation.reputation)) {
                                autoBlockIP(alert.source_ip);
                            }
                        });
                        highlightNewAlerts(data.length - oldLen);
                    }
                    updateDashboard();
                    updateAllAlerts();
                    updateThreatFeed();
                    updateMITRE();
                    updateReputationTable();
                    updateSidebarBadges();
                    updateLastUpdated();
                    updateCharts();
                    animateNewRows();
                    fetchCorrelationCount();
                })
                .catch(err => console.error('Error fetching alerts:', err));
        }

        function autoBlockIP(ip) {
            let blocked = getBlockedIPs();
            if (!blocked.includes(ip)) {
                blocked.push(ip);
                saveBlockedIPs(blocked);
                showNotification(`🔒 Auto‑blocked ${ip}`, 'warning');
            }
        }

        // ==================== CLIENT-SIDE BLOCKING ====================
        function getBlockedIPs() { return JSON.parse(localStorage.getItem('blockedIPs') || '[]'); }
        function saveBlockedIPs(ips) { localStorage.setItem('blockedIPs', JSON.stringify(ips)); }
        function isBlocked(ip) { return getBlockedIPs().includes(ip); }

        function blockIP(ip) {
            let blocked = getBlockedIPs();
            if (!blocked.includes(ip)) {
                blocked.push(ip);
                saveBlockedIPs(blocked);
                showNotification(`IP ${ip} blocked`, 'success');
                if (document.getElementById('page-blocked').classList.contains('active')) showBlockedList();
                updateDashboard(); updateAllAlerts(); updateThreatFeed();
            } else showNotification('IP already blocked', 'warning');
            closeModal('alertModal');
        }

        function blockAllSuspicious() {
            const suspiciousReps = ['Suspicious','Malicious','Critical'];
            let ips = new Set();
            alerts.forEach(a => { if (suspiciousReps.includes(a.reputation.reputation)) ips.add(a.source_ip); });
            if (ips.size === 0) { showNotification('No suspicious IPs found','info'); return; }
            let blocked = getBlockedIPs();
            let newBlocks = 0;
            ips.forEach(ip => { if (!blocked.includes(ip)) { blocked.push(ip); newBlocks++; } });
            if (newBlocks) { saveBlockedIPs(blocked); showNotification(`Blocked ${newBlocks} new IPs`,'success'); }
            else showNotification('All suspicious IPs already blocked','info');
            if (document.getElementById('page-blocked').classList.contains('active')) showBlockedList();
            updateDashboard(); updateAllAlerts(); updateThreatFeed();
        }

        function unblockIP(ip) {
            let blocked = getBlockedIPs().filter(i => i !== ip);
            saveBlockedIPs(blocked);
            showNotification(`IP ${ip} unblocked`,'info');
            showBlockedList();
            updateDashboard(); updateAllAlerts(); updateThreatFeed();
        }

        function clearAllBlocked() {
            if (confirm('Unblock all IPs?')) {
                localStorage.removeItem('blockedIPs');
                showNotification('All IPs unblocked','info');
                showBlockedList();
                updateDashboard(); updateAllAlerts(); updateThreatFeed();
            }
        }

        function showBlockedList() {
            const blocked = getBlockedIPs();
            const container = document.getElementById('blockedList');
            if (blocked.length === 0) { container.innerHTML = '<div style="padding:40px; text-align:center;">No blocked IPs</div>'; return; }
            let html = '<table><thead><tr><th>IP Address</th><th>Actions</th></tr></thead><tbody>';
            blocked.forEach(ip => { html += `<tr><td>${ip}</td><td><button class="btn btn-success" onclick="unblockIP('${ip}')"><i class="fas fa-unlock"></i> Unblock</button></td></tr>`; });
            html += '</tbody></table>';
            container.innerHTML = html;
        }

        // ==================== CORRELATIONS ====================
        function fetchCorrelations() {
            fetch('/api/correlations')
                .then(res => res.json())
                .then(data => {
                    renderCorrelations(data);
                    document.getElementById('correlationCountBadge').textContent = Object.keys(data).length;
                })
                .catch(()=>{});
        }
        function fetchCorrelationCount() {
            fetch('/api/correlations')
                .then(res => res.json())
                .then(data => document.getElementById('correlationCountBadge').textContent = Object.keys(data).length)
                .catch(()=>{});
        }
        function renderCorrelations(corrs) {
            const container = document.getElementById('correlationsTable');
            if (!container) return;
            if (Object.keys(corrs).length === 0) { container.innerHTML = '<div style="padding:40px; text-align:center;">No correlations yet.</div>'; return; }
            let html = '<table><thead><tr><th>Key</th><th>Type</th><th>First Seen</th><th>Last Seen</th><th>Count</th><th>Alert IDs</th></tr></thead><tbody>';
            for (const [key,val] of Object.entries(corrs)) {
                html += `<tr><td><span class="badge badge-info">${key}</span></td><td>${val.type}</td><td>${val.first_seen||'N/A'}</td><td>${val.last_seen||'N/A'}</td><td><span class="badge badge-critical">${val.count}</span></td><td>${val.alerts.join(', ')}</td></tr>`;
            }
            html += '</tbody></table>';
            container.innerHTML = html;
        }

        // ==================== UPDATE FUNCTIONS ====================
        function updateDashboard() {
            const total = alerts.length;
            const critical = alerts.filter(a => a.risk >= 90).length;
            const high = alerts.filter(a => a.risk >= 70 && a.risk < 90).length;
            const medium = alerts.filter(a => a.risk >= 40 && a.risk < 70).length;
            document.getElementById('totalAlerts').textContent = total;
            document.getElementById('criticalAlerts').textContent = critical;
            document.getElementById('highAlerts').textContent = high;
            document.getElementById('mediumAlerts').textContent = medium;
            updateTrend('totalTrend', total, previousCounts.total);
            updateTrend('criticalTrend', critical, previousCounts.critical);
            updateTrend('highTrend', high, previousCounts.high);
            updateTrend('mediumTrend', medium, previousCounts.medium);
            previousCounts = { total, critical, high, medium };
            let html = '';
            alerts.slice(-15).reverse().forEach((alert, idx) => {
                const blockedBadge = isBlocked(alert.source_ip) ? '<span class="blocked-badge"><i class="fas fa-ban"></i> BLOCKED</span>' : '';
                const riskClass = alert.risk>=90 ? 'badge-critical' : alert.risk>=70 ? 'badge-high' : alert.risk>=40 ? 'badge-medium' : 'badge-low';
                const rowClass = idx<3 ? 'new-row' : '';
                html += `<tr class="${rowClass}"><td>${alert.time}</td><td>${alert.source_ip} ${blockedBadge}</td><td>${alert.target_ip}</td><td>${alert.type}</td><td><span class="badge ${riskClass}">${alert.risk}%</span></td><td><span class="badge badge-mitre">${alert.mitre.technique}</span></td><td><span class="badge badge-${alert.reputation.reputation}">${alert.reputation.reputation}</span></td><td>${alert.country}</td><td>${alert.threat_actor}</td><td><button class="btn btn-secondary" onclick="showAlertDetails(${alert.id})"><i class="fas fa-eye"></i></button> <button class="btn btn-danger" onclick="blockIP('${alert.source_ip}')"><i class="fas fa-ban"></i></button></td></tr>`;
            });
            document.getElementById('recentAlerts').innerHTML = html;
        }
        function updateAllAlerts() {
            let html = '';
            alerts.slice().reverse().forEach(alert => {
                const blockedBadge = isBlocked(alert.source_ip) ? '<span class="blocked-badge"><i class="fas fa-ban"></i> BLOCKED</span>' : '';
                const riskClass = alert.risk>=90 ? 'badge-critical' : alert.risk>=70 ? 'badge-high' : alert.risk>=40 ? 'badge-medium' : 'badge-low';
                html += `<tr><td>${alert.time}</td><td>${alert.source_ip} ${blockedBadge}</td><td>${alert.target_ip}</td><td>${alert.type}</td><td><span class="badge ${riskClass}">${alert.risk}%</span></td><td><span class="badge badge-mitre">${alert.mitre.technique}</span></td><td><span class="badge badge-${alert.reputation.reputation}">${alert.reputation.reputation}</span></td><td>${alert.country}</td><td>${alert.threat_actor}</td><td><span class="badge badge-${alert.status}">${alert.status}</span></td><td><button class="btn btn-secondary" onclick="showAlertDetails(${alert.id})"><i class="fas fa-eye"></i></button> <button class="btn btn-danger" onclick="blockIP('${alert.source_ip}')"><i class="fas fa-ban"></i></button></td></tr>`;
            });
            document.getElementById('allAlerts').innerHTML = html;
        }
        function updateThreatFeed() {
            let html = '<table><thead><tr><th>Time</th><th>Source IP</th><th>Type</th><th>Risk</th><th>MITRE</th><th>Actor</th><th>Country</th></tr></thead><tbody>';
            alerts.slice(-100).reverse().forEach(alert => {
                const mark = isBlocked(alert.source_ip) ? ' [BLOCKED]' : '';
                const riskClass = alert.risk>=90 ? 'badge-critical' : alert.risk>=70 ? 'badge-high' : alert.risk>=40 ? 'badge-medium' : 'badge-low';
                html += `<tr><td>${alert.time}</td><td>${alert.source_ip}${mark}</td><td>${alert.type}</td><td><span class="badge ${riskClass}">${alert.risk}%</span></td><td><span class="badge badge-mitre">${alert.mitre.technique}</span></td><td>${alert.threat_actor}</td><td>${alert.country}</td></tr>`;
            });
            html += '</tbody></table>';
            document.getElementById('threatFeed').innerHTML = html;
        }
        function updateMITRE() {
            const counts = {};
            alerts.forEach(alert => {
                const tech = alert.mitre.technique;
                if (!counts[tech]) counts[tech] = { count:0, name: alert.mitre.name, tactic: alert.mitre.tactic };
                counts[tech].count++;
            });
            let html = '';
            for (const [tech, data] of Object.entries(counts)) {
                html += `<tr><td><span class="badge badge-mitre">${tech}</span></td><td>${data.name}</td><td>${data.tactic}</td><td>${data.count}</td><td><i class="fas fa-chart-line" style="color:var(--accent-primary);"></i></td><td><button class="btn btn-secondary" onclick="searchMITRE('${tech}')"><i class="fas fa-search"></i></button></td></tr>`;
            }
            document.getElementById('mitreTable').innerHTML = html;
        }
        function updateReputationTable() {
            const recent = alerts.slice(-50);
            let html = '';
            recent.forEach(alert => {
                html += `<tr><td>${alert.source_ip}</td><td><span class="badge badge-${alert.reputation.reputation}">${alert.reputation.reputation}</span></td><td>${alert.reputation.confidence}%</td><td>${alert.reputation.score}</td><td>${alert.reputation.source}</td><td>${alert.reputation.last_seen}</td><td>${alert.reputation.tags.slice(0,3).join(', ')}</td></tr>`;
            });
            document.getElementById('reputationTable').innerHTML = html;
        }
        function updateSidebarBadges() {
            const total = alerts.length;
            const critical = alerts.filter(a => a.risk >= 90).length;
            document.getElementById('totalAlertsBadge').textContent = total;
            document.getElementById('criticalAlertsBadge').textContent = critical;
        }
        function updateCharts() {
            if (!attackChart || !distributionChart) return;
            const last20 = alerts.slice(-20);
            const criticalData = last20.map(a => a.risk>=90 ? 1 : 0);
            const highData = last20.map(a => a.risk>=70 && a.risk<90 ? 1 : 0);
            const labels = last20.map(a => a.time);
            attackChart.data.labels = labels;
            attackChart.data.datasets[0].data = criticalData;
            attackChart.data.datasets[1].data = highData;
            attackChart.update();
            const critical = alerts.filter(a => a.risk>=90).length;
            const high = alerts.filter(a => a.risk>=70 && a.risk<90).length;
            const medium = alerts.filter(a => a.risk>=40 && a.risk<70).length;
            const low = alerts.filter(a => a.risk<40).length;
            distributionChart.data.datasets[0].data = [critical, high, medium, low];
            distributionChart.update();
        }
        function updateAnalyticsCharts() {
            if (!countryChart || !actorChart || !riskChart || !trendChart) return;
            const countries = {};
            alerts.slice(-200).forEach(alert => countries[alert.country] = (countries[alert.country]||0)+1);
            const topCountries = Object.entries(countries).sort((a,b)=>b[1]-a[1]).slice(0,10);
            countryChart.data.labels = topCountries.map(c=>c[0]);
            countryChart.data.datasets[0].data = topCountries.map(c=>c[1]);
            countryChart.update();
            const actors = {};
            alerts.slice(-200).forEach(alert => actors[alert.threat_actor] = (actors[alert.threat_actor]||0)+1);
            const topActors = Object.entries(actors).sort((a,b)=>b[1]-a[1]).slice(0,10);
            actorChart.data.labels = topActors.map(a=>a[0]);
            actorChart.data.datasets[0].data = topActors.map(a=>a[1]);
            actorChart.update();
            const critical = alerts.filter(a => a.risk>=90).length;
            const high = alerts.filter(a => a.risk>=70 && a.risk<90).length;
            const medium = alerts.filter(a => a.risk>=40 && a.risk<70).length;
            const low = alerts.filter(a => a.risk<40).length;
            riskChart.data.datasets[0].data = [critical, high, medium, low];
            riskChart.update();
            const last50 = alerts.slice(-50);
            trendChart.data.labels = last50.map(a=>a.time);
            trendChart.data.datasets[0].data = last50.map((_,i)=>i);
            trendChart.update();
        }

        // ==================== UTILITY ====================
        function updateTrend(elem, curr, prev) {
            const el = document.getElementById(elem);
            if (!el) return;
            if (curr > prev) el.innerHTML = `<span class="trend-up"><i class="fas fa-arrow-up"></i> +${curr-prev}</span>`;
            else if (curr < prev) el.innerHTML = `<span class="trend-down"><i class="fas fa-arrow-down"></i> -${prev-curr}</span>`;
            else el.innerHTML = `<span><i class="fas fa-minus"></i> 0</span>`;
        }
        function updateLastUpdated() {
            document.getElementById('lastUpdated').textContent = `Updated: ${new Date().toLocaleTimeString()}`;
        }
        function highlightNewAlerts(count) { /* optional – keep empty to suppress popups */ }
        function showNotification(msg, type) {
            const colors = { success:'linear-gradient(135deg,#10b981,#059669)', warning:'linear-gradient(135deg,#f59e0b,#d97706)', error:'linear-gradient(135deg,#ef4444,#dc2626)', info:'linear-gradient(135deg,#3b82f6,#2563eb)' };
            const n = document.createElement('div');
            n.style.cssText = `position:fixed; top:20px; right:20px; background:${colors[type]}; color:white; padding:12px 24px; border-radius:50px; font-weight:500; z-index:9999; animation:slideInRight 0.3s, fadeOut 0.3s 2.7s forwards; box-shadow:0 4px 12px rgba(0,0,0,0.3);`;
            n.innerHTML = `<i class="fas fa-${type==='success'?'check-circle':type==='warning'?'exclamation-triangle':type==='error'?'times-circle':'info-circle'}"></i> ${msg}`;
            document.body.appendChild(n);
            setTimeout(() => n.remove(), 3000);
        }
        function searchIOC() {
            const q = document.getElementById('globalSearch').value.trim();
            if (!q) return;
            document.querySelector('[data-page="reputation"]').click();
            document.getElementById('reputationSearch').value = q;
            checkReputation();
        }
        function checkReputation() {
            const ip = document.getElementById('reputationSearch').value.trim();
            if (!ip) return;
            const alert = alerts.find(a => a.source_ip===ip || a.target_ip===ip);
            if (alert) {
                document.getElementById('reputationResult').innerHTML = `<div class="detail-item"><h3 style="margin-bottom:15px;">Reputation for ${ip}</h3><p><strong>Reputation:</strong> <span class="badge badge-${alert.reputation.reputation}">${alert.reputation.reputation}</span></p><p><strong>Confidence:</strong> ${alert.reputation.confidence}%</p><p><strong>Score:</strong> ${alert.reputation.score}</p><p><strong>Source:</strong> ${alert.reputation.source}</p><p><strong>Last Seen:</strong> ${alert.reputation.last_seen}</p><p><strong>Tags:</strong> ${alert.reputation.tags.join(', ')}</p></div>`;
            } else {
                const rep = randomChoice(['Malicious','Suspicious','Unknown','Benign']);
                const conf = rep==='Malicious'?Math.floor(Math.random()*20+80): rep==='Suspicious'?Math.floor(Math.random()*30+50): rep==='Benign'?Math.floor(Math.random()*30+60): Math.floor(Math.random()*30+20);
                const score = rep==='Malicious'?Math.floor(Math.random()*20+80): rep==='Suspicious'?Math.floor(Math.random()*30+50): Math.floor(Math.random()*50);
                document.getElementById('reputationResult').innerHTML = `<div class="detail-item"><h3 style="margin-bottom:15px;">Reputation for ${ip}</h3><p><strong>Reputation:</strong> <span class="badge badge-${rep}">${rep}</span></p><p><strong>Confidence:</strong> ${conf}%</p><p><strong>Score:</strong> ${score}</p><p><strong>Source:</strong> VirusTotal / AlienVault</p><p><strong>Last Seen:</strong> ${new Date().toISOString().split('T')[0]}</p><p><strong>Tags:</strong> ${randomChoices(['scanner','malware','phishing','c2','botnet'],2).join(', ')}</p></div>`;
            }
        }
        function searchMITRE(t) { document.getElementById('globalSearch').value = t; showNotification(`Searching MITRE: ${t}`,'info'); }
        function refreshAlerts() { fetchAlerts(); showNotification('Refreshing...','info'); }
        function exportAlerts() { downloadFile('alerts_export.csv', convertToCSV(alerts.slice(-50))); showNotification('Exported','success'); }
        function exportAllAlerts() { downloadFile('all_alerts.csv', convertToCSV(alerts)); showNotification('All alerts exported','success'); }
        function exportAlert(id) { const a = alerts.find(a=>a.id===id); if (a) { downloadFile(`alert_${id}.csv`, convertToCSV([a])); showNotification(`Alert #${id} exported`,'success'); } }
        function convertToCSV(data) {
            if (!data.length) return '';
            const headers = ['ID','Timestamp','Source IP','Target IP','Type','Risk','Country','Threat Actor','MITRE Technique','Reputation'];
            const rows = data.map(a => [a.id, a.timestamp, a.source_ip, a.target_ip, a.type, a.risk, a.country, a.threat_actor, a.mitre.technique, a.reputation.reputation]);
            return [headers, ...rows].map(r=>r.join(',')).join('\\n');
        }
        function downloadFile(fname, content) {
            const blob = new Blob([content], {type:'text/csv'});
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href=url; a.download=fname; a.click();
            window.URL.revokeObjectURL(url);
        }
        function filterAlerts() { showNotification('Filter coming soon','info'); }
        function generatePDFReport(ip) { showNotification(`Generating report for ${ip}...`,'info'); setTimeout(()=>showNotification('PDF generated','success'),2000); }
        function animateElements() {
            anime({ targets: '.logo', scale: [1,1.1,1], duration:2000, loop:true, easing:'easeInOutQuad' });
            anime({ targets: '.status-dot', scale: [1,1.5,1], duration:2000, loop:true, easing:'easeInOutQuad' });
        }
        function animateNewRows() {
            anime({ targets: '.new-row', backgroundColor: ['rgba(0,255,157,0.3)','transparent'], duration:1500, easing:'linear' });
        }

        // ==================== MODAL FUNCTIONS ====================
        function showAlertDetails(id) {
            const alert = alerts.find(a => a.id === id);
            if (!alert) return;
            document.getElementById('modalContent').innerHTML = `
                <div class="detail-grid">
                    <div class="detail-item"><div class="detail-label">Alert ID</div><div class="detail-value">#${alert.id}</div></div>
                    <div class="detail-item"><div class="detail-label">Timestamp</div><div class="detail-value">${alert.timestamp}</div></div>
                    <div class="detail-item"><div class="detail-label">Source IP</div><div class="detail-value">${alert.source_ip}</div></div>
                    <div class="detail-item"><div class="detail-label">Target IP</div><div class="detail-value">${alert.target_ip}</div></div>
                    <div class="detail-item"><div class="detail-label">Attack Type</div><div class="detail-value">${alert.type}</div></div>
                    <div class="detail-item"><div class="detail-label">Risk Score</div><div class="detail-value" style="color:${alert.risk>=90?'#ef4444':alert.risk>=70?'#f59e0b':alert.risk>=40?'#3b82f6':'#10b981'}">${alert.risk}% (${alert.severity})</div></div>
                    <div class="detail-item"><div class="detail-label">MITRE Technique</div><div class="detail-value">${alert.mitre.technique}</div></div>
                    <div class="detail-item"><div class="detail-label">MITRE Name</div><div class="detail-value">${alert.mitre.name}</div></div>
                    <div class="detail-item"><div class="detail-label">Tactic</div><div class="detail-value">${alert.mitre.tactic}</div></div>
                    <div class="detail-item"><div class="detail-label">Reputation</div><div class="detail-value"><span class="badge badge-${alert.reputation.reputation}">${alert.reputation.reputation}</span> (${alert.reputation.confidence}%)</div></div>
                    <div class="detail-item"><div class="detail-label">Threat Actor</div><div class="detail-value">${alert.threat_actor}</div></div>
                    <div class="detail-item"><div class="detail-label">Country</div><div class="detail-value">${alert.country}</div></div>
                    <div class="detail-item"><div class="detail-label">Port/Protocol</div><div class="detail-value">${alert.port}/${alert.protocol}</div></div>
                    <div class="detail-item"><div class="detail-label">Status</div><div class="detail-value"><span class="badge badge-${alert.status}">${alert.status}</span></div></div>
                </div>
                <div class="detail-item"><div class="detail-label">MITRE Description</div><div>${alert.mitre.description}</div></div>
                <div class="detail-item"><div class="detail-label">Reputation Tags</div><div class="tags">${alert.reputation.tags.map(t=>`<span class="tag">${t}</span>`).join('')}</div></div>
                <div class="detail-item"><div class="detail-label">Alert Notes</div><div>${alert.notes}</div></div>
                <div style="margin-top:24px; display:flex; gap:10px;">
                    <button class="btn btn-danger" onclick="blockIP('${alert.source_ip}')"><i class="fas fa-ban"></i> Block IP</button>
                    <button class="btn btn-primary" onclick="investigateIP('${alert.source_ip}')"><i class="fas fa-microscope"></i> Investigate</button>
                    <button class="btn btn-secondary" onclick="exportAlert(${alert.id})"><i class="fas fa-download"></i> Export</button>
                </div>
            `;
            openModal('alertModal');
        }
        function investigateIP(ip) {
            const alert = alerts.find(a => a.source_ip === ip) || {};
            const intel = generateThreatIntel(ip);
            document.getElementById('investigationContent').innerHTML = `
                <div class="detail-grid">
                    <div class="detail-item"><div class="detail-label">IP</div><div class="detail-value">${ip}</div></div>
                    <div class="detail-item"><div class="detail-label">Country</div><div class="detail-value">${alert.country || intel.country}</div></div>
                    <div class="detail-item"><div class="detail-label">ASN</div><div class="detail-value">${intel.asn}</div></div>
                    <div class="detail-item"><div class="detail-label">ISP</div><div class="detail-value">${intel.isp}</div></div>
                    <div class="detail-item"><div class="detail-label">First Seen</div><div class="detail-value">${intel.firstSeen}</div></div>
                    <div class="detail-item"><div class="detail-label">Last Seen</div><div class="detail-value">${intel.lastSeen}</div></div>
                    <div class="detail-item"><div class="detail-label">Open Ports</div><div class="detail-value">${intel.ports}</div></div>
                    <div class="detail-item"><div class="detail-label">Risk</div><div class="detail-value">${intel.risk}/100</div></div>
                </div>
                <div class="detail-item"><div class="detail-label">Malware</div><div class="tags">${intel.malware.map(m=>`<span class="tag">${m}</span>`).join('')}</div></div>
                <div class="detail-item"><div class="detail-label">Threat Intel</div><div style="margin-top:10px;"><p><i class="fas fa-check-circle" style="color:#10b981;"></i> Reported in ${intel.reports} feeds</p><p><i class="fas fa-clock" style="color:#f59e0b;"></i> Active last 24h: ${intel.active?'Yes':'No'}</p><p><i class="fas ${intel.apt?'fa-skull':'fa-shield'}" style="color:${intel.apt?'#ef4444':'#10b981'};"></i> ${intel.apt?'APT associated':'No APT'}</p><p><i class="fas fa-tag" style="color:#3b82f6;"></i> Categories: ${intel.categories.join(', ')}</p></div></div>
                <div style="margin-top:24px;"><button class="btn btn-danger" onclick="blockIP('${ip}'); closeModal('investigationModal');"><i class="fas fa-ban"></i> Block IP</button> <button class="btn btn-primary" onclick="generatePDFReport('${ip}')"><i class="fas fa-file-pdf"></i> PDF</button></div>
            `;
            openModal('investigationModal');
        }
        function generateThreatIntel(ip) {
            return {
                country: randomChoice(['Russia','China','Iran','North Korea','Brazil','Ukraine']),
                asn: `AS${Math.floor(Math.random()*50000)+10000}`,
                isp: randomChoice(['Rostelecom','China Telecom','Iran Telecomm','Korea Telecom','Embratel','Kyivstar']),
                firstSeen: new Date(Date.now()-Math.random()*365*86400000).toISOString().split('T')[0],
                lastSeen: new Date().toISOString().split('T')[0],
                ports: [22,80,443,3389,8080].filter(()=>Math.random()>0.5).join(', ') || '80,443',
                risk: Math.floor(Math.random()*40+60),
                malware: randomChoices(['Emotet','TrickBot','Cobalt Strike','Ryuk','Dridex','QakBot','Ursnif','Remcos'],3),
                reports: Math.floor(Math.random()*5+3),
                active: Math.random()>0.3,
                apt: Math.random()>0.5,
                categories: randomChoices(['Malware C2','Phishing','Scanning','Brute Force','Data Exfiltration'],2)
            };
        }

        // ==================== MODAL CONTROLS ====================
        function openModal(id) { document.getElementById(id).classList.add('active'); }
        function closeModal(id) { document.getElementById(id).classList.remove('active'); }
        window.onclick = function(e) { if (e.target.classList.contains('modal')) e.target.classList.remove('active'); };

        // ==================== RANDOM HELPERS ====================
        function randomChoice(arr) { return arr[Math.floor(Math.random()*arr.length)]; }
        function randomChoices(arr, cnt) { const shuffled = [...arr].sort(()=>0.5-Math.random()); return shuffled.slice(0,cnt); }

        // ==================== CSS ANIMATIONS ====================
        const style = document.createElement('style');
        style.innerHTML = `@keyframes slideInRight{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}} @keyframes fadeOut{from{opacity:1}to{opacity:0}}`;
        document.head.appendChild(style);
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     A.T.I.C.E - Automated Threat Intelligence Engine         ║
    ║     v2.5 - Full Graphics + Auto‑Block Toggle                 ║
    ║     🌐 http://127.0.0.1:5001                                 ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    app.run(debug=True, host='127.0.0.1', port=5001)
