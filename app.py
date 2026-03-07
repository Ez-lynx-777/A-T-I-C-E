from flask import Flask, jsonify, render_template_string, request
from datetime import datetime
import random

app = Flask(__name__)

alerts = []
alert_id = 0

# ==================== MITRE ATT&CK MAPPING ====================
mitre_attack = {
    'Brute Force': {'tactic': 'Credential Access', 'technique': 'T1110', 'name': 'Brute Force', 'description': 'Attempting to guess passwords'},
    'Port Scan': {'tactic': 'Discovery', 'technique': 'T1046', 'name': 'Network Service Scanning', 'description': 'Scanning for open ports'},
    'SQL Injection': {'tactic': 'Initial Access', 'technique': 'T1190', 'name': 'Exploit Public-Facing Application', 'description': 'SQL injection attempt'},
    'Ransomware': {'tactic': 'Impact', 'technique': 'T1486', 'name': 'Data Encrypted for Impact', 'description': 'Ransomware detected'},
    'DDoS': {'tactic': 'Impact', 'technique': 'T1498', 'name': 'Network Denial of Service', 'description': 'DDoS attack in progress'},
    'Data Exfiltration': {'tactic': 'Exfiltration', 'technique': 'T1048', 'name': 'Exfiltration Over Alternative Protocol', 'description': 'Data being sent out'},
    'C2 Beacon': {'tactic': 'Command and Control', 'technique': 'T1071', 'name': 'Application Layer Protocol', 'description': 'C2 communication detected'},
    'RCE Exploit': {'tactic': 'Execution', 'technique': 'T1203', 'name': 'Exploitation for Client Execution', 'description': 'Remote code execution attempt'},
    'Phishing': {'tactic': 'Initial Access', 'technique': 'T1566', 'name': 'Phishing', 'description': 'Phishing email detected'},
    'Credential Dumping': {'tactic': 'Credential Access', 'technique': 'T1003', 'name': 'OS Credential Dumping', 'description': 'Password hash extraction'},
    'XSS': {'tactic': 'Initial Access', 'technique': 'T1189', 'name': 'Drive-by Compromise', 'description': 'Cross-site scripting'},
    'Directory Enumeration': {'tactic': 'Discovery', 'technique': 'T1046', 'name': 'Network Service Scanning', 'description': 'Directory enumeration'}
}

# ==================== THREAT REPUTATION ====================
def get_reputation(ip):
    if ip.startswith(('203.0.113', '198.51.100', '192.0.2')):
        rep = random.choice(['Malicious', 'Suspicious'])
        conf = random.randint(85, 98)
        tags = ['c2', 'malware', 'scanner']
    else:
        rep = random.choice(['Unknown', 'Suspicious'])
        conf = random.randint(40, 75)
        tags = ['unverified']
    return {
        'reputation': rep,
        'confidence': conf,
        'source': 'VirusTotal / AlienVault OTX',
        'last_seen': datetime.now().strftime("%Y-%m-%d"),
        'tags': tags
    }

# ==================== ATTACK ENDPOINT ====================
@app.route('/api/attack', methods=['POST'])
def receive_attack():
    global alert_id
    alert_id += 1
    data = request.json
    attack_type = data.get('type', 'Unknown')
    mitre = mitre_attack.get(attack_type, {
        'tactic': 'Unknown',
        'technique': 'T0000',
        'name': 'Unknown Technique',
        'description': 'No MITRE mapping'
    })
    reputation = get_reputation(data.get('ip', '0.0.0.0'))
    alert = {
        'id': alert_id,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'time': datetime.now().strftime("%H:%M:%S"),
        'ip': data.get('ip', '0.0.0.0'),
        'type': attack_type,
        'risk': data.get('risk', random.randint(60, 98)),
        'country': data.get('country', 'Unknown'),
        'port': data.get('port', random.randint(1, 65535)),
        'protocol': data.get('protocol', 'TCP'),
        'threat_actor': data.get('threat_actor', 'Unknown'),
        'mitre_tactic': mitre['tactic'],
        'mitre_technique': mitre['technique'],
        'mitre_name': mitre['name'],
        'mitre_description': mitre['description'],
        'reputation': reputation['reputation'],
        'confidence': reputation['confidence'],
        'reputation_source': reputation['source'],
        'tags': reputation['tags']
    }
    alerts.append(alert)
    print(f"\n🔥 ALERT #{alert_id}: {attack_type} from {data.get('ip')}")
    return jsonify({"status": "success", "alert_id": alert_id})

@app.route('/api/alerts')
def get_alerts():
    return jsonify(alerts)  # 👈 NO LIMIT — all alerts

@app.route('/api/alert/<int:alert_id>')
def get_alert(alert_id):
    for alert in alerts:
        if alert['id'] == alert_id:
            return jsonify(alert)
    return jsonify({"error": "Alert not found"}), 404

# ==================== MAIN DASHBOARD ====================
@app.route('/')
def home():
    return render_template_string(DASHBOARD_HTML)

# ==================== WAZUH-STYLE HTML ====================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ WAZUH-STYLE SOC DASHBOARD</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Inter', sans-serif; }
        body { background: #0a0c0f; color: #e5e9f0; }
        .app { display: flex; height: 100vh; }

        /* Sidebar */
        .sidebar {
            width: 260px;
            background: #0f1217;
            border-right: 1px solid #1e2329;
            padding: 24px 16px;
        }
        .logo {
            font-size: 20px;
            font-weight: 700;
            color: #66c0ff;
            margin-bottom: 32px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .nav-item {
            padding: 12px 16px;
            color: #9aa4b3;
            border-radius: 8px;
            margin-bottom: 4px;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .nav-item:hover { background: #1a1f26; color: #66c0ff; }
        .nav-item.active { background: #1a1f26; color: #66c0ff; font-weight: 600; }

        /* Main */
        .main {
            flex: 1;
            overflow-y: auto;
            padding: 24px 32px;
        }

        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 32px;
        }
        .stat-card {
            background: #0f1217;
            border: 1px solid #1e2329;
            border-radius: 12px;
            padding: 20px;
        }
        .stat-label { font-size: 14px; color: #9aa4b3; margin-bottom: 8px; }
        .stat-value { font-size: 32px; font-weight: 700; color: #66c0ff; }
        .stat-total .stat-value { color: #66c0ff; }
        .stat-critical .stat-value { color: #f06a6a; }
        .stat-high .stat-value { color: #f0a06a; }
        .stat-medium .stat-value { color: #f0d06a; }

        /* Tables */
        .table-container {
            background: #0f1217;
            border: 1px solid #1e2329;
            border-radius: 12px;
            overflow-x: auto;
            margin-bottom: 32px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            text-align: left;
            padding: 16px 20px;
            color: #9aa4b3;
            font-weight: 600;
            font-size: 14px;
            border-bottom: 1px solid #1e2329;
        }
        td {
            padding: 16px 20px;
            border-bottom: 1px solid #1a1f26;
            font-size: 14px;
        }
        tr:hover td { background: #1a1f26; }

        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge-critical { background: #f06a6a20; color: #f06a6a; }
        .badge-high { background: #f0a06a20; color: #f0a06a; }
        .badge-medium { background: #f0d06a20; color: #f0d06a; }
        .badge-mitre {
            background: #2d3748;
            color: #66c0ff;
        }
        .blocked-badge {
            background: #f06a6a;
            color: white;
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 12px;
            margin-left: 6px;
        }

        .btn {
            padding: 6px 12px;
            border-radius: 6px;
            border: none;
            font-weight: 600;
            font-size: 12px;
            cursor: pointer;
        }
        .btn-view { background: #2d3748; color: #66c0ff; }
        .btn-block { background: #f06a6a; color: white; }
        .btn-investigate { background: #2d3748; color: #66c0ff; }
        .btn-unblock { background: #4caf50; color: white; }

        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.7);
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        .modal.active { display: flex; }
        .modal-content {
            background: #0f1217;
            border: 1px solid #1e2329;
            border-radius: 16px;
            padding: 24px;
            max-width: 700px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }
        .modal-close {
            cursor: pointer;
            font-size: 24px;
            color: #9aa4b3;
        }
    </style>
</head>
<body>
    <div class="app">
        <div class="sidebar">
            <div class="logo">🔍 SOC DASHBOARD</div>
            <div class="nav-item active" data-page="dashboard">📊 Dashboard</div>
            <div class="nav-item" data-page="alerts">🚨 Alerts</div>
            <div class="nav-item" data-page="threatfeed">🌍 Threat Feed</div>
            <div class="nav-item" data-page="mitre">🧠 MITRE ATT&CK</div>
            <div class="nav-item" data-page="reputation">🔍 Reputation</div>
            <div class="nav-item" data-page="blocked">🔴 Blocked IPs</div>
        </div>

        <div class="main">
            <!-- Stats Cards -->
            <div class="stats-grid">
                <div class="stat-card stat-total"><div class="stat-label">Total Alerts</div><div class="stat-value" id="totalAlerts">0</div></div>
                <div class="stat-card stat-critical"><div class="stat-label">Critical (90%+)</div><div class="stat-value" id="criticalAlerts">0</div></div>
                <div class="stat-card stat-high"><div class="stat-label">High (70-89%)</div><div class="stat-value" id="highAlerts">0</div></div>
                <div class="stat-card stat-medium"><div class="stat-label">Medium (50-69%)</div><div class="stat-value" id="mediumAlerts">0</div></div>
            </div>

            <!-- Dashboard Page -->
            <div id="page-dashboard">
                <div class="table-container">
                    <table>
                        <thead><tr><th>Time</th><th>IP</th><th>Type</th><th>Risk</th><th>MITRE</th><th>Reputation</th><th>Action</th></tr></thead>
                        <tbody id="recentAlertsBody"></tbody>
                    </table>
                </div>
            </div>

            <!-- Alerts Page -->
            <div id="page-alerts" style="display:none;">
                <div class="table-container">
                    <table>
                        <thead><tr><th>Time</th><th>IP</th><th>Type</th><th>Risk</th><th>MITRE</th><th>Reputation</th><th>Country</th><th>Action</th></tr></thead>
                        <tbody id="allAlertsBody"></tbody>
                    </table>
                </div>
            </div>

            <!-- Threat Feed Page -->
            <div id="page-threatfeed" style="display:none;">
                <div class="table-container" id="threatFeed"></div>
            </div>

            <!-- MITRE Page -->
            <div id="page-mitre" style="display:none;">
                <div class="table-container">
                    <table><thead><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Count</th></tr></thead><tbody id="mitreTable"></tbody></table>
                </div>
            </div>

            <!-- Reputation Page -->
            <div id="page-reputation" style="display:none;">
                <div style="margin-bottom:20px; display:flex; gap:10px;">
                    <input type="text" id="reputationSearch" placeholder="Enter IP" style="flex:1; background:#0f1217; border:1px solid #1e2329; color:white; padding:12px; border-radius:8px;">
                    <button class="btn btn-view" onclick="checkReputation()">Check</button>
                </div>
                <div id="reputationResult" style="margin-bottom:20px;"></div>
                <div class="table-container">
                    <table><thead><tr><th>IP</th><th>Reputation</th><th>Confidence</th><th>Source</th></tr></thead><tbody id="reputationTable"></tbody></table>
                </div>
            </div>

            <!-- Blocked IPs Page -->
            <div id="page-blocked" style="display:none;">
                <div id="blockedList"></div>
            </div>
        </div>
    </div>

    <!-- Modals -->
    <div class="modal" id="alertModal">
        <div class="modal-content">
            <div class="modal-header"><h2>Alert Details</h2><span class="modal-close" onclick="closeModal('alertModal')">&times;</span></div>
            <div id="modalContent"></div>
        </div>
    </div>

    <div class="modal" id="investigationModal">
        <div class="modal-content">
            <div class="modal-header"><h2>Investigation Report</h2><span class="modal-close" onclick="closeModal('investigationModal')">&times;</span></div>
            <div id="investigationContent"></div>
        </div>
    </div>

    <script>
        let alerts = [];

        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', function() {
                document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
                this.classList.add('active');
                const page = this.dataset.page;
                document.querySelectorAll('.main > div[id^="page-"]').forEach(div => div.style.display = 'none');
                document.getElementById('page-' + page).style.display = 'block';
                if (page === 'blocked') showBlockedList();
            });
        });

        // Fetch alerts every 2 seconds
        setInterval(fetchAlerts, 2000);
        fetchAlerts();

        function fetchAlerts() {
            fetch('/api/alerts')
                .then(res => res.json())
                .then(data => {
                    alerts = data;
                    updateDashboard();
                    updateAllAlerts();
                    updateThreatFeed();
                    updateMITRE();
                    updateReputationTable();
                });
        }

        // Client-side blocking
        function getBlockedIPs() {
            return JSON.parse(localStorage.getItem('blockedIPs') || '[]');
        }
        function saveBlockedIPs(ips) {
            localStorage.setItem('blockedIPs', JSON.stringify(ips));
        }
        function isBlocked(ip) {
            return getBlockedIPs().includes(ip);
        }
        function blockIP(ip) {
            let blocked = getBlockedIPs();
            if (!blocked.includes(ip)) {
                blocked.push(ip);
                saveBlockedIPs(blocked);
                alert('IP ' + ip + ' blocked');
                if (document.getElementById('page-blocked').style.display === 'block') showBlockedList();
                updateDashboard();
                updateAllAlerts();
            } else {
                alert('IP already blocked');
            }
            closeModal('alertModal');
        }
        function unblockIP(ip) {
            let blocked = getBlockedIPs().filter(i => i !== ip);
            saveBlockedIPs(blocked);
            showBlockedList();
            updateDashboard();
            updateAllAlerts();
        }
        function showBlockedList() {
            const blocked = getBlockedIPs();
            const container = document.getElementById('blockedList');
            if (blocked.length === 0) {
                container.innerHTML = '<div class="table-container"><div style="padding:20px; text-align:center;">No blocked IPs</div></div>';
                return;
            }
            let html = '<div class="table-container"><table><thead><tr><th>IP</th><th>Action</th></tr></thead><tbody>';
            blocked.forEach(ip => {
                html += `<tr><td>${ip}</td><td><button class="btn btn-unblock" onclick="unblockIP('${ip}')">Unblock</button></td></tr>`;
            });
            html += '</tbody></table></div>';
            container.innerHTML = html;
        }

        // Update functions
        function updateDashboard() {
            document.getElementById('totalAlerts').textContent = alerts.length;
            document.getElementById('criticalAlerts').textContent = alerts.filter(a => a.risk >= 90).length;
            document.getElementById('highAlerts').textContent = alerts.filter(a => a.risk >= 70 && a.risk < 90).length;
            document.getElementById('mediumAlerts').textContent = alerts.filter(a => a.risk >= 50 && a.risk < 70).length;

            let html = '';
            alerts.slice(-10).reverse().forEach(alert => {
                let badge = isBlocked(alert.ip) ? '<span class="blocked-badge">BLOCKED</span>' : '';
                let riskClass = alert.risk >= 90 ? 'badge-critical' : alert.risk >= 70 ? 'badge-high' : 'badge-medium';
                html += `<tr>
                    <td>${alert.time}</td>
                    <td>${alert.ip} ${badge}</td>
                    <td>${alert.type}</td>
                    <td><span class="badge ${riskClass}">${alert.risk}%</span></td>
                    <td><span class="badge badge-mitre">${alert.mitre_technique}</span></td>
                    <td><span class="badge badge-${alert.reputation}">${alert.reputation}</span></td>
                    <td><button class="btn btn-view" onclick="showAlertDetails(${alert.id})">View</button></td>
                </tr>`;
            });
            document.getElementById('recentAlertsBody').innerHTML = html;
        }

        function updateAllAlerts() {
            let html = '';
            alerts.slice().reverse().forEach(alert => {
                let badge = isBlocked(alert.ip) ? '<span class="blocked-badge">BLOCKED</span>' : '';
                let riskClass = alert.risk >= 90 ? 'badge-critical' : alert.risk >= 70 ? 'badge-high' : 'badge-medium';
                html += `<tr>
                    <td>${alert.time}</td>
                    <td>${alert.ip} ${badge}</td>
                    <td>${alert.type}</td>
                    <td><span class="badge ${riskClass}">${alert.risk}%</span></td>
                    <td><span class="badge badge-mitre">${alert.mitre_technique}</span></td>
                    <td><span class="badge badge-${alert.reputation}">${alert.reputation}</span></td>
                    <td>${alert.country}</td>
                    <td><button class="btn btn-view" onclick="showAlertDetails(${alert.id})">View</button></td>
                </tr>`;
            });
            document.getElementById('allAlertsBody').innerHTML = html;
        }

        function updateThreatFeed() {
            let html = '<div class="table-container"><table><thead><tr><th>Time</th><th>IP</th><th>Type</th><th>Risk</th><th>Actor</th></tr></thead><tbody>';
            alerts.slice(-50).reverse().forEach(alert => {
                let mark = isBlocked(alert.ip) ? ' [BLOCKED]' : '';
                let riskClass = alert.risk >= 90 ? 'badge-critical' : alert.risk >= 70 ? 'badge-high' : 'badge-medium';
                html += `<tr>
                    <td>${alert.time}</td>
                    <td>${alert.ip}${mark}</td>
                    <td>${alert.type}</td>
                    <td><span class="badge ${riskClass}">${alert.risk}%</span></td>
                    <td>${alert.threat_actor}</td>
                </tr>`;
            });
            html += '</tbody></table></div>';
            document.getElementById('threatFeed').innerHTML = html || '<div class="table-container"><div style="padding:20px;">No threats yet</div></div>';
        }

        function updateMITRE() {
            let counts = {};
            alerts.forEach(alert => {
                let tech = alert.mitre_technique + ' - ' + alert.mitre_name;
                counts[tech] = (counts[tech] || 0) + 1;
            });
            let html = '';
            for (let [tech, count] of Object.entries(counts)) {
                let parts = tech.split(' - ');
                let tactic = alerts.find(a => a.mitre_technique === parts[0])?.mitre_tactic || 'Unknown';
                html += `<tr><td>${parts[0]}</td><td>${parts[1]}</td><td>${tactic}</td><td>${count}</td></tr>`;
            }
            document.getElementById('mitreTable').innerHTML = html;
        }

        function updateReputationTable() {
            let recent = alerts.slice(-20);
            let html = '';
            recent.forEach(alert => {
                html += `<tr><td>${alert.ip}</td><td><span class="badge badge-${alert.reputation}">${alert.reputation}</span></td><td>${alert.confidence}%</td><td>${alert.reputation_source}</td></tr>`;
            });
            document.getElementById('reputationTable').innerHTML = html;
        }

        function showAlertDetails(alertId) {
            const alert = alerts.find(a => a.id === alertId);
            if (!alert) return;
            document.getElementById('modalContent').innerHTML = `
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
                    <div><strong>Time:</strong> ${alert.timestamp}</div>
                    <div><strong>IP:</strong> ${alert.ip}</div>
                    <div><strong>Type:</strong> ${alert.type}</div>
                    <div><strong>Risk:</strong> <span class="badge ${alert.risk>=90?'badge-critical':alert.risk>=70?'badge-high':'badge-medium'}">${alert.risk}%</span></div>
                    <div><strong>MITRE:</strong> ${alert.mitre_technique}</div>
                    <div><strong>Name:</strong> ${alert.mitre_name}</div>
                    <div><strong>Tactic:</strong> ${alert.mitre_tactic}</div>
                    <div><strong>Description:</strong> ${alert.mitre_description}</div>
                    <div><strong>Reputation:</strong> <span class="badge badge-${alert.reputation}">${alert.reputation}</span> (${alert.confidence}%)</div>
                    <div><strong>Actor:</strong> ${alert.threat_actor}</div>
                    <div><strong>Port:</strong> ${alert.port}/${alert.protocol}</div>
                    <div><strong>Country:</strong> ${alert.country}</div>
                </div>
                <div style="margin-top:20px;"><strong>Tags:</strong> ${alert.tags.map(t => `<span class="badge" style="background:#2d3748;">${t}</span>`).join(' ')}</div>
                <div style="margin-top:24px;">
                    <button class="btn btn-block" onclick="blockIP('${alert.ip}')">🔴 Block IP</button>
                    <button class="btn btn-view" onclick="investigateIP('${alert.ip}')">🔍 Investigate</button>
                </div>
            `;
            openModal('alertModal');
        }

        function investigateIP(ip) {
            const alert = alerts.find(a => a.ip === ip) || {};
            const malware = ['Emotet', 'TrickBot', 'Cobalt Strike', 'Ryuk', 'Dridex'];
            document.getElementById('investigationContent').innerHTML = `
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
                    <div><strong>IP:</strong> ${ip}</div>
                    <div><strong>Country:</strong> ${alert.country || 'Unknown'}</div>
                    <div><strong>ASN:</strong> AS${Math.floor(Math.random()*50000)}</div>
                    <div><strong>Confidence:</strong> ${Math.floor(Math.random()*20+80)}%</div>
                    <div><strong>First Seen:</strong> ${new Date(Date.now() - Math.random()*30*86400000).toISOString().split('T')[0]}</div>
                    <div><strong>Open Ports:</strong> 80,443,${Math.floor(Math.random()*1000+1000)}</div>
                </div>
                <div style="margin-top:20px;">
                    <strong>Associated Malware:</strong> ${malware.slice(0,Math.floor(Math.random()*3+1)).join(', ')}
                </div>
                <div style="margin-top:24px;">
                    <button class="btn btn-block" onclick="blockIP('${ip}'); closeModal('investigationModal');">🔴 Block IP</button>
                    <button class="btn btn-view" onclick="closeModal('investigationModal')">Close</button>
                </div>
            `;
            openModal('investigationModal');
        }

        function checkReputation() {
            let ip = document.getElementById('reputationSearch').value.trim();
            if (!ip) return;
            let alert = alerts.find(a => a.ip === ip);
            if (alert) {
                document.getElementById('reputationResult').innerHTML = `
                    <div class="table-container" style="padding:20px;">
                        <p><strong>Reputation:</strong> <span class="badge badge-${alert.reputation}">${alert.reputation}</span></p>
                        <p><strong>Confidence:</strong> ${alert.confidence}%</p>
                        <p><strong>Source:</strong> ${alert.reputation_source}</p>
                        <p><strong>Tags:</strong> ${alert.tags.join(', ')}</p>
                    </div>`;
            } else {
                document.getElementById('reputationResult').innerHTML = `
                    <div class="table-container" style="padding:20px;">
                        <p><strong>Reputation:</strong> <span class="badge badge-Unknown">Unknown</span></p>
                        <p><strong>Confidence:</strong> 45%</p>
                        <p><strong>Source:</strong> VirusTotal</p>
                        <p><strong>Tags:</strong> unverified</p>
                    </div>`;
            }
        }

        function openModal(id) {
            document.getElementById(id).classList.add('active');
        }
        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
        }
        window.onclick = function(e) {
            if (e.target.classList.contains('modal')) {
                e.target.classList.remove('active');
            }
        }
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     🚀 WAZUH-STYLE SOC DASHBOARD                            ║
    ║     ✅ No attack limit — see ALL alerts                     ║
    ║     🌐 http://127.0.0.1:5001                                ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    app.run(debug=True, host='127.0.0.1', port=5001)
