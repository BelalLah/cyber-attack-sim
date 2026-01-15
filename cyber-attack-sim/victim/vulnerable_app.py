from flask import Flask, request, jsonify
import sqlite3
import time
from datetime import datetime
from collections import defaultdict
import threading
import os
import logging
import re
import signal

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/victim.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('Victim')

app = Flask(__name__)

# -------------------- System monitor for DDoS / overload --------------------

class SystemMonitor:
    def __init__(self):
        self.crash_threshold = int(os.getenv('CRASH_THRESHOLD', 500))
        self.total_requests = 0
        self.requests_last_minute = []
        self.health = 100.0
        self.lock = threading.Lock()
        self.start_time = time.time()

    def record(self):
        now = time.time()
        with self.lock:
            self.total_requests += 1
            self.requests_last_minute = [t for t in self.requests_last_minute
                                         if now - t < 60]
            self.requests_last_minute.append(now)
            rpm = len(self.requests_last_minute)
            if rpm > 200:
                self.health = max(0.0, 100.0 - (rpm - 200) / 5.0)
            if self.total_requests >= self.crash_threshold:
                logger.critical(f"System overload: {self.total_requests} requests, health={self.health}")
                return True
            return False

    def stats(self):
        with self.lock:
            uptime = time.time() - self.start_time
            return {
                "total_requests": self.total_requests,
                "requests_per_minute": len(self.requests_last_minute),
                "health": self.health,
                "uptime_seconds": uptime,
                "crash_threshold": self.crash_threshold
            }


system_monitor = SystemMonitor()

def trigger_crash():
    logger.critical("💀 Simulated system crash due to overload, exiting process")
    with open('/app/logs/crash.log', 'a') as f:
        f.write(f"[{datetime.now()}] Crash triggered due to overload, "
                f"total_requests={system_monitor.total_requests}\n")
    time.sleep(1)
    os.kill(os.getpid(), signal.SIGTERM)

# -------------------- Firewall and brute-force logic ------------------------

class Firewall:
    def __init__(self):
        self.request_counts = defaultdict(list)
        self.blocked_ips = {}
        self.suspicious = defaultdict(int)

        self.RATE_LIMIT = int(os.getenv('RATE_LIMIT', 100))
        self.RATE_WINDOW = 60
        self.BLOCK_THRESHOLD = int(os.getenv('BLOCK_THRESHOLD', 3))
        self.BLOCK_DURATION = int(os.getenv('BLOCK_DURATION', 300))

        self.SQL_PATTERNS = [
            r"(\bOR\b|\bAND\b).*=.*",
            r"'.*OR.*'.*=.*'",
            r"--", r"/\*.*\*/", r"#",
            r";\s*DROP\s+TABLE", r";\s*DELETE\s+FROM",
            r";\s*INSERT\s+INTO", r";\s*UPDATE\s+",
            r"UNION\s+SELECT", r"SLEEP\s*\(",
            r"WAITFOR\s+DELAY", r"BENCHMARK\s*\(",
            r"'.*\+.*'"
        ]
        self.XSS_PATTERNS = [
            r"<script[^>]*>.*</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe",
            r"<embed",
            r"<object",
            r"alert\s*\(",
            r"eval\s*\(",
            r"document\.cookie"
        ]

        self.alerts = []
        self.lock = threading.Lock()

        t = threading.Thread(target=self._cleanup_loop, daemon=True)
        t.start()

        logger.info(f"Firewall initialized: rate_limit={self.RATE_LIMIT}/min, block_threshold={self.BLOCK_THRESHOLD}")

    def _cleanup_loop(self):
        while True:
            time.sleep(60)
            now = time.time()
            with self.lock:
                self.blocked_ips = {ip: until for ip, until in self.blocked_ips.items()
                                    if until > now}
                for ip in list(self.request_counts.keys()):
                    self.request_counts[ip] = [t for t in self.request_counts[ip]
                                               if now - t < self.RATE_WINDOW]
                    if not self.request_counts[ip]:
                        del self.request_counts[ip]

    def add_alert(self, msg):
        alert = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "message": msg}
        with self.lock:
            self.alerts.append(alert)
            if len(self.alerts) > 100:
                self.alerts.pop(0)
        logger.warning(f"ALERT: {msg}")

    def block_ip(self, ip):
        until = time.time() + self.BLOCK_DURATION
        with self.lock:
            self.blocked_ips[ip] = until
        self.add_alert(f"IP BLACKLISTED: {ip} for {self.BLOCK_DURATION}s")

    def is_blocked(self, ip):
        now = time.time()
        with self.lock:
            until = self.blocked_ips.get(ip)
            if until and until > now:
                return True
            if until and until <= now:
                del self.blocked_ips[ip]
        return False

    def check_rate(self, ip):
        now = time.time()
        with self.lock:
            self.request_counts[ip] = [t for t in self.request_counts[ip]
                                       if now - t < self.RATE_WINDOW]
            self.request_counts[ip].append(now)
            count = len(self.request_counts[ip])
        if count > self.RATE_LIMIT:
            self.add_alert(f"Rate limit exceeded: {ip} ({count} req/min)")
            self.suspicious[ip] += 1
            if self.suspicious[ip] >= self.BLOCK_THRESHOLD:
                self.block_ip(ip)
            return False
        return True

    def check_sql(self, value, ip):
        if not value:
            return True
        s = str(value)
        for pat in self.SQL_PATTERNS:
            if re.search(pat, s, re.IGNORECASE):
                self.add_alert(f"SQL injection detected from {ip}, pattern={pat}")
                self.suspicious[ip] += 1
                if self.suspicious[ip] >= self.BLOCK_THRESHOLD:
                    self.block_ip(ip)
                return False
        return True

    def check_xss(self, value, ip):
        if not value:
            return True
        s = str(value)
        for pat in self.XSS_PATTERNS:
            if re.search(pat, s, re.IGNORECASE):
                self.add_alert(f"XSS attempt detected from {ip}, pattern={pat}")
                self.suspicious[ip] += 1
                if self.suspicious[ip] >= self.BLOCK_THRESHOLD:
                    self.block_ip(ip)
                return False
        return True

    def stats(self):
        now = time.time()
        with self.lock:
            active_blocks = [ip for ip, until in self.blocked_ips.items() if until > now]
            return {
                "total_ips_tracked": len(self.request_counts),
                "blocked_ips": active_blocks,
                "blocked_count": len(active_blocks),
                "suspicious_ips": dict(self.suspicious),
                "recent_alerts": self.alerts[-10:],
                "total_alerts": len(self.alerts),
                "config": {
                    "rate_limit": self.RATE_LIMIT,
                    "block_threshold": self.BLOCK_THRESHOLD,
                    "block_duration": self.BLOCK_DURATION
                }
            }


firewall = Firewall()

# brute-force tracking per IP
login_failures = defaultdict(int)
login_lock = threading.Lock()
MAX_FAILS_PER_IP = 8   # didactic: show lockout quickly


# -------------------- request hooks --------------------

@app.before_request
def pre():
    ip = request.remote_addr
    
    # Skip checks for login-form page (HTML content)
    if request.path == "/login-form":
        return None

    # overload check
    if system_monitor.record():
        threading.Thread(target=trigger_crash, daemon=True).start()
        return jsonify({
            "error": "System overload",
            "message": "Server is shutting down due to DDoS simulation",
            "system_health": 0
        }), 503

    # firewall block
    if firewall.is_blocked(ip):
        return jsonify({
            "error": "Access denied",
            "message": "Your IP is blocked by the firewall",
            "blocked": True
        }), 403

    # rate limit (skip stats endpoints)
    if request.path not in ("/firewall/stats", "/firewall/alerts", "/system/stats"):
        if not firewall.check_rate(ip):
            return jsonify({
                "error": "Rate limit exceeded",
                "message": "Too many requests from your IP",
                "blocked": False
            }), 429


@app.after_request
def headers(resp):
    # Allow iframes for login-form (so it can be embedded in controller)
    if request.path == "/login-form":
        resp.headers.pop("X-Frame-Options", None)
    else:
        resp.headers["X-Frame-Options"] = "DENY"
    
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    return resp


# -------------------- endpoints -----------------------

@app.route("/")
def root():
    s = system_monitor.stats()
    return jsonify({
        "status": "running",
        "service": "Vulnerable Web Server (educational)",
        "version": "2.0",
        "firewall": "active",
        "system_health": s["health"],
        "uptime_seconds": s["uptime_seconds"]
    })


@app.route("/login-form")
def login_form():
    """Visual login page for manual SQL injection testing"""
    return """
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Victim Server - Login Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%);
            color: #c9d1d9;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .login-container {
            background: #161b22;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
            width: 100%;
            max-width: 450px;
            border: 1px solid #30363d;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .header h2 { 
            color: #58a6ff; 
            font-size: 28px;
            margin-bottom: 5px;
        }
        .header p {
            color: #8b949e;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #8b949e;
            font-size: 13px;
            margin-bottom: 8px;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #30363d;
            border-radius: 6px;
            background: #0d1117;
            color: #c9d1d9;
            font-size: 14px;
            transition: all 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #58a6ff;
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.1);
        }
        button {
            width: 100%;
            padding: 14px;
            background: #58a6ff;
            border: none;
            border-radius: 6px;
            color: #0d1117;
            font-weight: bold;
            font-size: 15px;
            cursor: pointer;
            transition: all 0.3s;
        }
        button:hover { 
            background: #79c0ff; 
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(88, 166, 255, 0.3);
        }
        button:active {
            transform: translateY(0);
        }
        .result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            display: none;
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .success { 
            background: rgba(63, 185, 80, 0.15);
            border: 1px solid #3fb950;
            color: #3fb950;
        }
        .error { 
            background: rgba(248, 81, 73, 0.15);
            border: 1px solid #f85149;
            color: #f85149;
        }
        .result-title {
            font-weight: bold;
            font-size: 16px;
            margin-bottom: 8px;
        }
        .result-content {
            font-size: 14px;
            line-height: 1.6;
        }
        .hints {
            margin-top: 25px;
            padding: 20px;
            background: rgba(88, 166, 255, 0.05);
            border: 1px solid rgba(88, 166, 255, 0.2);
            border-radius: 8px;
        }
        .hints h4 {
            color: #58a6ff;
            font-size: 14px;
            margin-bottom: 12px;
        }
        .payload-example {
            display: inline-block;
            background: #0d1117;
            padding: 6px 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: #f0883e;
            margin: 4px;
            cursor: pointer;
            border: 1px solid #30363d;
            transition: all 0.2s;
        }
        .payload-example:hover {
            background: #1a1f2e;
            border-color: #58a6ff;
            transform: translateY(-1px);
        }
        .credentials {
            margin-top: 15px;
            font-size: 12px;
            color: #8b949e;
            padding: 12px;
            background: rgba(0,0,0,0.3);
            border-radius: 6px;
        }
        .credentials strong {
            color: #c9d1d9;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="header">
            <h2>🎯 Victim Login Portal</h2>
            <p>Educational SQL Injection Testing Environment</p>
        </div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter username" required autocomplete="off">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter password" required autocomplete="off">
            </div>
            
            <button type="submit">🔐 Login</button>
        </form>
        
        <div id="result" class="result"></div>
        
        <div class="hints">
            <h4>💡 SQL Injection Testing Payloads</h4>
            <div>
                <span class="payload-example" onclick="fillPayload(this)" data-user="' OR '1'='1" data-pass="anything">Basic OR</span>
                <span class="payload-example" onclick="fillPayload(this)" data-user="admin'--" data-pass="">Comment Bypass</span>
                <span class="payload-example" onclick="fillPayload(this)" data-user="' OR 1=1--" data-pass="">Boolean</span>
                <span class="payload-example" onclick="fillPayload(this)" data-user="admin' #" data-pass="">Hash Comment</span>
            </div>
            
            <div class="credentials">
                <strong>Valid Credentials:</strong><br>
                admin / admin123<br>
                user1 / pass123<br>
                alice / alice_secure
            </div>
        </div>
    </div>

    <script>
        function fillPayload(element) {
            const username = element.getAttribute('data-user');
            const password = element.getAttribute('data-pass');
            document.getElementById('username').value = username;
            document.getElementById('password').value = password;
        }

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const resultDiv = document.getElementById('result');
            const button = e.target.querySelector('button');

            // Loading state
            button.textContent = '⏳ Attempting Login...';
            button.disabled = true;

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password})
                });
                const data = await response.json();

                resultDiv.style.display = 'block';
                
                if (data.blocked) {
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = `
                        <div class="result-title">🛡️ BLOCKED BY FIREWALL</div>
                        <div class="result-content">
                            ${data.message}<br>
                            <small>Check the firewall logs in the controller dashboard.</small>
                        </div>
                    `;
                } else if (data.success) {
                    resultDiv.className = 'result success';
                    resultDiv.innerHTML = `
                        <div class="result-title">✅ Login Successful!</div>
                        <div class="result-content">
                            <strong>User:</strong> ${data.user}<br>
                            <strong>Email:</strong> ${data.email}<br>
                            <strong>Role:</strong> ${data.role}<br>
                            <small style="color: #8b949e; margin-top: 8px; display: block;">
                                SQL injection successful! Check victim logs to see the vulnerable query.
                            </small>
                        </div>
                    `;
                } else if (data.error === 'Too many failed attempts') {
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = `
                        <div class="result-title">🚫 Account Locked</div>
                        <div class="result-content">
                            ${data.message}<br>
                            <small>Brute-force protection activated. Check firewall alerts.</small>
                        </div>
                    `;
                } else {
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = `
                        <div class="result-title">❌ Login Failed</div>
                        <div class="result-content">${data.message || 'Invalid credentials'}</div>
                    `;
                }
            } catch (err) {
                resultDiv.style.display = 'block';
                resultDiv.className = 'result error';
                resultDiv.innerHTML = `
                    <div class="result-title">⚠️ Connection Error</div>
                    <div class="result-content">${err.message}</div>
                `;
            } finally {
                button.textContent = '🔐 Login';
                button.disabled = false;
            }
        });
    </script>
</body>
</html>
"""


@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr

    # simple brute-force lockout per IP
    with login_lock:
        if login_failures[ip] >= MAX_FAILS_PER_IP:
            firewall.add_alert(f"Brute-force pattern detected from {ip} (>{MAX_FAILS_PER_IP} fails)")
            firewall.block_ip(ip)
            return jsonify({
                "success": False,
                "error": "Too many failed attempts",
                "blocked": True,
                "message": "Brute-force protection activated for your IP"
            }), 403

    try:
        data = request.get_json() or {}
        username = data.get("username", "")
        password = data.get("password", "")

        if not firewall.check_sql(username, ip) or not firewall.check_sql(password, ip):
            return jsonify({
                "success": False,
                "error": "Blocked by WAF",
                "blocked": True,
                "message": "SQL injection pattern detected"
            }), 403

        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

        with open('/app/logs/victim.log', 'a') as f:
            f.write(f"[{datetime.now()}] Login attempt from {ip}, query={query}\n")

        conn = sqlite3.connect("vulnerable.db")
        c = conn.cursor()
        try:
            c.execute(query)
            row = c.fetchone()
        except sqlite3.Error as e:
            conn.close()
            return jsonify({"success": False, "error": str(e)}), 500
        conn.close()

        if row:
            with login_lock:
                login_failures[ip] = 0  # reset on success
            return jsonify({
                "success": True,
                "user": row[1],
                "email": row[3],
                "role": row[4],
                "message": "Login successful"
            })
        else:
            with login_lock:
                login_failures[ip] += 1
            return jsonify({
                "success": False,
                "message": "Invalid credentials"
            })

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/search", methods=["POST"])
def search():
    ip = request.remote_addr
    try:
        data = request.get_json() or {}
        q = data.get("query", "")

        if not firewall.check_xss(q, ip):
            return jsonify({
                "error": "Blocked by WAF",
                "message": "XSS pattern detected",
                "blocked": True
            }), 403

        # intentionally reflects input (didactic XSS scenario)
        return jsonify({
            "success": True,
            "query": q,
            "results": [
                {"id": 1, "title": f"Result for: {q}"},
                {"id": 2, "title": "Another example entry"}
            ]
        })
    except Exception as e:
        logger.error(f"Search error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/system/stats")
def system_stats():
    s = system_monitor.stats()
    with login_lock:
        brute = dict(login_failures)
    return jsonify({
        "system": s,
        "brute_force_failures_by_ip": brute,
        "max_fails_per_ip": MAX_FAILS_PER_IP
    })


@app.route("/firewall/stats")
def fw_stats():
    return jsonify(firewall.stats())


@app.route("/firewall/alerts")
def fw_alerts():
    return jsonify({
        "alerts": firewall.alerts[-50:],
        "total": len(firewall.alerts)
    })


def init_db():
    conn = sqlite3.connect("vulnerable.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        email TEXT,
        role TEXT
    )""")
    users = [
        (1, 'admin', 'admin123', 'admin@test.com', 'administrator'),
        (2, 'user1', 'pass123', 'user1@test.com', 'user'),
        (3, 'alice', 'alice_secure', 'alice@test.com', 'moderator')
    ]
    c.execute("DELETE FROM users")
    c.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", users)
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    logger.info("Victim server starting with brute-force & overload detection enabled")
    logger.info("Login form available at: http://localhost:5000/login-form")
    app.run(host="0.0.0.0", port=5000, debug=False)
