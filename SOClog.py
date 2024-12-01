import re
import time
from collections import defaultdict

# Simulated log file
LOG_FILE = "server_logs.txt"

# Threshold for suspicious activity
THRESHOLD = 5
TIME_WINDOW = 60  # seconds

# Track failed login attempts
failed_attempts = defaultdict(list)

# Regex pattern for failed login logs
FAILED_LOGIN_PATTERN = r"Failed login from (\d+\.\d+\.\d+\.\d+)"

def monitor_logs():
    """
    Monitors a log file for failed login attempts and triggers an alert 
    if suspicious activity is detected.
    """
    print("SOC Monitoring Started...\n")
    with open(LOG_FILE, "r") as logs:
        # Move to the end of the log file
        logs.seek(0, 2)
        while True:
            # Read new lines as they are added
            line = logs.readline()
            if not line:
                time.sleep(1)
                continue

            # Check for failed login pattern
            match = re.search(FAILED_LOGIN_PATTERN, line)
            if match:
                ip_address = match.group(1)
                print(f"[ALERT] Failed login detected from {ip_address}")

                # Record timestamp of failed attempt
                timestamp = time.time()
                failed_attempts[ip_address].append(timestamp)

                # Remove old attempts outside the time window
                failed_attempts[ip_address] = [
                    t for t in failed_attempts[ip_address]
                    if timestamp - t <= TIME_WINDOW
                ]

                # Check if the threshold is breached
                if len(failed_attempts[ip_address]) >= THRESHOLD:
                    alert(ip_address)


def alert(ip_address):
    """
    Sends an alert for suspicious activity.
    """
    print(f"\n🚨 ALERT: Possible brute force attack detected from {ip_address}")
    print(f"Multiple failed login attempts within {TIME_WINDOW} seconds.\n")
    # Add further actions, such as blocking the IP, sending an email, etc.


if __name__ == "__main__":
    monitor_logs()
