import re
import time
from datetime import datetime

failed_logins = {}
attack_times = {}

threshold = 3

log_file = open("/var/log/auth.log", "r")

for line in log_file:

    if line.strip() == "":
        continue

    if "Failed password" in line:

        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

        if ip_match:
            ip_address = ip_match.group(1)

            timestamp_text = line.split()[0]
            timestamp = datetime.fromisoformat(timestamp_text)

            if ip_address in failed_logins:
                failed_logins[ip_address] += 1
            else:
                failed_logins[ip_address] = 1

            if ip_address not in attack_times:
                attack_times[ip_address] = []

            attack_times[ip_address].append(timestamp)

log_file.close()

alerts = []

print("\n--- Failed Login Summary ---\n")

for ip, count in failed_logins.items():
    print(f"{ip} -> {count} failed attempts")

    if count >= threshold:
        alert_message = f"[ALERT] Possible brute force attack from {ip} ({count} failed attempts)"
        alerts.append(alert_message)

        print(alert_message)

        print("Attack Times:")
        for timestamp in attack_times[ip]:
            print(f" - {timestamp}")

        first_attempt = attack_times[ip][0]
        last_attempt = attack_times[ip][-1]
        attack_duration = last_attempt - first_attempt

        print(f"Attack Duration: {attack_duration}")
        print()

print("--- Alerts Generated ---")
print(f"Total alerts: {len(alerts)}")

alert_file = open("alerts.txt", "w")

for alert in alerts:
    alert_file.write(alert + "\n")

alert_file.close()

print("\nAlerts saved to alerts.txt")

print("Monitoring complete.")

    

