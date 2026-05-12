import json
import os
import re
import time
import platform
from datetime import datetime

# Keep counts of failed logins per IP address
failed_logins = {}
# Keep the timestamp history of attacks per IP address
attack_times = {}

# The threshold at which we consider failed attempts suspicious
threshold = 3

# Enable colors in the terminal output
os.system("")

# ANSI color codes for text output
RESET_COLOR = "\033[0m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"


def get_severity_color(severity):
    """Return a terminal color based on the severity string."""
    if severity == "LOW":
        return YELLOW
    elif severity == "MEDIUM":
        return MAGENTA
    else:
        return RED


def get_timestamp(line):
    """Extract a datetime object from a log line."""
    parts = line.split()

    try:
        # If the log line starts with an ISO timestamp, parse it directly
        return datetime.fromisoformat(parts[0])
    except ValueError:
        # Otherwise use the current year and parse the standard auth.log format
        timestamp_text = f"{datetime.now().year} {parts[0]} {parts[1]} {parts[2]}"
        return datetime.strptime(timestamp_text, "%Y %b %d %H:%M:%S")


# Choose the correct log file path for the current operating system
if platform.system() == "Windows":
    log_path = "sample_auth.log"
else:
    log_path = "/var/log/auth.log"

# Open the log file and read it line by line
log_file = open(log_path, "r")

for line in log_file:
    # Skip blank lines
    if line.strip() == "":
        continue

    # Only process failed SSH password attempts
    if "Failed password" in line:
        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

        if ip_match:
            ip_address = ip_match.group(1)
            timestamp = get_timestamp(line)

            # Count the number of failed attempts for this IP
            if ip_address in failed_logins:
                failed_logins[ip_address] += 1
            else:
                failed_logins[ip_address] = 1

            # Save the timestamp for this IP address
            if ip_address not in attack_times:
                attack_times[ip_address] = []

            attack_times[ip_address].append(timestamp)

log_file.close()

# Lists for human-readable alerts and alerts stored as JSON
alerts = []
json_alerts = []
high_severity_alerts = 0

print("\n--- Failed Login Summary ---\n")

for ip, count in failed_logins.items():
    print(f"{ip} -> {count} failed attempts")

    # Determine severity based on how many failed attempts were seen
    if count <= 2:
        severity = "LOW"
    elif count <= 5:
        severity = "MEDIUM"
    else:
        severity = "HIGH"

    severity_color = get_severity_color(severity)
    print(f"Severity: {severity_color}{severity}{RESET_COLOR}")

    # Only create alerts for suspicious IPs above the threshold
    if count >= threshold:
        alert_message = f"[ALERT] Severity: {severity} - Possible brute force attack from {ip} ({count} failed attempts)"
        alerts.append(alert_message)

        if severity == "HIGH":
            high_severity_alerts += 1

        print(f"{severity_color}{alert_message}{RESET_COLOR}")
        print("Attack Times:")

        for timestamp in attack_times[ip]:
            print(f" - {timestamp}")

        # Compute the duration of the attack based on the first and last failed attempt
        first_attempt = attack_times[ip][0]
        last_attempt = attack_times[ip][-1]
        attack_duration = last_attempt - first_attempt

        # Build the JSON alert entry using the same fields as main.py expects
        json_alert = {
            "ip_address": ip,
            "failed_attempt_count": count,
            "severity": severity,
            "attack_timestamps": [],
            "attack_duration": str(attack_duration),
            "generated_at": str(datetime.now())
        }

        for timestamp in attack_times[ip]:
            json_alert["attack_timestamps"].append(str(timestamp))

        json_alerts.append(json_alert)

        print(f"Attack Duration: {attack_duration}")
        print()

print("--- Alerts Generated ---")
print(f"Total alerts: {len(alerts)}")

# Basic statistics for the log file that was processed
total_failed_attempts = sum(failed_logins.values())
total_unique_attacker_ips = len(failed_logins)

print("\n--- Live Attack Statistics ---")
print(f"Total failed login attempts: {total_failed_attempts}")
print(f"Total unique attacker IPs: {total_unique_attacker_ips}")
print(f"HIGH severity alerts: {high_severity_alerts}")

# Save the human-readable alert messages to alerts.txt
alert_file = open("alerts.txt", "w")
for alert in alerts:
    alert_file.write(alert + "\n")
alert_file.close()

print("\nAlerts saved to alerts.txt")

# Save the structured alert data to alerts.json
json_file = open("alerts.json", "w")
json.dump(json_alerts, json_file, indent=4)
json_file.close()

print("Alerts saved to alerts.json")
print("Monitoring complete.")

    

