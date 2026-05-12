import json
import os
import re
import time
from datetime import datetime
from collections import defaultdict

log_file_path = "/var/log/auth.log"

# Track failed attempts per IP in memory
failed_attempts = defaultdict(list)

# Threshold for triggering an alert
threshold = 3

print("Mini SOC live monitor started...")
print("Watching for failed SSH login attempts...")
print(f"Alert threshold: {threshold} failed attempts\n")

def get_severity(count):
    """Determine severity based on number of failed attempts."""
    if count <= 2:
        return "LOW"
    elif count <= 5:
        return "MEDIUM"
    else:
        return "HIGH"

def load_alerts():
    """Load existing alerts from alerts.json."""
    if os.path.exists("alerts.json"):
        try:
            with open("alerts.json", "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    return []

def save_alerts(alerts):
    """Save alerts to alerts.json."""
    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)

def create_alert(ip_address, timestamps):
    """Create an alert in the same format as main.py."""
    count = len(timestamps)
    severity = get_severity(count)

    first_attempt = timestamps[0]
    last_attempt = timestamps[-1]
    attack_duration = last_attempt - first_attempt

    alert = {
        "ip_address": ip_address,
        "failed_attempt_count": count,
        "severity": severity,
        "attack_timestamps": [str(ts) for ts in timestamps],
        "attack_duration": str(attack_duration),
        "generated_at": str(datetime.now())
    }

    return alert

def update_alert(ip_address, timestamps):
    """Update an existing alert or append a new one."""
    alerts = load_alerts()
    count = len(timestamps)
    severity = get_severity(count)
    first_attempt = timestamps[0]
    last_attempt = timestamps[-1]
    attack_duration = last_attempt - first_attempt

    # Create or update the alert entry for this IP.
    updated = False
    for alert in alerts:
        if alert.get("ip_address") == ip_address:
            alert["failed_attempt_count"] = count
            alert["severity"] = severity
            alert["attack_timestamps"] = [str(ts) for ts in timestamps]
            alert["attack_duration"] = str(attack_duration)
            alert["generated_at"] = str(datetime.now())
            updated = True
            break

    if not updated:
        alerts.append({
            "ip_address": ip_address,
            "failed_attempt_count": count,
            "severity": severity,
            "attack_timestamps": [str(ts) for ts in timestamps],
            "attack_duration": str(attack_duration),
            "generated_at": str(datetime.now())
        })

    save_alerts(alerts)
    return updated

def extract_ip_and_time(line):
    """Extract IP address and timestamp from log line."""
    # Extract IP address
    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    if not ip_match:
        return None, None
    
    ip_address = ip_match.group(1)
    
    # Extract timestamp (format: Jun 10 10:01:22)
    parts = line.split()
    try:
        timestamp_text = f"{datetime.now().year} {parts[0]} {parts[1]} {parts[2]}"
        timestamp = datetime.strptime(timestamp_text, "%Y %b %d %H:%M:%S")
    except (ValueError, IndexError):
        timestamp = datetime.now()
    
    return ip_address, timestamp

# Start reading the log file
with open(log_file_path, "r") as log_file:
    log_file.seek(0, 2)

    while True:
        line = log_file.readline()

        if not line:
            time.sleep(1)
            continue

        if "Failed password" in line:
            ip_address, timestamp = extract_ip_and_time(line)
            
            if ip_address:
                print("[FAILED LOGIN DETECTED]")
                print(f"IP: {ip_address} | Time: {timestamp}")
                
                # Add timestamp to this IP's attempts
                failed_attempts[ip_address].append(timestamp)
                
                attempt_count = len(failed_attempts[ip_address])
                print(f"Attempts from {ip_address}: {attempt_count}\n")
                
                # If this IP reaches threshold, update or create the alert.
                if attempt_count >= threshold:
                    updated = update_alert(ip_address, failed_attempts[ip_address])
                    severity = get_severity(attempt_count)

                    if updated:
                        print(f"⚠️  ALERT UPDATED for {ip_address}!")
                    else:
                        print(f"⚠️  ALERT CREATED for {ip_address}!")

                    print(f"Severity: {severity}")
                    print("alerts.json updated\n")
            