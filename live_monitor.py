import json
import os
import re
import time
from datetime import datetime
from collections import defaultdict

log_file_path = "/var/log/auth.log"
state_file_path = "state.json"

# Track failed attempts per IP in memory
failed_attempts = defaultdict(list)

# Threshold for triggering an alert
threshold = 3

print("Mini SOC live monitor started...")
print("Watching for failed SSH login attempts...")
print(f"Alert threshold: {threshold} failed attempts\n")

def extract_timestamp(line):
    """Extract timestamp from log line, handles both formats."""
    iso_match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    if iso_match:
        try:
            return datetime.strptime(iso_match.group(1), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass
    parts = line.split()
    try:
        timestamp_text = f"{datetime.now().year} {parts[0]} {parts[1]} {parts[2]}"
        return datetime.strptime(timestamp_text, "%Y %b %d %H:%M:%S")
    except (ValueError, IndexError):
        return datetime.now()

def detect_sudo_failure(line):
    """Detect failed sudo attempts — privilege escalation indicator."""
    if "pam_unix(sudo:auth): authentication failure" in line:
        user_match = re.search(r"logname=(\S+)", line)
        username = user_match.group(1) if user_match else "unknown"
        timestamp = extract_timestamp(line)
        print(f"[SUDO FAILURE] User '{username}' failed sudo authentication at {timestamp}")

        alerts = load_alerts()
        alerts.append({
            "alert_type": "SUDO_FAILURE",
            "username": username,
            "severity": "MEDIUM",
            "generated_at": str(timestamp)
        })
        save_alerts(alerts)
        print("alerts.json updated\n")
        return username, timestamp
    return None, None

def detect_new_user(line):
    """Detect new user creation — backdoor persistence indicator."""
    if "useradd" in line and "new user:" in line:
        user_match = re.search(r"name=(\S+),", line)
        username = user_match.group(1) if user_match else "unknown"
        timestamp = extract_timestamp(line)
        print(f"🚨 NEW USER CREATED: '{username}' — possible backdoor at {timestamp}")

        alerts = load_alerts()
        alerts.append({
            "alert_type": "NEW_USER_CREATED",
            "username": username,
            "severity": "HIGH",
            "generated_at": str(timestamp)
        })
        save_alerts(alerts)
        print("alerts.json updated\n")
        return username, timestamp
    return None, None

def block_ip(ip_address):
    """Block an IP address using iptables."""
    import subprocess
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
            check=True
        )
        print(f"🔒 BLOCKED: {ip_address} added to iptables DROP rule")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to block {ip_address}: {e}")
        return False

def get_severity(count):
    """Determine severity based on number of failed attempts."""
    if count <= 2:
        return "LOW"
    elif count <= 5:
        return "MEDIUM"
    else:
        return "HIGH"
    
def save_state(failed_attempts, targeted_usernames):
    """Save in-memory state to disk so monitor can survive restarts."""
    state = {
        "failed_attempts": {ip: [str(ts) for ts in timestamps] for ip, timestamps in failed_attempts.items()},
        "targeted_usernames": dict(targeted_usernames)
    }
    with open(state_file_path, "w") as f:
        json.dump(state, f, indent=4)

def load_state():
    """Load state from disk on startup."""
    if os.path.exists(state_file_path):
        try:
            with open(state_file_path, "r") as f:
                state = json.load(f)
            failed_attempts = defaultdict(list)
            targeted_usernames = defaultdict(list)
            for ip, timestamps in state.get("failed_attempts", {}).items():
                failed_attempts[ip] = [datetime.strptime(ts, "%Y-%m-%d %H:%M:%S") for ts in timestamps]
            for ip, usernames in state.get("targeted_usernames", {}).items():
                targeted_usernames[ip] = usernames
            print(f"State loaded from disk — resuming tracking for {len(failed_attempts)} IPs")
            return failed_attempts, targeted_usernames
        except (json.JSONDecodeError, ValueError):
            print("Could not load state file, starting fresh")
    return defaultdict(list), defaultdict(list)

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

def create_alert(ip_address, timestamps, usernames):
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
        "targeted_usernames": list(set(usernames)),
        "attack_timestamps": [str(ts) for ts in timestamps],
        "attack_duration": str(attack_duration),
        "generated_at": str(datetime.now())
    }
    return alert

def update_alert(ip_address, timestamps, usernames):
    """Update an existing alert or append a new one."""
    alerts = load_alerts()
    count = len(timestamps)
    severity = get_severity(count)
    first_attempt = timestamps[0]
    last_attempt = timestamps[-1]
    attack_duration = last_attempt - first_attempt

    updated = False
    for alert in alerts:
        if alert.get("ip_address") == ip_address:
            alert["failed_attempt_count"] = count
            alert["severity"] = severity
            alert["targeted_usernames"] = list(set(usernames))
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
            "targeted_usernames": list(set(usernames)),
            "attack_timestamps": [str(ts) for ts in timestamps],
            "attack_duration": str(attack_duration),
            "generated_at": str(datetime.now())
        })

    save_alerts(alerts)
    return updated

def extract_ip_and_time(line):
    """Extract IP address, username, and timestamp from log line."""
    # Extract IP address
    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    if not ip_match:
        return None, None, None
    ip_address = ip_match.group(1)

    # Extract username — handles both "for invalid user X" and "for X"
    user_match = re.search(r"for (?:invalid user )?(\S+) from", line)
    username = user_match.group(1) if user_match else "unknown"

    # Extract timestamp — handles both formats:
    # Format 1: Jun 10 10:01:22 (SSH logs)
    # Format 2: 2026-07-12T20:38:50 (sudo/system logs)
    timestamp = None
    iso_match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    if iso_match:
        try:
            timestamp = datetime.strptime(iso_match.group(1), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass
    if not timestamp:
        parts = line.split()
        try:
            timestamp_text = f"{datetime.now().year} {parts[0]} {parts[1]} {parts[2]}"
            timestamp = datetime.strptime(timestamp_text, "%Y %b %d %H:%M:%S")
        except (ValueError, IndexError):
            timestamp = datetime.now()

    return ip_address, username, timestamp

# Load state from disk on startup (survives restarts)
failed_attempts, targeted_usernames = load_state()
blocked_ips = set()

# Start reading the log file
with open(log_file_path, "r") as log_file:
    log_file.seek(0, 2)
    while True:
        line = log_file.readline()
        if not line:
            time.sleep(1)
            continue

        # Pattern 1 — Failed password (existing detection, now with username)
        if "Failed password" in line:
            ip_address, username, timestamp = extract_ip_and_time(line)

            if ip_address:
                print("[FAILED LOGIN DETECTED]")
                print(f"IP: {ip_address} | User: {username} | Time: {timestamp}")

                failed_attempts[ip_address].append(timestamp)
                targeted_usernames[ip_address].append(username)

                attempt_count = len(failed_attempts[ip_address])
                print(f"Attempts from {ip_address}: {attempt_count}\n")

                if attempt_count >= threshold:
                    updated = update_alert(ip_address, failed_attempts[ip_address], targeted_usernames[ip_address])
                    save_state(failed_attempts, targeted_usernames)
                    severity = get_severity(attempt_count)
                    if updated:
                        print(f"⚠️  ALERT UPDATED for {ip_address}!")
                    else:
                        print(f"⚠️  ALERT CREATED for {ip_address}!")
                    print(f"Severity: {severity}")
                    print("alerts.json updated\n")

                    # Auto-block if HIGH severity and not already blocked
                    if severity == "HIGH" and ip_address not in blocked_ips:
                        print(f"🚨 HIGH severity detected — auto-blocking {ip_address}...")
                        if block_ip(ip_address):
                            blocked_ips.add(ip_address)

        # Pattern 2 — Invalid user probe
        elif "Invalid user" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            user_match = re.search(r"Invalid user (\S+) from", line)
            if ip_match and user_match:
                ip = ip_match.group(1)
                user = user_match.group(1)
                print(f"[INVALID USER PROBE] IP: {ip} probed non-existent username: {user}")

        # Pattern 3 — Successful login after failures (critical)
        elif "Accepted password" in line or "Accepted publickey" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            user_match = re.search(r"for (\S+) from", line)
            if ip_match:
                ip = ip_match.group(1)
                user = user_match.group(1) if user_match else "unknown"
                if ip in failed_attempts and len(failed_attempts[ip]) >= threshold:
                    print(f"🚨 CRITICAL: Successful login from {ip} as {user} AFTER {len(failed_attempts[ip])} failed attempts!")
                    update_alert(ip, failed_attempts[ip], targeted_usernames[ip])
        # Pattern 4 — Sudo failure (privilege escalation attempt)
        elif "pam_unix(sudo:auth): authentication failure" in line:
            detect_sudo_failure(line)

        # Pattern 5 — New user creation (backdoor persistence)
        elif "useradd" in line and "new user:" in line:
            detect_new_user(line)