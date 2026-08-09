import json
import os
import re
import time
import threading
from datetime import datetime
from collections import defaultdict

log_file_path = "/var/log/auth.log"
web_log_path = "/var/log/apache2/securebank_access.log"
state_file_path = "state.json"

# Track failed attempts per IP in memory
failed_attempts = defaultdict(list)
web_login_attempts = defaultdict(list)

# Threshold for triggering an alert
threshold = 3
web_threshold = 5

print("Mini SOC live monitor started...")
print("Watching for failed SSH login attempts...")
print(f"Alert threshold: {threshold} failed attempts\n")


def normalize_timestamp(dt):
    """Return a consistent YYYY-MM-DD HH:MM:SS string from a datetime object."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def extract_timestamp(line):
    """Extract and normalize timestamp from log line, handles both formats."""
    iso_match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    if iso_match:
        try:
            dt = datetime.strptime(iso_match.group(1), "%Y-%m-%dT%H:%M:%S")
            return dt
        except ValueError:
            pass
    parts = line.split()
    try:
        timestamp_text = f"{datetime.now().year} {parts[0]} {parts[1]} {parts[2]}"
        return datetime.strptime(timestamp_text, "%Y %b %d %H:%M:%S")
    except (ValueError, IndexError):
        return datetime.now()


def extract_apache_fields(line):
    """Extract IP, method, path, and status code from Apache access log line."""
    match = re.match(r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+)', line)
    if match:
        ip = match.group(1)
        method = match.group(3)
        path = match.group(4)
        status = match.group(5)
        return ip, method, path, status
    return None, None, None, None


def upsert_alert(match_key, match_value, alert_type, new_data):
    """Update an existing alert if one exists for this key/value, otherwise append a new one."""
    alerts = load_alerts()
    updated = False
    for alert in alerts:
        if alert.get("alert_type") == alert_type and alert.get(match_key) == match_value:
            alert.update(new_data)
            alert["last_seen"] = normalize_timestamp(datetime.now())
            alert["count"] = alert.get("count", 1) + 1
            updated = True
            break
    if not updated:
        new_alert = {
            "alert_type": alert_type,
            match_key: match_value,
            "status": "Open",
            "count": 1,
            "first_seen": normalize_timestamp(datetime.now()),
            "last_seen": normalize_timestamp(datetime.now()),
        }
        new_alert.update(new_data)
        alerts.append(new_alert)
    save_alerts(alerts)
    return updated


def detect_sudo_failure(line):
    """Detect failed sudo attempts — privilege escalation indicator."""
    if "pam_unix(sudo:auth): authentication failure" in line:
        user_match = re.search(r"logname=(\S+)", line)
        username = user_match.group(1) if user_match else "unknown"
        timestamp = extract_timestamp(line)
        print(f"[SUDO FAILURE] User '{username}' failed sudo authentication at {normalize_timestamp(timestamp)}")

        updated = upsert_alert(
            match_key="username",
            match_value=username,
            alert_type="SUDO_FAILURE",
            new_data={"severity": "MEDIUM", "generated_at": normalize_timestamp(timestamp)}
        )
        if updated:
            print("alerts.json updated — existing SUDO_FAILURE alert incremented\n")
        else:
            print("alerts.json updated — new SUDO_FAILURE alert created\n")
        return username, timestamp
    return None, None


def detect_new_user(line):
    """Detect new user creation — backdoor persistence indicator."""
    if "useradd" in line and "new user:" in line:
        user_match = re.search(r"name=(\S+),", line)
        username = user_match.group(1) if user_match else "unknown"
        timestamp = extract_timestamp(line)
        print(f"🚨 NEW USER CREATED: '{username}' — possible backdoor at {normalize_timestamp(timestamp)}")

        upsert_alert(
            match_key="username",
            match_value=username,
            alert_type="NEW_USER_CREATED",
            new_data={"severity": "HIGH", "generated_at": normalize_timestamp(timestamp)}
        )
        print("alerts.json updated\n")
        return username, timestamp
    return None, None


def detect_web_attack(ip, method, path, status):
    """Detect web application attacks from Apache access log."""
    path_decoded = re.sub(r'%[0-9a-fA-F]{2}', lambda m: chr(int(m.group(0)[1:], 16)), path)

    # SQLi patterns
    sqli_patterns = [
        r"'", r"--", r"OR\s+1=1", r"UNION\s+SELECT",
        r"DROP\s+TABLE", r"INSERT\s+INTO", r"SELECT\s+\*",
        r"1=1", r"admin'--", r"'\s+OR\s+'", r"SLEEP\(",
        r"BENCHMARK\(", r"xp_cmdshell"
    ]
    for pattern in sqli_patterns:
        if re.search(pattern, path_decoded, re.IGNORECASE):
            print(f"🚨 [SQL INJECTION] IP: {ip} | Path: {path}")
            upsert_alert(
                match_key="ip_address",
                match_value=ip,
                alert_type="SQL_INJECTION",
                new_data={
                    "severity": "HIGH",
                    "path": path,
                    "generated_at": normalize_timestamp(datetime.now())
                }
            )
            print("alerts.json updated\n")
            return

    # XSS patterns
    xss_patterns = [
        r"<script", r"</script>", r"alert\(", r"onerror=",
        r"onload=", r"javascript:", r"<img", r"<svg",
        r"document\.cookie", r"eval\("
    ]
    for pattern in xss_patterns:
        if re.search(pattern, path_decoded, re.IGNORECASE):
            print(f"🚨 [XSS ATTEMPT] IP: {ip} | Path: {path}")
            upsert_alert(
                match_key="ip_address",
                match_value=ip,
                alert_type="XSS_ATTEMPT",
                new_data={
                    "severity": "HIGH",
                    "path": path,
                    "generated_at": normalize_timestamp(datetime.now())
                }
            )
            print("alerts.json updated\n")
            return

    # Path traversal patterns
    traversal_patterns = [
        r"\.\./", r"\.\.\\", r"/etc/passwd", r"/etc/shadow",
        r"\.\.%2f", r"%2e%2e", r"\.\.%5c", r"\.\./"
    ]
    for pattern in traversal_patterns:
        if re.search(pattern, path_decoded, re.IGNORECASE):
            print(f"🚨 [PATH TRAVERSAL] IP: {ip} | Path: {path}")
            upsert_alert(
                match_key="ip_address",
                match_value=ip,
                alert_type="PATH_TRAVERSAL",
                new_data={
                    "severity": "HIGH",
                    "path": path,
                    "generated_at": normalize_timestamp(datetime.now())
                }
            )
            print("alerts.json updated\n")
            return

    # Web brute force — many POST requests to /login
    if method == "POST" and "/login" in path:
        web_login_attempts[ip].append(datetime.now())
        count = len(web_login_attempts[ip])
        if count >= web_threshold:
            print(f"🚨 [WEB BRUTE FORCE] IP: {ip} | {count} POST requests to /login")
            upsert_alert(
                match_key="ip_address",
                match_value=ip,
                alert_type="WEB_BRUTE_FORCE",
                new_data={
                    "severity": "HIGH",
                    "path": path,
                    "attempt_count": count,
                    "generated_at": normalize_timestamp(datetime.now())
                }
            )
            print("alerts.json updated\n")


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
        "failed_attempts": {ip: [normalize_timestamp(ts) for ts in timestamps] for ip, timestamps in failed_attempts.items()},
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


def update_alert(ip_address, timestamps, usernames):
    """Update an existing BRUTE_FORCE alert or append a new one."""
    alerts = load_alerts()
    count = len(timestamps)
    severity = get_severity(count)
    first_attempt = timestamps[0]
    last_attempt = timestamps[-1]
    attack_duration = last_attempt - first_attempt

    updated = False
    for alert in alerts:
        if alert.get("ip_address") == ip_address and alert.get("alert_type", "BRUTE_FORCE") == "BRUTE_FORCE":
            alert["failed_attempt_count"] = count
            alert["severity"] = severity
            alert["targeted_usernames"] = list(set(usernames))
            alert["attack_timestamps"] = [normalize_timestamp(ts) for ts in timestamps]
            alert["attack_duration"] = str(attack_duration)
            alert["generated_at"] = normalize_timestamp(datetime.now())
            updated = True
            break

    if not updated:
        alerts.append({
            "alert_type": "BRUTE_FORCE",
            "ip_address": ip_address,
            "failed_attempt_count": count,
            "severity": severity,
            "targeted_usernames": list(set(usernames)),
            "attack_timestamps": [normalize_timestamp(ts) for ts in timestamps],
            "attack_duration": str(attack_duration),
            "status": "Open",
            "generated_at": normalize_timestamp(datetime.now())
        })

    save_alerts(alerts)
    return updated


def extract_ip_and_time(line):
    """Extract IP address, username, and timestamp from log line."""
    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    if not ip_match:
        return None, None, None
    ip_address = ip_match.group(1)

    user_match = re.search(r"for (?:invalid user )?(\S+) from", line)
    username = user_match.group(1) if user_match else "unknown"

    timestamp = extract_timestamp(line)
    return ip_address, username, timestamp


def open_log_file(path):
    """Open log file and seek to end."""
    log_file = open(path, "r")
    log_file.seek(0, 2)
    return log_file


def check_log_rotated(log_file, path):
    """Check if the log file has been rotated by comparing inode numbers."""
    try:
        current_inode = os.fstat(log_file.fileno()).st_ino
        new_inode = os.stat(path).st_ino
        return current_inode != new_inode
    except (OSError, FileNotFoundError):
        return True


def monitor_web_log():
    """Monitor Apache access log for web attacks in a separate thread."""
    print("Opening web log file...")
    if not os.path.exists(web_log_path):
        print(f"⚠️  Web log not found at {web_log_path} — web monitoring disabled")
        return

    web_log = open_log_file(web_log_path)
    print("✅ Web attack monitoring active\n")

    while True:
        line = web_log.readline()
        if not line:
            if check_log_rotated(web_log, web_log_path):
                print("⚠️  Web log rotation detected — reopening...")
                web_log.close()
                web_log = open_log_file(web_log_path)
            time.sleep(1)
            continue

        ip, method, path, status = extract_apache_fields(line)
        if ip and path:
            detect_web_attack(ip, method, path, status)


# Load state from disk on startup (survives restarts)
failed_attempts, targeted_usernames = load_state()
blocked_ips = set()

# Start web log monitor in background thread
web_thread = threading.Thread(target=monitor_web_log, daemon=True)
web_thread.start()

# Start reading the auth log file
print("Opening log file...")
log_file = open_log_file(log_file_path)

while True:
    line = log_file.readline()

    if not line:
        if check_log_rotated(log_file, log_file_path):
            print("⚠️  Log rotation detected — reopening log file...")
            log_file.close()
            log_file = open_log_file(log_file_path)
            print("✅ Log file reopened successfully")
        time.sleep(1)
        continue

    # Pattern 1 — Failed password
    if "Failed password" in line:
        ip_address, username, timestamp = extract_ip_and_time(line)

        if ip_address:
            print("[FAILED LOGIN DETECTED]")
            print(f"IP: {ip_address} | User: {username} | Time: {normalize_timestamp(timestamp)}")

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
            timestamp = extract_timestamp(line)
            print(f"[INVALID USER PROBE] IP: {ip} probed non-existent username: {user}")
            updated = upsert_alert(
                match_key="ip_address",
                match_value=ip,
                alert_type="INVALID_USER_PROBE",
                new_data={
                    "severity": "LOW",
                    "username": user,
                    "generated_at": normalize_timestamp(timestamp)
                }
            )
            if updated:
                print("alerts.json updated — existing INVALID_USER_PROBE alert incremented\n")
            else:
                print("alerts.json updated — new INVALID_USER_PROBE alert created\n")

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