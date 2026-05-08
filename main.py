import re

failed_logins = {}

log_file = open("sample_auth.log", "r")

for line in log_file:
    if "Failed password" in line:
        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

        if ip_match:
            ip_address = ip_match.group(1)

            if ip_address in failed_logins:
                failed_logins[ip_address] += 1
            else:
                failed_logins[ip_address] = 1

log_file.close()

for ip, count in failed_logins.items():

    if count >= 3:
        print(f"[ALERT] Possible brute force attack from {ip}")
        print(f"Failed login attempts: {count}")
        
