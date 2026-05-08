import time

log_file_path = "/var/log/auth.log"

print("Mini SOC live monitor started...")
print("Watching for failed SSH login attempts...\n")

with open(log_file_path, "r") as log_file:
    log_file.seek(0, 2)

    while True:
        line = log_file.readline()

        if not line:
            time.sleep(1)
            continue

        if "Failed password" in line:
            print("[FAILED LOGIN DETECTED]")
            print(line)
            