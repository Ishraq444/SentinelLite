# SentinelLite - Step 1: Log Reader

log_file = "logs/auth.log"

with open(log_file, "r") as file:
    logs = file.readlines()

for log in logs:
    print(log.strip())

# SentinelLite - Step 2: Extract Events

failed_attempts = {}

for log in logs:
    parts = log.split()

    timestamp = parts[0] + " " + parts[1]
    event = parts[2]
    ip = parts[3]

    print(f"Event: {event} | IP: {ip}")

