# SentinelLite v0.1
# Brute Force Detection Engine

LOG_FILE = "logs/auth.log"
REPORT_FILE = "alerts/report.txt"
THRESHOLD = 5
from portscan_detector import detect_port_scans

failed_attempts = {}

# Read logs
with open(LOG_FILE, "r") as file:
    logs = file.readlines()

# Parse logs and count failed logins
for log in logs:
    parts = log.split()

    if len(parts) < 4:
        continue

    event = parts[2]
    ip = parts[3]

    if event == "LOGIN_FAILED":

        if ip not in failed_attempts:
            failed_attempts[ip] = 0

        failed_attempts[ip] += 1

# Generate alerts
alerts = []

for ip, count in failed_attempts.items():

    if count >= THRESHOLD:

        alert = f"""
================================
SECURITY ALERT
================================

IP: {ip}

Failed Attempts: {count}

Threat:
Possible Brute Force Attack
"""

        alerts.append(alert)

# Save report
with open(REPORT_FILE, "w") as report:

    if alerts:
        for alert in alerts:
            report.write(alert)
            report.write("\n")

    else:
        report.write("No threats detected.\n")

# Print results
if alerts:

    print("\nThreats Detected:\n")

    for alert in alerts:
        print(alert)

else:
    print("No threats detected.")

print("\nReport generated:")
print(REPORT_FILE)

portscan_alerts = detect_port_scans()
if portscan_alerts:

    print("\n===== PORT SCAN ALERTS =====\n")

    for alert in portscan_alerts:

        print(f"IP Address: {alert['ip']}")
        print(f"Ports Scanned: {alert['ports_scanned']}")
        print(f"Threat: {alert['threat']}")
        print("---------------------------")

else:

    print("\nNo port scans detected.")