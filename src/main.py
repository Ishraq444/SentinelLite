from bruteforce_detector import detect_bruteforce
from portscan_detector import detect_port_scans
from report_generator import generate_report


# Detect threats
bruteforce_alerts = detect_bruteforce()
portscan_alerts = detect_port_scans()


# Display brute force alerts
if bruteforce_alerts:

    print("\n===== BRUTE FORCE ALERTS =====\n")

    for alert in bruteforce_alerts:

        print(f"IP Address: {alert['ip']}")
        print(f"Failed Attempts: {alert['failed_attempts']}")
        print(f"Threat: {alert['threat']}")
        print("---------------------------")

else:

    print("\nNo brute force attacks detected.")


# Display port scan alerts
if portscan_alerts:

    print("\n===== PORT SCAN ALERTS =====\n")

    for alert in portscan_alerts:

        print(f"IP Address: {alert['ip']}")
        print(f"Ports Scanned: {alert['ports_scanned']}")
        print(f"Threat: {alert['threat']}")
        print("---------------------------")

else:

    print("\nNo port scans detected.")


# Generate security report
generate_report(bruteforce_alerts, portscan_alerts)