# Port Scan Detection Module

NETWORK_LOG = "logs/network.log"
PORT_SCAN_THRESHOLD = 5


def detect_port_scans():

    port_counts = {}

    with open(NETWORK_LOG, "r") as file:
        logs = file.readlines()

    for log in logs:

        parts = log.split()

        if len(parts) < 5:
            continue

        event = parts[2]
        ip = parts[3]

        if event == "PORT_SCAN":

            if ip not in port_counts:
                port_counts[ip] = 0

            port_counts[ip] += 1

    alerts = []

    for ip, count in port_counts.items():

        if count >= PORT_SCAN_THRESHOLD:

            alerts.append({
                "ip": ip,
                "ports_scanned": count,
                "threat": "Port Scan"
            })

    return alerts