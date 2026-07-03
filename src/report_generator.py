REPORT_FILE = "alerts/report.txt"


def generate_report(bruteforce_alerts, portscan_alerts):

    with open(REPORT_FILE, "w") as report:

        # Report Title
        report.write("========================================\n")
        report.write("SENTINELLITE SECURITY REPORT\n")
        report.write("========================================\n\n")

        # Brute Force Section
        if bruteforce_alerts:

            report.write("BRUTE FORCE ALERTS\n")
            report.write("------------------------\n")

            for alert in bruteforce_alerts:

                report.write(f"IP Address: {alert['ip']}\n")
                report.write(f"Failed Attempts: {alert['failed_attempts']}\n")
                report.write(f"Threat: {alert['threat']}\n")
                report.write("\n")

        else:

            report.write("No brute force attacks detected.\n\n")

        # Port Scan Section
        if portscan_alerts:

            report.write("PORT SCAN ALERTS\n")
            report.write("------------------------\n")

            for alert in portscan_alerts:

                report.write(f"IP Address: {alert['ip']}\n")
                report.write(f"Ports Scanned: {alert['ports_scanned']}\n")
                report.write(f"Threat: {alert['threat']}\n")
                report.write("\n")

        else:

            report.write("No port scans detected.\n")