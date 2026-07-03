# Brute Force Detection Module

AUTH_LOG = "logs/auth.log"
BRUTE_FORCE_THRESHOLD = 5


def detect_bruteforce():

    failed_attempts = {}

    with open(AUTH_LOG, "r") as file:
        logs = file.readlines()

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

    alerts = []

    for ip, count in failed_attempts.items():

        if count >= BRUTE_FORCE_THRESHOLD:

            alerts.append({
                "ip": ip,
                "failed_attempts": count,
                "threat": "Brute Force Attack"
            })

    return alerts