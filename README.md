# SentinelLite
SentinelLite is a lightweight Security Information and Event Management (SIEM) project written in Python.  The project analyzes authentication logs, detects suspicious login activity, and generates security alerts.  Features Log file ingestion, Authentication log parsing, Failed login tracking, Brute-force attack detection and Alert report generation
## Current Features

- Authentication log ingestion
- Log parsing
- Failed login tracking
- Brute force attack detection
- Alert report generation

## Detection Rules

### Brute Force Detection

An alert is generated when an IP address exceeds 5 failed login attempts.
