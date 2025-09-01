#!/usr/bin/env python3

import os
import re
from datetime import datetime
from collections import Counter

# Configuration
LOG_FILE = "/var/log/auth.log"  # Common Linux auth log (modify as needed)
ALERT_THRESHOLD = 5  # Number of failed attempts to trigger an alert
CHECK_WINDOW_MINUTES = 10  # Time window to check for repeated attempts
ALERT_FILE = "suspicious_activity.log"  # Output file for alerts
SCRIPT_LOG = "script_activity.log"  # Log file for script actions

def log_message(message):
    """Log script activity with timestamp to a file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(SCRIPT_LOG, "a") as log:
        log.write(f"[{timestamp}] {message}\n")
    print(f"[{timestamp}] {message}")

def check_file_exists(file_path):
    """Check if the log file exists and is readable."""
    if not os.path.exists(file_path):
        log_message(f"ERROR: Log file {file_path} does not exist.")
        return False
    if not os.access(file_path, os.R_OK):
        log_message(f"ERROR: Log file {file_path} is not readable.")
        return False
    return True

def parse_log_file():
    """Parse the log file for failed SSH login attempts."""
    failed_attempts = []
    pattern = re.compile(r"Failed password for (\w+) from ([\d.]+).*port (\d+)")
    current_time = datetime.now()

    try:
        with open(LOG_FILE, "r") as file:
            for line in file:
                match = pattern.search(line)
                if match:
                    username, ip, port = match.groups()
                    # Extract timestamp from log (assumes format like: Sep 01 04:43:12)
                    try:
                        log_time_str = " ".join(line.split()[:3])
                        log_time = datetime.strptime(log_time_str, "%b %d %H:%M:%S")
                        log_time = log_time.replace(year=current_time.year)  # Assume current year
                        time_diff = (current_time - log_time).total_seconds() / 60
                        if time_diff <= CHECK_WINDOW_MINUTES:
                            failed_attempts.append((username, ip, port, log_time))
                    except ValueError as e:
                        log_message(f"Warning: Could not parse timestamp in line: {line.strip()}")
                        continue
        log_message(f"Found {len(failed_attempts)} failed login attempts in the last {CHECK_WINDOW_MINUTES} minutes.")
        return failed_attempts
    except Exception as e:
        log_message(f"ERROR: Failed to read log file: {str(e)}")
        return []

def analyze_attempts(failed_attempts):
    """Analyze failed attempts and generate alerts for suspicious activity."""
    ip_attempts = Counter(ip for _, ip, _, _ in failed_attempts)
    suspicious_ips = {ip: count for ip, count in ip_attempts.items() if count >= ALERT_THRESHOLD}

    if suspicious_ips:
        log_message(f"ALERT: Suspicious activity detected from {len(suspicious_ips)} IP(s).")
        with open(ALERT_FILE, "a") as alert_file:
            for ip, count in suspicious_ips.items():
                usernames = {username for username, ip_addr, _, _ in failed_attempts if ip_addr == ip}
                alert_message = (
                    f"Suspicious activity from IP {ip}: {count} failed login attempts "
                    f"for user(s): {', '.join(usernames)}"
                )
                log_message(alert_message)
                alert_file.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {alert_message}\n")
    else:
        log_message("No suspicious activity detected.")

def main():
    """Main function to run the log monitoring script."""
    log_message("Starting log monitoring script...")
    
    if not check_file_exists(LOG_FILE):
        log_message("Exiting due to log file issues.")
        return

    failed_attempts = parse_log_file()
    if failed_attempts:
        analyze_attempts(failed_attempts)
    else:
        log_message("No failed login attempts found or error occurred.")

    log_message("Script execution completed.")

if __name__ == "__main__":
    main()