"""
SecLog Analyzer - Security Event Processing Engine

This module simulates a simplified SOC (Security Operations Center) workflow:
1. Log ingestion
2. Log parsing
3. Threat detection
4. Alert classification

Author: Your Name
"""

import re
from typing import List, Dict
import json
from datetime import datetime

# =========================
# LOG INGESTION
# =========================
def read_logs(file_path: str) -> List[str]:
    """
    Reads raw log entries from a file.

    Args:
        file_path (str): Path to the log file.

    Returns:
        List[str]: List of raw log lines.
    """
    try:
        # Open file safely using context manager
        with open(file_path, "r", encoding="utf-8") as file:
            return file.readlines()

    except FileNotFoundError:
        # Specific error for missing file
        print(f"[ERROR] Log file not found: {file_path}")
        return []

    except Exception as e:
        # Catch unexpected errors
        print(f"[ERROR] Unexpected error: {e}")
        return []


# =========================
# LOG PARSING
# =========================
def parse_log(log: str) -> Dict:
    """
    Converts a raw log string into a structured dictionary.

    Expected format:
    YYYY-MM-DD HH:MM:SS EVENT user=USERNAME ip=IP

    Args:
        log (str): Raw log entry.

    Returns:
        Dict: Parsed log fields or empty dict if parsing fails.
    """

    # Regular expression pattern for extracting log fields
    pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+) user=(\w+) ip=([\d\.]+)"

    # Attempt to match the pattern
    match = re.match(pattern, log)

    if match:
        # Return structured data
        return {
            "timestamp": match.group(1),
            "event": match.group(2),
            "user": match.group(3),
            "ip": match.group(4),
        }

    # Return empty dict if parsing fails
    return {}


def parse_logs(logs: List[str]) -> List[Dict]:
    """
    Parses multiple log entries into structured format.
    Skips empty lines and comments.
    """

    parsed_logs = []

    for log in logs:
        clean_log = log.strip()

        # Skip empty lines or comments
        if not clean_log or clean_log.startswith("#"):
            continue

        parsed = parse_log(clean_log)

        if parsed:
            parsed_logs.append(parsed)
        else:
            print(f"[WARNING] Failed to parse log: {clean_log}")

    return parsed_logs


# =========================
# DETECTION: BRUTE FORCE
# =========================
def detect_brute_force(parsed_logs: List[Dict]) -> Dict[str, int]:
    """
    Detects brute force attempts by counting failed logins per IP.

    Args:
        parsed_logs (List[Dict]): Structured logs.

    Returns:
        Dict[str, int]: Failed login attempts per IP.
    """

    failed_attempts = {}

    for log in parsed_logs:
        # Check if event is a failed login
        if log["event"] == "LOGIN_FAILED":
            ip = log["ip"]

            # Initialize counter if IP not seen before
            if ip not in failed_attempts:
                failed_attempts[ip] = 0

            # Increment failed attempts
            failed_attempts[ip] += 1

    return failed_attempts

# =========================
# DETECTION: SUSPICIOUS LOGIN
# =========================

def detect_suspicious_login(parsed_logs: List[Dict]) -> List[Dict]:
    """
    Detects suspicious login behavior (possible account sharing or compromise).

    Logic:
        - Same user logs in from different IPs
        - Within a short time window (e.g., 2 minutes)

    Returns:
        List[Dict]: Suspicious login alerts
    """

    suspicious_alerts = []

    # Track last login per user
    last_login = {}

    for log in parsed_logs:
        if log["event"] != "LOGIN_SUCCESS":
            continue

        user = log["user"]
        ip = log["ip"]

        # Convert timestamp string to datetime object
        try:
            current_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            print(f"[WARNING] Invalid timestamp format: {log['timestamp']}")
            continue

        if user in last_login:
            previous_ip = last_login[user]["ip"]
            previous_time = last_login[user]["time"]

            # Calculate time difference in seconds
            time_diff = (current_time - previous_time).total_seconds()

            # Detect suspicious behavior
            if ip != previous_ip and time_diff <= 120:
                suspicious_alerts.append({
                    "user": user,
                    "ip": ip,
                    "previous_ip": previous_ip,
                    "time_diff_seconds": int(time_diff),
                    "severity": "HIGH",
                    "message": "Suspicious login from different IP in short time"
                })

        # Update last login
        last_login[user] = {
            "ip": ip,
            "time": current_time
        }

    return suspicious_alerts

# =========================
# DETECTION: OFF HOURS LOGIN
# =========================

def detect_off_hours_login(parsed_logs: List[Dict]) -> List[Dict]:
    """
    Detects logins occurring outside of standard working hours.

    Logic:
        - Consider normal working hours between 08:00 and 18:00
        - Any login outside this range is flagged as suspicious

    Args:
        parsed_logs (List[Dict]): Structured logs

    Returns:
        List[Dict]: Off-hours login alerts
    """

    off_hours_alerts = []

    for log in parsed_logs:
        # We only care about successful logins
        if log["event"] != "LOGIN_SUCCESS":
            continue

        try:
            # Parse timestamp
            timestamp = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            print(f"[WARNING] Invalid timestamp format: {log['timestamp']}")
            continue

        hour = timestamp.hour

        # Define working hours (08:00 to 18:00)
        if hour < 8 or hour >= 18:
            off_hours_alerts.append({
                "user": log["user"],
                "ip": log["ip"],
                "timestamp": log["timestamp"],
                "severity": "MEDIUM",
                "message": "Login outside of working hours"
            })

    return off_hours_alerts

# =========================
# ALERT CLASSIFICATION
# =========================
def classify_alerts(failed_attempts: Dict[str, int]) -> List[Dict]:
    """
    Classifies alerts based on failed login attempts.

    Args:
        failed_attempts (Dict[str, int]): Failed attempts per IP.

    Returns:
        List[Dict]: Alerts with severity levels.
    """

    alerts = []

    for ip, count in failed_attempts.items():

        # Define severity thresholds
        if count >= 5:
            severity = "HIGH"
        elif count >= 3:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        alerts.append({
            "ip": ip,
            "failed_attempts": count,
            "severity": severity
        })

    return alerts


# =========================
# DETECTION: COMPROMISED ACCOUNT
# =========================
def detect_compromised_accounts(parsed_logs: List[Dict]) -> List[Dict]:
    """
    Detects potential account compromise scenarios.

    Logic:
        - Multiple failed login attempts
        - Followed by a successful login
        → Indicates possible brute force success

    Args:
        parsed_logs (List[Dict]): Structured logs.

    Returns:
        List[Dict]: Critical alerts.
    """

    failed_attempts = {}
    compromised_alerts = []

    for log in parsed_logs:
        ip = log["ip"]

        # Track failed login attempts
        if log["event"] == "LOGIN_FAILED":
            if ip not in failed_attempts:
                failed_attempts[ip] = 0

            failed_attempts[ip] += 1

        # Detect success after failures
        elif log["event"] == "LOGIN_SUCCESS":
            if ip in failed_attempts and failed_attempts[ip] >= 5:

                compromised_alerts.append({
                    "ip": ip,
                    "user": log["user"],
                    "failed_attempts": failed_attempts[ip],
                    "severity": "CRITICAL",
                    "message": "Possible account compromise after brute force"
                })

    return compromised_alerts


# =========================
# SAVE JSON FILE    
# =========================

def save_alerts_to_json(alerts: List[Dict], file_path: str) -> None:
    """
    Saves alerts to a JSON file.

    This simulates how SIEM systems store structured security events
    for further analysis and integration with other tools.

    Args:
        alerts (List[Dict]): List of alert dictionaries.
        file_path (str): Path to output JSON file.
    """

    try:
        # Add metadata to each alert (timestamp of detection)
        enriched_alerts = []

        for alert in alerts:
            enriched_alert = alert.copy()

            # Add detection timestamp
            enriched_alert["detected_at"] = datetime.utcnow().isoformat()

            enriched_alerts.append(enriched_alert)

        # Write JSON file with pretty formatting
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(enriched_alerts, file, indent=4)

        print(f"\n[INFO] Alerts successfully saved to {file_path}")

    except Exception as e:
        print(f"[ERROR] Failed to save alerts: {e}")

def save_critical_alerts_to_json(alerts: List[Dict], file_path: str) -> None:
    """
    Saves critical alerts (e.g., compromised accounts) to JSON.

    Args:
        alerts (List[Dict]): Critical alerts.
        file_path (str): Output file path.
    """

    try:
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(alerts, file, indent=4)

        print(f"[INFO] Critical alerts saved to {file_path}")

    except Exception as e:
        print(f"[ERROR] Failed to save critical alerts: {e}")

def save_suspicious_alerts_to_json(alerts: List[Dict], file_path: str) -> None:
    """
    Saves suspicious login alerts to JSON.
    """

    try:
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(alerts, file, indent=4)

        print(f"[INFO] Suspicious alerts saved to {file_path}")

    except Exception as e:
        print(f"[ERROR] Failed to save suspicious alerts: {e}")

def save_off_hours_alerts_to_json(alerts: List[Dict], file_path: str) -> None:
    """
    Saves off-hours alerts to JSON.
    """

    try:
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(alerts, file, indent=4)

        print(f"[INFO] Off-hours alerts saved to {file_path}")

    except Exception as e:
        print(f"[ERROR] Failed to save off-hours alerts: {e}")

# =========================
# OUTPUT
# =========================

def display_suspicious_alerts(alerts: List[Dict]) -> None:
    """
    Displays suspicious login alerts.
    """

    if not alerts:
        return

    print("\n=== SUSPICIOUS LOGIN ALERTS ===")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"User: {alert['user']} | "
            f"IP: {alert['ip']} | "
            f"Previous IP: {alert['previous_ip']} | "
            f"Time Diff: {alert['time_diff_seconds']}s"
        )

def display_off_hours_alerts(alerts: List[Dict]) -> None:
    """
    Displays off-hours login alerts.
    """

    if not alerts:
        return

    print("\n=== OFF-HOURS LOGIN ALERTS ===")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"User: {alert['user']} | "
            f"IP: {alert['ip']} | "
            f"Time: {alert['timestamp']} | "
            f"{alert['message']}"
        )

def display_alerts(alerts: List[Dict]) -> None:
    """
    Displays standard security alerts.
    """

    print("\n=== SECURITY ALERTS ===")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"IP: {alert['ip']} | "
            f"Failed Attempts: {alert['failed_attempts']}"
        )


def display_critical_alerts(alerts: List[Dict]) -> None:
    """
    Displays critical security alerts (compromised accounts).
    """

    if not alerts:
        return

    print("\n=== CRITICAL ALERTS ===")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"IP: {alert['ip']} | "
            f"User: {alert['user']} | "
            f"Failed Attempts: {alert['failed_attempts']} | "
            f"{alert['message']}"
        )


# =========================
# MAIN EXECUTION FLOW
# =========================
def main():
    """
    Main SOC simulation workflow.
    """

    log_file_path = "../logs/example_auth.log"

    # Step 1: Load logs
    logs = read_logs(log_file_path)

    # Step 2: Parse logs into structured format
    parsed_logs = parse_logs(logs)

    # Step 3: Detect brute force attempts
    failed_attempts = detect_brute_force(parsed_logs)

    # Step 4: Detect suspicious login
    suspicious_logins = detect_suspicious_login(parsed_logs)

    # Step 5: Detect off-hours login
    off_hours_alerts = detect_off_hours_login(parsed_logs)

    # Step 6: Classify alerts
    alerts = classify_alerts(failed_attempts)

    # Step 7: Detect compromised accounts
    compromised_alerts = detect_compromised_accounts(parsed_logs)

    # Step 8: Display results
    display_alerts(alerts)
    display_critical_alerts(compromised_alerts)
    display_suspicious_alerts(suspicious_logins)
    display_off_hours_alerts(off_hours_alerts)

    # =========================
    # SAVE RESULTS (SIMULATING SIEM STORAGE)
    # =========================

    # Save standard alerts
    save_alerts_to_json(alerts, "../output/alerts.json")

    # Save critical alerts
    save_critical_alerts_to_json(compromised_alerts, "../output/critical_alerts.json")

    #Save suspicion alerts
    save_suspicious_alerts_to_json(suspicious_logins,"../output/suspicious_alerts.json")

    #Save off hours alerts
    save_off_hours_alerts_to_json(off_hours_alerts,"../output/off_hours_alerts.json")


if __name__ == "__main__":
    main()