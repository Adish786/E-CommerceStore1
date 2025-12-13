#!/usr/bin/env python3

import json
import os
import requests


def read_scan_report(filepath):
    """Read and parse a JSON scan report file."""
    try:
        with open(filepath) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: File {filepath} not found")
        return None
    except json.JSONDecodeError:
        print(f"Error: {filepath} contains invalid JSON")
        return None


def main():
    """Main function to read scan reports and send Slack notification."""
    # Read scan reports
    backend_data = read_scan_report("reports/backend-scan.json")
    frontend_data = read_scan_report("reports/frontend-scan.json")
    
    # Count vulnerabilities (if data is available)
    backend_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    frontend_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    
    if backend_data:
        for r in backend_data.get("Results", []):
            for v in r.get("Vulnerabilities", []):
                severity = v.get("Severity", "UNKNOWN").upper()
                if severity in backend_counts:
                    backend_counts[severity] += 1
                else:
                    backend_counts["UNKNOWN"] += 1
    
    if frontend_data:
        for r in frontend_data.get("Results", []):
            for v in r.get("Vulnerabilities", []):
                severity = v.get("Severity", "UNKNOWN").upper()
                if severity in frontend_counts:
                    frontend_counts[severity] += 1
                else:
                    frontend_counts["UNKNOWN"] += 1
    
    # Calculate totals
    total_critical = backend_counts["CRITICAL"] + frontend_counts["CRITICAL"]
    total_high = backend_counts["HIGH"] + frontend_counts["HIGH"]
    total_medium = backend_counts["MEDIUM"] + frontend_counts["MEDIUM"]
    
    # Create message based on scan results
    if total_critical > 0 or total_high > 0:
        message_text = f"""🚨 *E-Commerce Store Security Alert!*
        
*Backend Vulnerabilities:*
CRITICAL: {backend_counts["CRITICAL"]} | HIGH: {backend_counts["HIGH"]} | MEDIUM: {backend_counts["MEDIUM"]}

*Frontend Vulnerabilities:*
CRITICAL: {frontend_counts["CRITICAL"]} | HIGH: {frontend_counts["HIGH"]} | MEDIUM: {frontend_counts["MEDIUM"]}

*Total Critical/High Issues:* {total_critical + total_high}

Check CI/CD logs for details."""
    else:
        message_text = f"""✅ *E-Commerce Store Security Scan Complete*
        
*Backend Vulnerabilities:*
CRITICAL: {backend_counts["CRITICAL"]} | HIGH: {backend_counts["HIGH"]} | MEDIUM: {backend_counts["MEDIUM"]}

*Frontend Vulnerabilities:*
CRITICAL: {frontend_counts["CRITICAL"]} | HIGH: {frontend_counts["HIGH"]} | MEDIUM: {frontend_counts["MEDIUM"]}

All critical and high severity issues have been addressed."""
    
    # Get webhook URL from environment
    webhook_url = os.getenv("SLACK_WEBHOOK")
    
    if not webhook_url:
        print("Error: SLACK_WEBHOOK environment variable not set")
        exit(1)
    
    # Create message payload
    message = {
        "text": message_text,
        "username": "Security Bot",
        "icon_emoji": ":warning:" if (total_critical > 0 or total_high > 0) else ":white_check_mark:"
    }
    
    try:
        # Send the request
        response = requests.post(
            webhook_url,
            json=message,
            timeout=5
        )
        
        # Check response
        if response.status_code == 200:
            print("Notification sent successfully")
        else:
            print(f"Failed to send notification. Status code: {response.status_code}")
            exit(1)
            
    except requests.exceptions.RequestException as e:
        print(f"Error sending notification: {e}")
        exit(1)


if __name__ == "__main__":
    main()