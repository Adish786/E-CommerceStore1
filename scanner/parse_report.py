#!/usr/bin/env python3

import json
import sys

# Check for file argument
if len(sys.argv) != 2:
    print("Usage: python script.py <json_file>")
    sys.exit(1)

file_path = sys.argv[1]

try:
    with open(file_path) as f:
        data = json.load(f)
except FileNotFoundError:
    print(f"Error: File '{file_path}' not found", file=sys.stderr)
    sys.exit(1)
except json.JSONDecodeError:
    print(f"Error: Invalid JSON in '{file_path}'", file=sys.stderr)
    sys.exit(1)

# Initialize counts for all severity levels
counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

# Count vulnerabilities
for result in data.get("Results", []):
    for vulnerability in result.get("Vulnerabilities", []):
        severity = vulnerability.get("Severity", "").upper()
        
        if severity in counts:
            counts[severity] += 1
        else:
            counts["UNKNOWN"] += 1

# Print as JSON
print(json.dumps(counts, indent=2))

# Exit with error code if critical or high vulnerabilities found
if counts["CRITICAL"] > 0 or counts["HIGH"] > 0:
    sys.exit(1)