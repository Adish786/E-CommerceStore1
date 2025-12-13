#!/bin/bash

# Simple Trivy scanner with basic error handling
IMAGE_NAME=$1
SEVERITY=${2:-HIGH,CRITICAL}

# Check if image name is provided
if [ -z "$IMAGE_NAME" ]; then
    echo "Error: Image name is required"
    echo "Usage: $0 <image-name> [severity]"
    exit 1
fi

# Create reports directory
mkdir -p security/reports

# Generate filename
FILENAME="security/reports/$(echo "$IMAGE_NAME" | tr ':/' '_').json"

echo "Scanning $IMAGE_NAME with severity: $SEVERITY"
echo "Report will be saved to: $FILENAME"

# Run Trivy scan
trivy image \
    --exit-code 1 \
    --severity "$SEVERITY" \
    --format json \
    --output "$FILENAME" \
    "$IMAGE_NAME"

# Check exit code and provide feedback
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Scan passed - No vulnerabilities found"
elif [ $EXIT_CODE -eq 1 ]; then
    echo "⚠️  Scan failed - Vulnerabilities found"
    echo "Check $FILENAME for details"
else
    echo "❌ Scan error - Trivy exited with code: $EXIT_CODE"
    exit $EXIT_CODE
fi