#!/bin/bash
# wpscan-wrapper.sh - Wrapper script to run WPScan with API token

WPSCAN_TOKEN="${WPSCAN_TOKEN:-}"

if [ -z "$WPSCAN_TOKEN" ]; then
    echo "Error: WPSCAN_TOKEN environment variable not set"
    echo "Please set it with: export WPSCAN_TOKEN='your_token_here'"
    exit 1
fi

URL="$1"
if [ -z "$URL" ]; then
    echo "Usage: $0 <url>"
    echo "Example: $0 https://example.com/blog/"
    exit 1
fi

# Locate WPScan binary
WPSCAN_CMD=""
if command -v wpscan &>/dev/null; then
    WPSCAN_CMD="wpscan"
elif [ -f "/opt/wpscan/wpscan.rb" ]; then
    WPSCAN_CMD="ruby /opt/wpscan/wpscan.rb"
elif [ -f "/usr/local/bin/wpscan" ]; then
    WPSCAN_CMD="/usr/local/bin/wpscan"
else
    echo "Error: WPScan binary not found. Please install wpscan."
    exit 1
fi

# Run WPScan with the provided URL and API token
$WPSCAN_CMD --url "$URL" \
    --api-token "$WPSCAN_TOKEN" \
    --enumerate vp,vt,u,cb,dbe \
    --plugins-detection aggressive \
    --plugins-version-detection aggressive \
    -f cli-no-color \
    -o "wpscan_$(date +%Y%m%d_%H%M%S).txt"
