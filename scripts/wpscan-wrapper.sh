#!/bin/bash
# scripts/wpscan-wrapper.sh - Wrapper script to run WPScan with API token

WPSCAN_TOKEN="${WPSCAN_TOKEN:-}"

if [ -z "$WPSCAN_TOKEN" ]; then
    echo "Error: WPSCAN_TOKEN environment variable not set"
    echo "Please set it with: export WPSCAN_TOKEN='your_token_here'"
    exit 1
fi

URL="$1"
if [ -z "$URL" ]; then
    echo "Usage: $0 <url> [options]"
    echo "Example: $0 https://example.com/blog/"
    exit 1
fi

WPSCAN_CMD=""
if command -v wpscan &>/dev/null; then
    WPSCAN_CMD="wpscan"
elif [ -f "/usr/local/bin/wpscan" ]; then
    WPSCAN_CMD="/usr/local/bin/wpscan"
elif [ -f "/opt/wpscan/bin/wpscan" ]; then
    WPSCAN_CMD="/opt/wpscan/bin/wpscan"
else
    echo "Error: WPScan binary not found"
    exit 1
fi

$WPSCAN_CMD --url "$URL" \
    --api-token "$WPSCAN_TOKEN" \
    --enumerate vp,vt,u,cb,dbe \
    --plugins-detection aggressive \
    --plugins-version-detection aggressive \
    -f cli-no-color \
    -o "wpscan_$(date +%Y%m%d_%H%M%S).txt"
