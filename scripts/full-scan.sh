#!/bin/bash
# scripts/full-scan.sh - Complete WordPress security scan pipeline

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

T="${1:-}"
WPSCAN_TOKEN="${WPSCAN_TOKEN:-}"

if [ -z "$T" ]; then
    echo "Usage: $0 <target-url>"
    echo "Example: $0 https://example.com/blog/"
    exit 1
fi

if [ -z "$WPSCAN_TOKEN" ]; then
    echo "Error: WPSCAN_TOKEN environment variable not set"
    echo "Please set it with: export WPSCAN_TOKEN='your_token_here'"
    exit 1
fi

echo "=========================================="
echo "WordPress Security Scan"
echo "Target: $T"
echo "=========================================="
echo ""

# PHP2Shell scan
echo "[1/3] Running PHP2Shell vulnerability check..."
"$SCRIPT_DIR/php2shell-wrapper.sh" "$T" --no-safe-mode || true
echo ""

# WPScan
echo "[2/3] Running WPScan..."
"$SCRIPT_DIR/wpscan-wrapper.sh" "$T" || true
echo ""

# Directory fuzzer
echo "[3/3] Running directory/file discovery..."
"$SCRIPT_DIR/directory-fuzzer.sh" "$T" || true
echo ""

echo "=========================================="
echo "Scan complete! Check output files."
echo "=========================================="
