#!/bin/bash
# scripts/php2shell-wrapper.sh - Wrapper script to run PHP2Shell exposure checker

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PHP2SHELL_SCRIPT="$REPO_DIR/php2shell/php2shell.py"

if [ ! -f "$PHP2SHELL_SCRIPT" ]; then
    echo "Error: php2shell.py not found at $PHP2SHELL_SCRIPT"
    exit 1
fi

URL="$1"
if [ -z "$URL" ]; then
    echo "Usage: $0 <url> [--no-safe-mode]"
    exit 1
fi

if [ "$2" == "--no-safe-mode" ]; then
    python3 "$PHP2SHELL_SCRIPT" --no-safe-mode "$URL"
else
    python3 "$PHP2SHELL_SCRIPT" "$URL"
fi
