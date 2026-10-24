#!/bin/bash
# php2shell-wrapper.sh - Wrapper script to run PHP2Shell exposure checker

# PHP2Shell script path
PHP2SHELL_SCRIPT="php2shell/php2shell.py"

# Check if script exists
if [ ! -f "$PHP2SHELL_SCRIPT" ]; then
    echo "Error: php2shell.py not found at $PHP2SHELL_SCRIPT"
    echo "Please clone the repository first:"
    echo "  git clone https://github.com/Masriyan/php2shell.git"
    exit 1
fi

# Check if URL is provided
URL="$1"
if [ -z "$URL" ]; then
    echo "Usage: $0 <url> [--no-safe-mode]"
    echo "Example: $0 https://example.com/blog/"
    echo "Example: $0 https://example.com/blog/ --no-safe-mode"
    exit 1
fi

# Check for --no-safe-mode flag
if [ "$2" == "--no-safe-mode" ]; then
    echo "Running PHP2Shell in ACTIVE mode (with version disclosure checks)..."
    python3 "$PHP2SHELL_SCRIPT" --no-safe-mode "$URL"
else
    echo "Running PHP2Shell in SAFE mode (passive checks only)..."
    python3 "$PHP2SHELL_SCRIPT" "$URL"
fi
