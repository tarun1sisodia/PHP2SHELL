#!/bin/bash
# scripts/directory-fuzzer.sh - Directory and file discovery with ffuf

T="${1:-}"
WORDLIST="${2:-/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt}"

if [ -z "$T" ]; then
    echo "Usage: $0 <target-url> [wordlist]"
    echo "Example: $0 https://example.com"
    exit 1
fi

# Get 404 page size for filtering
echo "Measuring 404 page size..."
NOTFOUND_SIZE=$(curl -s "${T}/this-does-not-exist-12345" | wc -c)
echo "404 page size: ${NOTFOUND_SIZE} bytes"

# Run ffuf
echo "Starting directory/file discovery..."
ffuf -u "${T}/FUZZ" \
    -w "$WORDLIST" \
    -mc 200,301,302,403 \
    -e .php,.bak,.old,.zip,.sql \
    -fs "$NOTFOUND_SIZE" \
    -t 20
