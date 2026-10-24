#!/bin/bash
# setup-automate.sh - Setup script for bulk PHP vulnerability scanner

set -e

echo "========================================"
echo "  PHP2Shell Bulk Scanner Setup"
echo "========================================"

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python3 is not installed"
    exit 1
fi

echo "[*] Python3 found: $(python3 --version)"

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "[*] Installing dependencies..."

# Install php2shell dependencies
if [ -f "../php2shell/requirements.txt" ]; then
    echo "[*] Installing php2shell dependencies..."
    pip install -r ../php2shell/requirements.txt
fi

# Install automate dependencies
echo "[*] Installing automate dependencies..."
pip install -r requirements-automate.txt

# Make scripts executable
echo "[*] Making scripts executable..."
chmod +x ../php2shell/recon.py
chmod +x ../php2shell/php2shell.py
chmod +x automate-php2shell.py

echo ""
echo "========================================"
echo "  Setup Complete!"
echo "========================================"
echo ""
echo "Usage:"
echo "  1. Prepare your Excel file with URLs in a column named 'URL'"
echo "  2. Run: python3 automate-php2shell.py --input sites.xlsx --output results.xlsx"
echo ""
echo "Options:"
echo "  --threads N    Number of concurrent threads (default: 5)"
echo "  --force        Skip precondition checks"
echo "  --oom          Exploit CVE-2026-109618 via OOM"
echo "  --verbose      Show verbose output"
echo ""
echo "Example Excel format:"
echo "  URL"
echo "  https://example.com"
echo "  https://example.org"
echo "  https://example.net"
echo ""
