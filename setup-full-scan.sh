#!/bin/bash
# setup-full-scan.sh - Complete setup for WordPress security scanning tools

set -e

echo "=========================================="
echo "Installing WordPress Security Tools"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Update system
echo -e "${YELLOW}Updating system packages...${NC}"
sudo apt update

# Install basic tools
echo -e "${YELLOW}Installing basic tools (curl, git, dnsutils)...${NC}"
sudo apt install -y curl git dnsutils

# Install Python and dependencies
echo -e "${YELLOW}Installing Python 3 and dependencies...${NC}"
sudo apt install -y python3 python3-pip python3-venv python3-requests python3-urllib3

# Install Ruby and build dependencies for WPScan
echo -e "${YELLOW}Installing Ruby and build dependencies...${NC}"
sudo apt install -y ruby-full ruby-dev build-essential libcurl4-openssl-dev zlib1g-dev

# Install WPScan
echo -e "${YELLOW}Installing WPScan...${NC}"
if ! command_exists wpscan; then
    sudo gem install wpscan --no-document
    echo -e "${GREEN}WPScan installed successfully!${NC}"
else
    echo -e "${YELLOW}WPScan is already installed${NC}"
fi

# Install ffuf
echo -e "${YELLOW}Installing ffuf...${NC}"
if ! command_exists ffuf; then
    if sudo apt install -y ffuf 2>/dev/null && command_exists ffuf; then
        echo -e "${GREEN}ffuf installed successfully via apt!${NC}"
    else
        ARCH_RAW="$(uname -m)"
        case "$ARCH_RAW" in
            x86_64) FFUF_ARCH="amd64" ;;
            aarch64|arm64) FFUF_ARCH="arm64" ;;
            *) FFUF_ARCH="amd64" ;;
        esac
        FFUF_VERSION="2.3.0"
        TMP_DIR=$(mktemp -d)
        if curl -fSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${FFUF_ARCH}.tar.gz" -o "$TMP_DIR/ffuf.tar.gz" 2>/dev/null; then
            tar -xzf "$TMP_DIR/ffuf.tar.gz" -C "$TMP_DIR" ffuf
            sudo mv "$TMP_DIR/ffuf" /usr/local/bin/ffuf
            sudo chmod +x /usr/local/bin/ffuf
            echo -e "${GREEN}ffuf installed successfully!${NC}"
        else
            echo -e "${RED}Failed to download ffuf. Try installing manually: sudo apt install ffuf${NC}"
        fi
        rm -rf "$TMP_DIR"
    fi
else
    echo -e "${YELLOW}ffuf already installed${NC}"
fi

# Install SecLists wordlists
echo -e "${YELLOW}Installing SecLists...${NC}"
if [ ! -d "/usr/share/seclists" ]; then
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
    echo -e "${GREEN}SecLists installed successfully!${NC}"
else
    echo -e "${YELLOW}SecLists already exists at /usr/share/seclists${NC}"
fi
# Ensure standard directory-list filenames exist for ffuf
if [ -f "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt" ]; then
    sudo ln -sf /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
    sudo ln -sf /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
    sudo ln -sf /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
fi

# Ensure we are in the repo directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/php2shell" ]; then
    REPO_DIR="$SCRIPT_DIR"
else
    REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
cd "$REPO_DIR"

# Create scripts directory
mkdir -p "$REPO_DIR/scripts"

# Create wrapper scripts
echo -e "${YELLOW}Creating wrapper scripts in scripts/...${NC}"

# Create scripts/wpscan-wrapper.sh
cat > "$REPO_DIR/scripts/wpscan-wrapper.sh" << 'EOF'
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
EOF

chmod +x "$REPO_DIR/scripts/wpscan-wrapper.sh"

# Create scripts/php2shell-wrapper.sh
cat > "$REPO_DIR/scripts/php2shell-wrapper.sh" << 'EOF'
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
EOF

chmod +x "$REPO_DIR/scripts/php2shell-wrapper.sh"

# Create scripts/directory-fuzzer.sh
cat > "$REPO_DIR/scripts/directory-fuzzer.sh" << 'EOF'
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
EOF

chmod +x "$REPO_DIR/scripts/directory-fuzzer.sh"

# Create scripts/full-scan.sh
cat > "$REPO_DIR/scripts/full-scan.sh" << 'EOF'
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
EOF

chmod +x "$REPO_DIR/scripts/full-scan.sh"

echo ""
echo -e "${GREEN}=========================================="
echo "Setup Complete!"
echo "==========================================${NC}"
echo ""
echo "Available scripts (in scripts/):"
echo "  1. ./scripts/wpscan-wrapper.sh <url>      - Run WPScan with API token"
echo "  2. ./scripts/php2shell-wrapper.sh <url>   - Run PHP2Shell check"
echo "  3. ./scripts/directory-fuzzer.sh <url>    - Run ffuf directory discovery"
echo "  4. ./scripts/full-scan.sh <url>           - Run complete security scan"
echo ""
echo "Unified Python scanner (in root):"
echo "  python3 full-scan.py <url> --token <token>"
echo ""
echo "Set your WPSCAN_TOKEN:"
echo "  export WPSCAN_TOKEN='your_token_here'"
echo ""
