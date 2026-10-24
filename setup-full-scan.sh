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

# Install Ruby and Bundler
echo -e "${YELLOW}Installing Ruby and Bundler...${NC}"
sudo apt install -y ruby-full ruby-bundler zlib1g-dev 2>/dev/null || {
    echo -e "${YELLOW}Trying alternative installation...${NC}"
    sudo apt install -y ruby-full zlib1g-dev
    sudo gem install bundler --no-document
}
if ! command_exists bundle; then
    echo -e "${YELLOW}Installing bundler via gem...${NC}"
    sudo gem install bundler --no-document
fi

# Install WPScan
echo -e "${YELLOW}Installing WPScan...${NC}"
if [ ! -d "/opt/wpscan" ]; then
    sudo git clone https://github.com/wpscanteam/wpscan.git /opt/wpscan
    (
        cd /opt/wpscan
        sudo bundle install --without test
        sudo ln -sf /opt/wpscan/wpscan.rb /usr/local/bin/wpscan
    )
    echo -e "${GREEN}WPScan installed successfully!${NC}"
else
    echo -e "${YELLOW}WPScan already exists at /opt/wpscan${NC}"
fi

# Install ffuf
echo -e "${YELLOW}Installing ffuf...${NC}"
if ! command_exists ffuf; then
    FFUF_VERSION="v2.2.0"
    curl -sL "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" | sudo tar xz -C /usr/local/bin
    sudo chmod +x /usr/local/bin/ffuf
    echo -e "${GREEN}ffuf installed successfully!${NC}"
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

# Ensure we are in the repo directory
cd "$(dirname "${BASH_SOURCE[0]}")"

# Create wrapper scripts
echo -e "${YELLOW}Creating wrapper scripts...${NC}"

# Create wpscan-wrapper.sh
cat > wpscan-wrapper.sh << 'EOF'
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
    echo "Usage: $0 <url> [options]"
    echo "Example: $0 https://example.com/blog/"
    exit 1
fi

ruby /opt/wpscan/wpscan.rb --url "$URL" \
    --api-token "$WPSCAN_TOKEN" \
    --enumerate vp,vt,u,cb,dbe \
    --plugins-detection aggressive \
    --plugins-version-detection aggressive \
    -f cli-no-color \
    -o "wpscan_$(date +%Y%m%d_%H%M%S).txt"
EOF

chmod +x wpscan-wrapper.sh

# Create php2shell-wrapper.sh
cat > php2shell-wrapper.sh << 'EOF'
#!/bin/bash
# php2shell-wrapper.sh - Wrapper script to run PHP2Shell exposure checker

PHP2SHELL_SCRIPT="php2shell/php2shell.py"

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

chmod +x php2shell-wrapper.sh

# Create directory-fuzzer.sh
cat > directory-fuzzer.sh << 'EOF'
#!/bin/bash
# directory-fuzzer.sh - Directory and file discovery with ffuf

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

chmod +x directory-fuzzer.sh

# Create full-scan.sh
cat > full-scan.sh << 'EOF'
#!/bin/bash
# full-scan.sh - Complete WordPress security scan

T="${1:-}"
WPSCAN_TOKEN="${WPSCAN_TOKEN:-}"

if [ -z "$T" ]; then
    echo "Usage: $0 <target-url>"
    echo "Example: $0 https://example.com/blog/"
    exit 1
fi

if [ -z "$WPSCAN_TOKEN" ]; then
    echo "Error: WPSCAN_TOKEN environment variable not set"
    exit 1
fi

echo "=========================================="
echo "WordPress Security Scan"
echo "Target: $T"
echo "=========================================="
echo ""

# PHP2Shell scan
echo "[1/3] Running PHP2Shell vulnerability check..."
python3 php2shell/php2shell.py --no-safe-mode "$T" || true
echo ""

# WPScan
echo "[2/3] Running WPScan..."
ruby /opt/wpscan/wpscan.rb --url "$T" \
    --api-token "$WPSCAN_TOKEN" \
    --enumerate vp,vt,u,cb,dbe \
    --plugins-detection aggressive \
    --plugins-version-detection aggressive \
    -f cli-no-color \
    -o "wpscan_$(date +%Y%m%d_%H%M%S).txt"
echo ""

# Directory fuzzer
echo "[3/3] Running directory/file discovery..."
NOTFOUND_SIZE=$(curl -s "${T}/this-does-not-exist-12345" | wc -c)
ffuf -u "${T}/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -mc 200,301,302,403 \
    -e .php,.bak,.old,.zip,.sql \
    -fs "$NOTFOUND_SIZE" \
    -t 20
echo ""

echo "=========================================="
echo "Scan complete! Check output files."
echo "=========================================="
EOF

chmod +x full-scan.sh

echo ""
echo -e "${GREEN}=========================================="
echo "Setup Complete!"
echo "==========================================${NC}"
echo ""
echo "Available scripts:"
echo "  1. wpscan-wrapper.sh <url>      - Run WPScan with API token"
echo "  2. php2shell-wrapper.sh <url>   - Run PHP2Shell check"
echo "  3. directory-fuzzer.sh <url>    - Run ffuf directory discovery"
echo "  4. full-scan.sh <url>           - Run complete security scan"
echo ""
echo "Set your WPSCAN_TOKEN:"
echo "  export WPSCAN_TOKEN='your_token_here'"
echo ""
