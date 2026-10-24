#!/bin/bash
# ==============================================================================
# setup-all-tools.sh - Complete Setup for WordPress Security Scanner Suite
# ==============================================================================
# Installs and configures:
#   1. System utilities (curl, wget, git, dnsutils, build-essential)
#   2. Python 3 & scanning dependencies (requests, urllib3)
#   3. WPScan (via gem, apt, or source build)
#   4. ffuf (Fast web fuzzer - precompiled release with architecture detection)
#   5. SecLists (Common discovery wordlists)
#   6. PHP2Shell (CVE-2026-109618 / 109619 exposure scanner)
#   7. Automated wrapper scripts (wpscan, php2shell, fuzzer, full-scan)
# ==============================================================================

# Determine repository root directory
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

log_info()    { echo -e "${CYAN}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }

command_exists() {
    command -v "$1" &> /dev/null
}

echo -e "${BOLD}${BLUE}====================================================${NC}"
echo -e "${BOLD}${BLUE}   WordPress Security Scanner Suite - Full Setup    ${NC}"
echo -e "${BOLD}${BLUE}====================================================${NC}"
echo ""

# ------------------------------------------------------------------------------
# 0. Sudo check
# ------------------------------------------------------------------------------
if [ "$EUID" -ne 0 ] && ! command_exists sudo; then
    log_error "This script requires sudo privileges to install system packages."
    exit 1
fi

SUDO_CMD=""
if [ "$EUID" -ne 0 ]; then
    SUDO_CMD="sudo"
fi

# ------------------------------------------------------------------------------
# 1. System Packages & Build Tools
# ------------------------------------------------------------------------------
log_info "Step 1/6: Updating package index and installing base dependencies..."
$SUDO_CMD apt update -y || log_warn "apt update encountered warnings, continuing..."

BASE_PKGS="curl wget git dnsutils netcat-openbsd jq unzip build-essential"
$SUDO_CMD apt install -y $BASE_PKGS || log_warn "Some base packages failed to install, proceeding..."

# ------------------------------------------------------------------------------
# 2. Python 3 & Dependencies
# ------------------------------------------------------------------------------
log_info "Step 2/6: Installing Python 3 and dependencies..."
$SUDO_CMD apt install -y python3 python3-pip python3-venv python3-requests python3-urllib3 || true

# Also attempt pip installation for requests and urllib3 safely
python3 -m pip install --upgrade requests urllib3 --break-system-packages 2>/dev/null || \
python3 -m pip install --upgrade requests urllib3 2>/dev/null || true

log_success "Python 3 environment configured."

# ------------------------------------------------------------------------------
# 3. Ruby & WPScan Installation
# ------------------------------------------------------------------------------
log_info "Step 3/6: Setting up WPScan..."

if command_exists wpscan; then
    log_success "WPScan is already installed ($(wpscan --version 2>/dev/null | head -1 || echo 'detected'))."
else
    # Install Ruby development headers and native libraries needed by WPScan
    $SUDO_CMD apt install -y ruby-full ruby-dev zlib1g-dev libcurl4-openssl-dev libffi-dev || true

    # Option A: Try native package (Kali / Parrot)
    if $SUDO_CMD apt install -y wpscan 2>/dev/null && command_exists wpscan; then
        log_success "WPScan installed via apt."
    else
        # Option B: Install via RubyGems (Standard on Debian/Ubuntu)
        log_info "Installing WPScan via RubyGems..."
        if $SUDO_CMD gem install wpscan --no-document 2>/dev/null && command_exists wpscan; then
            log_success "WPScan installed successfully via gem."
        else
            # Option C: Build from source in /opt/wpscan as fallback
            log_info "Falling back to installing WPScan from GitHub source..."
            $SUDO_CMD apt install -y ruby-bundler || $SUDO_CMD gem install bundler --no-document || true
            if [ ! -d "/opt/wpscan" ]; then
                $SUDO_CMD git clone https://github.com/wpscanteam/wpscan.git /opt/wpscan
            fi
            (
                cd /opt/wpscan || exit 1
                $SUDO_CMD bundle install --without test || true
                $SUDO_CMD ln -sf /opt/wpscan/wpscan.rb /usr/local/bin/wpscan
            )
            if [ -f "/usr/local/bin/wpscan" ] || command_exists wpscan; then
                log_success "WPScan installed from source to /usr/local/bin/wpscan."
            else
                log_warn "WPScan installation had warnings. Verify with: wpscan --help"
            fi
        fi
    fi
fi

# ------------------------------------------------------------------------------
# 4. ffuf Installation (Robust binary download with architecture detection)
# ------------------------------------------------------------------------------
log_info "Step 4/6: Setting up ffuf (Fast Web Fuzzer)..."

if command_exists ffuf; then
    log_success "ffuf is already installed ($(ffuf -V 2>&1 | head -1 || echo 'detected'))."
else
    # Option A: Check if distro apt has ffuf
    if $SUDO_CMD apt install -y ffuf 2>/dev/null && command_exists ffuf; then
        log_success "ffuf installed via apt."
    else
        # Option B: Download official precompiled release binary
        ARCH_RAW="$(uname -m)"
        case "$ARCH_RAW" in
            x86_64)       FFUF_ARCH="amd64" ;;
            aarch64|arm64) FFUF_ARCH="arm64" ;;
            armv7l|armv6l) FFUF_ARCH="armv6" ;;
            i386|i686)    FFUF_ARCH="386" ;;
            *)            FFUF_ARCH="amd64" ;;
        esac

        FFUF_VERSION="2.3.0"
        FFUF_TAG="v2.3.0"
        FFUF_FILENAME="ffuf_${FFUF_VERSION}_linux_${FFUF_ARCH}.tar.gz"
        FFUF_URL="https://github.com/ffuf/ffuf/releases/download/${FFUF_TAG}/${FFUF_FILENAME}"

        log_info "Downloading ffuf ${FFUF_VERSION} (${FFUF_ARCH}) from GitHub..."
        TMP_DIR=$(mktemp -d)
        
        if curl -fSL "$FFUF_URL" -o "$TMP_DIR/ffuf.tar.gz" 2>/dev/null; then
            # Verify file is a valid gzip archive before extracting
            if tar -tzf "$TMP_DIR/ffuf.tar.gz" >/dev/null 2>&1; then
                tar -xzf "$TMP_DIR/ffuf.tar.gz" -C "$TMP_DIR"
                $SUDO_CMD mv "$TMP_DIR/ffuf" /usr/local/bin/ffuf
                $SUDO_CMD chmod +x /usr/local/bin/ffuf
                log_success "ffuf installed successfully to /usr/local/bin/ffuf."
            else
                log_error "Downloaded ffuf archive was not in valid gzip format."
            fi
        else
            log_warn "Direct download from $FFUF_URL failed."
            # Option C: Fallback to Go if available
            if command_exists go; then
                log_info "Attempting installation via go install..."
                go install github.com/ffuf/ffuf/v2@latest || true
                if [ -f "$HOME/go/bin/ffuf" ]; then
                    $SUDO_CMD cp "$HOME/go/bin/ffuf" /usr/local/bin/ffuf
                    $SUDO_CMD chmod +x /usr/local/bin/ffuf
                    log_success "ffuf installed via Go."
                fi
            fi
        fi
        rm -rf "$TMP_DIR"
    fi

    if ! command_exists ffuf; then
        log_warn "ffuf was not installed automatically. You can install it manually: sudo apt install ffuf"
    fi
fi

# ------------------------------------------------------------------------------
# 5. SecLists Wordlists
# ------------------------------------------------------------------------------
log_info "Step 5/6: Setting up SecLists wordlists..."

SECLISTS_TARGET="/usr/share/seclists"
SECLISTS_KALI="/usr/share/wordlists/seclists"

if [ -f "$SECLISTS_TARGET/Discovery/Web-Content/directory-list-2.3-medium.txt" ]; then
    log_success "SecLists is already available at $SECLISTS_TARGET."
elif [ -f "$SECLISTS_KALI/Discovery/Web-Content/directory-list-2.3-medium.txt" ]; then
    log_info "SecLists found at $SECLISTS_KALI. Creating symlink to $SECLISTS_TARGET..."
    $SUDO_CMD ln -sfn "$SECLISTS_KALI" "$SECLISTS_TARGET"
    log_success "Symlinked $SECLISTS_TARGET -> $SECLISTS_KALI."
else
    # Try apt on Kali/Parrot
    if $SUDO_CMD apt install -y seclists 2>/dev/null && [ -d "$SECLISTS_KALI" ]; then
        $SUDO_CMD ln -sfn "$SECLISTS_KALI" "$SECLISTS_TARGET"
        log_success "SecLists installed via apt and symlinked."
    else
        log_info "Cloning SecLists (depth 1) to $SECLISTS_TARGET..."
        $SUDO_CMD mkdir -p "$SECLISTS_TARGET"
        $SUDO_CMD git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_TARGET" || log_warn "SecLists git clone had issues."
        if [ -f "$SECLISTS_TARGET/Discovery/Web-Content/directory-list-2.3-medium.txt" ]; then
            log_success "SecLists installed to $SECLISTS_TARGET."
        else
            log_warn "SecLists wordlists not fully present. Full-scan will fall back to other common lists."
        fi
    fi
fi

# ------------------------------------------------------------------------------
# 6. PHP2Shell (CVE-2026-109618 / 109619 exposure tool)
# ------------------------------------------------------------------------------
log_info "Step 6/6: Setting up PHP2Shell..."
cd "$REPO_DIR"

if [ ! -d "php2shell" ]; then
    git clone https://github.com/Masriyan/php2shell.git || log_warn "Failed to clone PHP2Shell repository."
    log_success "PHP2Shell cloned successfully."
else
    log_success "PHP2Shell already exists in repository."
fi

# ------------------------------------------------------------------------------
# 7. Create / Update Helper & Wrapper Scripts
# ------------------------------------------------------------------------------
log_info "Configuring wrapper scripts in repository..."

# --- wpscan-wrapper.sh ---
cat > "$REPO_DIR/wpscan-wrapper.sh" << 'EOF'
#!/bin/bash
# wpscan-wrapper.sh - Run WPScan with API token

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

shift || true
$WPSCAN_CMD --url "$URL" \
    --api-token "$WPSCAN_TOKEN" \
    --enumerate vp,vt,u,cb,dbe \
    --plugins-detection aggressive \
    --plugins-version-detection aggressive \
    -f cli-no-color \
    -o "wpscan_$(date +%Y%m%d_%H%M%S).txt" "$@"
EOF
chmod +x "$REPO_DIR/wpscan-wrapper.sh"

# --- php2shell-wrapper.sh ---
cat > "$REPO_DIR/php2shell-wrapper.sh" << 'EOF'
#!/bin/bash
# php2shell-wrapper.sh - Wrapper script for PHP2Shell exposure checker

PHP2SHELL_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/php2shell/php2shell.py"

if [ ! -f "$PHP2SHELL_SCRIPT" ]; then
    echo "Error: php2shell.py not found at $PHP2SHELL_SCRIPT"
    echo "Please clone the repository first: git clone https://github.com/Masriyan/php2shell.git"
    exit 1
fi

URL="$1"
if [ -z "$URL" ]; then
    echo "Usage: $0 <url> [--no-safe-mode]"
    echo "Example: $0 https://example.com/blog/"
    echo "Example: $0 https://example.com/blog/ --no-safe-mode"
    exit 1
fi

if [ "$2" == "--no-safe-mode" ]; then
    echo "Running PHP2Shell in ACTIVE mode (version disclosure checks)..."
    python3 "$PHP2SHELL_SCRIPT" --no-safe-mode "$URL"
else
    echo "Running PHP2Shell in SAFE mode (passive checks only)..."
    python3 "$PHP2SHELL_SCRIPT" "$URL"
fi
EOF
chmod +x "$REPO_DIR/php2shell-wrapper.sh"

# --- directory-fuzzer.sh ---
cat > "$REPO_DIR/directory-fuzzer.sh" << 'EOF'
#!/bin/bash
# directory-fuzzer.sh - Directory and file discovery with ffuf

T="${1:-}"
CUSTOM_WORDLIST="${2:-}"

if [ -z "$T" ]; then
    echo "Usage: $0 <target-url> [wordlist]"
    echo "Example: $0 https://example.com"
    exit 1
fi

# Locate wordlist
WORDLIST="$CUSTOM_WORDLIST"
if [ -z "$WORDLIST" ]; then
    for candidate in \
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" \
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" \
        "/usr/share/dirb/wordlists/common.txt"; do
        if [ -f "$candidate" ]; then
            WORDLIST="$candidate"
            break
        fi
    done
fi

if [ -z "$WORDLIST" ] || [ ! -f "$WORDLIST" ]; then
    echo "Error: Wordlist not found. Please provide a path as second argument."
    exit 1
fi

echo "Using wordlist: $WORDLIST"
echo "Measuring 404 response size..."
NOTFOUND_SIZE=$(curl -s "${T}/this-does-not-exist-12345" | wc -c)
echo "404 page size: ${NOTFOUND_SIZE} bytes"

echo "Starting directory/file discovery with ffuf..."
ffuf -u "${T}/FUZZ" \
    -w "$WORDLIST" \
    -mc 200,301,302,403 \
    -e .php,.bak,.old,.zip,.sql \
    -fs "$NOTFOUND_SIZE" \
    -t 20
EOF
chmod +x "$REPO_DIR/directory-fuzzer.sh"

# --- full-scan.sh ---
cat > "$REPO_DIR/full-scan.sh" << 'EOF'
#!/bin/bash
# full-scan.sh - Shell orchestrator for complete WordPress security scan

T="${1:-}"
WPSCAN_TOKEN="${WPSCAN_TOKEN:-}"

if [ -z "$T" ]; then
    echo "Usage: $0 <target-url>"
    echo "Example: $0 https://example.com/blog/"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "WordPress Security Scan Suite"
echo "Target: $T"
echo "=========================================="
echo ""

# 1. PHP2Shell
if [ -f "$SCRIPT_DIR/php2shell/php2shell.py" ]; then
    echo "[1/3] Running PHP2Shell vulnerability check..."
    python3 "$SCRIPT_DIR/php2shell/php2shell.py" --no-safe-mode "$T" || true
    echo ""
fi

# 2. WPScan
if [ -n "$WPSCAN_TOKEN" ]; then
    echo "[2/3] Running WPScan..."
    "$SCRIPT_DIR/wpscan-wrapper.sh" "$T" || true
    echo ""
else
    echo "[2/3] Skipping WPScan (WPSCAN_TOKEN not set). Set with: export WPSCAN_TOKEN='token'"
    echo ""
fi

# 3. Directory Fuzzer
if command -v ffuf &>/dev/null; then
    echo "[3/3] Running directory discovery..."
    "$SCRIPT_DIR/directory-fuzzer.sh" "$T" || true
    echo ""
fi

echo "=========================================="
echo "Scan complete! Check output files."
echo "=========================================="
EOF
chmod +x "$REPO_DIR/full-scan.sh"

# ------------------------------------------------------------------------------
# 8. Restore Non-Root Ownership (if script was run with sudo)
# ------------------------------------------------------------------------------
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    log_info "Ensuring workspace files are owned by user: $SUDO_USER..."
    chown -R "$SUDO_USER:$SUDO_USER" "$REPO_DIR" 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# 9. Verification Summary
# ------------------------------------------------------------------------------
echo ""
echo -e "${BOLD}${GREEN}====================================================${NC}"
echo -e "${BOLD}${GREEN}               Installation Summary                 ${NC}"
echo -e "${BOLD}${GREEN}====================================================${NC}"

# Check WPScan
if command_exists wpscan || [ -f "/opt/wpscan/wpscan.rb" ] || [ -f "/usr/local/bin/wpscan" ]; then
    log_success "WPScan: Available"
else
    log_warn "WPScan: Not detected (optional)"
fi

# Check ffuf
if command_exists ffuf; then
    log_success "ffuf: Available ($(ffuf -V 2>&1 | head -1))"
else
    log_warn "ffuf: Not detected (optional)"
fi

# Check Python requests
if python3 -c "import requests, urllib3" 2>/dev/null; then
    log_success "Python dependencies (requests, urllib3): Available"
else
    log_warn "Python dependencies: Incomplete"
fi

# Check PHP2Shell
if [ -f "$REPO_DIR/php2shell/php2shell.py" ]; then
    log_success "PHP2Shell: Ready ($REPO_DIR/php2shell/php2shell.py)"
else
    log_warn "PHP2Shell: Not cloned"
fi

# Check SecLists
if [ -f "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" ] || \
   [ -f "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" ]; then
    log_success "SecLists: Available"
else
    log_warn "SecLists: Not found"
fi

echo ""
echo -e "${BOLD}Next steps:${NC}"
echo "  1. Set WPScan token (optional for full scan):"
echo "     export WPSCAN_TOKEN='your_token_here'"
echo "  2. Run python scanner:"
echo "     python3 full-scan.py https://example.com/blog/"
echo "  3. Or run the wrapper scripts:"
echo "     ./full-scan.sh https://example.com/blog/"
echo "     ./php2shell-wrapper.sh https://example.com/blog/ --no-safe-mode"
echo ""
