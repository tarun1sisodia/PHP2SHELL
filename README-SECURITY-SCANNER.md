# WordPress Security Scanner Suite

A comprehensive WordPress security scanning suite that combines multiple tools for complete vulnerability assessment. Includes PHP2Shell (CVE-2026-109618/109619) checker, WPScan, directory fuzzer, and more.

## 📋 Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Scan Steps](#scan-steps)
- [Output Files](#output-files)
- [Troubleshooting](#troubleshooting)

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **Step A** | Server fingerprinting (headers, DNS, Cloudflare detection) |
| **Step B** | PHP version detection + phpinfo probe + leak file checks |
| **Step C** | WPScan (WordPress core + plugin enumeration) |
| **Step C2** | Plugin readme.txt brute force (version detection) |
| **Step D** | Directory/File discovery with ffuf |
| **Step E** | PHP2Shell vulnerability check (CVE-2026-109618/109619) |
| **Interactive Token** | WPScan API token entered interactively (no env vars needed) |

---

## 📦 Prerequisites

### Base System Requirements

**Debian/Ubuntu:**
```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install git curl wget python3 python3-pip python3-venv \
  dnsutils netcat-openbsd jq unzip build-essential golang-go
```

**Arch Linux:**
```bash
sudo pacman -S git curl wget python python-pip bind netcat jq unzip base-devel go
```

**Fedora:**
```bash
sudo dnf install git curl wget python3 python3-pip bind-utils nmap-ncat jq unzip @development-tools golang
```

### Tools to Install

#### 1. WPScan (Ruby)
```bash
sudo apt -y install ruby ruby-dev zlib1g-dev
sudo gem install wpscan
wpscan --version
```

#### 2. ffuf (Fast Fuzzer)
```bash
sudo apt -y install ffuf
# If not in repo:
go install github.com/ffuf/ffuf/v2@latest
sudo cp ~/go/bin/ffuf /usr/local/bin/
```

#### 3. SecLists (Wordlists)
```bash
sudo mkdir -p /usr/share/seclists
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists
# Verify:
ls /usr/share/seclists/Discovery/Web-Content/CMS/ | head
ls /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

#### 4. PHP2Shell (Python)
```bash
mkdir -p ~/php2shell && cd ~/php2shell
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install requests urllib3
git clone https://github.com/Masriyan/php2shell.git
```

#### 5. Optional Tools
```bash
sudo apt -y install whatweb nikto sqlmap gobuster
pip install httpie
```

---

## 🛠️ Installation

### Quick Setup (All-in-One)

Run the setup script to install all tools:

```bash
chmod +x setup-all-tools.sh
sudo ./setup-all-tools.sh
```

### Manual Setup

1. Clone this repository:
```bash
git clone <this-repo>
cd JOB-SENTRY
```

2. Install PHP2Shell:
```bash
git clone https://github.com/Masriyan/php2shell.git
```

3. Install SecLists:
```bash
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists
```

4. Verify installations:
```bash
which wpscan
which ffuf
python3 full-scan.py --help
```

---

## 📖 Usage

### Basic Usage

```bash
# Run full scan (all steps)
python3 full-scan.py https://example.com/blog/

# With active recon mode (version disclosure checks)
python3 full-scan.py https://example.com/blog/ --no-safe-mode

# Skip specific steps
python3 full-scan.py https://example.com/blog/ --skip-step-a --skip-step-d
```

### Step-by-Step Usage

```bash
# Step A: Fingerprint only
python3 full-scan.py https://example.com/blog/ --skip-step-b --skip-step-c --skip-step-c2 --skip-step-d --skip-step-e

# Step B: PHP probe only
python3 full-scan.py https://example.com/blog/ --skip-step-a --skip-step-c --skip-step-c2 --skip-step-d --skip-step-e

# Step C: WPScan only
python3 full-scan.py https://example.com/blog/ --skip-step-a --skip-step-b --skip-step-c2 --skip-step-d --skip-step-e

# Step D: Fuzzer only
python3 full-scan.py https://example.com/blog/ --skip-step-a --skip-step-b --skip-step-c --skip-step-c2 --skip-step-e
```

### Using Wrapper Scripts

```bash
# WPScan wrapper
./wpscan-wrapper.sh https://example.com/blog/

# PHP2Shell wrapper
./php2shell-wrapper.sh https://example.com/blog/ --no-safe-mode

# Directory fuzzer
./directory-fuzzer.sh https://example.com/blog/
```

---

## 🔍 Scan Steps

### Step A: Server/Fingerprint Analysis

Analyzes HTTP headers, DNS records, and Cloudflare detection.

**What it checks:**
- Server headers (`X-Powered-By`, `Server`)
- Cloudflare indicators (`CF-RAY`, `CF-Cache`)
- DNS resolution (A and AAAA records)
- CDN-cgi trace endpoint

**Example output:**
```
--- Root Headers ---
X-Powered-By: PHP/8.2.34
Server: hcdn

--- DNS Resolution ---
93.127.173.227
91.108.106.107
```

---

### Step B: PHP Version Detection

Probes for PHP version and vulnerable files.

**What it checks:**
- `X-Powered-By` header
- Common phpinfo pages (`phpinfo.php`, `info.php`, etc.)
- Leaked configuration files (`.env`, `.git/HEAD`, `wp-config.php.bak`)

**Example output:**
```
--- X-Powered-By Header ---
X-Powered-By: PHP/8.2.34

--- Probing phpinfo Candidates ---
phpinfo.php -> 404
info.php -> 404

--- Probing Leak Files ---
.env -> 404
.git/HEAD -> 404
wp-config.php.bak -> 404
```

---

### Step C: WPScan

Comprehensive WordPress security scan using WPScan API.

**What it checks:**
- WordPress core vulnerabilities
- Plugin vulnerabilities
- Theme vulnerabilities
- User enumeration
- Configuration issues

**Example output:**
```
--- Running WPScan ---
[i] WordPress found at: https://example.com/blog/
[+] WordPress version 6.7 identified
[+] 2 plugins found:
  - classic-editor (1.6.7)
  - akismet (5.3.5)
```

---

### Step C2: Plugin readme.txt Brute

Falls back to checking plugin versions via readme.txt files.

**What it checks:**
- Common plugins from SecLists
- Version disclosure via `Stable tag:` header

**Example output:**
```
--- Checking Plugin Versions via readme.txt ---
classic-editor -> 1.6.7
akismet -> 5.3.5
```

---

### Step D: Directory/File Discovery

Uses ffuf to discover hidden directories and files.

**What it checks:**
- Common directories
- Backup files (`.bak`, `.old`, `.zip`, `.sql`)
- PHP files

**Example output:**
```
--- Running ffuf ---
/index.php [Status: 200, Size: 12345, Words: 2345]
/admin [Status: 301, Size: 0, Words: 0]
/wp-config.php.bak [Status: 200, Size: 5678, Words: 123]
```

---

### Step E: PHP2Shell Vulnerability Check

Checks for CVE-2026-109618 and CVE-2026-109619 exposure.

**What it checks:**
- PHP version against fixed versions
- Vulnerability assessment based on CVE data
- Threat intelligence correlation (CISA KEV, EPSS)

**Example output:**
```
  ____  _   _ ____ ____  ____  _   _ _____ _     _  
 |  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | | 
 | |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | | 
 |  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___
 |_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____|

[VULN]  VULNERABLE  8.2.34  WordPress  https://example.com/blog/  
        PHP 8.2.34 < fixed 8.2.35 for this branch
```

---

## 📂 Output Files

| File | Description |
|------|-------------|
| `wpscan_YYYYMMDD_HHMMSS.txt` | WPScan results (timestamped) |
| `full-scan-summary.txt` | Complete scan summary (if saved) |

---

## 🐛 Troubleshooting

### WPScan Not Found
```bash
# Install WPScan
sudo apt install ruby ruby-dev zlib1g-dev
sudo gem install wpscan
```

### ffuf Not Found
```bash
# Install ffuf
sudo apt install ffuf
# or build from source
go install github.com/ffuf/ffuf/v2@latest
```

### SecLists Not Found
```bash
# Install SecLists
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists
```

### PHP2Shell Script Not Found
```bash
# Clone PHP2Shell
git clone https://github.com/Masriyan/php2shell.git
```

### Permission Denied
```bash
# Make scripts executable
chmod +x *.sh
chmod +x full-scan.py
```

---

## 📝 Example Workflow

```bash
# 1. Clone and setup
git clone <this-repo>
cd JOB-SENTRY
git clone https://github.com/Masriyan/php2shell.git
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists

# 2. Run full scan
python3 full-scan.py https://agrachiragtourandtravels.com/blog/

# 3. Review output
# - Check Step A for server configuration
# - Check Step B for PHP version
# - Check Step C for WordPress vulnerabilities
# - Check Step D for exposed files
# - Check Step E for PHP2Shell exposure
```

---

## ⚠️ Important Notes

1. **Authorized Testing Only**: Only scan websites you own or have explicit written permission to test.

2. **API Token Security**: The WPScan API token is entered interactively and never stored.

3. **Rate Limiting**: WPScan free tier has rate limits. Consider using `--skip-step-c` for quick scans.

4. **False Positives**: Some checks may produce false positives. Always verify findings manually.

5. **Legal Compliance**: Ensure you have proper authorization before scanning any target.

---

## 📄 License

This project is for educational and authorized security testing purposes only.

---

## 🙏 Credits

- **PHP2Shell**: [Masriyan](https://github.com/Masriyan/php2shell)
- **WPScan**: [WPScan Team](https://wpscan.com/)
- **ffuf**: [Joel Davis](https://github.com/ffuf/ffuf)
- **SecLists**: [Daniel Miessler](https://github.com/danielmiessler/SecLists)

---

## 📞 Support

For issues or questions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review the scan output for error messages
3. Verify all prerequisites are installed
