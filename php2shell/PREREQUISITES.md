# Prerequisites for php2shell

This guide contains verified installation commands and direct download links for all required tools and dependencies across Linux, macOS, and Windows.

---

## 1. Python Dependencies

The scanner and recon scripts require Python 3 and the `requests` and `urllib3` packages.

### Option A: Via System Package Manager (Debian / Ubuntu / Kali)
*Recommended for modern Linux to avoid PEP 668 `externally-managed-environment` errors:*
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-requests python3-urllib3
```

### Option B: Via Python Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r php2shell/requirements.txt
```

### Option C: Direct Pip Install
```bash
pip install requests urllib3 --break-system-packages
```

---

## 2. WPScan (WordPress Vulnerability Scanner)

WPScan requires Ruby and native C build libraries (`ruby-dev`, `libcurl4-openssl-dev`, `libffi-dev`) to compile native gems.

### Install Ruby and Build Dependencies

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install -y ruby-full ruby-dev build-essential zlib1g-dev libcurl4-openssl-dev libffi-dev
```

**macOS (Homebrew):**
```bash
brew install ruby
```

**Windows:**
Download and install the Ruby+Devkit package from: [https://rubyinstaller.org/](https://rubyinstaller.org/)

### Install WPScan

**Via RubyGems (Recommended for Ubuntu/Debian/macOS):**
```bash
sudo gem install wpscan
```

**Via APT (Kali Linux / Parrot OS):**
```bash
sudo apt install -y wpscan
```

**From Source (Alternative):**
```bash
sudo git clone https://github.com/wpscanteam/wpscan.git /opt/wpscan
(
    cd /opt/wpscan
    sudo gem install bundler --no-document
    sudo bundle install --without test
    sudo ln -sf /opt/wpscan/wpscan.rb /usr/local/bin/wpscan
)
```

---

## 3. ffuf (Fast Web Fuzzer)

### Option A: Via Package Manager (Easiest)

**Kali Linux / Debian Sid / Ubuntu 24.04+:**
```bash
sudo apt install -y ffuf
```

**macOS (Homebrew):**
```bash
brew install ffuf
```

### Option B: Precompiled Official Release Binaries (v2.3.0)

**Linux (x86_64 / amd64):**
```bash
curl -fSL "https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_linux_amd64.tar.gz" | sudo tar -xz -C /usr/local/bin ffuf
sudo chmod +x /usr/local/bin/ffuf
```

**Linux (ARM64 / aarch64):**
```bash
curl -fSL "https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_linux_arm64.tar.gz" | sudo tar -xz -C /usr/local/bin ffuf
sudo chmod +x /usr/local/bin/ffuf
```

**macOS (Intel - x86_64):**
```bash
curl -fSL "https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_macOS_amd64.tar.gz" | sudo tar -xz -C /usr/local/bin ffuf
sudo chmod +x /usr/local/bin/ffuf
```

**macOS (Apple Silicon M1/M2/M3/M4 - ARM64):**
```bash
curl -fSL "https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_macOS_arm64.tar.gz" | sudo tar -xz -C /usr/local/bin ffuf
sudo chmod +x /usr/local/bin/ffuf
```

**Windows:**
Download ZIP from: [https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_windows_amd64.zip](https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_windows_amd64.zip)

### Option C: Via Go (Alternative)
```bash
go install github.com/ffuf/ffuf/v2@latest
sudo cp ~/go/bin/ffuf /usr/local/bin/
```

---

## 4. SecLists (Discovery Wordlists)

The directory fuzzer searches for `directory-list-2.3-medium.txt`.

**Clone via Git (Recommended, shallow clone):**
```bash
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

**On Kali Linux:**
```bash
sudo apt install -y seclists
# Create symlink so /usr/share/seclists points to Kali wordlists:
sudo ln -sfn /usr/share/wordlists/seclists /usr/share/seclists
```

---

## 5. Automated Setup Scripts

Instead of installing manually, you can run the automated all-in-one setup script included in this repository:

```bash
chmod +x setup-all-tools.sh
./setup-all-tools.sh
```

---

## 6. Verification Checklist

Run these commands to verify that all tools are properly installed and accessible:

```bash
# 1. Python dependencies
python3 -c "import requests, urllib3; print('[✓] Python dependencies OK')"

# 2. WPScan binary
wpscan --version

# 3. ffuf binary
ffuf -V

# 4. SecLists directory wordlist
ls -lh /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# 5. Scanner script help
python3 full-scan.py --help
```

---

## 7. WPScan API Token (Optional but Recommended)

WPScan free tier provides 25 API requests/day for plugin and vulnerability database lookups:

1. Register a free account at [https://wpscan.com/api](https://wpscan.com/api).
2. Copy your API token from the user profile dashboard.
3. Export it in your environment:
   ```bash
   export WPSCAN_TOKEN='your_token_here'
   ```
