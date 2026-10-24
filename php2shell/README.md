# php2shell - CVE-2026-109618 / CVE-2026-109619 Exploit

A Python-based exploit for the PHP session upload progress vulnerabilities that can lead to remote code execution.

## ⚠️ Disclaimer

**This tool is for educational and authorized testing purposes only.**

- Unauthorized testing of systems you don't own is illegal
- The author is not responsible for misuse of this tool
- Always obtain proper authorization before testing

## Table of Contents

- [Overview](#overview)
- [Vulnerabilities](#vulnerabilities)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Files](#files)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

php2shell exploits two related PHP vulnerabilities (CVE-2026-109618 and CVE-2026-109619) that affect the session upload progress feature. When properly configured, these vulnerabilities can lead to remote code execution through:

1. Session poisoning via upload progress
2. Heap spray to reallocate freed memory
3. LFI/Include to load poisoned session

## Vulnerabilities

### CVE-2026-109618 (OOM Path)
When PHP hits `memory_limit` during multipart form parsing, freed `zval` structures are not properly cleaned up, creating a dangling pointer.

### CVE-2026-109619 (UAF Path)
After freeing `zval` structures, the attacker can spray the heap with controlled data to reallocate the freed chunk, leading to code execution when the session is loaded.

## Requirements

### PHP Configuration
- `session.upload_progress.enabled = On` (default)
- `session.upload_progress.min_freq <= 0.1` (default)
- `memory_limit` must be finite (not `-1`)

### Vulnerable PHP Versions
- PHP 5.x, 7.x (all versions)
- PHP 8.0.x, 8.1.x (all versions)
- PHP 8.2.x < 8.2.35
- PHP 8.3.x < 8.3.36
- PHP 8.4.x < 8.4.27
- Python 8.5.x < 8.5.12

### Python Dependencies
```bash
pip install -r requirements.txt
```

## Installation

```bash
git clone https://github.com/tarun1sisodia/php2shell.git
cd php2shell
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python3 php2shell.py <url> [options]
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `url` | Target URL | Required |
| `--path` | Path to include() sink | `/index.php` |
| `--lfi` | LFI payload for include | `/index.php` |
| `--param` | Parameter name for LFI | `page` |
| `--cmd` | Command to execute | `id` |
| `--port` | Port override | Auto-detect |
| `--host-header` | Override Host header | None |
| `--sid` | Session ID | Auto-generate |
| `--spray` | Heap spray count | `149` |
| `--spray-size` | Bytes per spray field | `288` |
| `--chunked` | Use chunked transfer | Disabled |
| `--force` | Skip precondition checks | Disabled |
| `--timeout` | Request timeout | `30` |
| `--json-out` | Output JSON file | None |
| `--verbose` | Show full response | Disabled |

## Examples

### Basic Exploit

```bash
python3 php2shell.py https://example.com --path /index.php --lfi /index.php --param page --cmd id
```

### With Custom Session ID

```bash
python3 php2shell.py https://example.com --sid abc123def456 --cmd "whoami"
```

### Bypassing CDN (Direct Origin Connection)

```bash
python3 php2shell.py https://192.168.1.100 --host-header example.com --path /index.php --cmd id
```

### Using Chunked Transfer

```bash
python3 php2shell.py https://example.com --chunked --path /index.php --cmd id
```

### Save Results to JSON

```bash
python3 php2shell.py https://example.com --path /index.php --json-out results.json
```

### Full Reconnaissance

```bash
# Phase A: Fingerprint
python3 recon.py https://example.com --json --output recon.json

# Check if target is ready
cat recon.json | jq '.go'

# If go is true, run exploit
python3 php2shell.py https://example.com --path /index.php --lfi /index.php --param page --cmd id

# Verify results
python3 verify.py --file results.json
```

## Files

```
php2shell/
├── php2shell.py          # Main exploit script
├── recon.py              # Phase A fingerprint helper
├── verify.py             # Post-run verification
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── wordlists/
│   └── wp-plugins.found # WordPress plugin names
└── docs/
    ├── php2shell-theory.md      # Technical theory
    └── cve-2026-109618-109619.md # CVE details
```

## Testing

### Step 1: Reconnaissance

Run `recon.py` to verify preconditions:

```bash
python3 recon.py https://example.com
```

Look for:
r
- `go: true` - Target is ready for exploitation
- `go: false` - Precondition check failed (see reason)

### Step 2: Exploit

If reconnaissance shows `go: true`:

```bash
python3 php2shell.py https://example.com --path /index.php --lfi /index.php --param page --cmd id
```

### Step 3: Verification

```bash
python3 verify.py --file results.json
```

## Troubleshooting

### "phpinfo() not found"

Run `recon.py` to check available PHP info sources. If not found, you may need to:
- Look for alternative paths (e.g., `/blog/phpinfo.php`)
- Check if the server uses a different PHP configuration

### "session.upload_progress.enabled is not On"

The target PHP configuration doesn't have session upload progress enabled. This exploit won't work without it.

### "No command output"

Possible causes:
1. **CDN buffering**: The CDN is buffering POST bodies, killing the sub-second stall. Try `--host-header` to connect directly to origin.
2. **Wrong spray count**: Try different spray counts: `--spray 100`, `--spray 150`, `--spray 200`
3. **Wrong include sink**: Verify the target PHP file actually includes user-controlled input

### "Connection refused"

- Check if the target is reachable
- Verify the port is correct
- Check firewall rules

### "SSL certificate verify failed"

Use `--force` to skip certificate verification (not recommended for production):

```bash
python3 php2shell.py https://example.com --force
```

## PHP Version Table

| PHP Version | Vulnerable | Patched |
|-------------|------------|---------|
| 5.x | ✅ Yes | N/A |
| 6.x | ✅ Yes | N/A |
| 7.x | ✅ Yes | N/A |
| 8.0.x | ✅ Yes | N/A |
| 8.1.x | ✅ Yes | N/A |
| 8.2.x | ✅ Yes | < 8.2.35 |
| 8.3.x | ✅ Yes | < 8.3.36 |
| 8.4.x | ✅ Yes | < 8.4.27 |
| 8.5.x | ✅ Yes | < 8.5.12 |

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Developed for educational and authorized security testing purposes.

## Acknowledgments

- PHP Security Team for identifying and patching these vulnerabilities
- Security researchers who discovered the exploitation techniques
