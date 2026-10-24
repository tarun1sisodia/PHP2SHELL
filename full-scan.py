#!/usr/bin/env python3
"""
full-scan.py - Complete WordPress Security Scanner (Steps A-E)

A unified Python script that combines multiple security scanning tools:
- Step A: Cloudflare/server fingerprinting
- Step B: PHP version + phpinfo probe
- Step C: WPScan + plugin enumeration
- Step C2: readme.txt plugin brute
- Step D: Directory/File discovery (ffuf-style)

Usage:
    python3 full-scan.py https://example.com/blog/
"""

import argparse
import subprocess
import sys
import os
import re
import json
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse
import urllib.request
import urllib.error
import getpass


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_banner():
    banner = r"""
   ____  _   _ ____ ____  ____  _   _ _____ _     _  
  |  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | | 
  | |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | | 
  |  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___
  |_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____|
         P H P 2 S H E L L   ·   W O R D P R E S S   S C A N N E R
    CVE-2026-109618 / CVE-2026-109619  +  WPScan  +  ffuf
    """
    print(bcolors.OKCYAN + banner + bcolors.ENDC)


def run_command(cmd, capture_output=True, timeout=300):
    """Run a shell command and return the result."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def get_404_size(target_url):
    """Get the size of a 404 page for filtering."""
    print(bcolors.WARNING + "[*] Measuring 404 page size..." + bcolors.ENDC)
    not_found_url = urljoin(target_url, "/this-does-not-exist-12345")
    try:
        req = urllib.request.Request(not_found_url, headers={'User-Agent': 'full-scan/1.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read()
            size = len(content)
            print(bcolors.OKGREEN + f"[+] 404 page size: {size} bytes" + bcolors.ENDC)
            return size
    except urllib.error.HTTPError as e:
        if e.code == 404:
            content = e.read()
            size = len(content)
            print(bcolors.OKGREEN + f"[+] 404 page size: {size} bytes" + bcolors.ENDC)
            return size
        return 0
    except Exception as e:
        print(bcolors.FAIL + f"[-] Error getting 404 size: {e}" + bcolors.ENDC)
        return 0


def step_a_fingerprint(target_url, host):
    """Step A: Cloudflare/server fingerprinting."""
    print(bcolors.OKBLUE + "\n" + "="*60 + bcolors.ENDC)
    print(bcolors.OKBLUE + "[Step A] Server/Fingerprint Analysis" + bcolors.ENDC)
    print(bcolors.OKBLUE + "="*60 + bcolors.ENDC)
    
    print(bcolors.OKCYAN + "\n--- Root Headers ---" + bcolors.ENDC)
    cmd = f'curl -sSI "{target_url}/" | grep -iE "server|x-powered-by|cf-ray|cf-cache|x-litespeed|via|x-cache"'
    returncode, stdout, stderr = run_command(cmd)
    print(stdout if stdout else "(no output)")
    
    print(bcolors.OKCYAN + "\n--- Blog Headers ---" + bcolors.ENDC)
    cmd = f'curl -sSI "{target_url}/blog/" | grep -iE "server|x-powered-by|cf-ray|cf-cache|x-litespeed|via"'
    returncode, stdout, stderr = run_command(cmd)
    print(stdout if stdout else "(no output)")
    
    print(bcolors.OKCYAN + "\n--- /cdn-cgi/trace ---" + bcolors.ENDC)
    cmd = f'curl -sS "{target_url}/cdn-cgi/trace" | head -20'
    returncode, stdout, stderr = run_command(cmd)
    print(stdout if stdout else "(no output)")
    
    print(bcolors.OKCYAN + "\n--- DNS Resolution ---" + bcolors.ENDC)
    cmd = f'dig +short "{host}"'
    returncode, stdout, stderr = run_command(cmd)
    print(stdout if stdout else "(no output)")
    
    print(bcolors.OKCYAN + "\n--- AAAA Record ---" + bcolors.ENDC)
    cmd = f'dig +short "{host}" AAAA'
    returncode, stdout, stderr = run_command(cmd)
    print(stdout if stdout else "(no output)")
    
    return True


def step_b_php(target_url):
    """Step B: PHP version + phpinfo probe."""
    print(bcolors.OKBLUE + "\n" + "="*60 + bcolors.ENDC)
    print(bcolors.OKBLUE + "[Step B] PHP Version Detection" + bcolors.ENDC)
    print(bcolors.OKBLUE + "="*60 + bcolors.ENDC)
    
    print(bcolors.OKCYAN + "\n--- X-Powered-By Header ---" + bcolors.ENDC)
    cmd = f'curl -sSI "{target_url}/" | grep -i x-powered-by'
    returncode, stdout, stderr = run_command(cmd)
    print(stdout if stdout else "(no output)")
    
    print(bcolors.OKCYAN + "\n--- Probing phpinfo Candidates ---" + bcolors.ENDC)
    phpinfo_pages = ["phpinfo.php", "info.php", "_pi.php", "i.php", "pi.php", "test.php", "php.php"]
    for page in phpinfo_pages:
        cmd = f'curl -s -o /dev/null -w "%{{http_code}}" "{target_url}/{page}"'
        returncode, stdout, stderr = run_command(cmd)
        print(f"{page} -> {stdout.strip()}")
    
    print(bcolors.OKCYAN + "\n--- Probing Leak Files ---" + bcolors.ENDC)
    leak_files = [".env", ".git/HEAD", "wp-config.php.bak", "blog/wp-config.php.bak",
                  "blog/wp-content/debug.log", "blog/.env", "blog/.git/HEAD"]
    for f in leak_files:
        cmd = f'curl -s -o /dev/null -w "%{{http_code}}" "{target_url}/{f}"'
        returncode, stdout, stderr = run_command(cmd)
        print(f"{f} -> {stdout.strip()}")
    
    return True


def step_c_wpscan(target_url, api_token):
    """Step C: WPScan + plugin enumeration."""
    print(bcolors.OKBLUE + "\n" + "="*60 + bcolors.ENDC)
    print(bcolors.OKBLUE + "[Step C] WPScan + Plugin Enumeration" + bcolors.ENDC)
    print(bcolors.OKBLUE + "="*60 + bcolors.ENDC)
    
    wpscan_cmd = None
    if subprocess.run("which wpscan", shell=True, capture_output=True).returncode == 0:
        wpscan_cmd = "wpscan"
    elif Path("/opt/wpscan/wpscan.rb").exists():
        wpscan_cmd = "ruby /opt/wpscan/wpscan.rb"
    elif Path("/usr/local/bin/wpscan").exists():
        wpscan_cmd = "/usr/local/bin/wpscan"
    
    if not wpscan_cmd:
        print(bcolors.FAIL + "[-] WPScan not found. Skipping..." + bcolors.ENDC)
        return False
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"wpscan_{timestamp}.txt"
    
    print(bcolors.OKCYAN + f"\n--- Running WPScan (output: {output_file}) ---" + bcolors.ENDC)
    cmd = f'{wpscan_cmd} --url "{target_url}" --api-token "{api_token}" \\'
    cmd += ' --enumerate vp,vt,u,cb,dbe --plugins-detection aggressive \\'
    cmd += ' --plugins-version-detection aggressive -f cli-no-color -o ' + output_file
    returncode, stdout, stderr = run_command(cmd)
    print(stdout if stdout else "(no output)")
    
    print(bcolors.OKCYAN + "\n--- XML-RPC Users ---" + bcolors.ENDC)
    xmlrpc_cmd = f'''curl -s "{target_url}/xmlrpc.php" -d '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>x</string></value></param><param><value><string>x</string></value></param></params></methodCall>' | head -40'''
    returncode, stdout, stderr = run_command(xmlrpc_cmd)
    print(stdout if stdout else "(no output)")
    
    print(bcolors.OKCYAN + "\n--- REST API Users ---" + bcolors.ENDC)
    rest_cmd = f'curl -s "{target_url}/wp-json/wp/v2/users?per_page=100"'
    returncode, stdout, stderr = run_command(rest_cmd)
    print(stdout if stdout else "(no output)")
    
    print(bcolors.OKCYAN + "\n--- REST Routes (filtered) ---" + bcolors.ENDC)
    routes_cmd = f'curl -s "{target_url}/wp-json/" | grep -oE "yoast|search|user|comment|xmlrpc" | head -40'
    returncode, stdout, stderr = run_command(routes_cmd)
    print(stdout if stdout else "(no output)")
    
    return True


def step_c2_plugins(target_url):
    """Step C2: readme.txt plugin brute."""
    print(bcolors.OKBLUE + "\n" + "="*60 + bcolors.ENDC)
    print(bcolors.OKBLUE + "[Step C2] Plugin readme.txt Brute Force" + bcolors.ENDC)
    print(bcolors.OKBLUE + "="*60 + bcolors.ENDC)
    
    # Common plugins list
    plugins = [
        "akismet", "jetpack", "woocommerce", "contact-form-7", "wp-super-cache",
        "all-in-one-seo-pack", "yoast-seo", "gravity-forms", "elementor", "wpforms",
        "smush-image-compression", "regenerate-thumbnails", "rank-math-seo",
        "monsterinsights", "ithemes-security", "updraftplus", "backup-wp",
        "wp-rocket", "lazy-load", "imagify", "shortpixel-image-optimiser",
        "complianz-gdpr", "cookie-notice", "classic-editor"
    ]
    
    print(bcolors.OKCYAN + "\n--- Checking Plugin Versions via readme.txt ---" + bcolors.ENDC)
    found_plugins = []
    for plugin in plugins:
        cmd = f'curl -s "{target_url}/wp-content/plugins/{plugin}/readme.txt" | grep -i "Stable tag:"'
        returncode, stdout, stderr = run_command(cmd)
        if stdout:
            version = stdout.strip().replace("Stable tag: ", "").strip()
            print(f"{plugin} -> {version}")
            found_plugins.append((plugin, version))
    
    if not found_plugins:
        print("(no plugins found)")
    
    return True


def step_d_fuzzer(target_url):
    """Step D: Directory/File discovery using ffuf."""
    print(bcolors.OKBLUE + "\n" + "="*60 + bcolors.ENDC)
    print(bcolors.OKBLUE + "[Step D] Directory/File Discovery (ffuf)" + bcolors.ENDC)
    print(bcolors.OKBLUE + "="*60 + bcolors.ENDC)
    
    # Check if ffuf is available
    returncode, stdout, stderr = run_command("which ffuf")
    if returncode != 0:
        print(bcolors.FAIL + "[-] ffuf not found. Skipping..." + bcolors.ENDC)
        return False
    
    # Get 404 page size
    notfound_size = get_404_size(target_url)
    
    # Check wordlist candidates
    wordlist = None
    candidates = [
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/dirb/wordlists/common.txt"
    ]
    for c in candidates:
        if os.path.exists(c):
            wordlist = c
            break
            
    if not wordlist:
        print(bcolors.WARNING + "[-] No common wordlist found in /usr/share/seclists/ or /usr/share/wordlists/seclists/" + bcolors.ENDC)
        print(bcolors.WARNING + "[*] Skipping fuzzer..." + bcolors.ENDC)
        return False
    
    print(bcolors.OKCYAN + f"\n--- Running ffuf (wordlist: {wordlist}) ---" + bcolors.ENDC)
    cmd = f'ffuf -u "{target_url}/FUZZ" \\'
    cmd += f' -w {wordlist} \\'
    cmd += " -mc 200,301,302,403 \\"
    cmd += " -e .php,.bak,.old,.zip,.sql \\"
    cmd += f" -fs {notfound_size} \\"
    cmd += " -t 20"
    returncode, stdout, stderr = run_command(cmd, timeout=600)
    print(stdout if stdout else "(no output)")
    
    return True


def step_e_php2shell(target_url, no_safe_mode=False):
    """Step E: PHP2Shell vulnerability check."""
    print(bcolors.OKBLUE + "\n" + "="*60 + bcolors.ENDC)
    print(bcolors.OKBLUE + "[Step E] PHP2Shell Vulnerability Check" + bcolors.ENDC)
    print(bcolors.OKBLUE + "="*60 + bcolors.ENDC)
    
    script_path = Path(__file__).parent / "php2shell" / "php2shell.py"
    
    if not script_path.exists():
        print(bcolors.FAIL + f"[-] PHP2Shell script not found at {script_path}" + bcolors.ENDC)
        return False
    
    cmd = f"python3 {script_path}"
    if no_safe_mode:
        cmd += " --no-safe-mode"
    cmd += f" {target_url}"
    
    returncode, stdout, stderr = run_command(cmd)
    
    if returncode == 0:
        print(bcolors.OKGREEN + "[+] PHP2Shell completed" + bcolors.ENDC)
        print(stdout)
        return True
    else:
        print(bcolors.FAIL + f"[-] PHP2Shell failed with code {returncode}" + bcolors.ENDC)
        if stderr:
            print(stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Complete WordPress Security Scanner - Steps A-E",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 full-scan.py https://example.com/blog/
  python3 full-scan.py https://example.com/blog/ --no-safe-mode
  python3 full-scan.py https://example.com/blog/ --skip-step-a
        """
    )
    
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--no-safe-mode", action="store_true",
                        help="Enable active recon (version disclosure checks)")
    parser.add_argument("--skip-step-a", action="store_true", help="Skip Step A (fingerprint)")
    parser.add_argument("--skip-step-b", action="store_true", help="Skip Step B (PHP probe)")
    parser.add_argument("--skip-step-c", action="store_true", help="Skip Step C (WPScan)")
    parser.add_argument("--skip-step-c2", action="store_true", help="Skip Step C2 (plugin brute)")
    parser.add_argument("--skip-step-d", action="store_true", help="Skip Step D (fuzzer)")
    parser.add_argument("--skip-step-e", action="store_true", help="Skip Step E (PHP2Shell)")
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Validate URL
    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        print(bcolors.FAIL + "[-] Invalid URL. Please provide a valid URL with scheme (http/https)" + bcolors.ENDC)
        sys.exit(1)
    
    # Extract host from URL
    host = parsed.netloc
    if ":" in host:
        host = host.split(":")[0]
    
    print(bcolors.OKGREEN + f"[+] Target: {args.url}" + bcolors.ENDC)
    print(bcolors.OKGREEN + f"[+] Host: {host}" + bcolors.ENDC)
    print()
    
    # Prompt for WPScan token if not skipped
    api_token = None
    if not args.skip_step_c:
        print(bcolors.WARNING + "[*] WPScan requires an API token" + bcolors.ENDC)
        api_token = getpass.getpass("Enter WPScan API token: ").strip()
        if not api_token:
            print(bcolors.FAIL + "[-] API token is required for Step C" + bcolors.ENDC)
            sys.exit(1)
        print()
    
    # Run steps
    results = {
        "target": args.url,
        "timestamp": datetime.now().isoformat(),
        "steps": {}
    }
    
    # Step A: Fingerprint
    if not args.skip_step_a:
        results["steps"]["A"] = step_a_fingerprint(args.url, host)
        time.sleep(1)
    
    # Step B: PHP probe
    if not args.skip_step_b:
        results["steps"]["B"] = step_b_php(args.url)
        time.sleep(1)
    
    # Step C: WPScan
    if not args.skip_step_c and api_token:
        results["steps"]["C"] = step_c_wpscan(args.url, api_token)
        time.sleep(1)
    
    # Step C2: Plugin brute
    if not args.skip_step_c2:
        results["steps"]["C2"] = step_c2_plugins(args.url)
        time.sleep(1)
    
    # Step D: Fuzzer
    if not args.skip_step_d:
        results["steps"]["D"] = step_d_fuzzer(args.url)
        time.sleep(1)
    
    # Step E: PHP2Shell
    if not args.skip_step_e:
        results["steps"]["E"] = step_e_php2shell(args.url, no_safe_mode=args.no_safe_mode)
    
    # Summary
    print(bcolors.OKBLUE + "\n" + "="*60 + bcolors.ENDC)
    print(bcolors.OKBLUE + "SCAN SUMMARY" + bcolors.ENDC)
    print(bcolors.OKBLUE + "="*60 + bcolors.ENDC)
    
    for step, status in results["steps"].items():
        status_str = "COMPLETED" if status else "SKIPPED/FAILED"
        print(f"{bcolors.OKGREEN}[+] Step {step}: {status_str}{bcolors.ENDC}")
    
    print()


if __name__ == "__main__":
    main()
