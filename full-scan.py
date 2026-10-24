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


def step_c2_plugin_brute(target_url):
    """Step C2: Plugin readme.txt brute force."""
    print(bcolors.OKBLUE + "\n" + "="*60 + bcolors.ENDC)
    print(bcolors.OKBLUE + "[Step C2] Plugin Version Detection" + bcolors.ENDC)
    print(bcolors.OKBLUE + "="*60 + bcolors.ENDC)
    
    # Common WordPress plugins
    plugins = [
        "akismet", "all-in-one-seo-pack", "contact-form-7", "elementor",
        "jetpack", "master-slider", "nextgen-gallery", "ninja-forms",
        "polylang", "regenerate-thumbnails", "seo-by-rank-math", "slider-wp",
        "theme-my-login", "updraftplus", "woocommerce", "wp-backup-plus",
        "wp-db-manager", "wp-super-cache", "wpml", "wpforms", "yoast-seo"
    ]
    
    print(bcolors.OKCYAN + "\n--- Probing Plugin Versions via readme.txt ---" + bcolors.ENDC)
    for plugin in plugins:
        readme_url = f"{target_url}/wp-content/plugins/{plugin}/readme.txt"
        cmd = f'curl -s -o /dev/null -w "%{{http_code}}" "{readme_url}"'
        returncode, stdout, stderr = run_command(cmd)
        if stdout.strip() == "200":
            cmd = f'curl -s "{readme_url}" | grep -i "stable tag"'
            returncode, stdout, stderr = run_command(cmd)
            print(f"{bcolors.OKGREEN}[+] {plugin}: {stdout.strip()}{bcolors.ENDC}")
        else:
            print(f"  {plugin} -> {stdout.strip()}")
    
    return True


def step_d_directory_fuzz(target_url):
    """Step D: Directory/File discovery with ffuf."""
    print(bcolors.OKBLUE + "\n" + "="*60 + bcolors.ENDC)
    print(bcolors.OKBLUE + "[Step D] Directory/File Discovery" + bcolors.ENDC)
    print(bcolors.OKBLUE + "="*60 + bcolors.ENDC)
    
    # Get 404 size
    not_found_size = get_404_size(target_url)
    
    print(bcolors.OKCYAN + f"\n--- Running ffuf (404 size: {not_found_size} bytes) ---" + bcolors.ENDC)
    
    cmd = f'ffuf -u "{target_url}/FUZZ" \\'
    cmd += ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \\'
    cmd += ' -mc 200,301,302,403 \\'
    cmd += ' -e .php,.bak,.old,.zip,.sql \\'
    cmd += f' -fs {not_found_size} \\'
    cmd += ' -t 20'
    
    returncode, stdout, stderr = run_command(cmd)
    print(stdout if stdout else "(no output)")
    
    return True


def step_e_php2shell_check(target_url):
    """Step E: PHP2Shell vulnerability check."""
    print(bcolors.OKBLUE + "\n" + "="*60 + bcolors.ENDC)
    print(bcolors.OKBLUE + "[Step E] PHP2Shell Vulnerability Check" + bcolors.ENDC)
    print(bcolors.OKBLUE + "="*60 + bcolors.ENDC)
    
    php2shell_script = Path("php2shell/php2shell.py")
    
    if not php2shell_script.exists():
        print(bcolors.WARNING + "[-] php2shell.py not found. Skipping..." + bcolors.ENDC)
        return False
    
    print(bcolors.OKCYAN + "\n--- Running PHP2Shell recon ---" + bcolors.ENDC)
    cmd = f'python3 php2shell/recon.py "{target_url}" --json'
    returncode, stdout, stderr = run_command(cmd)
    print(stdout if stdout else "(no output)")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Full WordPress Security Scanner (Steps A-E)"
    )
    parser.add_argument("url", help="Target URL (e.g., https://example.com/blog/)")
    parser.add_argument("--token", help="WPScan API token")
    parser.add_argument("--skip-a", action="store_true", help="Skip Step A")
    parser.add_argument("--skip-b", action="store_true", help="Skip Step B")
    parser.add_argument("--skip-c", action="store_true", help="Skip Step C (WPScan)")
    parser.add_argument("--skip-c2", action="store_true", help="Skip Step C2 (Plugin brute)")
    parser.add_argument("--skip-d", action="store_true", help="Skip Step D (Directory fuzz)")
    parser.add_argument("--skip-e", action="store_true", help="Skip Step E (PHP2Shell)")
    
    args = parser.parse_args()
    
    print_banner()
    
    parsed = urlparse(args.url)
    host = parsed.netloc
    base_path = parsed.path.rstrip('/')
    
    # Determine target URL (with or without /blog/)
    target_url = f"{parsed.scheme}://{host}"
    if base_path:
        target_url = f"{target_url}{base_path}"
    
    print(bcolors.OKBLUE + f"[*] Target: {target_url}" + bcolors.ENDC)
    print(bcolors.OKBLUE + f"[*] Host: {host}" + bcolors.ENDC)
    
    # Step A: Fingerprint
    if not args.skip_a:
        step_a_fingerprint(target_url, host)
    
    # Step B: PHP detection
    if not args.skip_b:
        step_b_php(target_url)
    
    # Step C: WPScan
    if not args.skip_c:
        if args.token:
            step_c_wpscan(target_url, args.token)
        else:
            print(bcolors.WARNING + "[-] WPScan token not provided. Skipping..." + bcolors.ENDC)
    
    # Step C2: Plugin brute
    if not args.skip_c2:
        step_c2_plugin_brute(target_url)
    
    # Step D: Directory fuzz
    if not args.skip_d:
        step_d_directory_fuzz(target_url)
    
    # Step E: PHP2Shell check
    if not args.skip_e:
        step_e_php2shell_check(target_url)
    
    print(bcolors.OKGREEN + "\n" + "="*60 + bcolors.ENDC)
    print(bcolors.OKGREEN + "Scan complete!" + bcolors.ENDC)
    print(bcolors.OKGREEN + "="*60 + bcolors.ENDC)


if __name__ == "__main__":
    main()
