#!/usr/bin/env python3
"""
recon.py - Phase A Fingerprint Helper for php2shell

Performs comprehensive reconnaissance on the target to determine:
- Server stack (Apache/LiteSpeed/Nginx/Cloudflare)
- PHP version and configuration
- Available sinks for LFI
- Precondition verification
"""

import argparse
import sys
import re
import json
import time
from datetime import datetime
import requests
from urllib.parse import urlparse, urljoin


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def fetch_headers(url, timeout=10):
    """Fetch response headers."""
    try:
        r = requests.head(url, timeout=timeout, verify=False, allow_redirects=True)
        return dict(r.headers), r.status_code
    except Exception as e:
        return {}, 0


def probe_phpinfo(host, path="/", tls=True, port=443):
    """Probe for phpinfo() pages."""
    candidates = ["phpinfo.php", "info.php", "_pi.php", "i.php", "php.php", "test.php"]
    results = {}
    
    for candidate in candidates:
        url = f"{'https' if tls else 'http'}://{host}:{port}{path.rstrip('/')}/{candidate}"
        try:
            r = requests.get(url, timeout=10, verify=False)
            if "PHP Version" in r.text:
                results[candidate] = {
                    "status": r.status_code,
                    "found": True,
                    "size": len(r.content)
                }
                return results[candidate], r.text
        except:
            pass
        results[candidate] = {"status": 0, "found": False}
    
    return None, None


def probe_leak_files(host, path="/", tls=True, port=443):
    """Probe for sensitive leak files."""
    leak_files = [
        ".env",
        ".git/HEAD",
        "wp-config.php.bak",
        "blog/wp-config.php.bak",
        "blog/wp-content/debug.log",
        "blog/.env",
        "blog/.git/HEAD",
        "config.php.bak",
        ".htaccess",
        "phpinfo.php",
        "info.php"
    ]
    
    results = {}
    for f in leak_files:
        url = f"{'https' if tls else 'http'}://{host}:{port}{path.rstrip('/')}/{f}"
        try:
            r = requests.get(url, timeout=10, verify=False)
            results[f] = {
                "status": r.status_code,
                "size": len(r.content),
                "exists": r.status_code == 200
            }
        except:
            results[f] = {"status": 0, "size": 0, "exists": False}
    
    return results


def fetch_sitemap(host, path="/", tls=True, port=443):
    """Fetch and parse sitemap.xml."""
    sitemap_urls = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.php"]
    
    for sitemap in sitemap_urls:
        url = f"{'https' if tls else 'http'}://{host}:{port}{path.rstrip('/')}{sitemap}"
        try:
            r = requests.get(url, timeout=10, verify=False)
            if r.status_code == 200:
                # Extract URLs from sitemap
                urls = re.findall(r'<loc>([^<]+)</loc>', r.text)
                return urls
        except:
            pass
    
    return []


def fetch_wp_json(host, path="/", tls=True, port=443):
    """Fetch WordPress REST API endpoints."""
    endpoints = {
        "wp-json": None,
        "wp/v2/users": None,
        "wp/v2/posts": None,
        "wp/v2/pages": None,
        "wp/v2/taxonomies": None,
        "wp/v2/categories": None,
        "wp/v2/tags": None
    }
    
    for endpoint in endpoints.keys():
        url = f"{'https' if tls else 'http'}://{host}:{port}{path.rstrip('/')}/{endpoint}"
        try:
            r = requests.get(url, timeout=10, verify=False)
            endpoints[endpoint] = {
                "status": r.status_code,
                "size": len(r.content),
                "available": r.status_code == 200
            }
        except:
            endpoints[endpoint] = {"status": 0, "size": 0, "available": False}
    
    return endpoints


def detect_cdn(headers):
    """Detect if CDN/WAF is in front."""
    cdn_indicators = {
        "cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "akamai": ["x-akamai", "x-akamai-origin-host"],
        "fastly": ["x-served-by", "x-cache"],
        "aws-cloudfront": ["x-amz-cf-pop", "x-cache"],
        "mod_security": ["mod_security"]
    }
    
    detected = []
    headers_str = str(headers).lower()
    
    for cdn, indicators in cdn_indicators.items():
        for indicator in indicators:
            if indicator.lower() in headers_str:
                detected.append(cdn)
                break
    
    return detected


def parse_phpinfo_from_html(html):
    """Parse PHP version from phpinfo() HTML."""
    match = re.search(r'<h1[^>]*>PHP Version\s*([^<]+)</h1>', html)
    if match:
        return match.group(1).strip()
    return None


def run_recon(target_url):
    """Run full reconnaissance on target."""
    parsed = urlparse(target_url)
    host = parsed.netloc
    base_path = parsed.path.rstrip('/')
    
    tls = parsed.scheme == 'https'
    port = parsed.port or (443 if tls else 80)
    
    print(f"{bcolors.OKBLUE}[*] Starting reconnaissance on {target_url}{bcolors.ENDC}")
    print(f"    Host: {host}, Port: {port}, TLS: {tls}")
    
    result = {
        "target": target_url,
        "host": host,
        "port": port,
        "tls": tls,
        "timestamp": datetime.now().isoformat(),
        "server_stack": {},
        "php_info": {},
        "sinks": [],
        "preconditions": {},
        "cdn": [],
        "wp_info": {},
        "leak_files": {},
        "go": False,
        "reason": ""
    }
    
    # 1. Root headers
    print(f"{bcolors.OKBLUE}[*] Fetching root headers...{bcolors.ENDC}")
    headers, status = fetch_headers(f"{'https' if tls else 'http'}://{host}:{port}{base_path}/")
    result["server_stack"]["root_headers"] = headers
    result["server_stack"]["root_status"] = status
    
    # Detect CDN
    result["cdn"] = detect_cdn(headers)
    if result["cdn"]:
        print(f"{bcolors.WARNING}[!] CDN detected: {', '.join(result['cdn'])}{bcolors.ENDC}")
    
    # 2. Blog headers (if different path)
    if base_path != "/":
        print(f"{bcolors.OKBLUE}[*] Fetching blog headers...{bcolors.ENDC}")
        blog_headers, blog_status = fetch_headers(f"{'https' if tls else 'http'}://{host}:{port}{base_path}/")
        result["server_stack"]["blog_headers"] = blog_headers
        result["server_stack"]["blog_status"] = blog_status
    
    # 3. Probe phpinfo
    print(f"{bcolors.OKBLUE}[*] Probing phpinfo()...{bcolors.ENDC}")
    phpinfo_result, phpinfo_html = probe_phpinfo(host, base_path, tls, port)
    result["php_info"]["probe"] = phpinfo_result
    
    if phpinfo_result:
        result["php_info"]["version"] = parse_phpinfo_from_html(phpinfo_html)
        result["php_info"]["source"] = phpinfo_result.get("source", "unknown")
        
        # Parse phpinfo for directives
        for line in phpinfo_html.split('\n'):
            if 'memory_limit' in line.lower():
                match = re.search(r'<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>', line)
                if match:
                    result["php_info"]["memory_limit"] = match.group(2).strip()
            if 'session.upload_progress.enabled' in line.lower():
                match = re.search(r'<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>', line)
                if match:
                    result["php_info"]["session_upload_progress_enabled"] = match.group(2).strip()
        
        print(f"{bcolors.OKGREEN}[+] Found phpinfo at: {phpinfo_result}{bcolors.ENDC}")
    
    # 4. Probe leak files
    print(f"{bcolors.OKBLUE}[*] Probing leak files...{bcolors.ENDC}")
    result["leak_files"] = probe_leak_files(host, base_path, tls, port)
    
    # 5. Fetch sitemap
    print(f"{bcolors.OKBLUE}[*] Fetching sitemap...{bcolors.ENDC}")
    sitemap_urls = fetch_sitemap(host, base_path, tls, port)
    result["sitemap_urls"] = sitemap_urls
    
    # 6. Find PHP sinks from sitemap
    php_sinks = [u for u in sitemap_urls if u.endswith('.php')]
    result["sinks"] = php_sinks[:20]  # Limit to first 20
    
    # 7. WordPress info
    print(f"{bcolors.OKBLUE}[*] Checking WordPress endpoints...{bcolors.ENDC}")
    result["wp_info"] = fetch_wp_json(host, base_path, tls, port)
    
    # 8. Check for wp-login.php
    login_url = f"{'https' if tls else 'http'}://{host}:{port}{base_path}/wp-login.php"
    try:
        r = requests.get(login_url, timeout=10, verify=False)
        result["wp_info"]["wp_login"] = {"status": r.status_code, "exists": r.status_code == 200}
    except:
        result["wp_info"]["wp_login"] = {"status": 0, "exists": False}
    
    # 9. Determine go/no-go
    print(f"{bcolors.OKBLUE}[*] Checking preconditions...{bcolors.ENDC}")
    
    issues = []
    
    # Check PHP version
    if not result["php_info"].get("version"):
        issues.append("phpinfo() not found - cannot verify PHP version")
    else:
        version = result["php_info"]["version"]
        match = re.search(r'(\d+)\.(\d+)\.(\d+)', version)
        if match:
            major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
            if major == 8:
                if minor == 2 and patch >= 35:
                    issues.append(f"PHP {version} may be patched (need < 8.2.35)")
                elif minor == 3 and patch >= 36:
                    issues.append(f"PHP {version} may be patched (need < 8.3.36)")
                elif minor == 4 and patch >= 27:
                    issues.append(f"PHP {version} may be patched (need < 8.4.27)")
                elif minor == 5 and patch >= 12:
                    issues.append(f"PHP {version} may be patched (need < 8.5.12)")
            elif major < 8:
                pass  # 5.x, 7.x are vulnerable
            else:
                issues.append(f"PHP {version} - unknown version")
    
    # Check session.upload_progress.enabled
    if result["php_info"].get("session_upload_progress_enabled") != "On":
        issues.append("session.upload_progress.enabled is not On")
    
    # Check memory_limit
    if not result["php_info"].get("memory_limit"):
        issues.append("memory_limit not found")
    
    # Check for PHP sinks
    if not result["sinks"]:
        issues.append("No PHP sinks found in sitemap")
    
    if issues:
        result["reason"] = "; ".join(issues)
        result["go"] = False
        print(f"{bcolors.WARNING}[-] Precondition check failed: {result['reason']}{bcolors.ENDC}")
    else:
        result["reason"] = "All preconditions met"
        result["go"] = True
        print(f"{bcolors.OKGREEN}[+] Target is ready for exploitation{bcolors.ENDC}")
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="php2shell Recon - Phase A Fingerprint Helper"
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--output", default=None, help="Output file")
    
    args = parser.parse_args()
    
    result = run_recon(args.url)
    
    if args.json or args.output:
        output = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"{bcolors.OKGREEN}[+] Results saved to {args.output}{bcolors.ENDC}")
        else:
            print(output)
    else:
        # Human-readable output
        print(f"\n{bcolors.OKBLUE}{'='*60}{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}Reconnaissance Results{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}{'='*60}{bcolors.ENDC}")
        
        print(f"\n{bcolors.BOLD}Target:{bcolors.ENDC} {result['target']}")
        print(f"{bcolors.BOLD}Server Stack:{bcolors.ENDC}")
        for key, value in result.get('server_stack', {}).items():
            if isinstance(value, dict):
                for k, v in value.items():
                    print(f"  {k}: {v}")
        
        print(f"\n{bcolors.BOLD}PHP Info:{bcolors.ENDC}")
        for key, value in result.get('php_info', {}).items():
            print(f"  {key}: {value}")
        
        print(f"\n{bcolors.BOLD}CDN/WAF:{bcolors.ENDC} {', '.join(result['cdn']) if result['cdn'] else 'None detected'}")
        
        print(f"\n{bcolors.BOLD}PHP Sinks Found:{bcolors.ENDC} {len(result['sinks'])}")
        for sink in result['sinks'][:10]:
            print(f"  - {sink}")
        if len(result['sinks']) > 10:
            print(f"  ... and {len(result['sinks']) - 10} more")
        
        print(f"\n{bcolors.BOLD}Leak Files:{bcolors.ENDC}")
        for f, info in result.get('leak_files', {}).items():
            if info.get('exists'):
                print(f"  {bcolors.OKGREEN}[+] {f}{bcolors.ENDC}")
            elif info.get('status') == 403:
                print(f"  {bcolors.WARNING}[?] {f} (403 - exists but blocked){bcolors.ENDC}")
        
        print(f"\n{bcolors.BOLD}WordPress REST API:{bcolors.ENDC}")
        for endpoint, info in result.get('wp_info', {}).items():
            if isinstance(info, dict) and info.get('available'):
                print(f"  {bcolors.OKGREEN}[+] {endpoint}{bcolors.ENDC}")
        
        print(f"\n{bcolors.BOLD}Decision:{bcolors.ENDC}")
        if result['go']:
            print(f"  {bcolors.OKGREEN}[+] GO - Target is vulnerable{bcolors.ENDC}")
            print(f"  {bcolors.OKGREEN}    {result['reason']}{bcolors.ENDC}")
        else:
            print(f"  {bcolors.FAIL}[!] NO-GO - Cannot exploit{bcolors.ENDC}")
            print(f"  {bcolors.FAIL}    {result['reason']}{bcolors.ENDC}")
    
    return 0 if result.get('go', False) else 1


if __name__ == "__main__":
    sys.exit(main())
