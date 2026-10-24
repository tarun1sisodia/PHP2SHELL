#!/usr/bin/env python3
"""
verify.py - Post-Run Verification for php2shell

Verifies the exploit result and checks for command execution output.
"""

import argparse
import sys
import re
import json
from datetime import datetime


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def verify_output(output, expected_cmd=None):
    """Verify if command output is present in the response."""
    results = {
        "command_executed": False,
        "output_found": False,
        "extracted_output": None,
        "details": []
    }
    
    # Check for common command outputs
    checks = [
        (r'uid=\d+', "UID found"),
        (r'gid=\d+', "GID found"),
        (r'root:x:\d+:\d+', "Root user found"),
        (r'www-data', "Web user found"),
        (r'apache', "Apache user found"),
        (r'nginx', "Nginx user found"),
        (r'login as:', "SSH prompt - possible shell"),
        (r'bash-', "Bash shell detected"),
        (r'PS >', "PowerShell detected"),
        (r'Command executed successfully', "PHP2Shell success message"),
        (r'PHP2Shell', "PHP2Shell marker found"),
    ]
    
    for pattern, description in checks:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            results["details"].append(description)
            if "uid=" in pattern or "gid=" in pattern:
                results["command_executed"] = True
                results["output_found"] = True
                results["extracted_output"] = match.group(0)
    
    # Try to extract command output
    if not results["extracted_output"]:
        # Look for output after command
        cmd_patterns = [
            r'Command:\s*(.+?)(?:\n|$)',
            r'Output:\s*(.+?)(?:\n|$)',
            r'uid=\d+.*?(.+?)(?:\n\n|$)',
        ]
        for pattern in cmd_patterns:
            match = re.search(pattern, output, re.DOTALL)
            if match:
                results["extracted_output"] = match.group(1).strip()
                break
    
    return results


def verify_session_poison(output, session_id):
    """Verify if session poison was successful."""
    if not session_id:
        return {"verified": False, "reason": "No session ID provided"}
    
    # Check if session poison marker is present
    if session_id in output:
        return {
            "verified": True,
            "reason": f"Session ID '{session_id}' found in response",
            "session_id": session_id
        }
    
    return {
        "verified": False,
        "reason": f"Session ID '{session_id}' not found in response",
        "session_id": session_id
    }


def analyze_response(response_text, response_code=200):
    """Analyze the full HTTP response."""
    analysis = {
        "status_code": response_code,
        "size": len(response_text),
        "headers_present": [],
        "suspicious_patterns": [],
        "php_errors": [],
        "shell_output": None
    }
    
    # Check for PHP errors
    php_error_patterns = [
        r'PHP Warning',
        r'PHP Error',
        r'PHP Fatal error',
        r'Warning:',
        r'Error:',
        r'Fatal error:'
    ]
    
    for pattern in php_error_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            analysis["php_errors"].append(pattern)
    
    # Check for shell output patterns
    shell_patterns = [
        r'uid=\d+\(.*?\) gid=\d+\(.*?\)',
        r'root:x:\d+:\d+',
        r'www-data:x:\d+:\d+',
        r'apache:x:\d+:\d+',
        r'nginx:x:\d+:\d+',
        r'login as:',
        r'bash-[0-9]',
        r'PS >',
        r'Command executed successfully',
        r'PHP2Shell'
    ]
    
    for pattern in shell_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            analysis["shell_output"] = pattern
    
    return analysis


def verify_exploit(result_file=None, result_dict=None, cmd=None):
    """Verify exploit result from file or dict."""
    if result_file:
        with open(result_file, 'r') as f:
            result = json.load(f)
    elif result_dict:
        result = result_dict
    else:
        return None
    
    verification = {
        "target": result.get("target", "unknown"),
        "timestamp": result.get("timestamp", "unknown"),
        "php_version": result.get("php_version", "unknown"),
        "session_id": result.get("session_id", "unknown"),
        "command": cmd or result.get("command", "id"),
        "output": result.get("output", ""),
        "ip": result.get("ip", "unknown"),
        "verification": {}
    }
    
    # Verify command execution
    output = result.get("output", "")
    verify_result = verify_output(output, cmd)
    verification["verification"]["command_execution"] = verify_result
    
    # Verify session poison
    session_verify = verify_session_poison(output, result.get("session_id"))
    verification["verification"]["session_poison"] = session_verify
    
    # Analyze response
    response_analysis = analyze_response(output)
    verification["verification"]["response_analysis"] = response_analysis
    
    # Overall verdict
    if verify_result["command_executed"] and session_verify["verified"]:
        verification["verdict"] = "SUCCESS"
        verification["message"] = "Exploit successful - command executed"
    elif verify_result["command_executed"]:
        verification["verdict"] = "PARTIAL"
        verification["message"] = "Command executed but session poison unclear"
    elif session_verify["verified"]:
        verification["verdict"] = "PARTIAL"
        verification["message"] = "Session poison successful but no command output"
    else:
        verification["verdict"] = "FAILED"
        verification["message"] = "Exploit failed - no evidence of execution"
    
    return verification


def main():
    parser = argparse.ArgumentParser(
        description="php2shell Verify - Post-Run Verification"
    )
    parser.add_argument("--file", "-f", help="JSON result file to verify")
    parser.add_argument("--output", "-o", help="Command output to verify")
    parser.add_argument("--cmd", "-c", default="id", help="Expected command (default: id)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    
    args = parser.parse_args()
    
    if args.file:
        result = verify_exploit(result_file=args.file, cmd=args.cmd)
    elif args.output:
        result = verify_exploit(result_dict={"output": args.output, "command": args.cmd}, cmd=args.cmd)
    else:
        parser.print_help()
        return 1
    
    if not result:
        print(f"{bcolors.FAIL}[-] No result to verify{bcolors.ENDC}")
        return 1
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{bcolors.OKBLUE}{'='*60}{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}Exploit Verification Results{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}{'='*60}{bcolors.ENDC}")
        
        print(f"\n{bcolors.BOLD}Target:{bcolors.ENDC} {result['target']}")
        print(f"{bcolors.BOLD}PHP Version:{bcolors.ENDC} {result['php_version']}")
        print(f"{bcolors.BOLD}Command:{bcolors.ENDC} {result['command']}")
        print(f"{bcolors.BOLD}IP:{bcolors.ENDC} {result['ip']}")
        print(f"{bcolors.BOLD}Timestamp:{bcolors.ENDC} {result['timestamp']}")
        
        print(f"\n{bcolors.BOLD}Verification:{bcolors.ENDC}")
        for key, value in result['verification'].items():
            print(f"  {bcolors.BOLD}{key}:{bcolors.ENDC}")
            if isinstance(value, dict):
                for k, v in value.items():
                    if isinstance(v, list):
                        print(f"    {k}: {', '.join(v) if v else '(none)'}")
                    else:
                        print(f"    {k}: {v}")
        
        print(f"\n{bcolors.BOLD}Verdict:{bcolors.ENDC}")
        if result['verdict'] == "SUCCESS":
            print(f"  {bcolors.OKGREEN}[+] {result['verdict']}{bcolors.ENDC}")
            print(f"  {bcolors.OKGREEN}    {result['message']}{bcolors.ENDC}")
        elif result['verdict'] == "PARTIAL":
            print(f"  {bcolors.WARNING}[!] {result['verdict']}{bcolors.ENDC}")
            print(f"  {bcolors.WARNING}    {result['message']}{bcolors.ENDC}")
        else:
            print(f"  {bcolors.FAIL}[-] {result['verdict']}{bcolors.ENDC}")
            print(f"  {bcolors.FAIL}    {result['message']}{bcolors.ENDC}")
        
        if result['output']:
            print(f"\n{bcolors.BOLD}Output:{bcolors.ENDC}")
            # Extract and highlight command output
            output = result['output']
            if len(output) > 2000:
                output = output[:2000] + "\n... (truncated)"
            print(output)
    
    return 0 if result['verdict'] == "SUCCESS" else 1


if __name__ == "__main__":
    sys.exit(main())
