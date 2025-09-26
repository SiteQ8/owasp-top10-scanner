#!/usr/bin/env python3
"""
OWASP Top 10 Security Scanner with Nmap Integration
Author: SiteQ8 (https://github.com/SiteQ8)
Contact: site@hotmail.com
Date: September 2025
Version: 1.0.0
Description: A comprehensive Python tool that scans for OWASP Top 10 vulnerabilities 
             using nmap for initial reconnaissance followed by targeted vulnerability checks

GitHub: https://github.com/SiteQ8
License: MIT License

DISCLAIMER: This tool is for authorized security testing only. 
           Users must obtain proper permission before scanning any systems.
"""

import sys
import json
import time
import threading
import subprocess
import re
import requests
import socket
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import argparse
import colorama
from colorama import Fore, Back, Style
import warnings

# Suppress SSL warnings for testing purposes
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

class OWASPTopTenScanner:
    """
    OWASP Top 10 Security Scanner with integrated Nmap reconnaissance
    """

    def __init__(self, target: str, port_range: str = "1-1000", output_file: str = None):
        self.target = target
        self.port_range = port_range
        self.output_file = output_file
        self.scan_results = {
            "target": target,
            "scan_timestamp": datetime.now().isoformat(),
            "nmap_results": {},
            "owasp_vulnerabilities": [],
            "summary": {}
        }
        self.open_ports = []
        self.web_ports = []
        self.services = {}

        # OWASP Top 10 2021 categories
        self.owasp_categories = {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design", 
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable and Outdated Components",
            "A07": "Identification and Authentication Failures",
            "A08": "Software and Data Integrity Failures",
            "A09": "Security Logging and Monitoring Failures",
            "A10": "Server-Side Request Forgery (SSRF)"
        }

        # Common payloads for testing
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            "1'; DROP TABLE users--"
        ]

        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]

        self.lfi_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/shadow",
            "C:\\windows\\system32\\config\\sam"
        ]

    def print_banner(self):
        """Print ASCII banner"""
        banner = f"""
{Fore.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║                OWASP Top 10 Security Scanner                  ║
║                   with Nmap Integration                       ║
║                                                               ║
║  Target: {self.target:<50} ║
║  Port Range: {self.port_range:<44} ║
║  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<42} ║
╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)

    def run_nmap_scan(self):
        """Run comprehensive nmap scan for host reconnaissance"""
        print(f"{Fore.YELLOW}[INFO] Starting Nmap reconnaissance...{Style.RESET_ALL}")

        try:
            # Basic port scan with service detection
            print(f"{Fore.BLUE}[NMAP] Running port scan and service detection...{Style.RESET_ALL}")
            cmd_basic = [
                "nmap", "-sS", "-sV", "-O", "--version-intensity", "5",
                "-p", self.port_range, self.target
            ]

            result_basic = subprocess.run(cmd_basic, capture_output=True, text=True, timeout=300)
            self.scan_results["nmap_results"]["basic_scan"] = result_basic.stdout

            # Parse open ports and services
            self._parse_nmap_output(result_basic.stdout)

            # Run NSE vulnerability scripts
            if self.open_ports:
                print(f"{Fore.BLUE}[NMAP] Running NSE vulnerability scripts...{Style.RESET_ALL}")
                port_list = ",".join(str(port) for port in self.open_ports)

                cmd_vuln = [
                    "nmap", "--script", "vuln,safe,auth,default", 
                    "-p", port_list, self.target
                ]

                result_vuln = subprocess.run(cmd_vuln, capture_output=True, text=True, timeout=600)
                self.scan_results["nmap_results"]["vulnerability_scan"] = result_vuln.stdout

                # Additional HTTP enumeration for web ports
                if self.web_ports:
                    print(f"{Fore.BLUE}[NMAP] Running HTTP enumeration scripts...{Style.RESET_ALL}")
                    web_port_list = ",".join(str(port) for port in self.web_ports)

                    cmd_http = [
                        "nmap", "--script", "http-enum,http-headers,http-methods,http-robots.txt,http-title",
                        "-p", web_port_list, self.target
                    ]

                    result_http = subprocess.run(cmd_http, capture_output=True, text=True, timeout=300)
                    self.scan_results["nmap_results"]["http_enumeration"] = result_http.stdout

            print(f"{Fore.GREEN}[SUCCESS] Nmap reconnaissance completed{Style.RESET_ALL}")
            self._display_nmap_summary()

        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[ERROR] Nmap scan timed out{Style.RESET_ALL}")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[ERROR] Nmap scan failed: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Unexpected error during Nmap scan: {e}{Style.RESET_ALL}")

    def _parse_nmap_output(self, output: str):
        """Parse nmap output to extract ports and services"""
        lines = output.split('
')

        for line in lines:
            # Parse open ports
            if '/tcp' in line and 'open' in line:
                port_match = re.search(r'(\\d+)/tcp\\s+open\\s+(\\S+)', line)
                if port_match:
                    port = int(port_match.group(1))
                    service = port_match.group(2)

                    self.open_ports.append(port)
                    self.services[port] = service

                    # Identify web ports
                    if service.lower() in ['http', 'https', 'http-alt', 'http-proxy'] or port in [80, 443, 8080, 8443, 8000, 8888]:
                        self.web_ports.append(port)

    def _display_nmap_summary(self):
        """Display summary of nmap results"""
        print(f"
{Fore.CYAN}=== NMAP SCAN SUMMARY ==={Style.RESET_ALL}")
        print(f"{Fore.WHITE}Open Ports Found: {len(self.open_ports)}{Style.RESET_ALL}")

        for port in self.open_ports:
            service = self.services.get(port, 'unknown')
            color = Fore.GREEN if port in self.web_ports else Fore.YELLOW
            print(f"  {color}Port {port}: {service}{Style.RESET_ALL}")

    def scan_owasp_top_10(self):
        """Run OWASP Top 10 vulnerability scans"""
        print(f"
{Fore.YELLOW}[INFO] Starting OWASP Top 10 vulnerability scanning...{Style.RESET_ALL}")

        # A01: Broken Access Control
        self._scan_broken_access_control()

        # A02: Cryptographic Failures  
        self._scan_cryptographic_failures()

        # A03: Injection
        self._scan_injection_vulnerabilities()

        # A05: Security Misconfiguration
        self._scan_security_misconfiguration()

        # A06: Vulnerable Components
        self._scan_vulnerable_components()

        # A10: Server-Side Request Forgery
        self._scan_ssrf_vulnerabilities()

    def _scan_broken_access_control(self):
        """A01: Scan for Broken Access Control vulnerabilities"""
        print(f"{Fore.BLUE}[A01] Scanning for Broken Access Control...{Style.RESET_ALL}")

        vulnerabilities = []

        for port in self.web_ports:
            try:
                base_url = f"http://{self.target}:{port}"

                # Test for directory traversal
                test_paths = [
                    "/admin",
                    "/administrator", 
                    "/login",
                    "/dashboard",
                    "/config",
                    "/backup",
                    "/.env",
                    "/robots.txt"
                ]

                for path in test_paths:
                    try:
                        response = requests.get(f"{base_url}{path}", timeout=10, verify=False)
                        if response.status_code == 200:
                            vulnerabilities.append({
                                "category": "A01",
                                "title": "Potential Sensitive Directory Access",
                                "severity": "Medium",
                                "url": f"{base_url}{path}",
                                "description": f"Accessible path found: {path}",
                                "status_code": response.status_code
                            })
                    except:
                        continue

            except Exception as e:
                continue

        self.scan_results["owasp_vulnerabilities"].extend(vulnerabilities)
        print(f"{Fore.GREEN}[A01] Found {len(vulnerabilities)} potential access control issues{Style.RESET_ALL}")

    def _scan_cryptographic_failures(self):
        """A02: Scan for Cryptographic Failures"""
        print(f"{Fore.BLUE}[A02] Scanning for Cryptographic Failures...{Style.RESET_ALL}")

        vulnerabilities = []

        for port in self.web_ports:
            try:
                # Test for HTTP instead of HTTPS
                if port == 80:
                    vulnerabilities.append({
                        "category": "A02",
                        "title": "Unencrypted HTTP Traffic",
                        "severity": "Medium",
                        "port": port,
                        "description": "Web service running on unencrypted HTTP"
                    })

                # Test SSL/TLS configuration for HTTPS ports
                if port in [443, 8443]:
                    try:
                        import ssl
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE

                        sock = socket.create_connection((self.target, port), timeout=10)
                        ssock = context.wrap_socket(sock, server_hostname=self.target)

                        # Get SSL certificate info
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()

                        if cipher and len(cipher) >= 3:
                            if 'RC4' in cipher[0] or 'DES' in cipher[0]:
                                vulnerabilities.append({
                                    "category": "A02", 
                                    "title": "Weak SSL/TLS Cipher",
                                    "severity": "High",
                                    "port": port,
                                    "cipher": cipher[0],
                                    "description": "Weak encryption cipher detected"
                                })

                        ssock.close()
                    except:
                        continue

            except Exception as e:
                continue

        self.scan_results["owasp_vulnerabilities"].extend(vulnerabilities)
        print(f"{Fore.GREEN}[A02] Found {len(vulnerabilities)} cryptographic issues{Style.RESET_ALL}")

    def _scan_injection_vulnerabilities(self):
        """A03: Scan for Injection vulnerabilities"""
        print(f"{Fore.BLUE}[A03] Scanning for Injection vulnerabilities...{Style.RESET_ALL}")

        vulnerabilities = []

        for port in self.web_ports:
            try:
                base_url = f"http://{self.target}:{port}"

                # Test for SQL injection in common parameters
                test_params = ['id', 'user', 'search', 'q', 'query', 'name']

                for param in test_params:
                    for payload in self.sql_payloads[:3]:  # Test first 3 payloads
                        try:
                            test_url = f"{base_url}/?{param}={payload}"
                            response = requests.get(test_url, timeout=10, verify=False)

                            # Look for SQL error indicators
                            sql_errors = [
                                "sql syntax", "mysql_fetch", "ORA-", "PostgreSQL",
                                "Microsoft JET Database", "ODBC", "SQLServer"
                            ]

                            for error in sql_errors:
                                if error.lower() in response.text.lower():
                                    vulnerabilities.append({
                                        "category": "A03",
                                        "title": "Potential SQL Injection",
                                        "severity": "High", 
                                        "url": test_url,
                                        "payload": payload,
                                        "error_indicator": error,
                                        "description": f"SQL error detected with payload: {payload}"
                                    })
                                    break
                        except:
                            continue

                # Test for XSS
                for payload in self.xss_payloads[:2]:  # Test first 2 payloads
                    try:
                        test_url = f"{base_url}/?test={payload}"
                        response = requests.get(test_url, timeout=10, verify=False)

                        if payload in response.text:
                            vulnerabilities.append({
                                "category": "A03",
                                "title": "Potential Cross-Site Scripting (XSS)",
                                "severity": "Medium",
                                "url": test_url, 
                                "payload": payload,
                                "description": f"XSS payload reflected: {payload}"
                            })
                    except:
                        continue

            except Exception as e:
                continue

        self.scan_results["owasp_vulnerabilities"].extend(vulnerabilities)
        print(f"{Fore.GREEN}[A03] Found {len(vulnerabilities)} potential injection issues{Style.RESET_ALL}")

    def _scan_security_misconfiguration(self):
        """A05: Scan for Security Misconfiguration"""
        print(f"{Fore.BLUE}[A05] Scanning for Security Misconfiguration...{Style.RESET_ALL}")

        vulnerabilities = []

        for port in self.web_ports:
            try:
                base_url = f"http://{self.target}:{port}"

                # Test for common misconfigurations
                response = requests.get(base_url, timeout=10, verify=False)

                # Check security headers
                security_headers = {
                    'X-Frame-Options': 'Missing clickjacking protection',
                    'X-XSS-Protection': 'Missing XSS protection',
                    'X-Content-Type-Options': 'Missing MIME type sniffing protection',
                    'Strict-Transport-Security': 'Missing HSTS header',
                    'Content-Security-Policy': 'Missing CSP header'
                }

                for header, description in security_headers.items():
                    if header.lower() not in [h.lower() for h in response.headers.keys()]:
                        vulnerabilities.append({
                            "category": "A05",
                            "title": f"Missing Security Header: {header}",
                            "severity": "Medium",
                            "url": base_url,
                            "port": port,
                            "description": description
                        })

                # Check for server information disclosure
                server_header = response.headers.get('Server', '')
                if server_header and any(info in server_header.lower() for info in ['apache/', 'nginx/', 'iis/']):
                    vulnerabilities.append({
                        "category": "A05",
                        "title": "Server Information Disclosure",
                        "severity": "Low",
                        "url": base_url,
                        "server": server_header,
                        "description": f"Server version disclosed: {server_header}"
                    })

            except Exception as e:
                continue

        self.scan_results["owasp_vulnerabilities"].extend(vulnerabilities)
        print(f"{Fore.GREEN}[A05] Found {len(vulnerabilities)} security misconfiguration issues{Style.RESET_ALL}")

    def _scan_vulnerable_components(self):
        """A06: Scan for Vulnerable and Outdated Components"""
        print(f"{Fore.BLUE}[A06] Scanning for Vulnerable Components...{Style.RESET_ALL}")

        vulnerabilities = []

        # This would typically integrate with CVE databases
        # For demonstration, we'll check for common outdated software indicators

        for port in self.open_ports:
            service = self.services.get(port, 'unknown')

            # Check for commonly vulnerable services
            vulnerable_services = {
                'ssh': ['OpenSSH 7.4', 'OpenSSH 6.'],
                'ftp': ['vsftpd 2.3.4'],
                'telnet': ['any version'],
                'http': ['Apache 2.2', 'Apache 2.4.6']
            }

            for vuln_service, vuln_versions in vulnerable_services.items():
                if vuln_service.lower() in service.lower():
                    vulnerabilities.append({
                        "category": "A06", 
                        "title": f"Potentially Vulnerable Service: {service}",
                        "severity": "Medium",
                        "port": port,
                        "service": service,
                        "description": f"Service {service} may be outdated or vulnerable"
                    })

        self.scan_results["owasp_vulnerabilities"].extend(vulnerabilities)
        print(f"{Fore.GREEN}[A06] Found {len(vulnerabilities)} potentially vulnerable components{Style.RESET_ALL}")

    def _scan_ssrf_vulnerabilities(self):
        """A10: Scan for Server-Side Request Forgery"""
        print(f"{Fore.BLUE}[A10] Scanning for SSRF vulnerabilities...{Style.RESET_ALL}")

        vulnerabilities = []

        for port in self.web_ports:
            try:
                base_url = f"http://{self.target}:{port}"

                # Test for SSRF in common parameters
                ssrf_payloads = [
                    "http://localhost:22",
                    "http://127.0.0.1:3306",
                    "http://169.254.169.254/latest/meta-data/",
                    "file:///etc/passwd"
                ]

                ssrf_params = ['url', 'link', 'src', 'source', 'target', 'redirect']

                for param in ssrf_params:
                    for payload in ssrf_payloads:
                        try:
                            test_url = f"{base_url}/?{param}={payload}"
                            response = requests.get(test_url, timeout=5, verify=False)

                            # Look for indicators of SSRF
                            if response.status_code == 200 and len(response.text) > 0:
                                # This is a simplified check - real SSRF detection is more complex
                                if "root:" in response.text or "mysql" in response.text.lower():
                                    vulnerabilities.append({
                                        "category": "A10",
                                        "title": "Potential SSRF Vulnerability", 
                                        "severity": "High",
                                        "url": test_url,
                                        "payload": payload,
                                        "description": f"SSRF may be possible with parameter: {param}"
                                    })
                        except:
                            continue

            except Exception as e:
                continue

        self.scan_results["owasp_vulnerabilities"].extend(vulnerabilities)
        print(f"{Fore.GREEN}[A10] Found {len(vulnerabilities)} potential SSRF issues{Style.RESET_ALL}")

    def generate_report(self):
        """Generate comprehensive scan report"""
        print(f"
{Fore.CYAN}=== SCAN REPORT ==={Style.RESET_ALL}")

        # Summary statistics
        total_vulns = len(self.scan_results["owasp_vulnerabilities"])
        high_vulns = len([v for v in self.scan_results["owasp_vulnerabilities"] if v.get("severity") == "High"])
        medium_vulns = len([v for v in self.scan_results["owasp_vulnerabilities"] if v.get("severity") == "Medium"])
        low_vulns = len([v for v in self.scan_results["owasp_vulnerabilities"] if v.get("severity") == "Low"])

        self.scan_results["summary"] = {
            "total_vulnerabilities": total_vulns,
            "high_severity": high_vulns,
            "medium_severity": medium_vulns, 
            "low_severity": low_vulns,
            "open_ports": len(self.open_ports),
            "web_ports": len(self.web_ports)
        }

        print(f"{Fore.WHITE}Target: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Total Vulnerabilities Found: {total_vulns}{Style.RESET_ALL}")
        print(f"{Fore.RED}  High Severity: {high_vulns}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Medium Severity: {medium_vulns}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  Low Severity: {low_vulns}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Open Ports: {len(self.open_ports)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Web Ports: {len(self.web_ports)}{Style.RESET_ALL}")

        # Display vulnerabilities by category
        categories = {}
        for vuln in self.scan_results["owasp_vulnerabilities"]:
            cat = vuln.get("category", "Unknown")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(vuln)

        print(f"
{Fore.CYAN}=== VULNERABILITIES BY OWASP CATEGORY ==={Style.RESET_ALL}")
        for cat in sorted(categories.keys()):
            owasp_name = self.owasp_categories.get(cat, "Unknown Category")
            print(f"
{Fore.MAGENTA}{cat}: {owasp_name} ({len(categories[cat])} issues){Style.RESET_ALL}")

            for vuln in categories[cat]:
                severity_color = Fore.RED if vuln.get("severity") == "High" else Fore.YELLOW if vuln.get("severity") == "Medium" else Fore.GREEN
                print(f"  {severity_color}[{vuln.get('severity', 'Unknown')}] {vuln.get('title', 'No title')}{Style.RESET_ALL}")
                print(f"    {vuln.get('description', 'No description')}")
                if 'url' in vuln:
                    print(f"    URL: {vuln['url']}")

        # Save to file if specified
        if self.output_file:
            try:
                with open(self.output_file, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
                print(f"
{Fore.GREEN}[SUCCESS] Report saved to: {self.output_file}{Style.RESET_ALL}")
            except Exception as e:
                print(f"
{Fore.RED}[ERROR] Failed to save report: {e}{Style.RESET_ALL}")

    def run_full_scan(self):
        """Run complete security scan"""
        self.print_banner()

        # Phase 1: Nmap reconnaissance
        self.run_nmap_scan()

        # Phase 2: OWASP Top 10 vulnerability scanning
        if self.open_ports:
            self.scan_owasp_top_10()
        else:
            print(f"{Fore.YELLOW}[WARNING] No open ports found, skipping vulnerability scans{Style.RESET_ALL}")

        # Phase 3: Generate report
        self.generate_report()

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="OWASP Top 10 Security Scanner with Nmap Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python owasp_scanner.py -t 192.168.1.1
  python owasp_scanner.py -t example.com -p 1-65535 -o report.json
  python owasp_scanner.py -t 10.0.0.1 -p 80,443,8080 -o scan_results.json
        """
    )

    parser.add_argument('-t', '--target', required=True, 
                       help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1000',
                       help='Port range to scan (default: 1-1000)')
    parser.add_argument('-o', '--output', 
                       help='Output file for JSON results')

    args = parser.parse_args()

    # Validate target
    try:
        socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"{Fore.RED}[ERROR] Unable to resolve target: {args.target}{Style.RESET_ALL}")
        sys.exit(1)

    # Check if nmap is available
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Fore.RED}[ERROR] Nmap not found. Please install nmap first.{Style.RESET_ALL}")
        sys.exit(1)

    # Initialize and run scanner
    try:
        scanner = OWASPTopTenScanner(
            target=args.target,
            port_range=args.ports,
            output_file=args.output
        )

        scanner.run_full_scan()

    except KeyboardInterrupt:
        print(f"
{Fore.YELLOW}[INFO] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"
{Fore.RED}[ERROR] Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
