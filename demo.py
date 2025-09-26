#!/usr/bin/env python3
"""
OWASP Scanner Demo Script
This script demonstrates how to use the OWASP Top 10 scanner programmatically
"""

import sys
import subprocess
import json
from datetime import datetime

def run_demo_scan():
    """Demonstrate scanner usage with a test target"""

    print("🔍 OWASP Top 10 Scanner Demo")
    print("=" * 50)

    # Example 1: Basic scan
    print("\n📋 Example 1: Basic scan of a local target")
    print("Command: python owasp_scanner.py -t 127.0.0.1 -p 1-100")
    print("This would scan localhost ports 1-100 for OWASP Top 10 vulnerabilities")

    # Example 2: Web application scan  
    print("\n📋 Example 2: Web application focused scan")
    print("Command: python owasp_scanner.py -t example.com -p 80,443,8080,8443 -o webapp_scan.json")
    print("This scans common web ports and saves results to JSON")

    # Example 3: Comprehensive scan
    print("\n📋 Example 3: Comprehensive network scan")
    print("Command: python owasp_scanner.py -t 192.168.1.0/24 -p 1-65535 -o network_scan.json")
    print("This performs a full port scan with OWASP vulnerability testing")

    # Show expected output structure
    print("\n📊 Expected JSON Output Structure:")
    sample_output = {
        "target": "example.com",
        "scan_timestamp": datetime.now().isoformat(),
        "nmap_results": {
            "basic_scan": "Nmap scan output...",
            "vulnerability_scan": "NSE script results...",
            "http_enumeration": "HTTP-specific findings..."
        },
        "owasp_vulnerabilities": [
            {
                "category": "A01",
                "title": "Broken Access Control Example",
                "severity": "High",
                "description": "Admin panel accessible without authentication",
                "url": "http://example.com/admin"
            },
            {
                "category": "A02", 
                "title": "Cryptographic Failure Example",
                "severity": "Medium",
                "description": "Weak SSL/TLS cipher suite detected",
                "port": 443
            }
        ],
        "summary": {
            "total_vulnerabilities": 15,
            "high_severity": 3,
            "medium_severity": 8,
            "low_severity": 4,
            "open_ports": 5,
            "web_ports": 2
        }
    }

    print(json.dumps(sample_output, indent=2)[:500] + "...")

    print("\n🔧 Installation Commands:")
    print("1. Install Nmap: sudo apt-get install nmap")
    print("2. Install Python deps: pip install -r requirements.txt")
    print("3. Run scanner: python owasp_scanner.py -t <target>")

    print("\n⚠️  Security Reminder:")
    print("Always get authorization before scanning any systems!")
    print("This tool is for authorized security testing only.")

if __name__ == "__main__":
    run_demo_scan()
