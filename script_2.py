# Create a demo/example script showing how to use the scanner
demo_script = '''#!/usr/bin/env python3
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
    print("\\n📋 Example 1: Basic scan of a local target")
    print("Command: python owasp_scanner.py -t 127.0.0.1 -p 1-100")
    print("This would scan localhost ports 1-100 for OWASP Top 10 vulnerabilities")
    
    # Example 2: Web application scan  
    print("\\n📋 Example 2: Web application focused scan")
    print("Command: python owasp_scanner.py -t example.com -p 80,443,8080,8443 -o webapp_scan.json")
    print("This scans common web ports and saves results to JSON")
    
    # Example 3: Comprehensive scan
    print("\\n📋 Example 3: Comprehensive network scan")
    print("Command: python owasp_scanner.py -t 192.168.1.0/24 -p 1-65535 -o network_scan.json")
    print("This performs a full port scan with OWASP vulnerability testing")
    
    # Show expected output structure
    print("\\n📊 Expected JSON Output Structure:")
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
    
    print("\\n🔧 Installation Commands:")
    print("1. Install Nmap: sudo apt-get install nmap")
    print("2. Install Python deps: pip install -r requirements.txt")
    print("3. Run scanner: python owasp_scanner.py -t <target>")
    
    print("\\n⚠️  Security Reminder:")
    print("Always get authorization before scanning any systems!")
    print("This tool is for authorized security testing only.")

if __name__ == "__main__":
    run_demo_scan()
'''

with open('demo.py', 'w') as f:
    f.write(demo_script)

# Create a simple test script for basic functionality
test_script = '''#!/usr/bin/env python3
"""
Basic functionality test for OWASP Scanner
Tests core components without requiring target systems
"""

def test_scanner_components():
    """Test scanner initialization and basic methods"""
    print("🧪 Testing OWASP Scanner Components")
    print("=" * 40)
    
    try:
        # Test imports
        print("✓ Testing imports...")
        import sys
        import json
        import requests
        import colorama
        print("✓ All required modules available")
        
        # Test scanner class initialization
        print("✓ Testing scanner class...")
        from owasp_scanner import OWASPTopTenScanner
        
        scanner = OWASPTopTenScanner("127.0.0.1", "80,443", "test_output.json")
        print("✓ Scanner initialized successfully")
        
        # Test OWASP categories
        print("✓ Testing OWASP categories...")
        expected_categories = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]
        for cat in expected_categories:
            if cat in scanner.owasp_categories:
                print(f"  ✓ {cat}: {scanner.owasp_categories[cat]}")
            else:
                print(f"  ✗ Missing category: {cat}")
        
        # Test payloads
        print("✓ Testing vulnerability payloads...")
        print(f"  SQL payloads: {len(scanner.sql_payloads)}")
        print(f"  XSS payloads: {len(scanner.xss_payloads)}")
        print(f"  LFI payloads: {len(scanner.lfi_payloads)}")
        
        print("\\n🎉 All component tests passed!")
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        print("Run: pip install -r requirements.txt")
    except Exception as e:
        print(f"✗ Test failed: {e}")

def test_nmap_availability():
    """Test if nmap is available on the system"""
    print("\\n🔍 Testing Nmap Availability")
    print("=" * 30)
    
    try:
        import subprocess
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            version_line = result.stdout.split('\\n')[0]
            print(f"✓ Nmap found: {version_line}")
        else:
            print("✗ Nmap not working properly")
    except FileNotFoundError:
        print("✗ Nmap not found in PATH")
        print("Install with: sudo apt-get install nmap")
    except Exception as e:
        print(f"✗ Error checking nmap: {e}")

if __name__ == "__main__":
    test_scanner_components()
    test_nmap_availability()
'''

with open('test_scanner.py', 'w') as f:
    f.write(test_script)

# Create a configuration file for advanced users
config_file = '''# OWASP Top 10 Scanner Configuration
# Advanced configuration options for customizing scans

[DEFAULT]
# Default timeout for HTTP requests (seconds)
http_timeout = 10

# Maximum number of threads for concurrent scanning
max_threads = 5

# Default nmap scan arguments
nmap_basic_args = -sS,-sV,-O,--version-intensity,5
nmap_vuln_args = --script,vuln,safe,auth,default
nmap_http_args = --script,http-enum,http-headers,http-methods,http-robots.txt,http-title

[PAYLOADS]
# Enable/disable specific payload categories
sql_injection = true
xss_testing = true
lfi_testing = true
command_injection = false

# Custom payload files (one payload per line)
custom_sql_file = 
custom_xss_file = 
custom_lfi_file = 

[REPORTING]
# Output format options
json_output = true
html_output = false
csv_output = false

# Include raw nmap output in reports
include_nmap_raw = true

# Minimum severity to report (low, medium, high)
min_severity = low

[SCANNING]
# Skip certain OWASP categories (comma-separated)
skip_categories = 

# Only scan specific categories (comma-separated, overrides skip_categories)
only_categories = 

# Custom HTTP headers to include in requests
custom_headers = User-Agent: OWASP-Scanner/1.0

# Follow redirects during HTTP testing
follow_redirects = true

# Maximum redirect depth
max_redirects = 3

[ADVANCED]
# Enable experimental checks
experimental_checks = false

# Verbose logging
verbose_logging = false

# Rate limiting (requests per second)
rate_limit = 10

# Custom wordlist for directory enumeration
custom_wordlist = 
'''

with open('scanner_config.ini', 'w') as f:
    f.write(config_file)

print("✅ Additional files created!")
print("📋 Demo and testing files:")
print("  - demo.py (usage examples and demonstration)")
print("  - test_scanner.py (component testing script)")  
print("  - scanner_config.ini (advanced configuration options)")
print("\n🚀 Your OWASP Top 10 scanner toolkit is ready!")
print("\nNext steps:")
print("1. Install dependencies: pip install -r requirements.txt")
print("2. Install nmap: sudo apt-get install nmap (Linux)")
print("3. Test components: python test_scanner.py")
print("4. Run demo: python demo.py")
print("5. Scan a target: python owasp_scanner.py -t <target>")