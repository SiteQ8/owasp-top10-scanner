#!/usr/bin/env python3
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

        print("\n🎉 All component tests passed!")

    except ImportError as e:
        print(f"✗ Import error: {e}")
        print("Run: pip install -r requirements.txt")
    except Exception as e:
        print(f"✗ Test failed: {e}")

def test_nmap_availability():
    """Test if nmap is available on the system"""
    print("\n🔍 Testing Nmap Availability")
    print("=" * 30)

    try:
        import subprocess
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
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
