# OWASP Top 10 Security Scanner with Nmap Integration

A comprehensive Python tool that performs security assessments against the OWASP Top 10 vulnerabilities, with integrated Nmap reconnaissance capabilities.

## Features

### 🔍 Comprehensive Reconnaissance
- **Nmap Integration**: Uses nmap for initial host discovery and port scanning
- **Service Detection**: Identifies running services and versions
- **NSE Scripts**: Leverages Nmap Scripting Engine for vulnerability detection
- **SSL/TLS Analysis**: Checks encryption configurations

### 🎯 OWASP Top 10 2021 Coverage
- **A01: Broken Access Control** - Tests for unauthorized access to directories and resources
- **A02: Cryptographic Failures** - Identifies weak encryption and missing HTTPS
- **A03: Injection** - Scans for SQL injection and XSS vulnerabilities
- **A04: Insecure Design** - Checks for design flaws (basic implementation)
- **A05: Security Misconfiguration** - Identifies missing security headers and server disclosure
- **A06: Vulnerable Components** - Detects outdated services and software
- **A07: Authentication Failures** - Tests for weak authentication mechanisms
- **A08: Data Integrity Failures** - Checks for insecure data handling
- **A09: Logging/Monitoring Failures** - Identifies insufficient logging
- **A10: SSRF** - Tests for Server-Side Request Forgery vulnerabilities

### 📊 Professional Reporting
- **Colored Terminal Output**: Easy-to-read results with severity-based colors
- **JSON Export**: Structured output for integration with other tools
- **Vulnerability Categorization**: Results organized by OWASP categories
- **Risk Prioritization**: Issues classified by severity (High/Medium/Low)

## Installation

### Prerequisites
1. **Python 3.7+** installed
2. **Nmap** installed and accessible in PATH
3. **pip** package manager

### Install Nmap
```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install nmap

# CentOS/RHEL
sudo yum install nmap

# macOS (with Homebrew)
brew install nmap

# Windows
# Download from: https://nmap.org/download.html
```

### Install Python Dependencies
```bash
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
python owasp_scanner.py -t 192.168.1.1
```

### Advanced Options
```bash
# Scan specific port range
python owasp_scanner.py -t example.com -p 1-65535

# Scan common ports with output to file
python owasp_scanner.py -t 10.0.0.1 -p 80,443,8080,8443 -o scan_results.json

# Scan with full port range and save results
python owasp_scanner.py -t target.com -p 1-65535 -o comprehensive_scan.json
```

### Command Line Arguments
- `-t, --target`: Target IP address or hostname (required)
- `-p, --ports`: Port range to scan (default: 1-1000)
- `-o, --output`: Output file for JSON results (optional)

## Sample Output

```
╔═══════════════════════════════════════════════════════════════╗
║                OWASP Top 10 Security Scanner                  ║
║                   with Nmap Integration                       ║
║                                                               ║
║  Target: example.com                                          ║
║  Port Range: 1-1000                                           ║
║  Timestamp: 2025-09-26 20:50:00                               ║
╚═══════════════════════════════════════════════════════════════╝

[INFO] Starting Nmap reconnaissance...
[NMAP] Running port scan and service detection...
[NMAP] Running NSE vulnerability scripts...
[NMAP] Running HTTP enumeration scripts...
[SUCCESS] Nmap reconnaissance completed

=== NMAP SCAN SUMMARY ===
Open Ports Found: 3
  Port 22: ssh
  Port 80: http
  Port 443: https

[INFO] Starting OWASP Top 10 vulnerability scanning...
[A01] Scanning for Broken Access Control...
[A01] Found 2 potential access control issues
[A02] Scanning for Cryptographic Failures...
[A02] Found 1 cryptographic issues
[A03] Scanning for Injection vulnerabilities...
[A03] Found 0 potential injection issues
[A05] Scanning for Security Misconfiguration...
[A05] Found 3 security misconfiguration issues
[A06] Scanning for Vulnerable Components...
[A06] Found 1 potentially vulnerable components
[A10] Scanning for SSRF vulnerabilities...
[A10] Found 0 potential SSRF issues

=== SCAN REPORT ===
Target: example.com
Total Vulnerabilities Found: 7
  High Severity: 1
  Medium Severity: 4
  Low Severity: 2
Open Ports: 3
Web Ports: 2
```

## Security Considerations

⚠️ **IMPORTANT DISCLAIMERS**:

1. **Authorization Required**: Only use this tool against systems you own or have explicit permission to test
2. **Responsible Disclosure**: Report discovered vulnerabilities through proper channels
3. **No Warranty**: This tool is for educational and authorized testing purposes only
4. **False Positives**: Always manually verify results before taking action

## Technical Details

### Scanning Methodology
1. **Host Discovery**: Nmap ping sweep and port enumeration
2. **Service Detection**: Version detection with intensity level 5
3. **Vulnerability Scripts**: NSE vuln, safe, auth, and default categories
4. **HTTP Analysis**: Specialized web application testing
5. **OWASP Testing**: Targeted checks for Top 10 vulnerabilities

### Vulnerability Detection Techniques
- **SQL Injection**: Error-based detection with common payloads
- **XSS**: Reflection-based testing with sanitization bypass
- **Access Control**: Directory enumeration and privilege escalation tests
- **Cryptography**: SSL/TLS configuration analysis
- **Headers**: Security header presence validation
- **SSRF**: Internal service access attempts

## Customization

### Adding Custom Payloads
Edit the payload lists in the `__init__` method:
```python
self.sql_payloads = [
    # Add your custom SQL injection payloads
]

self.xss_payloads = [
    # Add your custom XSS payloads
]
```

### Extending Vulnerability Checks
Create new scanning methods following the pattern:
```python
def _scan_custom_vulnerability(self):
    """Custom vulnerability scanner"""
    vulnerabilities = []
    # Your custom logic here
    self.scan_results["owasp_vulnerabilities"].extend(vulnerabilities)
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: Security Scan
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Install dependencies
      run: |
        sudo apt-get install nmap
        pip install -r requirements.txt
    - name: Run security scan
      run: python owasp_scanner.py -t ${{ secrets.TARGET_HOST }} -o results.json
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'python owasp_scanner.py -t ${TARGET} -o scan_results.json'
                archiveArtifacts 'scan_results.json'
            }
        }
    }
}
```

## Troubleshooting

### Common Issues

**1. Nmap Not Found**
```bash
# Verify nmap installation
nmap --version

# Add to PATH if needed (Linux/macOS)
export PATH=$PATH:/usr/local/bin
```

**2. Permission Denied**
```bash
# Run with sudo if needed for certain scans
sudo python owasp_scanner.py -t target
```

**3. SSL Certificate Errors**
The tool uses `verify=False` for SSL requests during testing. This is intentional for security testing but should not be used in production applications.

**4. Timeouts**
Increase timeout values in the requests calls if scanning slow targets:
```python
response = requests.get(url, timeout=30, verify=False)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add new vulnerability checks or improvements
4. Submit a pull request

### Development Guidelines
- Follow OWASP testing standards
- Add proper error handling
- Include severity classifications
- Document new features
- Test against known vulnerable applications

## Legal Notice

This tool is intended for authorized security testing only. Users must:
- Obtain proper authorization before scanning any systems
- Comply with all applicable laws and regulations
- Use the tool responsibly and ethically
- Report vulnerabilities through appropriate channels

## License

MIT License - See LICENSE file for details

## Author

Created by a cybersecurity professional for the community.
Maintained and updated regularly to reflect current OWASP standards.

---

**Remember**: Great power comes with great responsibility. Use this tool to make the internet safer! 🛡️
