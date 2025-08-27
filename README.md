# bb_recon

Bug bounty recon tool optimized for Kali Linux that scans websites for OWASP Top 10 vulnerabilities.

## Features

- **OWASP Top 10 Coverage**: Comprehensive vulnerability scanning for all major security issues
- **Input Parameter Analysis**: Automatically discovers and tests all forms and input fields
- **Dynamic Content Scanning**: Uses Selenium for JavaScript-heavy applications
- **Kali Linux Enhanced**: 
  - Network reconnaissance with nmap
  - DNS enumeration
  - Port scanning and service detection
  - Enhanced payload testing
- **Vulnerability Detection**: 
  - SQL Injection (including time-based)
  - Cross-Site Scripting (XSS)
  - Authentication vulnerabilities
  - Sensitive data exposure
  - Access control issues
  - Security misconfigurations
  - And more...

## Installation

### Kali Linux
```bash
# Make script executable
chmod +x run.sh

# Run the tool
./run.sh
```

### Manual Installation
```bash
pip3 install -r requirements.txt
python3 bb_scanner.py
```

## Usage

```bash
# On Kali Linux
./run.sh

# Manual execution
python3 bb_scanner.py
```

Enter the target URL when prompted. The tool will:
1. Perform network reconnaissance (DNS, ports, services)
2. Gather target information
3. Discover forms and input fields
4. Test for various vulnerabilities
5. Generate a detailed report

## Requirements

- Python 3.7+
- Kali Linux (recommended) or Linux with nmap
- Chrome browser (for Selenium)
- Internet connection

## Kali Linux Dependencies

The tool automatically installs:
- `python-nmap` for port scanning
- `lxml` for fast HTML parsing
- `dnspython` for DNS operations

## Output

- Console output with real-time scan results
- JSON report file with detailed findings
- Color-coded vulnerability severity levels
- Network reconnaissance data

## Disclaimer

This tool is for educational and authorized testing purposes only. Always ensure you have permission to test the target website.
