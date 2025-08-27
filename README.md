# bb_recon

Bug bounty recon tool that scans websites for OWASP Top 10 vulnerabilities.

## Features

- **OWASP Top 10 Coverage**: Comprehensive vulnerability scanning for all major security issues
- **Input Parameter Analysis**: Automatically discovers and tests all forms and input fields
- **Dynamic Content Scanning**: Uses Selenium for JavaScript-heavy applications
- **Vulnerability Detection**: 
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Authentication vulnerabilities
  - Sensitive data exposure
  - Access control issues
  - Security misconfigurations
  - And more...

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python bb_scanner.py
```

Enter the target URL when prompted. The tool will:
1. Gather target information
2. Discover forms and input fields
3. Test for various vulnerabilities
4. Generate a detailed report

## Requirements

- Python 3.7+
- Chrome browser (for Selenium)
- Internet connection

## Output

- Console output with real-time scan results
- JSON report file with detailed findings
- Color-coded vulnerability severity levels

## Disclaimer

This tool is for educational and authorized testing purposes only. Always ensure you have permission to test the target website.
