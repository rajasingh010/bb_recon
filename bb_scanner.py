#!/usr/bin/env python3
"""
Bug Bounty Recon Tool - OWASP Top 10 Scanner
Scans websites for common vulnerabilities and security issues
"""

import requests
import time
import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from colorama import init, Fore, Style
import json

init(autoreset=True)

class BugBountyScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.forms = []
        self.inputs = []
        
    def setup_driver(self):
        """Setup Chrome driver for dynamic content analysis"""
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            service = Service(ChromeDriverManager().install())
            return webdriver.Chrome(service=service, options=chrome_options)
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to setup Chrome driver: {e}")
            return None
    
    def scan_website(self):
        """Main scanning function"""
        print(f"{Fore.CYAN}[*] Starting scan for: {self.target_url}")
        
        # Basic reconnaissance
        self.gather_info()
        
        # Find forms and inputs
        self.find_forms_and_inputs()
        
        # OWASP Top 10 vulnerability checks
        self.check_injection_vulnerabilities()
        self.check_authentication_vulnerabilities()
        self.check_sensitive_data_exposure()
        self.check_xml_external_entity()
        self.check_access_control()
        self.check_security_misconfiguration()
        self.check_xss_vulnerabilities()
        self.check_insecure_deserialization()
        self.check_vulnerable_components()
        self.check_insufficient_logging()
        
        # Generate report
        self.generate_report()
    
    def gather_info(self):
        """Gather basic information about the target"""
        print(f"{Fore.YELLOW}[*] Gathering target information...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            print(f"{Fore.GREEN}[+] Status Code: {response.status_code}")
            print(f"{Fore.GREEN}[+] Server: {response.headers.get('Server', 'Unknown')}")
            print(f"{Fore.GREEN}[+] Technologies: {self.detect_technologies(response)}")
            
            # Check for common security headers
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                              'X-XSS-Protection', 'Strict-Transport-Security']
            for header in security_headers:
                if header in response.headers:
                    print(f"{Fore.GREEN}[+] {header}: {response.headers[header]}")
                else:
                    print(f"{Fore.RED}[!] Missing security header: {header}")
                    
        except Exception as e:
            print(f"{Fore.RED}[!] Error gathering info: {e}")
    
    def detect_technologies(self, response):
        """Detect technologies used by the website"""
        tech = []
        
        # Check for common frameworks
        if 'X-Powered-By' in response.headers:
            tech.append(response.headers['X-Powered-By'])
        
        # Check HTML content for frameworks
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for React
        if soup.find('div', {'data-reactroot': True}):
            tech.append('React')
        
        # Check for Angular
        if soup.find(attrs={'ng-app': True}):
            tech.append('Angular')
        
        # Check for jQuery
        if soup.find('script', src=re.compile(r'jquery')):
            tech.append('jQuery')
        
        return ', '.join(tech) if tech else 'Unknown'
    
    def find_forms_and_inputs(self):
        """Find all forms and input fields"""
        print(f"{Fore.YELLOW}[*] Analyzing forms and inputs...")
        
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            for form in forms:
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                # Find all inputs in the form
                inputs = form.find_all(['input', 'textarea', 'select'])
                for inp in inputs:
                    input_info = {
                        'type': inp.get('type', 'text'),
                        'name': inp.get('name', ''),
                        'id': inp.get('id', ''),
                        'placeholder': inp.get('placeholder', '')
                    }
                    form_info['inputs'].append(input_info)
                    self.inputs.append(input_info)
                
                self.forms.append(form_info)
            
            print(f"{Fore.GREEN}[+] Found {len(forms)} forms with {len(self.inputs)} input fields")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error analyzing forms: {e}")
    
    def check_injection_vulnerabilities(self):
        """Check for injection vulnerabilities (A03:2021)"""
        print(f"{Fore.YELLOW}[*] Checking for injection vulnerabilities...")
        
        # SQL Injection test payloads
        sql_payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users--", "1' UNION SELECT NULL--"]
        
        for form in self.forms:
            if form['method'] == 'POST':
                for payload in sql_payloads:
                    try:
                        data = {}
                        for inp in form['inputs']:
                            if inp['type'] in ['text', 'textarea']:
                                data[inp['name']] = payload
                        
                        response = self.session.post(urljoin(self.target_url, form['action']), data=data)
                        
                        # Check for SQL error patterns
                        sql_errors = ['sql syntax', 'mysql_fetch', 'oracle error', 'sqlite']
                        if any(error in response.text.lower() for error in sql_errors):
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'High',
                                'description': f'Potential SQL injection in form {form["action"]}',
                                'payload': payload,
                                'url': urljoin(self.target_url, form['action'])
                            })
                            print(f"{Fore.RED}[!] Potential SQL Injection found!")
                            break
                            
                    except Exception as e:
                        continue
    
    def check_authentication_vulnerabilities(self):
        """Check for authentication vulnerabilities (A07:2021)"""
        print(f"{Fore.YELLOW}[*] Checking authentication vulnerabilities...")
        
        # Check for weak authentication mechanisms
        weak_auth_patterns = [
            '/login', '/admin', '/user', '/account'
        ]
        
        for pattern in weak_auth_patterns:
            try:
                url = urljoin(self.target_url, pattern)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    # Check if it's a login form
                    soup = BeautifulSoup(response.text, 'html.parser')
                    if soup.find('input', {'type': 'password'}):
                        print(f"{Fore.YELLOW}[*] Found login form at: {url}")
                        
                        # Check for common weak authentication issues
                        if 'password' in response.text.lower() and 'username' in response.text.lower():
                            if not soup.find('input', {'type': 'hidden', 'name': re.compile(r'token|csrf')}):
                                self.vulnerabilities.append({
                                    'type': 'Weak Authentication',
                                    'severity': 'Medium',
                                    'description': f'Login form at {url} lacks CSRF protection',
                                    'url': url
                                })
                                print(f"{Fore.RED}[!] Login form lacks CSRF protection!")
                                
            except Exception as e:
                continue
    
    def check_sensitive_data_exposure(self):
        """Check for sensitive data exposure (A02:2021)"""
        print(f"{Fore.YELLOW}[*] Checking for sensitive data exposure...")
        
        # Check for common sensitive files
        sensitive_files = [
            '/robots.txt', '/sitemap.xml', '/.env', '/config.php',
            '/wp-config.php', '/.git/config', '/.htaccess'
        ]
        
        for file_path in sensitive_files:
            try:
                url = urljoin(self.target_url, file_path)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    print(f"{Fore.YELLOW}[*] Found accessible file: {file_path}")
                    
                    # Check for sensitive information
                    sensitive_patterns = [
                        r'password\s*=', r'api_key\s*=', r'secret\s*=',
                        r'database\s*=', r'admin\s*=', r'root\s*='
                    ]
                    
                    for pattern in sensitive_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            self.vulnerabilities.append({
                                'type': 'Sensitive Data Exposure',
                                'severity': 'High',
                                'description': f'Sensitive data found in {file_path}',
                                'url': url,
                                'pattern': pattern
                            })
                            print(f"{Fore.RED}[!] Sensitive data found in {file_path}!")
                            break
                            
            except Exception as e:
                continue
    
    def check_xml_external_entity(self):
        """Check for XXE vulnerabilities (A05:2021)"""
        print(f"{Fore.YELLOW}[*] Checking for XXE vulnerabilities...")
        
        # This would require more sophisticated testing with actual XML payloads
        # For now, we'll check if XML processing is likely
        try:
            response = self.session.get(self.target_url)
            if 'xml' in response.text.lower() or 'soap' in response.text.lower():
                print(f"{Fore.YELLOW}[*] XML processing detected - manual XXE testing recommended")
        except:
            pass
    
    def check_access_control(self):
        """Check for access control vulnerabilities (A01:2021)"""
        print(f"{Fore.YELLOW}[*] Checking access control vulnerabilities...")
        
        # Check for common admin paths
        admin_paths = ['/admin', '/administrator', '/manage', '/control', '/dashboard']
        
        for path in admin_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    print(f"{Fore.YELLOW}[*] Admin area accessible: {path}")
                    
                    # Check if it's actually an admin interface
                    if any(keyword in response.text.lower() for keyword in ['admin', 'dashboard', 'manage']):
                        self.vulnerabilities.append({
                            'type': 'Access Control',
                            'severity': 'Medium',
                            'description': f'Admin area {path} accessible without authentication',
                            'url': url
                        })
                        print(f"{Fore.RED}[!] Admin area accessible without authentication!")
                        
            except Exception as e:
                continue
    
    def check_security_misconfiguration(self):
        """Check for security misconfiguration (A05:2021)"""
        print(f"{Fore.YELLOW}[*] Checking security misconfiguration...")
        
        # Check for common misconfigurations
        try:
            response = self.session.get(self.target_url)
            
            # Check for verbose error messages
            if 'error' in response.text.lower() and len(response.text) > 1000:
                print(f"{Fore.YELLOW}[*] Verbose error messages detected")
            
            # Check for directory listing
            test_dir = urljoin(self.target_url, '/images/')
            dir_response = self.session.get(test_dir)
            if 'index of' in dir_response.text.lower():
                self.vulnerabilities.append({
                    'type': 'Security Misconfiguration',
                    'severity': 'Medium',
                    'description': 'Directory listing enabled',
                    'url': test_dir
                })
                print(f"{Fore.RED}[!] Directory listing enabled!")
                
        except Exception as e:
            pass
    
    def check_xss_vulnerabilities(self):
        """Check for XSS vulnerabilities (A03:2021)"""
        print(f"{Fore.YELLOW}[*] Checking for XSS vulnerabilities...")
        
        # Basic XSS payloads
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            'javascript:alert("XSS")'
        ]
        
        for form in self.forms:
            if form['method'] == 'GET':
                for payload in xss_payloads:
                    try:
                        params = {}
                        for inp in form['inputs']:
                            if inp['type'] in ['text', 'textarea']:
                                params[inp['name']] = payload
                        
                        if params:
                            response = self.session.get(urljoin(self.target_url, form['action']), params=params)
                            
                            # Check if payload is reflected
                            if payload in response.text:
                                self.vulnerabilities.append({
                                    'type': 'Cross-Site Scripting (XSS)',
                                    'severity': 'High',
                                    'description': f'XSS payload reflected in {form["action"]}',
                                    'payload': payload,
                                    'url': urljoin(self.target_url, form['action'])
                                })
                                print(f"{Fore.RED}[!] XSS vulnerability found!")
                                break
                                
                    except Exception as e:
                        continue
    
    def check_insecure_deserialization(self):
        """Check for insecure deserialization (A08:2021)"""
        print(f"{Fore.YELLOW}[*] Checking for insecure deserialization...")
        # This requires more sophisticated testing with actual serialized objects
        # For now, we'll note that manual testing is needed
        pass
    
    def check_vulnerable_components(self):
        """Check for vulnerable components (A06:2021)"""
        print(f"{Fore.YELLOW}[*] Checking for vulnerable components...")
        
        try:
            response = self.session.get(self.target_url)
            
            # Check for common vulnerable components
            vulnerable_components = {
                'jquery': r'jquery[.-](\d+\.\d+\.\d+)',
                'bootstrap': r'bootstrap[.-](\d+\.\d+\.\d+)',
                'wordpress': r'wp-content|wp-includes'
            }
            
            for component, pattern in vulnerable_components.items():
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    print(f"{Fore.YELLOW}[*] {component.title()} detected")
                    # Version checking would require more sophisticated analysis
                    
        except Exception as e:
            pass
    
    def check_insufficient_logging(self):
        """Check for insufficient logging (A09:2021)"""
        print(f"{Fore.YELLOW}[*] Checking for insufficient logging...")
        
        # This is difficult to test automatically
        # We'll check for common logging endpoints
        logging_endpoints = ['/logs', '/admin/logs', '/debug', '/status']
        
        for endpoint in logging_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    print(f"{Fore.YELLOW}[*] Logging endpoint accessible: {endpoint}")
                    
            except Exception as e:
                continue
    
    def generate_report(self):
        """Generate comprehensive vulnerability report"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN} VULNERABILITY SCAN REPORT")
        print(f"{Fore.CYAN}{'='*60}")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No vulnerabilities detected!")
        else:
            print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} vulnerabilities:\n")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_color = Fore.RED if vuln['severity'] == 'High' else Fore.YELLOW
                print(f"{severity_color}[{i}] {vuln['type']} ({vuln['severity']})")
                print(f"    Description: {vuln['description']}")
                print(f"    URL: {vuln.get('url', 'N/A')}")
                if 'payload' in vuln:
                    print(f"    Payload: {vuln['payload']}")
                print()
        
        # Save report to file
        report_data = {
            'target_url': self.target_url,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'forms_found': len(self.forms),
            'inputs_found': len(self.inputs)
        }
        
        filename = f"scan_report_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"{Fore.CYAN}[*] Report saved to: {filename}")

def main():
    print(f"{Fore.CYAN}🐛 Bug Bounty Recon Tool - OWASP Top 10 Scanner")
    print(f"{Fore.CYAN}{'='*50}")
    
    target_url = input(f"{Fore.YELLOW}Enter target URL: ").strip()
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    scanner = BugBountyScanner(target_url)
    scanner.scan_website()

if __name__ == "__main__":
    main()
