# bb_recon/modules/js_discovery.py
"""
Module Purpose: Discover JS files via historical URLs and scan for secrets.
Uses gau/waybackurls for URLs, filters .js, regex for common secrets.
"""
import re
import subprocess
from modules.utils import run_command

def discover_js(domain, subdomains):
    """Fetch URLs, filter JS, scan for secrets."""
    # Get URLs from gau and waybackurls
    urls = set()
    cmd_gau = ['gau', domain]
    urls.update(run_command(cmd_gau).splitlines())
    
    cmd_wayback = ['waybackurls', domain]
    urls.update(run_command(cmd_wayback).splitlines())
    
    # Filter JS
    js_files = [url for url in urls if url.endswith('.js')]
    
    # Scan for secrets (simple regex: AWS keys, tokens, etc.)
    secrets = []
    for js in js_files[:50]:  # Limit to avoid overload
        try:
            content = subprocess.check_output(['curl', '-s', js]).decode()
            # Regex for secrets (example: AWS key, API tokens)
            aws_keys = re.findall(r'AKIA[0-9A-Z]{16}', content)
            if aws_keys:
                secrets.append({'file': js, 'secrets': aws_keys})
        except:
            pass
    
    return js_files, secrets