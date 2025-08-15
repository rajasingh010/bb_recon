# bb_recon/modules/vuln_scan.py
"""
Module Purpose: Scan live hosts with nuclei templates (non-intrusive, info/low severity).
Uses default templates; can filter severity.
"""
from modules.utils import run_command

def scan_vulns(hosts):
    """Run nuclei on hosts."""
    with open('temp_live.txt', 'w') as f:
        f.write('\n'.join(hosts))
    
    # Use -severity info,low to stay non-intrusive
    cmd = ['nuclei', '-l', 'temp_live.txt', '-severity', 'info,low', '-json', '-silent']
    output = run_command(cmd)
    
    import json
    results = []
    for line in output.splitlines():
        if line:
            results.append(json.loads(line))
    
    import os
    os.remove('temp_live.txt')
    return results