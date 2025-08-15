# bb_recon/modules/http_probe.py
"""
Module Purpose: Probe subdomains for HTTP status, titles, tech using httpx.
Filters alive hosts and gathers metadata.
"""
from modules.utils import run_command

def probe_hosts(hosts):
    """Probe list of hosts with httpx."""
    # Write hosts to temp file
    with open('temp_hosts.txt', 'w') as f:
        f.write('\n'.join(hosts))
    
    cmd = ['httpx', '-l', 'temp_hosts.txt', '-title', '-tech-detect', '-status-code', '-json', '-silent']
    output = run_command(cmd)
    
    import json
    results = {}
    for line in output.splitlines():
        if line:
            data = json.loads(line)
            host = data['url']
            results[host] = {
                'status': data.get('status_code'),
                'title': data.get('title'),
                'tech': data.get('technologies', [])
            }
    
    import os
    os.remove('temp_hosts.txt')
    return results