# bb_recon/modules/subdomain_enum.py
"""
Module Purpose: Enumerate subdomains using passive/active tools and fetch ASN.
Uses amass and subfinder for comprehensive coverage, including hidden subdomains from passive sources.
"""
import subprocess
from modules.utils import run_command

def enumerate_subdomains(domain, passive_only=False):
    """Enumerate subdomains and get ASN."""
    subdomains = set()

    # Subfinder (passive by default, add --active if not passive_only)
    cmd = ['subfinder', '-d', domain, '-silent']
    if not passive_only:
        cmd.append('--active')
    output = run_command(cmd)
    subdomains.update(output.splitlines())

    # Amass passive
    cmd = ['amass', 'enum', '-passive', '-d', domain]
    output = run_command(cmd)
    subdomains.update([line for line in output.splitlines() if '.' in line])

    # ASN via amass intel
    cmd = ['amass', 'intel', '-d', domain, '-asn']
    asn_output = run_command(cmd)
    asn = [line.split()[0] for line in asn_output.splitlines() if line]  # Extract ASN numbers

    # Deduplicate
    subdomains = list(subdomains)
    return subdomains, asn