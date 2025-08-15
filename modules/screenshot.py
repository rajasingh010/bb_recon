# bb_recon/modules/screenshot.py
"""
Module Purpose: Capture screenshots of live assets using httpx.
Stores images in output dir.
"""
from modules.utils import run_command

def capture_screenshots(hosts, output_dir):
    """Capture screenshots with httpx."""
    with open('temp_live.txt', 'w') as f:
        f.write('\n'.join(hosts))
    
    cmd = ['httpx', '-l', 'temp_live.txt', '-screenshot', '-screenshots', output_dir, '-silent']
    run_command(cmd)
    
    import os
    os.remove('temp_live.txt')