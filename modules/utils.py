# bb_recon/modules/utils.py
"""
Module Purpose: Shared utilities for subprocess, logging, exports.
Handles errors and output parsing.
"""
import subprocess
import logging
import json
import csv

def run_command(cmd):
    """Run subprocess command, log errors."""
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
        return output
    except subprocess.CalledProcessError as e:
        logging.error(f"Command {' '.join(cmd)} failed: {e.output.decode()}")
        return ""
    except Exception as e:
        logging.error(f"Error running {' '.join(cmd)}: {e}")
        return ""

def export_to_json(data, filepath):
    """Export dict to JSON."""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

def export_to_csv(data, filepath):
    """Flatten dict and export to CSV (simple flattening for nested)."""
    # For simplicity, flatten to list of dicts
    flattened = []
    for key, val in data.items():
        if isinstance(val, list):
            for item in val:
                flattened.append({'key': key, 'value': str(item)})
        elif isinstance(val, dict):
            for subkey, subval in val.items():
                flattened.append({'key': f"{key}_{subkey}", 'value': str(subval)})
        else:
            flattened.append({'key': key, 'value': str(val)})
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['key', 'value'])
        writer.writeheader()
        writer.writerows(flattened)