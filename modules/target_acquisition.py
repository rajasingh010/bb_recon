# bb_recon/modules/target_acquisition.py
"""
Module Purpose: Handles acquisition of targets from files or inputs.
Future: Integrate APIs from HackerOne/Bugcrowd (requires auth tokens).
"""

def get_targets(target_input):
    """Read targets from file or comma-separated string."""
    if ',' in target_input:
        return [t.strip() for t in target_input.split(',')]
    else:
        with open(target_input, 'r') as f:
            return [line.strip() for line in f if line.strip()]