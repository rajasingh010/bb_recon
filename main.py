# bb_recon/main.py
import argparse
import concurrent.futures
import os
import logging
from modules import target_acquisition, subdomain_enum, http_probe, vuln_scan, js_discovery, screenshot, utils

# Setup logging
logging.basicConfig(filename='logs/recon.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Recon Automation Tool")
    parser.add_argument('--targets', required=True, help='File with list of targets (one domain per line) or comma-separated domains')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads for parallel processing')
    parser.add_argument('--output-dir', default='outputs', help='Output directory')
    parser.add_argument('--passive-only', action='store_true', help='Use only passive recon methods')
    parser.add_argument('--delay', type=int, default=1, help='Delay in seconds between tool calls to handle rate limits')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs('logs', exist_ok=True)

    # Step 1: Acquire targets
    targets = target_acquisition.get_targets(args.targets)
    logging.info(f"Acquired {len(targets)} targets")

    # Process each target in parallel where possible
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_target = {executor.submit(process_target, target, args): target for target in targets}
        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            try:
                results[target] = future.result()
            except Exception as e:
                logging.error(f"Error processing {target}: {e}")

    # Export aggregated results
    utils.export_to_json(results, os.path.join(args.output_dir, 'full_results.json'))
    utils.export_to_csv(results, os.path.join(args.output_dir, 'full_results.csv'))  # Flatten for CSV
    logging.info("Recon completed")

def process_target(target, args):
    """Process recon steps for a single target with delays for rate limiting."""
    import time
    result = {'target': target}

    # Subdomain enum and ASN
    subdomains, asn = subdomain_enum.enumerate_subdomains(target, passive_only=args.passive_only)
    result['subdomains'] = subdomains
    result['asn'] = asn
    time.sleep(args.delay)

    # HTTP probe
    probe_results = http_probe.probe_hosts(subdomains)
    result['probes'] = probe_results
    time.sleep(args.delay)

    # Vuln scan on live hosts
    live_hosts = [host for host, data in probe_results.items() if data['status'] in [200, 301, 302]]
    vuln_results = vuln_scan.scan_vulns(live_hosts)
    result['vulns'] = vuln_results
    time.sleep(args.delay)

    # JS discovery
    js_files, secrets = js_discovery.discover_js(target, subdomains)
    result['js_files'] = js_files
    result['secrets'] = secrets
    time.sleep(args.delay)

    # Screenshots
    screenshot.capture_screenshots(live_hosts, args.output_dir)
    result['screenshots'] = [f"{host}.png" for host in live_hosts]  # Assuming filenames
    time.sleep(args.delay)

    # Per-target export
    utils.export_to_json(result, os.path.join(args.output_dir, f"{target}_results.json"))
    utils.export_to_csv(result, os.path.join(args.output_dir, f"{target}_results.csv"))

    return result

if __name__ == "__main__":
    main()