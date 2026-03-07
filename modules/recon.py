# modules/recon.py

import urllib.parse
import shlex
import concurrent.futures
from core.executor import run_command


def extract_domain(target):
    """Strips https:// and paths to provide a clean domain/IP for whois and nmap"""
    if target.startswith("http://") or target.startswith("https://"):
        # Extracts just the domain from a full URL
        return urllib.parse.urlparse(target).netloc.split(':')[0]
    return target.split(':')[0]


def parse_whois(output):
    """Extracts key intelligence from the raw whois text"""
    parsed = {}
    # Convert to lowercase for easier matching, though keeping original case for values is ideal
    for line in output.split('\n'):
        if "Registrar:" in line and "URL" not in line:
            parsed["registrar"] = line.split(":", 1)[-1].strip()
        elif "Creation Date:" in line:
            parsed["creation_date"] = line.split(":", 1)[-1].strip()
    return parsed


def run(target, verbose=False):
    # 1. Clean the target so whois and nmap don't crash on full URLs
    clean_target = extract_domain(target)

    # 2. Prevent command injection
    safe_target = shlex.quote(clean_target)

    # 3. Run Whois and Nmap concurrently to save time
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_whois = executor.submit(run_command, f"whois {safe_target}", verbose)

        # -F: Fast scan (top 100 ports)
        # -Pn: Skip ping discovery (useful if target blocks ICMP)
        future_nmap = executor.submit(run_command, f"nmap -F -Pn {safe_target}", verbose)

        whois_output, _ = future_whois.result()
        nmap_output, _ = future_nmap.result()

    return {
        "raw": {
            "whois": whois_output,
            "nmap": nmap_output
        },
        "parsed": {
            "whois_data": parse_whois(whois_output),
            "open_ports_detected": "open" in nmap_output.lower()
        }
    }