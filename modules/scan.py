# modules/scan.py

import re
import shlex
import urllib.parse
from core.executor import run_command


def extract_domain(target):
    """Strips https:// and paths to provide a clean IP or domain for Nmap"""
    if target.startswith("http://") or target.startswith("https://"):
        return urllib.parse.urlparse(target).netloc.split(':')[0]
    return target.split(':')[0]


def extract_service_data(nmap_output):
    """
    Extracts the port, service name, and specific version running.
    Example Nmap line: '22/tcp  open  ssh   OpenSSH 8.2p1'
    """
    services = []
    # Regex captures Group 1 (Port), Group 2 (Service), Group 3 (Version details)
    pattern = re.compile(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)")

    for line in nmap_output.split('\n'):
        match = pattern.search(line)
        if match:
            services.append({
                "port": match.group(1),
                "service": match.group(2),
                "version": match.group(3).strip()
            })

    return services


def run(target, verbose=False):
    clean_target = extract_domain(target)
    safe_target = shlex.quote(clean_target)

    # -sV: Version detection
    # -Pn: Skip host discovery
    # -T4: Aggressive timing template to speed up the scan
    # --open: Only show open ports to reduce noise in the raw output
    command = f"nmap -sV -Pn -T4 --open {safe_target}"
    nmap_output, _ = run_command(command, verbose)

    services = extract_service_data(nmap_output)

    return {
        "raw": {
            "nmap": nmap_output
        },
        "parsed": {
            "services": services,
            "port_count": len(services)
        }
    }