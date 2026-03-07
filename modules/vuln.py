# modules/vuln.py

import re
import shlex
import concurrent.futures
from core.executor import run_command


def extract_nuclei_severity(output):
    severities = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0  # Added 'info' to catch all Nuclei findings
    }

    # Convert output to lowercase once for efficiency
    output_lower = output.lower()

    for sev in severities.keys():
        # Using raw string (rf"") to properly escape the brackets in the regex
        severities[sev] = len(re.findall(rf"\[{sev}\]", output_lower))

    return severities


def run(target, verbose=False):
    # Defense-in-depth against command injection
    safe_target = shlex.quote(target)

    # Run Nikto and Nuclei concurrently to drastically reduce module execution time
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # -ask no: Prevents Nikto from hanging on interactive prompts
        future_nikto = executor.submit(
            run_command,
            f"nikto -h {safe_target} -maxtime 600 -ask no",
            verbose
        )

        # -ni (no-interact): Prevents Nuclei from prompting for updates/inputs
        future_nuclei = executor.submit(
            run_command,
            f"nuclei -u {safe_target} -ni",
            verbose
        )

        nikto_output, _ = future_nikto.result()
        nuclei_output, _ = future_nuclei.result()

    severity_counts = extract_nuclei_severity(nuclei_output)

    return {
        "raw": {
            "nikto": nikto_output,
            "nuclei": nuclei_output
        },
        "parsed": {
            "severity_counts": severity_counts
        }
    }