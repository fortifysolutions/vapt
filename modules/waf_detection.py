# modules/waf_detection.py

import re
import shlex
from core.executor import run_command


def extract_waf_name(output):
    """
    Parses wafw00f output to extract the specific WAF vendor.
    Example WAFw00f output: 'The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.'
    """
    # Regex looks for the vendor name sandwiched between 'is behind' and 'WAF'
    match = re.search(r"is behind (.*?) WAF", output, re.IGNORECASE)

    if match:
        return match.group(1).strip()

    # Fallback if a WAF is detected but the specific vendor isn't named in the standard format
    if "is behind" in output.lower():
        return "Generic / Unidentified WAF"

    return "None"


def run(target, verbose=False):
    # 1. Defense-in-depth against command injection
    safe_target = shlex.quote(target)

    # 2. Execute wafw00f (No URL stripping needed, wafw00f handles full URLs perfectly)
    waf_output, _ = run_command(f"wafw00f {safe_target}", verbose)

    # 3. Extract the specific vendor name
    waf_name = extract_waf_name(waf_output)
    detected = waf_name != "None"

    return {
        "raw": {
            "wafw00f": waf_output
        },
        "parsed": {
            "waf_detected": detected,
            "waf_name": waf_name
        }
    }