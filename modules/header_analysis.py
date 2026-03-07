# modules/header_analysis.py

import shlex
from core.executor import run_command

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options"
]


def run(target, verbose=False):
    # Defense-in-depth against basic shell injection
    safe_target = shlex.quote(target)

    # -s: silent (removes progress bar)
    # -I: fetch headers only
    # -L: follow redirects to scan the final destination
    headers_output, _ = run_command(f"curl -s -I -L {safe_target}", verbose)

    missing = []

    # Convert the entire curl output to lowercase once for accurate matching
    headers_lower = headers_output.lower()

    for header in SECURITY_HEADERS:
        if header not in headers_lower:
            missing.append(header)

    return {
        "raw": {
            "headers": headers_output
        },
        "parsed": {
            "missing_security_headers": missing,
            "missing_count": len(missing)
        }
    }