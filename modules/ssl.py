# modules/ssl.py

import re
import shlex
import urllib.parse
import concurrent.futures
from core.executor import run_command


def extract_domain(target):
    """Strips https:// and paths to provide a clean IP or domain for SSL tools"""
    if target.startswith("http://") or target.startswith("https://"):
        return urllib.parse.urlparse(target).netloc.split(':')[0]
    return target.split(':')[0]


def detect_weak_tls(output):
    """
    Parses testssl.sh output using regex to avoid false positives.
    Looks specifically for findings marked as 'offered' or vulnerable.
    """
    weak_versions = ["TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"]
    found = []

    for version in weak_versions:
        # Regex looks for the version name followed by "offered" on the same line
        pattern = rf"{version}.*offered"
        if re.search(pattern, output, re.IGNORECASE):
            found.append(version)

    return found


def run(target, verbose=False):
    # 1. Clean the target to prevent tool crashes
    clean_target = extract_domain(target)

    # 2. Prevent command injection
    safe_target = shlex.quote(clean_target)

    # 3. Run sslscan and testssl.sh concurrently to drastically reduce scan time
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Standard fast scan
        future_sslscan = executor.submit(
            run_command,
            f"sslscan {safe_target}",
            verbose
        )

        # --quiet: Suppress banner
        # --fast: Skip advanced time-consuming tests (like exact cipher enumeration) to prioritize protocol versions
        future_testssl = executor.submit(
            run_command,
            f"testssl.sh --quiet --fast {safe_target}",
            verbose
        )

        sslscan_output, _ = future_sslscan.result()
        testssl_output, _ = future_testssl.result()

    weak_tls = detect_weak_tls(testssl_output)

    return {
        "raw": {
            "sslscan": sslscan_output,
            "testssl": testssl_output
        },
        "parsed": {
            "weak_tls_versions": weak_tls,
            "weak_tls_detected": len(weak_tls) > 0
        }
    }