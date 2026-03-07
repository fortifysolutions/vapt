import re
import shlex

from core.executor import run_command


def extract_nuclei_severity(output):
    severities = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    output_lower = output.lower()
    for sev in severities:
        severities[sev] = len(re.findall(rf"\[{sev}\]", output_lower))

    return severities


def run(target, verbose=False):
    safe_target = shlex.quote(target)
    output, code = run_command(f"nuclei -u {safe_target} -silent -ni", verbose)

    result = {
        "raw": {
            "nuclei": output
        },
        "parsed": {
            "target": target,
            "severity_counts": extract_nuclei_severity(output)
        }
    }

    if code != 0:
        result["error"] = "nuclei execution failed"

    return result
