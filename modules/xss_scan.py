import shlex

from core.executor import run_command


def run(target, verbose=False):
    safe_target = shlex.quote(target)
    output, code = run_command(f"dalfox url {safe_target} --skip-bav --silence", verbose)

    result = {
        "raw": {
            "dalfox": output
        },
        "parsed": {
            "target": target,
            "possible_findings": "[POC]" in output or "VULN" in output.upper()
        }
    }

    if code != 0:
        result["error"] = "dalfox execution failed"

    return result
