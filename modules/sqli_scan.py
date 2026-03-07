import shlex

from core.executor import run_command


def run(target, verbose=False):
    safe_target = shlex.quote(target)
    cmd = f"sqlmap -u {safe_target} --batch --crawl=1 --level=2 --smart"
    output, code = run_command(cmd, verbose)

    output_lower = output.lower()
    likely_sqli = "sql injection" in output_lower and ("vulnerable" in output_lower or "is vulnerable" in output_lower)

    result = {
        "raw": {
            "sqlmap": output
        },
        "parsed": {
            "target": target,
            "possible_sqli": likely_sqli
        }
    }

    if code != 0:
        result["error"] = "sqlmap execution failed"

    return result
