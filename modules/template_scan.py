import re
import shlex

from core.executor import run_command


def extract_nuclei_severity(output):
    severities = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    output_lower = output.lower()
    for sev in severities:
        severities[sev] = len(re.findall(rf"\[{sev}\]", output_lower))

    return severities


def run(target, verbose=False, config=None):
    cfg = config or {}
    tags = cfg.get("nuclei_tags", "")
    timeout = int(cfg.get("template_timeout", 360))

    safe_target = shlex.quote(target)
    cmd = f"nuclei -u {safe_target} -silent -ni"
    if tags:
        cmd += f" -tags {shlex.quote(tags)}"

    output, code = run_command(cmd, verbose, timeout=timeout)
    severity_counts = extract_nuclei_severity(output)
    finding_count = sum(severity_counts.values())

    status = "ok"
    if code == 124:
        status = "timeout"
    elif code != 0 and finding_count == 0:
        status = "tool_error"

    return {
        "status": status,
        "raw": {"nuclei": output},
        "parsed": {
            "target": target,
            "severity_counts": severity_counts,
            "finding_count": finding_count,
            "exit_code": code,
        },
    }
