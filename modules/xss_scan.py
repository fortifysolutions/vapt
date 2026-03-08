import shlex

from core.executor import run_command


XSS_MARKERS = [
    "[poc]",
    "vulnerable",
    "found xss",
    "triggered",
    "reflected",
]


def _extract_evidence(output):
    lines = []
    for line in output.splitlines():
        low = line.lower()
        if any(marker in low for marker in XSS_MARKERS):
            lines.append(line.strip())
    return lines


def run(target, verbose=False, config=None):
    cfg = config or {}
    timeout = int(cfg.get("xss_timeout", 300))
    cookie = (cfg.get("cookie") or "").strip()
    auth_header = (cfg.get("auth_header") or "").strip()

    safe_target = shlex.quote(target)
    cmd = f"dalfox url {safe_target} --skip-bav --no-color"
    if cookie:
        cmd += f" --cookie {shlex.quote(cookie)}"
    if auth_header:
        cmd += f" -H {shlex.quote(f'Authorization: {auth_header}')}"
    output, code = run_command(cmd, verbose, timeout=timeout)

    evidence = _extract_evidence(output)

    status = "ok"
    if code == 124:
        status = "timeout"
    elif code != 0:
        status = "tool_error"

    return {
        "status": status,
        "raw": {"dalfox": output},
        "parsed": {
            "target": target,
            "finding_count": len(evidence),
            "possible_findings": len(evidence) > 0,
            "evidence_lines": evidence[:20],
            "exit_code": code,
        },
    }
