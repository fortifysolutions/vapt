import shlex

from core.executor import run_command


SQLI_MARKERS = [
    "is vulnerable",
    "parameter",
    "appears to be injectable",
    "sql injection",
]


NO_SQLI_MARKERS = [
    "all tested parameters do not appear to be injectable",
    "not injectable",
]


def _extract_sqli_evidence(output):
    evidence = []
    for line in output.splitlines():
        low = line.lower()
        if any(marker in low for marker in SQLI_MARKERS):
            evidence.append(line.strip())
    return evidence


def run(target, verbose=False, config=None):
    cfg = config or {}
    risk = int(cfg.get("sqli_risk", 1))
    level = int(cfg.get("sqli_level", 2))
    timeout = int(cfg.get("sqli_timeout", 420))
    cookie = (cfg.get("cookie") or "").strip()
    auth_header = (cfg.get("auth_header") or "").strip()

    safe_target = shlex.quote(target)
    cmd = f"sqlmap -u {safe_target} --batch --risk={risk} --level={level} --smart"
    if cookie:
        cmd += f" --cookie {shlex.quote(cookie)}"
    if auth_header:
        cmd += f" --headers {shlex.quote(f'Authorization: {auth_header}')}"
    output, code = run_command(cmd, verbose, timeout=timeout)

    lower = output.lower()
    evidence = _extract_sqli_evidence(output)
    no_injection = any(x in lower for x in NO_SQLI_MARKERS)
    likely_sqli = len(evidence) > 0 and not no_injection

    status = "ok"
    if code == 124:
        status = "timeout"
    elif code != 0 and not likely_sqli:
        status = "tool_error"

    return {
        "status": status,
        "raw": {"sqlmap": output},
        "parsed": {
            "target": target,
            "finding_count": len(evidence) if likely_sqli else 0,
            "possible_sqli": likely_sqli,
            "evidence_lines": evidence[:20],
            "exit_code": code,
        },
    }
