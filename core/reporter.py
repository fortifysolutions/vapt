# core/reporter.py

import datetime
import html
import json
import os
import re
from core.config import OUTPUT_DIR


def initialize_report(target):
    return {
        "target": target,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "modules": {},
        "summary": {},
    }


def calculate_risk_score(data):
    score = 0
    vuln = data.get("modules", {}).get("vuln", {}).get("parsed", {})
    ssl = data.get("modules", {}).get("ssl", {}).get("parsed", {})
    headers = data.get("modules", {}).get("header_analysis", {}).get("parsed", {})

    if vuln:
        score += vuln.get("severity_counts", {}).get("critical", 0) * 5
        score += vuln.get("severity_counts", {}).get("high", 0) * 3
        score += vuln.get("severity_counts", {}).get("medium", 0) * 1

    if ssl.get("weak_tls_detected"):
        score += 3

    score += headers.get("missing_count", 0)
    return score


def _build_safe_report_stem(data):
    raw_target = data.get("target", "unknown_target")
    safe_target = re.sub(r"^https?://", "", raw_target)
    safe_target = re.sub(r"[\\/*?:\"<>|]", "_", safe_target)

    raw_time = data.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    safe_time = raw_time.replace(":", "-").replace(" ", "_")

    return f"{safe_target}_{safe_time}"


def _collect_findings(data):
    findings = []
    status_counts = {"ok": 0, "no_targets": 0, "tool_error": 0, "timeout": 0, "parse_error": 0, "error": 0}

    for module_name, content in data.get("modules", {}).items():
        if not isinstance(content, dict):
            status_counts["parse_error"] += 1
            continue

        status = content.get("status", "ok")
        status_counts[status] = status_counts.get(status, 0) + 1

        parsed = content.get("parsed", {})
        if isinstance(parsed, dict):
            if parsed.get("possible_findings"):
                findings.append({"module": module_name, "type": "xss", "count": parsed.get("finding_count", 0)})
            if parsed.get("possible_sqli"):
                findings.append({"module": module_name, "type": "sqli", "count": parsed.get("finding_count", 0)})
            if parsed.get("finding_count", 0) and module_name == "template_scan":
                findings.append({"module": module_name, "type": "template", "count": parsed.get("finding_count", 0)})

        raw = content.get("raw", {})
        if isinstance(raw, dict) and "batch" in raw:
            for target, result in raw.get("batch", {}).items():
                if not isinstance(result, dict):
                    continue
                p = result.get("parsed", {})
                if not isinstance(p, dict):
                    continue
                if p.get("possible_findings"):
                    findings.append({"module": module_name, "target": target, "type": "xss", "count": p.get("finding_count", 0)})
                if p.get("possible_sqli"):
                    findings.append({"module": module_name, "target": target, "type": "sqli", "count": p.get("finding_count", 0)})
                if module_name == "template_scan" and p.get("finding_count", 0) > 0:
                    findings.append({"module": module_name, "target": target, "type": "template", "count": p.get("finding_count", 0)})

    data["summary"]["status_counts"] = status_counts
    data["summary"]["findings"] = findings


def save_json_report(data, filename=None):
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    _collect_findings(data)

    if not filename:
        filename = f"{_build_safe_report_stem(data)}.json"

    path = os.path.join(OUTPUT_DIR, filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print(f"[✓] JSON report saved to {path}")


def save_html_report(data, filename=None):
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    if not filename:
        filename = f"{_build_safe_report_stem(data)}.html"

    risk_score = calculate_risk_score(data)

    if risk_score >= 8:
        risk_color = "#e74c3c"
        risk_level = "HIGH"
    elif risk_score >= 4:
        risk_color = "#f39c12"
        risk_level = "MEDIUM"
    else:
        risk_color = "#27ae60"
        risk_level = "LOW"

    status_counts = data.get("summary", {}).get("status_counts", {})
    findings = data.get("summary", {}).get("findings", [])

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Fortify Solutions | VAPT Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8f9fa; color: #333; margin: 0; padding: 40px; }}
            .container {{ max-width: 1100px; margin: 0 auto; }}
            .header {{ background: #2c3e50; color: white; padding: 30px; border-radius: 8px; }}
            .block {{ background: #fff; margin-top: 20px; border: 1px solid #ddd; border-radius: 8px; padding: 16px; }}
            .risk {{ background: {risk_color}; color: white; padding: 4px 10px; border-radius: 4px; }}
            pre {{ white-space: pre-wrap; background: #f4f6f7; border: 1px solid #e2e6e8; padding: 10px; border-radius: 6px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>FORTIFY SOLUTIONS | VAPT ASSESSMENT</h1>
                <p><b>Target:</b> {html.escape(data.get('target', 'Unknown'))}</p>
                <p><b>Timestamp:</b> {html.escape(data.get('timestamp', 'Unknown'))}</p>
                <p><b>Risk:</b> <span class="risk">{risk_score} - {risk_level}</span></p>
            </div>
            <div class="block">
                <h3>Execution Status</h3>
                <pre>{html.escape(json.dumps(status_counts, indent=2))}</pre>
                <h3>Findings Summary</h3>
                <pre>{html.escape(json.dumps(findings, indent=2))}</pre>
            </div>
    """

    for module, content in data.get("modules", {}).items():
        html_content += f"""
            <div class="block">
                <h3>{html.escape(module.upper())}</h3>
                <pre>{html.escape(json.dumps(content, indent=2)[:12000])}</pre>
            </div>
        """

    html_content += "</div></body></html>"

    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[✓] HTML report saved to {path}")
