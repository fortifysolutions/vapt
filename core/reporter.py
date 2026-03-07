# core/reporter.py

import json
import datetime
import os
import html
import re
from core.config import OUTPUT_DIR


def initialize_report(target):
    return {
        "target": target,
        "timestamp": str(datetime.datetime.now()),
        "modules": {},
        "summary": {}
    }


def calculate_risk_score(data):
    score = 0
    # Uses .get() chaining to safely check values even if the module wasn't run
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


def save_json_report(data, filename="report.json"):
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

        # 1. Extract and sanitize the target name for the OS file system
    raw_target = data.get("target", "unknown_target")
        # Strip http/https and replace illegal characters (like slashes or colons) with underscores
    safe_target = re.sub(r'^https?://', '', raw_target)
    safe_target = re.sub(r'[\\/*?:"<>|]', '_', safe_target)

        # 2. Extract and format the timestamp
        # Converts "2026-03-03 09:24:55.586114" to "20260303_092455"
    raw_time = data.get("timestamp", "unknown_time")
    safe_time = raw_time.replace("-", "").replace(":", "").replace(" ", "_").split(".")[0]

        # 3. Construct the dynamic filename
    filename = f"{safe_target}_{safe_time}.json"

    path = os.path.join(OUTPUT_DIR, filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print(f"[✓] JSON report dynamically saved to {path}")



def save_html_report(data, filename="report.html"):
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    risk_score = calculate_risk_score(data)

    # Dynamic Risk Badging
    if risk_score >= 8:
        risk_color = "#e74c3c"  # Red
        risk_level = "HIGH"
    elif risk_score >= 4:
        risk_color = "#f39c12"  # Orange
        risk_level = "MEDIUM"
    else:
        risk_color = "#27ae60"  # Green
        risk_level = "LOW"

    # Executive Dashboard Template for Fortify Solutions
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Fortify Solutions | VAPT Report</title>
        <style>
            :root {{
                --primary: #2c3e50;
                --bg: #f8f9fa;
                --card-bg: #ffffff;
                --text: #333333;
                --border: #e0e0e0;
            }}
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 40px; }}
            .container {{ max-width: 1100px; margin: 0 auto; }}
            .header {{ background: var(--primary); color: white; padding: 30px; border-radius: 8px 8px 0 0; display: flex; justify-content: space-between; align-items: center; }}
            .header h1 {{ margin: 0; font-size: 24px; font-weight: 600; letter-spacing: 1px; }}
            .summary-bar {{ background: var(--card-bg); padding: 20px 30px; border-radius: 0 0 8px 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); display: flex; justify-content: space-between; border: 1px solid var(--border); border-top: none; margin-bottom: 30px; }}
            .metric {{ display: flex; flex-direction: column; }}
            .metric-title {{ font-size: 12px; text-transform: uppercase; color: #7f8c8d; font-weight: 600; margin-bottom: 5px; }}
            .metric-value {{ font-size: 18px; font-weight: bold; color: var(--primary); }}
            .risk-badge {{ background: {risk_color}; color: white; padding: 5px 12px; border-radius: 4px; font-size: 14px; font-weight: bold; }}

            .module-card {{ background: var(--card-bg); border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border: 1px solid var(--border); margin-bottom: 25px; overflow: hidden; }}
            .module-header {{ background: #ecf0f1; padding: 15px 20px; border-bottom: 1px solid var(--border); font-size: 16px; font-weight: bold; color: var(--primary); text-transform: uppercase; }}
            .module-body {{ padding: 20px; }}

            .parsed-data pre {{ background: #f4f6f7; padding: 15px; border-radius: 6px; font-family: 'Courier New', Courier, monospace; font-size: 14px; color: #d35400; overflow-x: auto; border: 1px solid #e2e6e8; }}

            details {{ margin-top: 15px; background: #fafafa; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }}
            summary {{ font-weight: bold; cursor: pointer; color: #3498db; outline: none; }}
            details pre {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 6px; font-size: 12px; overflow-x: auto; margin-top: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>FORTIFY SOLUTIONS | VAPT ASSESSMENT</h1>
            </div>
            <div class="summary-bar">
                <div class="metric">
                    <span class="metric-title">Target Infrastructure</span>
                    <span class="metric-value">{html.escape(data.get("target", "Unknown"))}</span>
                </div>
                <div class="metric">
                    <span class="metric-title">Scan Timestamp</span>
                    <span class="metric-value">{html.escape(data.get("timestamp", "Unknown"))}</span>
                </div>
                <div class="metric">
                    <span class="metric-title">Calculated Risk Score</span>
                    <span class="metric-value risk-badge">{risk_score} - {risk_level}</span>
                </div>
            </div>
    """

    for module, content in data.get("modules", {}).items():
        html_content += f"""
            <div class="module-card">
                <div class="module-header">{html.escape(module.upper())}</div>
                <div class="module-body">
        """

        if "parsed" in content:
            # Safely serialize and escape JSON blocks
            parsed_json = json.dumps(content['parsed'], indent=4)
            html_content += f'<div class="parsed-data"><pre>{html.escape(parsed_json)}</pre></div>'

        if "raw" in content:
            # Safely escape raw terminal output
            html_content += "<details><summary>View Raw Technical Output</summary>"
            for tool_name, tool_output in content["raw"].items():
                html_content += f"<h4 style='margin-bottom: 5px; color: #7f8c8d;'>{html.escape(tool_name.upper())}</h4>"
                html_content += f"<pre>{html.escape(str(tool_output))}</pre>"
            html_content += "</details>"

        html_content += "</div></div>"

    html_content += "</div></body></html>"

    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[✓] HTML report saved to {path}")