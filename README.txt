=========================================================
Fortify VAPT Framework v3.0
Internal Offensive Security Automation Tool
=========================================================

Author: Fortify Solutions
Environment: Kali Linux / Ubuntu / Debian
Version: 3.0 (Modular Architecture)
Output: JSON + HTML Reports
Execution: CLI-Based


=========================================================
1. OVERVIEW
=========================================================

Fortify VAPT Framework is a modular, profile-based
Web Vulnerability Assessment & Penetration Testing
automation framework.

It supports:

• Dependency validation (Precheck engine)
• Modular scan architecture
• Profile-based execution (quick / standard / deep)
• Parallel module execution
• Structured JSON output
• Professional HTML reporting
• Severity scoring engine
• Cross-compatibility (Kali / Ubuntu / Debian)


=========================================================
2. DIRECTORY STRUCTURE
=========================================================

fortify_vapt/
│
├── main.py
├── core/
│   ├── config.py
│   ├── executor.py
│   ├── precheck.py
│   ├── reporter.py
│   ├── profile_loader.py
│
├── modules/
│   ├── recon.py
│   ├── scan.py
│   ├── ssl.py
│   ├── vuln.py
│   ├── header_analysis.py
│   ├── waf_detection.py
│
├── profiles/
│   ├── quick.json
│   ├── standard.json
│   ├── deep.json
│
└── output/
    ├── report.json
    └── report.html


=========================================================
3. SYSTEM REQUIREMENTS
=========================================================

Operating Systems:
• Kali Linux (Recommended)
• Ubuntu
• Debian

Python:
• Python 3.8+

Required Tools (Auto-Detected):
• whois
• nmap
• curl
• sslscan
• testssl.sh
• nikto
• nuclei
• wafw00f

Optional:
• subfinder
• assetfinder
• httpx


=========================================================
4. INSTALLATION
=========================================================

Step 1 – Clone / Copy Framework

Place the fortify_vapt folder in desired location.

Step 2 – Ensure Python 3 is installed:

    python3 --version

Step 3 – Install dependencies (if missing):

    python3 main.py --target example.com --auto-install


=========================================================
5. USAGE
=========================================================

Basic Usage:

    python3 main.py --target example.com

With Profile Selection:

    python3 main.py --target example.com --profile standard

Deep Scan (Full Modules):

    python3 main.py --target example.com --profile deep

Verbose Mode:

    python3 main.py --target example.com --profile deep --verbose

Auto Install Missing Tools:

    python3 main.py --target example.com --auto-install


=========================================================
6. SCAN PROFILES
=========================================================

Quick Profile:
• recon module only

Standard Profile:
• recon
• scan

Deep Profile:
• recon
• scan
• ssl
• header_analysis
• waf_detection
• vuln


=========================================================
7. OUTPUT FILES
=========================================================

After scan completion:

output/report.json
    → Structured machine-readable report

output/report.html
    → Human-readable professional report

JSON report contains:
• Raw tool outputs
• Parsed intelligence
• Severity counts
• SSL weaknesses
• Missing headers
• WAF detection
• Open ports


=========================================================
8. RISK SCORING
=========================================================

Risk Score is calculated based on:

• Critical vulnerabilities
• High vulnerabilities
• Weak TLS versions
• Missing security headers

Higher score = Higher risk exposure.


=========================================================
9. LEGAL DISCLAIMER
=========================================================

This framework is strictly for:

• Authorized security testing
• Internal VAPT
• Client-approved engagements

Unauthorized scanning of systems without written
permission is illegal and punishable by law.

Fortify Solutions is not responsible for misuse.


=========================================================
10. TROUBLESHOOTING
=========================================================

If scan appears stuck:

• testssl.sh may take time (deep SSL checks)
• Use --verbose to monitor activity
• Try quick profile to isolate issue

If indentation error occurs:

Convert tabs to spaces:

    sed -i 's/\t/    /g' main.py

If module fails:

Check:
• Tool installation
• Internet connectivity
• Target reachability


=========================================================
11. FUTURE ROADMAP
=========================================================

Planned Enhancements:

• Subdomain aggregation engine
• HTTPx integration
• Screenshot capture
• CVSS mapping
• Recommendation engine
• Dashboard UI
• Docker containerization
• SOC integration


=========================================================
END OF DOCUMENT
=========================================================
