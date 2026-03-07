# core/config.py

APP_NAME = "Fortify Solutions - VAPT Framework"
VERSION = "3.1 Core 2026"

DEFAULT_TIMEOUT = 900  # seconds

REQUIRED_TOOLS = [
    "whois",
    "nmap",
    "curl",
    "wafw00f",
    "sslscan",
    "testssl.sh",
    "nikto",
    "nuclei",
    "katana",
    "paramspider",
    "dalfox",
    "sqlmap",
    "lsb_release",
    "stdbuf"
]

OUTPUT_DIR = "output"
LOG_FILE = "fortify.log"
