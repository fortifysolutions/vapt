# core/precheck.py

from core.config import REQUIRED_TOOLS
from core.installer import tool_exists, install_tool
from core.logger import log


def run_precheck(auto_install=False):

    missing = []

    for tool in REQUIRED_TOOLS:
        if not tool_exists(tool):
            missing.append(tool)

    if missing:
        print(f"[!] Missing tools: {missing}")
        log(f"Missing tools detected: {missing}")

        if auto_install:
            for tool in missing:
                install_tool(tool)

        else:
            print("Please install required tools.")
            return False

    print("[✓] Precheck completed.")
    return True
