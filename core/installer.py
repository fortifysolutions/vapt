# core/installer.py
import shutil
import subprocess
from core.system import get_package_manager
from core.logger import log

def tool_exists(tool):
    return shutil.which(tool) is not None

def install_tool(tool):
    pkg_manager = get_package_manager()
    # Converted to a secure list to avoid shell injection during package installs
    command = ["sudo", pkg_manager, "install", "-y", tool]

    log(f"Installing tool: {tool}")
    subprocess.run(command, shell=False)