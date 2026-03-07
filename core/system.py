# core/system.py
import platform
import subprocess

def detect_os():
    return platform.system()

def detect_distro():
    try:
        # shell=False for security, using list format
        output = subprocess.check_output(["lsb_release", "-si"], text=True)
        return output.strip()
    except FileNotFoundError:
        return "Unknown (lsb_release not installed)"
    except subprocess.CalledProcessError:
        return "Unknown"

def get_package_manager():
    return "apt"