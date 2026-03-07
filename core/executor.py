# core/executor.py

import subprocess
import shlex
from core.config import DEFAULT_TIMEOUT
from core.logger import log


def run_command(command, verbose=False, timeout=DEFAULT_TIMEOUT):
    log(f"Executing: {command}")

    try:
        # 1. Safely parse the command string into a list of arguments
        command_list = shlex.split(command)

        # 2. Prepend the stdbuf command elements safely to the list
        full_command_list = ["stdbuf", "-oL"] + command_list

        process = subprocess.Popen(
            full_command_list,
            shell=False,  # <-- CRITICAL FIX: OS Command Injection neutralized
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1  # Ensures line-buffering for real-time verbose output
        )

        output = ""

        # Read output line-by-line for the verbose flag
        for line in iter(process.stdout.readline, ''):
            if not line:
                break
            output += line
            if verbose:
                print(line.strip())

        # Enforce the timeout
        process.wait(timeout=timeout)

        return output, process.returncode

    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()  # Clean up the zombie process after killing it
        log(f"Command timed out: {command}")
        return "[!] Command timed out.", 1

    except Exception as e:
        log(f"Execution error ({command}): {str(e)}")
        return str(e), 1