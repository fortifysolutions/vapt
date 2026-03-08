# core/executor.py

import shlex
import subprocess
from core.config import DEFAULT_TIMEOUT
from core.logger import log


def run_command(command, verbose=False, timeout=DEFAULT_TIMEOUT):
    """Run command safely with timeout and merged stdout/stderr."""
    log(f"Executing: {command}")

    try:
        cmd = ["stdbuf", "-oL"] + shlex.split(command)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )

        output = (proc.stdout or "") + (proc.stderr or "")
        if verbose and output:
            print(output)

        return output, proc.returncode

    except subprocess.TimeoutExpired:
        log(f"Command timed out: {command}")
        return "[!] Command timed out.", 124

    except Exception as exc:
        log(f"Execution error ({command}): {str(exc)}")
        return str(exc), 1
