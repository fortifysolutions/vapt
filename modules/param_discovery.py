import shlex
import urllib.parse

from core.executor import run_command


def extract_domain(target):
    if target.startswith("http://") or target.startswith("https://"):
        return urllib.parse.urlparse(target).netloc.split(":")[0]
    return target.split(":")[0]


def run(target, verbose=False):
    domain = extract_domain(target)
    safe_domain = shlex.quote(domain)

    output, code = run_command(f"paramspider -d {safe_domain}", verbose)

    params = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("http://") or line.startswith("https://"):
            if "?" in line:
                params.append(line)

    deduped = list(dict.fromkeys(params))

    result = {
        "raw": {
            "paramspider": output
        },
        "parsed": {
            "parameter_urls": deduped,
            "parameter_count": len(deduped)
        }
    }

    if code != 0:
        result["error"] = "paramspider execution failed"

    return result
