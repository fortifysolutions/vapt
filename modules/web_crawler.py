import shlex

from core.executor import run_command


def run(target, verbose=False):
    safe_target = shlex.quote(target)
    output, code = run_command(f"katana -u {safe_target} -silent", verbose)

    urls = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)

    # Preserve order while de-duplicating
    deduped = list(dict.fromkeys(urls))

    result = {
        "raw": {
            "katana": output
        },
        "parsed": {
            "urls": deduped,
            "url_count": len(deduped)
        }
    }

    if code != 0:
        result["error"] = "katana execution failed"

    return result
