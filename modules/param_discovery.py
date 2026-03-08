import glob
import os
import shlex
import urllib.parse

from core.executor import run_command
from core.web_utils import dedupe_normalized_urls, extract_urls


def extract_domain(target):
    if target.startswith("http://") or target.startswith("https://"):
        return urllib.parse.urlparse(target).netloc.split(":")[0]
    return target.split(":")[0]


def _read_paramspider_files(domain):
    candidates = [
        f"results/{domain}.txt",
        f"output/{domain}.txt",
        f"{domain}.txt",
    ]
    candidates.extend(glob.glob("results/*.txt"))

    text_chunks = []
    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text_chunks.append(f.read())
            except Exception:
                continue
    return "\n".join(text_chunks)


def run(target, verbose=False, config=None):
    domain = extract_domain(target)
    safe_domain = shlex.quote(domain)

    timeout = int((config or {}).get("param_timeout", 240))
    output, code = run_command(f"paramspider -d {safe_domain}", verbose, timeout=timeout)

    file_output = _read_paramspider_files(domain)
    combined = f"{output}\n{file_output}"

    urls = [url for url in extract_urls(combined) if "?" in url]
    deduped = dedupe_normalized_urls(urls)

    status = "ok"
    if code == 124:
        status = "timeout"
    elif code != 0 and not deduped:
        status = "tool_error"
    elif not deduped:
        status = "no_targets"

    return {
        "status": status,
        "raw": {"paramspider": output},
        "parsed": {
            "parameter_urls": deduped,
            "parameter_count": len(deduped),
            "exit_code": code,
            "source_file_used": bool(file_output.strip()),
        },
    }
