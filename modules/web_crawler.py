import shlex

from core.executor import run_command
from core.web_utils import dedupe_normalized_urls, extract_urls


def run(target, verbose=False, config=None):
    cfg = config or {}
    depth = int(cfg.get("crawl_depth", 2))
    timeout = int(cfg.get("crawl_timeout", 180))

    safe_target = shlex.quote(target)
    cmd = f"katana -u {safe_target} -silent -d {depth}"
    output, code = run_command(cmd, verbose, timeout=timeout)

    urls = dedupe_normalized_urls(extract_urls(output))

    status = "ok"
    if code == 124:
        status = "timeout"
    elif code != 0:
        status = "tool_error"
    elif not urls:
        status = "no_targets"

    return {
        "status": status,
        "raw": {"katana": output},
        "parsed": {
            "urls": urls,
            "url_count": len(urls),
            "exit_code": code,
        },
    }
