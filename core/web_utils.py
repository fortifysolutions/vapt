import os
import re
import urllib.parse


URL_RE = re.compile(r"https?://[^\s'\"<>]+")


def extract_urls(text):
    if not text:
        return []
    return URL_RE.findall(text)


def normalize_url(url):
    try:
        parsed = urllib.parse.urlsplit(url.strip())
        if not parsed.scheme or not parsed.netloc:
            return ""

        query_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query = urllib.parse.urlencode(sorted(query_items))

        normalized = urllib.parse.urlunsplit((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            query,
            "",
        ))
        return normalized
    except Exception:
        return ""


def dedupe_normalized_urls(urls):
    seen = set()
    out = []
    for url in urls:
        norm = normalize_url(url)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return out


def parameterized_urls(urls):
    results = []
    for url in urls:
        try:
            if urllib.parse.urlsplit(url).query:
                results.append(url)
        except Exception:
            continue
    return dedupe_normalized_urls(results)


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(f"{line}\n")
