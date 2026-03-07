#!/usr/bin/env python3

import argparse
import os
import importlib
import re
import urllib.parse

from core.config import APP_NAME, VERSION, OUTPUT_DIR
from core.precheck import run_precheck
from core.reporter import (
    initialize_report,
    save_json_report,
    save_html_report
)
from core.profile_loader import load_profile


WEB_CHAIN_RUNNERS = {"xss_scan", "sqli_scan", "template_scan"}


def create_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)


def is_valid_target(target):
    pattern = re.compile(r"^[a-zA-Z0-9\.\-\:\/\_\?\=\&]+$")
    return bool(pattern.match(target))


def dedupe(items):
    return list(dict.fromkeys([x for x in items if x]))


def parameterized_urls(urls):
    items = []
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                items.append(url)
        except Exception:
            continue
    return items


def run_batch_module(module, targets, verbose):
    batch = {}
    errors = 0

    for t in targets:
        result = module.run(t, verbose)
        batch[t] = result
        if isinstance(result, dict) and "error" in result:
            errors += 1

    return {
        "raw": {
            "batch": batch
        },
        "parsed": {
            "scanned_targets": len(targets),
            "errors": errors,
            "successful": len(targets) - errors
        }
    }


def main():

    parser = argparse.ArgumentParser(description=APP_NAME)

    parser.add_argument("--target", required=True, help="Target domain or IP")
    parser.add_argument(
        "--profile",
        default="quick",
        help="Scan profile (quick / standard / deep / webapp)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose mode"
    )
    parser.add_argument(
        "--auto-install",
        action="store_true",
        help="Automatically install missing tools"
    )
    parser.add_argument(
        "--max-web-targets",
        type=int,
        default=20,
        help="Maximum discovered URLs for chained web scanning"
    )

    args = parser.parse_args()

    print(f"\n{APP_NAME} v{VERSION}\n")

    if not is_valid_target(args.target):
        print("[!] Invalid target format. Aborting to prevent execution errors.")
        return

    create_output_dir()

    if not run_precheck(auto_install=args.auto_install):
        print("[!] Precheck failed. Exiting.")
        return

    report_data = initialize_report(args.target)
    modules_to_run = load_profile(args.profile)

    if not modules_to_run:
        print("[!] No modules found in selected profile.")
        return

    print(f"[+] Modules to run: {modules_to_run}\n")

    chain_context = {
        "crawler_urls": [args.target],
        "parameter_urls": parameterized_urls([args.target])
    }

    for module_name in modules_to_run:
        try:
            module = importlib.import_module(f"modules.{module_name}")

            if module_name in WEB_CHAIN_RUNNERS:
                targets = chain_context["parameter_urls"]
                if not targets:
                    targets = chain_context["crawler_urls"]
                targets = dedupe(targets)[: max(args.max_web_targets, 1)]

                result = run_batch_module(module, targets, args.verbose)
            else:
                result = module.run(args.target, args.verbose)

                if module_name == "web_crawler":
                    discovered = result.get("parsed", {}).get("urls", [])
                    chain_context["crawler_urls"] = dedupe(chain_context["crawler_urls"] + discovered)
                    chain_context["parameter_urls"] = dedupe(
                        chain_context["parameter_urls"] + parameterized_urls(discovered)
                    )

                if module_name == "param_discovery":
                    discovered = result.get("parsed", {}).get("parameter_urls", [])
                    chain_context["parameter_urls"] = dedupe(chain_context["parameter_urls"] + discovered)

            report_data["modules"][module_name] = result
            print(f"[✓] Module completed: {module_name}")

        except Exception as e:
            print(f"[!] Module failed: {module_name} - Error: {str(e)}")
            report_data["modules"][module_name] = {
                "error": str(e)
            }

    report_data["summary"]["chain_context"] = {
        "discovered_urls": len(chain_context["crawler_urls"]),
        "parameter_urls": len(chain_context["parameter_urls"]),
        "max_web_targets": args.max_web_targets
    }

    save_json_report(report_data)
    save_html_report(report_data)

    print("\n[✓] Scan completed successfully.")
    print("[✓] Reports generated inside output/ directory.\n")


if __name__ == "__main__":
    main()
