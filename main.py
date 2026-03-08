#!/usr/bin/env python3

import argparse
import datetime
import importlib
import os
import re

from core.config import APP_NAME, VERSION, OUTPUT_DIR
from core.precheck import run_precheck
from core.profile_loader import load_profile
from core.reporter import initialize_report, save_json_report, save_html_report
from core.web_utils import dedupe_normalized_urls, parameterized_urls, write_lines


WEB_CHAIN_RUNNERS = {"xss_scan", "sqli_scan", "template_scan"}


def create_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)


def is_valid_target(target):
    pattern = re.compile(r"^[a-zA-Z0-9\.\-\:\/\_\?\=\&]+$")
    return bool(pattern.match(target))


def run_module(module, target, verbose=False, config=None):
    try:
        return module.run(target, verbose, config=config)
    except TypeError:
        return module.run(target, verbose)


def ensure_status(result):
    if not isinstance(result, dict):
        return {"status": "parse_error", "error": "module returned non-dict"}
    if "status" not in result:
        if "error" in result:
            result["status"] = "tool_error"
        else:
            result["status"] = "ok"
    return result


def run_batch_module(module, targets, verbose, config, max_targets):
    targets = dedupe_normalized_urls(targets)[: max(max_targets, 1)]

    if not targets:
        return {
            "status": "no_targets",
            "raw": {"batch": {}},
            "parsed": {
                "executed_targets": [],
                "skipped_targets": [],
                "scanned_targets": 0,
                "errors": 0,
                "successful": 0,
            },
        }

    batch = {}
    errors = 0
    skipped = []

    for t in targets:
        result = ensure_status(run_module(module, t, verbose, config=config))
        batch[t] = result
        if result.get("status") in {"tool_error", "timeout", "parse_error", "error"}:
            errors += 1
        if result.get("status") == "no_targets":
            skipped.append({"target": t, "reason": "no_parameter_targets"})

    return {
        "status": "ok" if errors == 0 else "tool_error",
        "raw": {"batch": batch},
        "parsed": {
            "executed_targets": targets,
            "skipped_targets": skipped,
            "scanned_targets": len(targets),
            "errors": errors,
            "successful": len(targets) - errors,
        },
    }


def save_chain_artifacts(run_id, chain_context):
    artifact_dir = os.path.join(OUTPUT_DIR, "artifacts", run_id)
    os.makedirs(artifact_dir, exist_ok=True)

    write_lines(os.path.join(artifact_dir, "crawler_urls.txt"), chain_context["crawler_urls"])
    write_lines(os.path.join(artifact_dir, "parameter_urls.txt"), chain_context["parameter_urls"])
    write_lines(os.path.join(artifact_dir, "xss_targets.txt"), chain_context.get("xss_targets", []))
    write_lines(os.path.join(artifact_dir, "sqli_targets.txt"), chain_context.get("sqli_targets", []))
    write_lines(os.path.join(artifact_dir, "template_targets.txt"), chain_context.get("template_targets", []))

    return artifact_dir


def main():
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--target", required=True, help="Target domain or IP")
    parser.add_argument("--profile", default="quick", help="Scan profile (quick / standard / deep / webapp / regression_web)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--auto-install", action="store_true", help="Automatically install missing tools")

    parser.add_argument("--max-web-targets", type=int, default=20, help="Maximum discovered URLs for chained web scanning")
    parser.add_argument("--crawl-depth", type=int, default=2)
    parser.add_argument("--xss-max-targets", type=int, default=30)
    parser.add_argument("--sqli-max-targets", type=int, default=20)
    parser.add_argument("--sqli-risk", type=int, default=1)
    parser.add_argument("--sqli-level", type=int, default=2)
    parser.add_argument("--nuclei-tags", default="")
    parser.add_argument("--cookie", default="", help="Session cookie for authenticated scanning (example: session=abc123)")
    parser.add_argument("--auth-header", default="", help="Authorization header value (example: Bearer <token>)")

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
        "crawler_urls": dedupe_normalized_urls([args.target]),
        "parameter_urls": parameterized_urls([args.target]),
        "xss_targets": [],
        "sqli_targets": [],
        "template_targets": [],
    }

    module_config = {
        "crawl_depth": args.crawl_depth,
        "sqli_risk": args.sqli_risk,
        "sqli_level": args.sqli_level,
        "nuclei_tags": args.nuclei_tags,
        "cookie": args.cookie,
        "auth_header": args.auth_header,
    }

    for module_name in modules_to_run:
        try:
            module = importlib.import_module(f"modules.{module_name}")

            if module_name in WEB_CHAIN_RUNNERS:
                if module_name in {"xss_scan", "sqli_scan"}:
                    targets = chain_context["parameter_urls"]
                    if not targets:
                        result = {
                            "status": "no_targets",
                            "raw": {"batch": {}},
                            "parsed": {
                                "executed_targets": [],
                                "skipped_targets": [{"target": args.target, "reason": "no_parameter_targets"}],
                                "scanned_targets": 0,
                                "errors": 0,
                                "successful": 0,
                            },
                        }
                        report_data["modules"][module_name] = result
                        print(f"[!] Module skipped: {module_name} (no parameterized URLs)")
                        continue
                else:
                    targets = chain_context["parameter_urls"] or chain_context["crawler_urls"]

                max_targets = args.max_web_targets
                if module_name == "xss_scan":
                    max_targets = args.xss_max_targets
                    chain_context["xss_targets"] = dedupe_normalized_urls(targets)[: max_targets]
                elif module_name == "sqli_scan":
                    max_targets = args.sqli_max_targets
                    chain_context["sqli_targets"] = dedupe_normalized_urls(targets)[: max_targets]
                elif module_name == "template_scan":
                    chain_context["template_targets"] = dedupe_normalized_urls(targets)[: max_targets]

                result = run_batch_module(module, targets, args.verbose, module_config, max_targets)
            else:
                result = ensure_status(run_module(module, args.target, args.verbose, config=module_config))

                if module_name == "web_crawler":
                    discovered = result.get("parsed", {}).get("urls", [])
                    chain_context["crawler_urls"] = dedupe_normalized_urls(chain_context["crawler_urls"] + discovered)
                    chain_context["parameter_urls"] = parameterized_urls(chain_context["crawler_urls"])

                if module_name == "param_discovery":
                    discovered = result.get("parsed", {}).get("parameter_urls", [])
                    chain_context["parameter_urls"] = dedupe_normalized_urls(chain_context["parameter_urls"] + discovered)

            report_data["modules"][module_name] = result
            print(f"[✓] Module completed: {module_name}")

        except Exception as e:
            print(f"[!] Module failed: {module_name} - Error: {str(e)}")
            report_data["modules"][module_name] = {"status": "error", "error": str(e)}

    run_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    artifact_dir = save_chain_artifacts(run_id, chain_context)

    report_data["summary"]["chain_context"] = {
        "discovered_urls": len(chain_context["crawler_urls"]),
        "parameter_urls": len(chain_context["parameter_urls"]),
        "max_web_targets": args.max_web_targets,
        "xss_max_targets": args.xss_max_targets,
        "sqli_max_targets": args.sqli_max_targets,
        "artifacts_dir": artifact_dir,
    }

    save_json_report(report_data)
    save_html_report(report_data)

    print("\n[✓] Scan completed successfully.")
    print("[✓] Reports generated inside output/ directory.\n")


if __name__ == "__main__":
    main()
