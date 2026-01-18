#!/usr/bin/env python3
"""
Launch a ZAP Docker daemon, run the daemon scan helper, then stop the container.

This is used when advanced ZAP options (auth, AJAX spider, seed URLs) are enabled
but the configured mode is docker.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse
import urllib.request


def _wait_for_api(api_url: str, timeout_s: int = 180) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{api_url.rstrip('/')}/JSON/core/view/version/") as resp:
                if resp.read():
                    return
        except Exception:
            time.sleep(2)
    raise RuntimeError("Timed out waiting for ZAP daemon API to become ready")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default="ghcr.io/zaproxy/zaproxy:stable")
    ap.add_argument("--api-url", default="http://127.0.0.1:8080")
    ap.add_argument("--container-name", default="guardian-zapd")
    ap.add_argument("--api-key", default="")
    ap.add_argument("--target", required=True)
    ap.add_argument("--max-minutes", type=int, default=10)
    ap.add_argument("--startup-timeout", type=int, default=180)
    ap.add_argument("--spider", action="store_true")
    ap.add_argument("--ajax-spider", action="store_true")
    ap.add_argument("--active", action="store_true")
    ap.add_argument("--ignore-robots", action="store_true")
    ap.add_argument("--seed-urls", default="")
    ap.add_argument("--seed-file", default="")
    ap.add_argument("--context-name", default="")
    ap.add_argument("--include-regex", default="")
    ap.add_argument("--login-url", default="")
    ap.add_argument("--login-request-data", default="")
    ap.add_argument("--username", default="")
    ap.add_argument("--password", default="")
    ap.add_argument("--username-field", default="username")
    ap.add_argument("--password-field", default="password")
    ap.add_argument("--logged-in-regex", default="")
    ap.add_argument("--logged-out-regex", default="")
    ap.add_argument("--har-out", default="")
    ap.add_argument("--json-out", default="")
    ap.add_argument("--html-out", default="")
    ap.add_argument("--md-out", default="")
    args = ap.parse_args(argv)

    api_url = args.api_url.rstrip("/")
    parsed = urlparse(api_url)
    port = parsed.port or 8080

    docker_cmd = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        args.container_name,
        "-p",
        f"{port}:8080",
        args.image,
        "zap.sh",
        "-daemon",
        "-host",
        "0.0.0.0",
        "-port",
        "8080",
        "-config",
        "api.disablekey=true",
        "-config",
        "api.addrs.addr.name=.*",
        "-config",
        "api.addrs.addr.regex=true",
    ]

    zap_daemon_scan = Path(__file__).resolve().parent / "zap_daemon_scan.py"
    scan_cmd = [
        sys.executable,
        str(zap_daemon_scan),
        "--api-url",
        api_url,
        "--target",
        args.target,
        "--max-minutes",
        str(int(args.max_minutes)),
    ]
    if args.api_key:
        scan_cmd += ["--api-key", args.api_key]
    if args.spider:
        scan_cmd.append("--spider")
    if args.ajax_spider:
        scan_cmd.append("--ajax-spider")
    if args.active:
        scan_cmd.append("--active")
    if args.ignore_robots:
        scan_cmd.append("--ignore-robots")
    if args.seed_urls:
        scan_cmd += ["--seed-urls", args.seed_urls]
    if args.seed_file:
        scan_cmd += ["--seed-file", args.seed_file]
    if args.context_name:
        scan_cmd += ["--context-name", args.context_name]
    if args.include_regex:
        scan_cmd += ["--include-regex", args.include_regex]
    if args.login_url:
        scan_cmd += ["--login-url", args.login_url]
    if args.login_request_data:
        scan_cmd += ["--login-request-data", args.login_request_data]
    if args.username:
        scan_cmd += ["--username", args.username]
    if args.password:
        scan_cmd += ["--password", args.password]
    if args.username_field:
        scan_cmd += ["--username-field", args.username_field]
    if args.password_field:
        scan_cmd += ["--password-field", args.password_field]
    if args.logged_in_regex:
        scan_cmd += ["--logged-in-regex", args.logged_in_regex]
    if args.logged_out_regex:
        scan_cmd += ["--logged-out-regex", args.logged_out_regex]
    if args.har_out:
        scan_cmd += ["--har-out", args.har_out]
    if args.json_out:
        scan_cmd += ["--json-out", args.json_out]
    if args.html_out:
        scan_cmd += ["--html-out", args.html_out]
    if args.md_out:
        scan_cmd += ["--md-out", args.md_out]

    try:
        subprocess.run(docker_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _wait_for_api(api_url, timeout_s=int(args.startup_timeout))
        proc = subprocess.run(scan_cmd, check=False)
        return int(proc.returncode or 0)
    finally:
        subprocess.run(["docker", "stop", args.container_name], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


if __name__ == "__main__":
    raise SystemExit(main())
