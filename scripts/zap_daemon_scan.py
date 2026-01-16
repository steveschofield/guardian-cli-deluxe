#!/usr/bin/env python3
"""
Run an OWASP ZAP scan using an already-running ZAP daemon (local or remote) via the ZAP API.

This is intentionally conservative by default:
- Spider (optional) + passive scan (baseline-ish)
- Optional active scan only when explicitly requested (and Guardian safe_mode allows it)

Outputs a JSON document to stdout containing alerts.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional


def _join(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


def _get_json(url: str, timeout: float = 30.0) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "guardian-zap-daemon-scan/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    try:
        return json.loads(data.decode("utf-8", errors="replace") or "{}")
    except Exception as e:
        raise RuntimeError(f"Failed to parse JSON from {url}: {e}")


def _api_url(api_base: str, component: str, kind: str, method: str, params: Dict[str, Any]) -> str:
    # ZAP API paths look like: /JSON/<component>/<view|action>/<method>/
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    return _join(api_base, f"JSON/{component}/{kind}/{method}/") + (f"?{query}" if query else "")


def _api_other_url(api_base: str, component: str, method: str, params: Dict[str, Any]) -> str:
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    return _join(api_base, f"OTHER/{component}/other/{method}/") + (f"?{query}" if query else "")


def _get_raw(url: str, timeout: float = 30.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "guardian-zap-daemon-scan/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _sleep_poll(deadline: float, interval: float = 2.0) -> None:
    if time.time() >= deadline:
        raise TimeoutError("Timed out waiting for ZAP scan to finish")
    time.sleep(interval)


def _parse_seed_urls(seed_urls: str, seed_file: str) -> list[str]:
    urls: list[str] = []
    if seed_urls:
        parts = [p.strip() for p in seed_urls.replace("\n", ",").split(",")]
        urls.extend([p for p in parts if p])
    if seed_file:
        try:
            with open(seed_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        urls.append(line)
        except Exception:
            pass
    return urls


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-url", default="http://127.0.0.1:8080", help="ZAP daemon base URL")
    ap.add_argument("--api-key", default="", help="ZAP API key (optional; empty when api.disablekey=true)")
    ap.add_argument("--target", required=True, help="Target base URL (e.g., https://example.com)")
    ap.add_argument("--spider", action="store_true", help="Run spider scan before passive/active scan")
    ap.add_argument("--ajax-spider", action="store_true", help="Run AJAX spider (useful for SPA apps)")
    ap.add_argument("--active", action="store_true", help="Run active scan (more intrusive)")
    ap.add_argument("--max-minutes", type=int, default=10, help="Max time budget for scan (minutes)")
    ap.add_argument("--max-alerts", type=int, default=5000, help="Max number of alerts to fetch")
    ap.add_argument("--har-out", default="", help="Write HAR output to this path (optional)")
    ap.add_argument("--ignore-robots", action="store_true", help="Ignore robots.txt for spider")
    ap.add_argument("--seed-urls", default="", help="Comma-separated seed URLs")
    ap.add_argument("--seed-file", default="", help="File containing seed URLs (one per line)")
    ap.add_argument("--context-name", default="", help="ZAP context name (optional)")
    ap.add_argument("--include-regex", default="", help="Regex to include in context scope")
    ap.add_argument("--login-url", default="", help="Login URL for form-based auth")
    ap.add_argument("--login-request-data", default="", help="POST data template (use {username}/{password})")
    ap.add_argument("--username", default="", help="Username for auth")
    ap.add_argument("--password", default="", help="Password for auth")
    ap.add_argument("--username-field", default="username", help="Username field name for login form")
    ap.add_argument("--password-field", default="password", help="Password field name for login form")
    ap.add_argument("--logged-in-regex", default="", help="Regex indicating logged-in state")
    ap.add_argument("--logged-out-regex", default="", help="Regex indicating logged-out state")
    args = ap.parse_args(argv)

    api_base = args.api_url.rstrip("/")
    api_key = args.api_key or ""
    target = args.target.strip()

    deadline = time.time() + max(1, args.max_minutes) * 60

    warnings: list[str] = []

    # Verify ZAP is reachable.
    ver_url = _api_url(api_base, "core", "view", "version", {"apikey": api_key})
    version = _get_json(ver_url).get("version")
    if not version:
        raise RuntimeError("ZAP API reachable but version not returned; check api-url/api-key")

    # Make sure passive scanners are enabled.
    _get_json(_api_url(api_base, "pscan", "action", "enableAllScanners", {"apikey": api_key}))

    if args.ignore_robots:
        try:
            _get_json(_api_url(api_base, "spider", "action", "setOptionHandleRobotsTxt", {"apikey": api_key, "Boolean": "false"}))
        except Exception as e:
            warnings.append(f"Failed to disable robots.txt handling: {e}")

    # Access target once to seed the sites tree.
    _get_json(_api_url(api_base, "core", "action", "accessUrl", {"apikey": api_key, "url": target}))

    # Seed additional URLs if provided.
    seed_urls = _parse_seed_urls(args.seed_urls, args.seed_file)
    for url in seed_urls:
        try:
            _get_json(_api_url(api_base, "core", "action", "accessUrl", {"apikey": api_key, "url": url}))
        except Exception as e:
            warnings.append(f"Seed URL failed ({url}): {e}")

    # Create context and configure auth if requested.
    context_id = ""
    user_id = ""
    context_name = ""
    if args.context_name or args.login_url or args.username:
        context_name = args.context_name or "Guardian"
        ctx = _get_json(_api_url(api_base, "context", "action", "newContext", {"apikey": api_key, "contextName": context_name}))
        context_id = ctx.get("contextId", "")
        include_regex = args.include_regex
        if not include_regex:
            parsed = urllib.parse.urlparse(target)
            include_regex = f"{parsed.scheme}://{parsed.netloc}.*"
        try:
            _get_json(
                _api_url(
                    api_base,
                    "context",
                    "action",
                    "includeInContext",
                    {"apikey": api_key, "contextName": context_name, "regex": include_regex},
                )
            )
        except Exception as e:
            warnings.append(f"Failed to include regex in context: {e}")

        if args.logged_in_regex:
            try:
                _get_json(
                    _api_url(
                        api_base,
                        "authentication",
                        "action",
                        "setLoggedInIndicator",
                        {"apikey": api_key, "contextId": context_id, "loggedInIndicatorRegex": args.logged_in_regex},
                    )
                )
            except Exception as e:
                warnings.append(f"Failed to set logged-in indicator: {e}")
        if args.logged_out_regex:
            try:
                _get_json(
                    _api_url(
                        api_base,
                        "authentication",
                        "action",
                        "setLoggedOutIndicator",
                        {"apikey": api_key, "contextId": context_id, "loggedOutIndicatorRegex": args.logged_out_regex},
                    )
                )
            except Exception as e:
                warnings.append(f"Failed to set logged-out indicator: {e}")

        if args.login_url:
            login_request_data = args.login_request_data
            if not login_request_data and args.username and args.password:
                login_request_data = f"{args.username_field}={{username}}&{args.password_field}={{password}}"
            if login_request_data:
                login_request_data = login_request_data.replace("{username}", args.username).replace("{password}", args.password)
            auth_params = {
                "loginUrl": args.login_url,
                "loginRequestData": login_request_data or "",
            }
            auth_cfg = urllib.parse.urlencode(auth_params)
            try:
                _get_json(
                    _api_url(
                        api_base,
                        "authentication",
                        "action",
                        "setAuthenticationMethod",
                        {
                            "apikey": api_key,
                            "contextId": context_id,
                            "authMethodName": "formBasedAuthentication",
                            "authMethodConfigParams": auth_cfg,
                        },
                    )
                )
            except Exception as e:
                warnings.append(f"Failed to set authentication method: {e}")

        if args.username:
            try:
                usr = _get_json(
                    _api_url(
                        api_base,
                        "users",
                        "action",
                        "newUser",
                        {"apikey": api_key, "contextId": context_id, "name": args.username},
                    )
                )
                user_id = usr.get("userId", "")
                creds = urllib.parse.urlencode({"username": args.username, "password": args.password})
                _get_json(
                    _api_url(
                        api_base,
                        "users",
                        "action",
                        "setAuthenticationCredentials",
                        {
                            "apikey": api_key,
                            "contextId": context_id,
                            "userId": user_id,
                            "authCredentialsConfigParams": creds,
                        },
                    )
                )
                _get_json(
                    _api_url(
                        api_base,
                        "users",
                        "action",
                        "setUserEnabled",
                        {"apikey": api_key, "contextId": context_id, "userId": user_id, "enabled": "true"},
                    )
                )
            except Exception as e:
                warnings.append(f"Failed to configure user: {e}")

    if args.spider:
        if context_id and user_id:
            scan_id = _get_json(
                _api_url(
                    api_base,
                    "spider",
                    "action",
                    "scanAsUser",
                    {"apikey": api_key, "contextId": context_id, "userId": user_id, "url": target},
                )
            ).get("scan")
        else:
            scan_id = _get_json(_api_url(api_base, "spider", "action", "scan", {"apikey": api_key, "url": target})).get(
                "scan"
            )
        if not scan_id:
            raise RuntimeError("Failed to start spider scan (no scan id returned)")

        while True:
            status = _get_json(_api_url(api_base, "spider", "view", "status", {"apikey": api_key, "scanId": scan_id}))
            pct = int(status.get("status") or 0)
            if pct >= 100:
                break
            _sleep_poll(deadline)

    if args.ajax_spider:
        try:
            params = {"apikey": api_key, "url": target}
            if context_name:
                params["contextName"] = context_name
            _get_json(_api_url(api_base, "spiderAjax", "action", "scan", params))
            while True:
                status = _get_json(_api_url(api_base, "spiderAjax", "view", "status", {"apikey": api_key})).get(
                    "status"
                )
                status_str = str(status or "").lower()
                if status_str in {"stopped", "0", "completed"}:
                    break
                _sleep_poll(deadline, interval=5.0)
        except Exception as e:
            warnings.append(f"AJAX spider failed: {e}")

    if args.active:
        if context_id and user_id:
            scan_id = _get_json(
                _api_url(
                    api_base,
                    "ascan",
                    "action",
                    "scanAsUser",
                    {"apikey": api_key, "contextId": context_id, "userId": user_id, "url": target},
                )
            ).get("scan")
        else:
            scan_id = _get_json(_api_url(api_base, "ascan", "action", "scan", {"apikey": api_key, "url": target})).get(
                "scan"
            )
        if not scan_id:
            raise RuntimeError("Failed to start active scan (no scan id returned)")

        while True:
            status = _get_json(_api_url(api_base, "ascan", "view", "status", {"apikey": api_key, "scanId": scan_id}))
            pct = int(status.get("status") or 0)
            if pct >= 100:
                break
            _sleep_poll(deadline, interval=5.0)

    # Wait for passive scanning queue to drain.
    while True:
        rec = _get_json(_api_url(api_base, "pscan", "view", "recordsToScan", {"apikey": api_key}))
        remaining = int(rec.get("recordsToScan") or 0)
        if remaining <= 0:
            break
        _sleep_poll(deadline)

    # Fetch alerts (paged).
    alerts: list[dict[str, Any]] = []
    start = 0
    page = 500
    max_alerts = max(1, args.max_alerts)
    while start < max_alerts:
        resp = _get_json(
            _api_url(
                api_base,
                "core",
                "view",
                "alerts",
                {"apikey": api_key, "baseurl": target, "start": start, "count": page},
            )
        )
        batch = resp.get("alerts") or []
        if not isinstance(batch, list) or not batch:
            break
        alerts.extend(batch)
        start += len(batch)
        if len(batch) < page:
            break

    har_path = ""
    har_error = ""
    if args.har_out:
        try:
            har_url = _api_other_url(api_base, "core", "har", {"apikey": api_key, "baseurl": target})
            har_data = _get_raw(har_url)
            out_path = Path(args.har_out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(har_data)
            har_path = str(out_path)
        except Exception as e:
            har_error = str(e)

    out = {
        "zap": {"api_url": api_base, "version": version},
        "target": target,
        "mode": "daemon",
        "spider": bool(args.spider),
        "ajax_spider": bool(args.ajax_spider),
        "active": bool(args.active),
        "context": args.context_name or "",
        "warnings": warnings,
        "har_path": har_path,
        "har_error": har_error,
        "alerts": alerts,
        "count": len(alerts),
    }
    sys.stdout.write(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise
    except Exception as e:
        sys.stderr.write(f"ERROR: {e}\n")
        raise SystemExit(2)
