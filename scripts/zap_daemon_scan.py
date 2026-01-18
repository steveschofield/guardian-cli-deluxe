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


def _generate_html_report(data: Dict[str, Any]) -> str:
    """Generate a simple HTML report from ZAP scan data."""
    alerts = data.get("alerts", [])
    target = data.get("target", "")
    zap_info = data.get("zap", {})
    warnings = data.get("warnings", [])

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>ZAP Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; margin-top: 30px; }}
        .alert {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .alert-high {{ border-left: 5px solid #d9534f; }}
        .alert-medium {{ border-left: 5px solid #f0ad4e; }}
        .alert-low {{ border-left: 5px solid #5bc0de; }}
        .alert-info {{ border-left: 5px solid #5cb85c; }}
        .meta {{ color: #777; font-size: 0.9em; }}
        .warning {{ background: #fff3cd; padding: 10px; border-left: 3px solid #ffc107; margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>OWASP ZAP Scan Report</h1>
    <div class="meta">
        <p><strong>Target:</strong> {target}</p>
        <p><strong>ZAP Version:</strong> {zap_info.get('version', 'unknown')}</p>
        <p><strong>Mode:</strong> {data.get('mode', 'daemon')}</p>
        <p><strong>Spider:</strong> {data.get('spider', False)}</p>
        <p><strong>AJAX Spider:</strong> {data.get('ajax_spider', False)}</p>
        <p><strong>Active Scan:</strong> {data.get('active', False)}</p>
        <p><strong>Total Alerts:</strong> {len(alerts)}</p>
    </div>
"""

    if warnings:
        html += "    <h2>Warnings</h2>\n"
        for warning in warnings:
            html += f'    <div class="warning">{warning}</div>\n'

    html += "    <h2>Alerts</h2>\n"

    if not alerts:
        html += "    <p>No alerts found.</p>\n"
    else:
        for alert in alerts:
            risk = str(alert.get("risk") or alert.get("riskdesc", "")).lower()
            alert_class = f"alert-{risk}" if risk in ["high", "medium", "low", "info"] else "alert"
            name = alert.get("name") or alert.get("alert", "Unknown")
            desc = alert.get("desc") or alert.get("description", "")
            solution = alert.get("solution", "")
            confidence = alert.get("confidence", "")
            url = alert.get("url", "")
            evidence = alert.get("evidence", "")

            html += f'    <div class="alert {alert_class}">\n'
            html += f'        <h3>{name}</h3>\n'
            html += f'        <p><strong>Risk:</strong> {risk.upper()} | <strong>Confidence:</strong> {confidence}</p>\n'
            if url:
                html += f'        <p><strong>URL:</strong> {url}</p>\n'
            if evidence:
                html += f'        <p><strong>Evidence:</strong> <code>{evidence}</code></p>\n'
            if desc:
                html += f'        <p><strong>Description:</strong> {desc}</p>\n'
            if solution:
                html += f'        <p><strong>Solution:</strong> {solution}</p>\n'
            html += '    </div>\n'

    html += """</body>
</html>
"""
    return html


def _generate_md_report(data: Dict[str, Any]) -> str:
    """Generate a Markdown report from ZAP scan data."""
    alerts = data.get("alerts", [])
    target = data.get("target", "")
    zap_info = data.get("zap", {})
    warnings = data.get("warnings", [])

    md = f"""# OWASP ZAP Scan Report

## Target Information
- **Target**: {target}
- **ZAP Version**: {zap_info.get('version', 'unknown')}
- **Mode**: {data.get('mode', 'daemon')}
- **Spider**: {data.get('spider', False)}
- **AJAX Spider**: {data.get('ajax_spider', False)}
- **Active Scan**: {data.get('active', False)}
- **Total Alerts**: {len(alerts)}

"""

    if warnings:
        md += "## Warnings\n\n"
        for warning in warnings:
            md += f"- {warning}\n"
        md += "\n"

    md += "## Alerts\n\n"

    if not alerts:
        md += "No alerts found.\n"
    else:
        for i, alert in enumerate(alerts, 1):
            risk = str(alert.get("risk") or alert.get("riskdesc", "")).upper()
            name = alert.get("name") or alert.get("alert", "Unknown")
            desc = alert.get("desc") or alert.get("description", "")
            solution = alert.get("solution", "")
            confidence = alert.get("confidence", "")
            url = alert.get("url", "")
            evidence = alert.get("evidence", "")

            md += f"### {i}. {name}\n\n"
            md += f"**Risk**: {risk} | **Confidence**: {confidence}\n\n"
            if url:
                md += f"**URL**: `{url}`\n\n"
            if evidence:
                md += f"**Evidence**: `{evidence}`\n\n"
            if desc:
                md += f"**Description**: {desc}\n\n"
            if solution:
                md += f"**Solution**: {solution}\n\n"
            md += "---\n\n"

    return md


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
    ap.add_argument("--json-out", default="", help="Write JSON report to this path (optional)")
    ap.add_argument("--html-out", default="", help="Write HTML report to this path (optional)")
    ap.add_argument("--md-out", default="", help="Write Markdown report to this path (optional)")
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

    # Write JSON report to file if requested
    if args.json_out:
        try:
            json_path = Path(args.json_out)
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to write JSON report: {e}\n")

    # Write HTML report if requested
    if args.html_out:
        try:
            html_path = Path(args.html_out)
            html_path.parent.mkdir(parents=True, exist_ok=True)
            html_content = _generate_html_report(out)
            html_path.write_text(html_content, encoding="utf-8")
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to write HTML report: {e}\n")

    # Write Markdown report if requested
    if args.md_out:
        try:
            md_path = Path(args.md_out)
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_content = _generate_md_report(out)
            md_path.write_text(md_content, encoding="utf-8")
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to write Markdown report: {e}\n")

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
