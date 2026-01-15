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


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-url", default="http://127.0.0.1:8080", help="ZAP daemon base URL")
    ap.add_argument("--api-key", default="", help="ZAP API key (optional; empty when api.disablekey=true)")
    ap.add_argument("--target", required=True, help="Target base URL (e.g., https://example.com)")
    ap.add_argument("--spider", action="store_true", help="Run spider scan before passive/active scan")
    ap.add_argument("--active", action="store_true", help="Run active scan (more intrusive)")
    ap.add_argument("--max-minutes", type=int, default=10, help="Max time budget for scan (minutes)")
    ap.add_argument("--max-alerts", type=int, default=5000, help="Max number of alerts to fetch")
    ap.add_argument("--har-out", default="", help="Write HAR output to this path (optional)")
    args = ap.parse_args(argv)

    api_base = args.api_url.rstrip("/")
    api_key = args.api_key or ""
    target = args.target.strip()

    deadline = time.time() + max(1, args.max_minutes) * 60

    # Verify ZAP is reachable.
    ver_url = _api_url(api_base, "core", "view", "version", {"apikey": api_key})
    version = _get_json(ver_url).get("version")
    if not version:
        raise RuntimeError("ZAP API reachable but version not returned; check api-url/api-key")

    # Make sure passive scanners are enabled.
    _get_json(_api_url(api_base, "pscan", "action", "enableAllScanners", {"apikey": api_key}))

    # Access target once to seed the sites tree.
    _get_json(_api_url(api_base, "core", "action", "accessUrl", {"apikey": api_key, "url": target}))

    if args.spider:
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

    if args.active:
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
        "active": bool(args.active),
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
