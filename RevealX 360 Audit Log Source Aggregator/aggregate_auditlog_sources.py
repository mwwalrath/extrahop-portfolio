#!/usr/bin/env python3
# Copyright (c) 2026, ExtraHop Networks. All rights reserved.
# Licensed under the BSD 2-Clause License. See LICENSE for details.
"""
aggregate_auditlog_sources.py

Pulls RevealX 360 audit log entries via REST API, extracts source IPs from
authentication events (UI Login and REST API Auth), and aggregates per /24
network for scoping a RevealX 360 Allow List.

Version: 1.0

Required environment variables (use a .env file in the same directory):
  EH_API_HOST    Hostname from the RX360 API Access page, e.g.
                 <tenant>.api.cloud.extrahop.com (no scheme, no path)
  EH_API_ID      REST API credential ID
  EH_API_SECRET  REST API credential secret

Minimum required REST API credential privilege: System Administration.
"""

from __future__ import annotations

import argparse
import base64
import csv
import ipaddress
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Callable

import requests
from dotenv import load_dotenv


PAGE_SIZE_DEFAULT = 1000
MAX_PAGES_DEFAULT = 200
LOOKBACK_DAYS_DEFAULT = 30
RETRY_ATTEMPTS = 3
RETRY_BACKOFF_INITIAL = 1.0

DETAILS_IP_RE = re.compile(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE)

# Plain DNS hostname: letters, digits, dots, hyphens. No scheme, path, or whitespace.
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.-]+$")

# RFC 6598 Shared Address Space. AWS NLB internal hops fall in this range.
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

# Characters that trigger formula evaluation when a spreadsheet opens a CSV cell.
# OWASP CSV injection mitigation: prefix any cell starting with these.
CSV_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


# ---------------------------------------------------------------------------
# Pure helpers (covered by tests)
# ---------------------------------------------------------------------------

def _validate_ip(s: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return an ip_address object if s parses, else None. Try/except wrapper."""
    if not isinstance(s, str):
        return None
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def extract_source_ip(body: object) -> str | None:
    """Return the source IP for an audit entry, or None.

    Two paths because the audit log is inconsistent:
      - REST API 'Auth' events expose a structured 'src_ip' field, sometimes
        as an X-Forwarded-For chain. We take the leftmost (original client).
      - UI 'Login' events leave src_ip empty and embed the IP in the free-text
        'details' string ("Login succeeded from <IP> ..."). Regex fallback.
    """
    if not isinstance(body, dict):
        return None
    src_field = body.get("src_ip")
    if isinstance(src_field, str) and src_field.strip():
        first = src_field.split(",")[0].strip()
        if _validate_ip(first):
            return first
    details = body.get("details")
    if isinstance(details, str):
        m = DETAILS_IP_RE.search(details)
        if m and _validate_ip(m.group(1)):
            return m.group(1)
    return None


def to_bucket(ip_str: str) -> str | None:
    """Bucket an IP into its containing /24 (IPv4) or /48 (IPv6). None on garbage."""
    addr = _validate_ip(ip_str)
    if addr is None:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip_str}/48", strict=False))


def classify_address(ip_str: str) -> str:
    """Classify an IP for Allow List scoping.

    Returns:
      public      Routable, valid Allow List candidate.
      private     RFC 1918 (10/8, 172.16/12, 192.168/16).
      cgnat       RFC 6598 (100.64/10). Includes AWS NLB internal hops.
      loopback    127/8.
      link_local  169.254/16.
      reserved    Multicast, broadcast, other non-public.
      invalid     Did not parse.
    """
    addr = _validate_ip(ip_str)
    if addr is None:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if isinstance(addr, ipaddress.IPv4Address):
        if addr in CGNAT_NETWORK:
            return "cgnat"
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return "reserved"
    if addr.is_private:
        return "private"
    if not addr.is_global:
        return "reserved"
    return "public"


def classify_event(operation: object, details: object) -> tuple[str, str]:
    """Map operation+details to (category, outcome).

    category: UI (UI Login), API (REST API token request), other (post-auth ops).
    outcome:  success or fail, based on a 'failed' marker in details.

    Heuristic. May need adjustment for audit log formats produced by older
    firmware versions or alternate identity providers.
    """
    op = operation.lower() if isinstance(operation, str) else ""
    det = details.lower() if isinstance(details, str) else ""
    if op == "login":
        category = "UI"
    elif op == "auth":
        category = "API"
    else:
        category = "other"
    if det.startswith("failed") or "login failed" in det:
        outcome = "fail"
    else:
        outcome = "success"
    return category, outcome


def sanitize_csv_cell(value: object) -> str:
    """Neutralize CSV formula injection on cells from untrusted sources.

    Excel and other spreadsheet apps execute cells starting with =, +, -, @,
    tab, or CR as formulas. Audit log strings can flow into the output, so
    we prefix anything starting with a trigger character with an apostrophe.
    """
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in CSV_FORMULA_TRIGGERS:
        return "'" + s
    return s


def validate_hostname(host: object) -> bool:
    """Return True if host is a plain DNS hostname (no scheme, no path, no whitespace)."""
    return isinstance(host, str) and bool(HOSTNAME_RE.match(host))


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

def get_token(host: str, client_id: str, client_secret: str) -> str:
    """Exchange OIDC client credentials for a 10-minute access token."""
    auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    resp = requests.post(
        f"https://{host}/oauth2/token",
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data="grant_type=client_credentials",
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def fetch_page(host: str, token: str, limit: int, offset: int) -> list:
    """One GET /auditlog page. Raises HTTPError on non-2xx."""
    resp = requests.get(
        f"https://{host}/api/v1/auditlog",
        headers={"Authorization": f"Bearer {token}"},
        params={"limit": limit, "offset": offset},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, list) else []


def fetch_page_with_retry(
    host: str,
    get_fresh_token: Callable[[], str],
    current_token: str,
    limit: int,
    offset: int,
) -> tuple[list, str]:
    """Fetch a page with bounded retry.

    Behavior:
      - 401 (token expired): refresh via get_fresh_token() and retry without sleeping.
      - 5xx or connection error: sleep with exponential backoff and retry.
      - Other 4xx: raise immediately.
      - Out of attempts: raise the last exception.

    Returns (page, current_token). current_token may be updated by a refresh.
    """
    backoff = RETRY_BACKOFF_INITIAL
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            page = fetch_page(host, current_token, limit, offset)
            return page, current_token
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else 0
            if status == 401 and attempt < RETRY_ATTEMPTS:
                print("  token expired, refreshing...", file=sys.stderr)
                current_token = get_fresh_token()
                continue
            if 500 <= status < 600 and attempt < RETRY_ATTEMPTS:
                print(f"  status {status}, retrying after {backoff:.1f}s...", file=sys.stderr)
                time.sleep(backoff)
                backoff *= 2
                continue
            raise
        except (requests.ConnectionError, requests.Timeout):
            if attempt < RETRY_ATTEMPTS:
                print(f"  network error, retrying after {backoff:.1f}s...", file=sys.stderr)
                time.sleep(backoff)
                backoff *= 2
                continue
            raise


# ---------------------------------------------------------------------------
# CLI / orchestration
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aggregate RevealX 360 audit log source IPs into /24 buckets.",
    )
    parser.add_argument("--lookback-days", type=int, default=LOOKBACK_DAYS_DEFAULT,
                        help=f"How far back to scan, in days (default {LOOKBACK_DAYS_DEFAULT}, must be > 0)")
    parser.add_argument("--output", default="auditlog_sources.csv",
                        help="Output CSV path (default auditlog_sources.csv)")
    parser.add_argument("--page-size", type=int, default=PAGE_SIZE_DEFAULT,
                        help=f"Entries per page (default {PAGE_SIZE_DEFAULT}, must be > 0)")
    parser.add_argument("--max-pages", type=int, default=MAX_PAGES_DEFAULT,
                        help=f"Safety cap on pages (default {MAX_PAGES_DEFAULT}, must be > 0)")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite output file if it already exists")
    args = parser.parse_args(argv)

    if args.lookback_days <= 0:
        parser.error("--lookback-days must be > 0")
    if args.page_size <= 0:
        parser.error("--page-size must be > 0")
    if args.max_pages <= 0:
        parser.error("--max-pages must be > 0")
    return args


def load_credentials() -> tuple[str, str, str] | None:
    """Read env vars. Return (host, id, secret) or print error and return None."""
    host = os.environ.get("EH_API_HOST")
    cid = os.environ.get("EH_API_ID")
    secret = os.environ.get("EH_API_SECRET")
    missing = [k for k, v in (("EH_API_HOST", host), ("EH_API_ID", cid), ("EH_API_SECRET", secret)) if not v]
    if missing:
        print(f"ERROR: missing env vars: {', '.join(missing)}", file=sys.stderr)
        return None
    if not validate_hostname(host):
        print(f"ERROR: EH_API_HOST must be a plain hostname with no scheme or path. "
              f"Got: {host!r}", file=sys.stderr)
        return None
    return host, cid, secret


def aggregate(
    host: str,
    cid: str,
    secret: str,
    lookback_days: int,
    page_size: int,
    max_pages: int,
) -> tuple[dict, dict] | None:
    """Walk the audit log and return the populated buckets dict plus stats."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    cutoff_ms = int(cutoff.timestamp() * 1000)
    print(f"Cutoff: {cutoff.isoformat()} (occur_time >= {cutoff_ms})", file=sys.stderr)

    def get_fresh_token():
        return get_token(host, cid, secret)

    try:
        token = get_fresh_token()
    except requests.HTTPError as e:
        status = e.response.status_code if e.response is not None else 0
        print(f"ERROR: token request failed with status {status}. "
              f"Check credentials and network.", file=sys.stderr)
        return None
    except (requests.ConnectionError, requests.Timeout) as e:
        print(f"ERROR: token request network failure: {type(e).__name__}", file=sys.stderr)
        return None
    except requests.RequestException as e:
        print(f"ERROR: token request failed: {type(e).__name__}. "
              f"Check the API endpoint and any intercepting proxy.", file=sys.stderr)
        return None

    buckets = defaultdict(lambda: {
        "events_total": 0,
        "ui_success": 0, "ui_fail": 0,
        "api_success": 0, "api_fail": 0,
        "other": 0,
        "users": set(),
        "operations": set(),
        "address_class": None,
        "first_seen_ms": None,
        "last_seen_ms": None,
    })
    stats = {
        "total_processed": 0,
        "skipped_no_ip": 0,
        "skipped_malformed": 0,
        "pages_pulled": 0,
        "hit_page_cap": False,
    }
    offset = 0
    stop = False
    exited_cleanly = False

    while not stop and stats["pages_pulled"] < max_pages:
        try:
            page, token = fetch_page_with_retry(host, get_fresh_token, token, page_size, offset)
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else 0
            print(f"ERROR: page fetch failed at offset {offset} with status {status}.", file=sys.stderr)
            return None
        except (requests.ConnectionError, requests.Timeout) as e:
            print(f"ERROR: page fetch network failure at offset {offset}: {type(e).__name__}", file=sys.stderr)
            return None
        except requests.RequestException as e:
            print(f"ERROR: page fetch failed at offset {offset}: {type(e).__name__}.", file=sys.stderr)
            return None

        stats["pages_pulled"] += 1

        for entry in page:
            if not isinstance(entry, dict):
                stats["skipped_malformed"] += 1
                continue
            occur_time = entry.get("occur_time")
            if not isinstance(occur_time, (int, float)):
                stats["skipped_malformed"] += 1
                continue
            if occur_time < cutoff_ms:
                stop = True
                exited_cleanly = True
                break

            body = entry.get("body")
            if not isinstance(body, dict):
                stats["skipped_malformed"] += 1
                continue
            src_ip = extract_source_ip(body)
            if not src_ip:
                stats["skipped_no_ip"] += 1
                continue
            bucket_key = to_bucket(src_ip)
            if not bucket_key:
                stats["skipped_no_ip"] += 1
                continue

            stats["total_processed"] += 1
            op = body.get("operation")
            category, outcome = classify_event(op, body.get("details"))
            b = buckets[bucket_key]
            b["events_total"] += 1
            if category == "UI":
                b[f"ui_{outcome}"] += 1
            elif category == "API":
                b[f"api_{outcome}"] += 1
            else:
                b["other"] += 1
            user = body.get("user")
            if isinstance(user, str) and user:
                b["users"].add(user)
            if isinstance(op, str) and op:
                b["operations"].add(op)
            if b["address_class"] is None:
                b["address_class"] = classify_address(src_ip)
            if b["first_seen_ms"] is None or occur_time < b["first_seen_ms"]:
                b["first_seen_ms"] = occur_time
            if b["last_seen_ms"] is None or occur_time > b["last_seen_ms"]:
                b["last_seen_ms"] = occur_time

        print(f"  page {stats['pages_pulled']}: offset={offset} entries={len(page)} "
              f"total_processed={stats['total_processed']} buckets={len(buckets)}",
              file=sys.stderr)
        offset += len(page)
        if len(page) < page_size:
            print(f"Short page at offset {offset}. End of audit log reached.", file=sys.stderr)
            exited_cleanly = True
            break

    if not exited_cleanly and stats["pages_pulled"] >= max_pages:
        stats["hit_page_cap"] = True

    return buckets, stats


def write_csv(buckets: dict, output_path: str) -> int:
    """Render buckets dict to CSV, sanitizing user-controlled cells."""
    rows = []
    for cidr, b in buckets.items():
        users_clean = [sanitize_csv_cell(u) for u in sorted(b["users"]) if u.lower() != "unknown"]
        ops_clean = [sanitize_csv_cell(o) for o in sorted(b["operations"])]
        rows.append({
            "cidr": cidr,
            "address_class": b["address_class"],
            "events_total": b["events_total"],
            "ui_success": b["ui_success"],
            "ui_fail": b["ui_fail"],
            "api_success": b["api_success"],
            "api_fail": b["api_fail"],
            "other": b["other"],
            "distinct_users": len(b["users"]),
            "users": "; ".join(users_clean),
            "operations": "; ".join(ops_clean),
            "first_seen": datetime.fromtimestamp(b["first_seen_ms"] / 1000, tz=timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(b["last_seen_ms"] / 1000, tz=timezone.utc).isoformat(),
        })
    rows.sort(key=lambda r: r["events_total"], reverse=True)

    fieldnames = [
        "cidr", "address_class", "events_total",
        "ui_success", "ui_fail",
        "api_success", "api_fail",
        "other",
        "distinct_users", "users",
        "operations",
        "first_seen", "last_seen",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        w.writeheader()
        w.writerows(rows)
    return len(rows)


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    args = parse_args(argv)

    if os.path.exists(args.output) and not args.force:
        print(f"ERROR: output file {args.output} already exists. "
              f"Use --force to overwrite.", file=sys.stderr)
        return 1

    creds = load_credentials()
    if creds is None:
        return 1
    host, cid, secret = creds

    result = aggregate(host, cid, secret,
                       args.lookback_days, args.page_size, args.max_pages)
    if result is None:
        return 1
    buckets, stats = result

    print(f"\nDone. Processed {stats['total_processed']} entries across "
          f"{stats['pages_pulled']} pages. "
          f"Skipped: {stats['skipped_no_ip']} entries without a usable source IP, "
          f"{stats['skipped_malformed']} malformed entries.\n",
          file=sys.stderr)

    if stats["hit_page_cap"]:
        print(f"WARNING: hit --max-pages={args.max_pages} cap before reaching the "
              f"--lookback-days={args.lookback_days} cutoff. Output is INCOMPLETE. "
              f"Either raise --max-pages or shorten --lookback-days, then rerun.",
              file=sys.stderr)

    n_rows = write_csv(buckets, args.output)
    print(f"Wrote {n_rows} /24 buckets to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
