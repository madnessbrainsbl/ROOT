#!/usr/bin/env python3
"""Download CVE archive from ZeroDay Signal and rebuild local chunks."""

from __future__ import annotations

import json
import math
import os
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# ── Configuration ─────────────────────────────────────────────────────────────
EMAIL = os.environ.get("ZERODAY_EMAIL", "")
PASSWORD = os.environ.get("ZERODAY_PASSWORD", "")
API_KEY = os.environ.get("ZERODAY_API_KEY", "")
LOGIN_URL = "https://api.zerodaysignal.com/api/auth/login"
BASE_URL = "https://api.zerodaysignal.com/api/cve/recent"
PAGE_SIZE = 10
CHUNK_SIZE = 10_000
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "cves.sqlite3"
# ──────────────────────────────────────────────────────────────────────────────


def get_token(email: str, password: str) -> str:
    if not email or not password:
        raise ValueError(
            "Set ZERODAY_EMAIL and ZERODAY_PASSWORD or pass --email and --password"
        )
    payload = json.dumps({"email": email, "password": password}).encode()
    req = Request(LOGIN_URL, data=payload, headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=15) as resp:
        body = json.loads(resp.read())
    return body["access"]


def fetch_page(page: int, token: str) -> dict:
    url = f"{BASE_URL}?page={page}&limit={PAGE_SIZE}"
    req = Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 ROOT-CVE-Updater/1.0",
        },
    )
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def deduplicate(records: list[dict]) -> list[dict]:
    """Keep the newest occurrence of each CVE ID."""
    unique: dict[str, dict] = {}
    for record in records:
        unique.setdefault(record["cve_id"], record)
    return list(unique.values())


def save_chunks(records: list[dict]) -> list[Path]:
    records = deduplicate(records)
    DATA_DIR.mkdir(exist_ok=True)
    paths = []
    n_chunks = max(1, math.ceil(len(records) / CHUNK_SIZE))
    for i in range(n_chunks):
        chunk = records[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]
        path = DATA_DIR / f"cves_{i:03d}.json"
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(chunk, ensure_ascii=False, separators=(",", ":"))
        )
        temporary.replace(path)
        paths.append(path)
    for old in sorted(DATA_DIR.glob("cves_[0-9]*.json")):
        if old not in paths:
            old.unlink()
    return paths


def insert_into_db(records: list[dict]) -> None:
    if not DB_PATH.exists() or not records:
        return
    db = sqlite3.connect(DB_PATH, timeout=30)
    db.execute("PRAGMA busy_timeout=30000")
    db.executemany(
        "INSERT OR REPLACE INTO cves "
        "(cve_id, severity, cvss_score, affected_vendor, affected_product, published_at, title, data) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                r["cve_id"],
                r.get("severity"),
                r.get("cvss_score"),
                r.get("affected_vendor"),
                r.get("affected_product"),
                r.get("published_at"),
                r.get("title"),
                json.dumps(r, ensure_ascii=False, separators=(",", ":")),
            )
            for r in records
        ],
    )
    db.commit()
    db.close()


def incremental_update(token: str) -> None:
    """Fetch only pages newer than what we have, based on page-count delta."""
    chunks = sorted(DATA_DIR.glob("cves_[0-9][0-9][0-9].json"))
    local_count = sum(len(json.loads(c.read_text())) for c in chunks) if chunks else 0
    print(f"Local: {local_count} CVEs across {len(chunks)} chunks", flush=True)

    # Probe page 1 to get current total
    probe = fetch_page(1, token)
    pag = probe.get("pagination") or {}
    remote_total = pag.get("total_items", 0)
    new_count = remote_total - local_count
    if new_count <= 0:
        print(f"Already up to date ({remote_total} remote = {local_count} local).")
        return

    pages_to_fetch = math.ceil(new_count / PAGE_SIZE)
    print(
        f"Remote: {remote_total}. Need {new_count} new CVEs = {pages_to_fetch} pages.",
        flush=True,
    )

    new_records: list[dict] = []
    # Page 1 already fetched — grab its items first
    items0 = probe.get("results") or []
    new_records.extend(items0[:new_count])  # cap in case new_count < PAGE_SIZE

    pages = range(2, pages_to_fetch + 1)
    with ThreadPoolExecutor(max_workers=8) as executor:
        for page, data in zip(
            pages, executor.map(lambda page: fetch_page(page, token), pages)
        ):
            items = data.get("results") or []
            new_records.extend(items)
            print(f"PROGRESS:{page}/{pages_to_fetch}", flush=True)

    if not new_records:
        print("Nothing to add.")
        return

    print(f"Fetched {len(new_records)} new CVEs. Saving...", flush=True)

    # New records come first, so a revised CVE replaces the older copy.
    existing = [record for chunk in chunks for record in json.loads(chunk.read_text())]
    save_chunks(new_records + existing)

    insert_into_db(new_records)
    print(f"Done. {len(new_records)} CVEs added to DB and chunks.")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Update CVE archive from ZeroDay Signal"
    )
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--email", default=EMAIL)
    parser.add_argument("--password", default=PASSWORD)
    parser.add_argument(
        "--incremental",
        action="store_true",
        help="Only download CVEs not already on disk (fast)",
    )
    args = parser.parse_args()

    token = args.api_key.strip()
    if not token:
        print("Logging in to ZeroDay Signal...")
        token = get_token(args.email.strip(), args.password)
        print("  logged in")

    if args.incremental:
        incremental_update(token)
        return

    print("Fetching full CVE archive...")
    records: list[dict] = []
    page = 1
    total_pages = None

    while True:
        try:
            data = fetch_page(page, token)
        except HTTPError as e:
            print(f"HTTP {e.code}: {e.reason}", file=sys.stderr)
            sys.exit(1)
        except URLError as e:
            print(f"Network error: {e.reason}", file=sys.stderr)
            sys.exit(1)

        items = data.get("results") or (data if isinstance(data, list) else [])
        pag = data.get("pagination") or {}
        if not items:
            break
        records.extend(items)
        total_pages = pag.get("total_pages") or total_pages or 1
        print(f"  page {page}/{total_pages}: {len(records)}", flush=True)
        if page >= total_pages:
            break
        page += 1
        time.sleep(0.05)

    if not records:
        print("No records received.", file=sys.stderr)
        sys.exit(1)

    print(f"Downloaded {len(records)} CVEs. Saving chunks...")
    paths = save_chunks(records)
    print(f"Saved {len(paths)} chunk(s) to {DATA_DIR}")
    print("Restart serve.py to rebuild the SQLite database.")


if __name__ == "__main__":
    main()
