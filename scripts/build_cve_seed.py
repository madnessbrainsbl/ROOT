#!/usr/bin/env python3
"""Build the bundled CVE seed from CISA KEV and CVE List V5."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / "data" / "cves_public.json"
CISA_KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
CVELIST_RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
USER_AGENT = "ROOT/0.1 public-seed-builder"
CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")


def fetch_json(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise TypeError(f"Expected a JSON object from {url}")
    return payload


def cvelist_url(cve_id: str) -> str:
    match = CVE_ID_RE.fullmatch(cve_id)
    if match is None:
        raise ValueError(f"Invalid CVE ID: {cve_id}")
    year, number = match.groups()
    bucket = f"{int(number) // 1000}xxx"
    return f"{CVELIST_RAW}/{year}/{bucket}/{cve_id}.json"


def english(items: list[dict[str, Any]] | None, key: str = "value") -> str:
    for item in items or []:
        if item.get("lang") == "en" and item.get(key):
            return str(item[key])
    return next((str(item[key]) for item in items or [] if item.get(key)), "")


def normalize_cvelist(record: dict[str, Any]) -> dict[str, Any]:
    metadata = record["cveMetadata"]
    cna = record.get("containers", {}).get("cna", {})
    affected = cna.get("affected", [])
    metrics = cna.get("metrics", [])
    metric = next(
        (
            item[key]
            for item in metrics
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
            if key in item
        ),
        {},
    )
    cwes = {
        description["cweId"]
        for problem in cna.get("problemTypes", [])
        for description in problem.get("descriptions", [])
        if description.get("cweId")
    }
    references = [
        reference["url"]
        for reference in cna.get("references", [])
        if reference.get("url")
    ]
    title = cna.get("title") or english(cna.get("descriptions"))
    return {
        "cve_id": metadata["cveId"],
        "title": title,
        "description": english(cna.get("descriptions")),
        "severity": metric.get("baseSeverity", "NONE"),
        "cvss_score": metric.get("baseScore"),
        "cvss_vector": metric.get("vectorString"),
        "cwe_id": ", ".join(sorted(cwes)) or None,
        "affected_vendor": ", ".join(
            sorted({str(item["vendor"]) for item in affected if item.get("vendor")})
        ),
        "affected_product": ", ".join(
            sorted({str(item["product"]) for item in affected if item.get("product")})
        ),
        "published_at": metadata.get("datePublished"),
        "updated_at": metadata.get("dateUpdated"),
        "references": references,
        "is_kev": True,
        "source": "CVE List V5 + CISA KEV",
    }


def fallback_record(kev: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": kev["cveID"],
        "title": kev.get("vulnerabilityName", ""),
        "description": kev.get("shortDescription", ""),
        "severity": "NONE",
        "cvss_score": None,
        "cvss_vector": None,
        "cwe_id": None,
        "affected_vendor": kev.get("vendorProject", ""),
        "affected_product": kev.get("product", ""),
        "published_at": kev.get("dateAdded"),
        "updated_at": None,
        "references": [CISA_KEV_URL],
        "is_kev": True,
        "source": "CISA KEV",
    }


def build_record(kev: dict[str, Any], timeout: float) -> dict[str, Any]:
    try:
        record = normalize_cvelist(fetch_json(cvelist_url(kev["cveID"]), timeout))
    except (KeyError, ValueError, urllib.error.URLError, TimeoutError) as error:
        print(f"warning: {kev['cveID']}: {error}", file=sys.stderr)
        record = fallback_record(kev)
    record.update(
        kev_date_added=kev.get("dateAdded"),
        kev_due_date=kev.get("dueDate"),
        kev_required_action=kev.get("requiredAction"),
        known_ransomware_campaign_use=kev.get("knownRansomwareCampaignUse"),
    )
    return record


def write_seed(rows: list[dict[str, Any]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(rows, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    output.write_bytes(encoded)
    provenance = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "records": len(rows),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "sources": [
            {
                "name": "CISA Known Exploited Vulnerabilities",
                "url": "https://github.com/cisagov/kev-data",
            },
            {"name": "CVE List V5", "url": "https://github.com/CVEProject/cvelistV5"},
        ],
    }
    output.with_suffix(".provenance.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=250)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if not 1 <= args.limit <= 2_000:
        parser.error("--limit must be between 1 and 2000")
    if not 1 <= args.workers <= 16:
        parser.error("--workers must be between 1 and 16")

    catalog = fetch_json(CISA_KEV_URL, args.timeout)
    vulnerabilities = catalog.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise TypeError("CISA KEV response has no vulnerabilities array")
    selected = sorted(
        vulnerabilities,
        key=lambda item: (str(item.get("dateAdded", "")), str(item.get("cveID", ""))),
        reverse=True,
    )[: args.limit]
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        rows = list(executor.map(lambda row: build_record(row, args.timeout), selected))
    write_seed(rows, args.output)
    print(f"wrote {len(rows)} public records to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
