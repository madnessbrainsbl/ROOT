"""Append newly listed CISA KEV CVEs to the local Zero-Days catalog."""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "js" / "data" / "zerodays.js"
KEV_SEED = ROOT / "data" / "cves_kev_sync.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_catalog() -> dict:
    text = CATALOG.read_text(encoding="utf-8")
    prefix = "const ZERO_DAYS = "
    start = text.find(prefix)
    if start < 0 or not text.rstrip().endswith(";"):
        raise ValueError("Unexpected zero-day catalog format")
    return json.loads(text[start + len(prefix) :].rstrip()[:-1])


def fetch_kev() -> dict:
    request = Request(KEV_URL, headers={"User-Agent": "ROOT-zero-day-sync/1.0"})
    with urlopen(request, timeout=15) as response:
        return json.load(response)


def entry(record: dict, number: int) -> dict:
    cve = record["cveID"]
    product = (
        " ".join(
            value
            for value in (record.get("vendorProject"), record.get("product"))
            if value
        )
        or "CISA KEV entry"
    )
    summary = record.get("shortDescription") or record.get("vulnerabilityName") or cve
    description = html.escape(summary)
    return {
        "n": number,
        "id": f"zd-{number:02d}",
        "cve": cve,
        "product": product,
        "cwe": "CISA KEV",
        "category": "kev",
        "category_en": "CISA KEV",
        "category_ru": "CISA KEV",
        "summary_en": summary,
        "summary_ru": summary,
        "practice": "generic",
        "owasp_note": "—",
        "flag": f"FLAG{{zd_{number:02d}_{cve.replace('-', '').lower()}}}",
        "points": 10,
        "diff": 2,
        "theory_en": f"<h3>What happened</h3><p>{description}</p><h3>Recommended action</h3><p>{html.escape(record.get('requiredAction') or 'Apply the vendor update and verify remediation.')}</p>",
        "theory_ru": f"<h3>Что произошло</h3><p>{description}</p><h3>Рекомендуемое действие</h3><p>{html.escape(record.get('requiredAction') or 'Установите обновление производителя и проверьте устранение.')}</p>",
        "sources": [{"name": "CISA KEV", "url": KEV_URL}],
        "feed_from": "CISA KEV",
    }


def write_kev_seed(catalog: dict, kev: dict) -> None:
    known = {
        item.get("cve")
        for item in catalog.get("items", [])
        if item.get("feed_from") == "CISA KEV"
    }
    rows = [
        {
            "cve_id": record["cveID"],
            "title": record.get("vulnerabilityName") or record["cveID"],
            "description": record.get("shortDescription", ""),
            "severity": "NONE",
            "cvss_score": None,
            "affected_vendor": record.get("vendorProject", ""),
            "affected_product": record.get("product", ""),
            "published_at": f"{record.get('dateAdded', '')}T00:00:00Z",
            "updated_at": f"{record.get('dateAdded', '')}T00:00:00Z",
            "references": [KEV_URL],
            "is_kev": True,
            "source": "CISA KEV",
        }
        for record in kev.get("vulnerabilities", [])
        if record.get("cveID") in known
    ]
    KEV_SEED.parent.mkdir(exist_ok=True)
    KEV_SEED.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    try:
        catalog = load_catalog()
        kev = fetch_kev()
    except (OSError, ValueError, json.JSONDecodeError, URLError) as error:
        print(f":: Zero-Days sync skipped: {error}", file=sys.stderr)
        return 0

    items = catalog.get("items", [])
    known = {item.get("cve") for item in items}
    dates = {
        row.get("cveID"): row.get("dateAdded", "")
        for row in kev.get("vulnerabilities", [])
    }
    latest = max((dates.get(cve, "") for cve in known), default="")
    new = sorted(
        (
            row
            for row in kev.get("vulnerabilities", [])
            if row.get("cveID") not in known and row.get("dateAdded", "") > latest
        ),
        key=lambda row: (row.get("dateAdded", ""), row.get("cveID", "")),
    )
    if not new:
        write_kev_seed(catalog, kev)
        print(
            f":: Zero-Days: up to date (CISA KEV {kev.get('catalogVersion', 'unknown')})"
        )
        return 0

    start = max((int(item.get("n", 0)) for item in items), default=0)
    items.extend(entry(row, start + offset) for offset, row in enumerate(new, 1))
    catalog["version"] = int(catalog.get("version", 0)) + 1
    CATALOG.write_text(
        "const ZERO_DAYS = "
        + json.dumps(catalog, ensure_ascii=False, indent=2)
        + ";\n",
        encoding="utf-8",
    )
    write_kev_seed(catalog, kev)
    print(
        f":: Zero-Days: added {len(new)} CISA KEV entries (catalogVersion={kev.get('catalogVersion', 'unknown')})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
