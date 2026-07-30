from scripts import update_cves


def test_deduplicate_keeps_first_record() -> None:
    rows = [
        {"cve_id": "CVE-2026-0001", "title": "new"},
        {"cve_id": "CVE-2026-0001", "title": "old"},
        {"cve_id": "CVE-2026-0002", "title": "other"},
    ]
    assert update_cves.deduplicate(rows) == [rows[0], rows[2]]
