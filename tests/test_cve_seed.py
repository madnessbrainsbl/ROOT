import hashlib
import json
from pathlib import Path

import pytest

from scripts import build_cve_seed


def test_cvelist_url_uses_expected_bucket() -> None:
    assert build_cve_seed.cvelist_url("CVE-2023-23397").endswith(
        "/2023/23xxx/CVE-2023-23397.json"
    )


def test_write_seed_records_hash(tmp_path: Path) -> None:
    output = tmp_path / "cves_public.json"
    rows = [{"cve_id": "CVE-2026-0001", "title": "RØOT"}]
    build_cve_seed.write_seed(rows, output)
    provenance = json.loads(
        output.with_suffix(".provenance.json").read_text(encoding="utf-8")
    )
    assert provenance["records"] == 1
    assert provenance["sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()


@pytest.mark.parametrize("cve_id", ["CVE-2026-1", "invalid"])
def test_cvelist_url_rejects_malformed_id(cve_id: str) -> None:
    with pytest.raises((ValueError, IndexError)):
        build_cve_seed.cvelist_url(cve_id)
