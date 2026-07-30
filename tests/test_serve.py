import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock

import pytest

import serve


@pytest.fixture
def api_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    rows = [
        {
            "cve_id": "CVE-2026-0001",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "affected_vendor": "Acme",
            "affected_product": "Widget",
            "published_at": "2026-07-01T00:00:00Z",
            "title": "Проверка RØOT",
        },
        {
            "cve_id": "CVE-2026-0002",
            "severity": "HIGH",
            "affected_vendor": "Example",
            "affected_product": "API",
            "published_at": "2026-06-01T00:00:00Z",
            "title": "Authorization issue",
        },
    ]
    seed = tmp_path / "cves_public.json"
    seed.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    monkeypatch.setattr(serve, "SEED_PATH", seed)
    monkeypatch.setattr(serve, "DB_PATH", tmp_path / "cves.sqlite3")
    monkeypatch.setattr(serve, "DB_BUILD_DIR", tmp_path)
    serve.set_state(imported=0, total=0, ready=False, error=None)
    serve.build_cve_db()

    server = ThreadingHTTPServer(("127.0.0.1", 0), serve.RootHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def get_json(url: str) -> tuple[dict[str, object], object]:
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.load(response), response.headers


def test_build_cve_db_reads_utf8(api_url: str) -> None:
    payload, _ = get_json(f"{api_url}/api/cves/CVE-2026-0001")
    assert payload["title"] == "Проверка RØOT"


def test_api_filters_and_validates_input(api_url: str) -> None:
    payload, headers = get_json(
        f"{api_url}/api/cves?severity=CRITICAL&q=acme&limit=10&offset=0"
    )
    assert payload["total"] == 1
    assert payload["rows"][0]["cve_id"] == "CVE-2026-0001"
    assert headers["X-Content-Type-Options"] == "nosniff"

    with pytest.raises(urllib.error.HTTPError) as error:
        get_json(f"{api_url}/api/cves?limit=invalid")
    assert error.value.code == 400
    assert json.load(error.value)["error"] == "limit must be an integer"


def test_api_is_read_only(api_url: str) -> None:
    request = urllib.request.Request(f"{api_url}/api/cves", method="POST", data=b"{}")
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request, timeout=5)
    assert error.value.code == 405
    assert json.load(error.value)["error"] == "read-only API"


def test_invalid_seed_is_rejected(tmp_path: Path) -> None:
    seed = tmp_path / "seed.json"
    seed.write_text('[{"cve_id":"not-a-cve"}]', encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid CVE record"):
        serve.load_seed(seed)


def test_auto_mode_prefers_local_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    public = tmp_path / "cves_public.json"
    public.write_text("[]", encoding="utf-8")
    chunk = tmp_path / "cves_000.json"
    chunk.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(serve, "DATA_DIR", tmp_path)
    monkeypatch.setattr(serve, "PUBLIC_SEED_PATH", public)
    monkeypatch.setattr(serve, "SEED_PATH", public)
    monkeypatch.setattr(serve, "CVE_MODE", "auto")
    assert serve.cve_source_paths() == ([chunk], "full")


def test_full_chunk_total_only_reads_last_chunk(tmp_path: Path) -> None:
    chunks = [tmp_path / f"cves_{index:03d}.json" for index in range(3)]
    chunks[-1].write_text('[{"cve_id":"CVE-2026-0001"}]', encoding="utf-8")
    assert serve.source_total(chunks, "full") == 20_001


def test_configure_stdio_uses_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    stdout = Mock()
    stderr = Mock()
    monkeypatch.setattr(serve.sys, "stdout", stdout)
    monkeypatch.setattr(serve.sys, "stderr", stderr)
    serve.configure_stdio()
    stdout.reconfigure.assert_called_once_with(encoding="utf-8")
    stderr.reconfigure.assert_called_once_with(encoding="utf-8")
