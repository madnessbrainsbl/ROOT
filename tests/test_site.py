from html.parser import HTMLParser
from pathlib import Path
import shlex
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent


class AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: list[str] = []
        self.base = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "base" and values.get("href"):
            self.base = values["href"] or ""
            return
        for key in ("href", "src"):
            if values.get(key):
                self.assets.append(values[key] or "")


def test_local_html_assets_exist() -> None:
    missing: list[str] = []
    for html in ROOT.rglob("*.html"):
        if any(part in {"node_modules", "playwright-report"} for part in html.parts):
            continue
        parser = AssetParser()
        parser.feed(html.read_text(encoding="utf-8"))
        base = (html.parent / parser.base).resolve() if parser.base else html.parent
        for asset in parser.assets:
            parsed = urlparse(asset)
            if (
                parsed.scheme
                or parsed.netloc
                or not parsed.path
                or parsed.path.startswith("#")
            ):
                continue
            target = (
                (ROOT / parsed.path.lstrip("/"))
                if parsed.path.startswith("/")
                else (base / parsed.path)
            )
            target = target.resolve()
            if target.is_dir():
                target /= "index.html"
            if not target.exists():
                missing.append(f"{html.relative_to(ROOT)} -> {asset}")
    assert missing == []


def test_runtime_has_no_proprietary_sync_path() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            ROOT / "serve.py",
            ROOT / "js/cve-db.js",
            ROOT / "js/cves-cvss9.js",
        ]
    ).lower()
    for forbidden in ("zerodaysignal", "/api/cves/update", "zeroday_api_key"):
        assert forbidden not in source


def test_docker_copy_sources_exist() -> None:
    missing: list[str] = []
    for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines():
        if not line.startswith("COPY "):
            continue
        sources = shlex.split(line)[1:-1]
        for source in sources:
            if not list(ROOT.glob(source.rstrip("/"))):
                missing.append(source)
    assert missing == []
