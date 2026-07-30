#!/usr/bin/env python3
"""Serve RØOT and its read-only SQLite CVE API."""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
from contextlib import closing
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
PUBLIC_SEED_PATH = DATA_DIR / "cves_public.json"
KEV_SYNC_NAME = "cves_kev_sync.json"
SEED_PATH = Path(os.environ.get("ROOT_CVE_SEED", str(PUBLIC_SEED_PATH)))
CVE_MODE = os.environ.get("ROOT_CVE_MODE", "auto").strip().lower()
DB_PATH = Path(os.environ.get("ROOT_DB_PATH", str(DATA_DIR / "cves.sqlite3")))
# SQLite locking is unreliable on shared folders (for example vmhgfs-fuse).
# Build locally, then copy the completed database into its configured location.
DB_BUILD_DIR = Path(os.environ.get("ROOT_DB_BUILD_DIR", tempfile.gettempdir()))
TEXT_ENCODING = "utf-8"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
MAX_LIMIT = 100
MAX_QUERY_LENGTH = 200
CVE_CHUNK_SIZE = 10_000
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
STATE: dict[str, Any] = {
    "imported": 0,
    "total": 0,
    "ready": False,
    "error": None,
    "dataset": None,
}
STATE_LOCK = threading.Lock()


def configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding=TEXT_ENCODING)


def connect(path: Path | None = None) -> sqlite3.Connection:
    target = path or DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    database = sqlite3.connect(target, timeout=30)
    database.execute("PRAGMA busy_timeout=30000")
    return database


def set_state(**values: Any) -> None:
    with STATE_LOCK:
        STATE.update(values)


def load_seed(path: Path | None = None) -> list[dict[str, Any]]:
    seed = path or SEED_PATH
    payload = json.loads(seed.read_text(encoding=TEXT_ENCODING))
    if not isinstance(payload, list):
        raise TypeError(f"{seed} must contain a JSON array")
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(payload):
        if not isinstance(row, dict) or not CVE_ID_RE.fullmatch(
            str(row.get("cve_id", ""))
        ):
            raise ValueError(f"Invalid CVE record at index {index}")
        rows.append(row)
    return rows


def cve_source_paths() -> tuple[list[Path], str]:
    if CVE_MODE not in {"auto", "public", "full"}:
        raise ValueError("ROOT_CVE_MODE must be auto, public, or full")
    if SEED_PATH != PUBLIC_SEED_PATH:
        return [SEED_PATH], "custom"
    if CVE_MODE == "public":
        return [PUBLIC_SEED_PATH], "public"
    chunks = sorted(DATA_DIR.glob("cves_[0-9][0-9][0-9].json"))
    if chunks:
        kev = DATA_DIR / KEV_SYNC_NAME
        return ([kev] if kev.is_file() else []) + chunks, "full"
    if CVE_MODE == "full":
        raise FileNotFoundError("Full CVE dataset chunks are missing")
    return [PUBLIC_SEED_PATH], "public"


def source_signature(paths: list[Path]) -> str:
    return json.dumps(
        [(path.name, path.stat().st_size, path.stat().st_mtime_ns) for path in paths],
        separators=(",", ":"),
    )


def source_total(paths: list[Path], dataset: str) -> int:
    chunks = [p for p in paths if re.fullmatch(r"cves_\d{3}\.json", p.name)]
    extras = [path for path in paths if path not in chunks]
    if dataset == "full" and chunks:
        return sum(len(load_seed(path)) for path in extras) + (
            (len(chunks) - 1) * CVE_CHUNK_SIZE + len(load_seed(chunks[-1]))
        )
    return sum(len(load_seed(path)) for path in paths)


def use_current_database(signature: str, dataset: str) -> bool:
    if not DB_PATH.is_file():
        return False
    try:
        with closing(sqlite3.connect(DB_PATH, timeout=30)) as database:
            stored = database.execute(
                "SELECT value FROM metadata WHERE key = 'source_signature'"
            ).fetchone()
            if stored is None or stored[0] != signature:
                return False
            total = database.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        set_state(imported=total, total=total, ready=True, error=None, dataset=dataset)
        return True
    except sqlite3.Error:
        return False


def create_schema(database: sqlite3.Connection) -> None:
    database.executescript(
        """
        CREATE TABLE cves (
          cve_id TEXT PRIMARY KEY,
          severity TEXT NOT NULL,
          cvss_score REAL,
          affected_vendor TEXT NOT NULL,
          affected_product TEXT NOT NULL,
          published_at TEXT,
          title TEXT NOT NULL,
          data TEXT NOT NULL
        );
        CREATE TABLE metadata (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        """
    )


def build_cve_db() -> None:
    temporary = DB_BUILD_DIR / f".{DB_PATH.name}.tmp"
    staging = DB_PATH.with_suffix(".staging.sqlite3")
    try:
        paths, dataset = cve_source_paths()
        signature = source_signature(paths)
        if use_current_database(signature, dataset):
            return
        total = source_total(paths, dataset)
        set_state(imported=0, total=total, ready=False, error=None, dataset=dataset)
        DB_BUILD_DIR.mkdir(parents=True, exist_ok=True)
        temporary.unlink(missing_ok=True)
        database = connect(temporary)
        try:
            database.execute("PRAGMA journal_mode=OFF")
            database.execute("PRAGMA synchronous=OFF")
            create_schema(database)
            imported = 0
            for path in paths:
                rows = load_seed(path)
                for start in range(0, len(rows), 500):
                    batch = rows[start : start + 500]
                    database.executemany(
                        """
                        INSERT OR REPLACE INTO cves
                        (cve_id, severity, cvss_score, affected_vendor,
                         affected_product, published_at, title, data)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        [
                            (
                                row["cve_id"],
                                str(row.get("severity") or "NONE").upper(),
                                row.get("cvss_score"),
                                str(row.get("affected_vendor") or ""),
                                str(row.get("affected_product") or ""),
                                row.get("published_at"),
                                str(row.get("title") or row["cve_id"]),
                                json.dumps(
                                    row,
                                    ensure_ascii=False,
                                    separators=(",", ":"),
                                ),
                            )
                            for row in batch
                        ],
                    )
                    imported += len(batch)
                    set_state(imported=imported)
                database.commit()
            database.executescript(
                """
                CREATE INDEX cves_published_idx ON cves(published_at DESC);
                CREATE INDEX cves_severity_published_idx
                  ON cves(severity, published_at DESC, cve_id DESC);
                """
            )
            database.executemany(
                "INSERT INTO metadata (key, value) VALUES (?, ?)",
                (("source_signature", signature), ("dataset", dataset)),
            )
            database.commit()
        finally:
            database.close()
        if temporary.parent.resolve() == DB_PATH.parent.resolve():
            temporary.replace(DB_PATH)
        else:
            staging.unlink(missing_ok=True)
            shutil.copyfile(temporary, staging)
            staging.replace(DB_PATH)
            temporary.unlink()
        with closing(connect()) as database:
            imported = database.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        set_state(imported=imported, total=imported, ready=True)
    except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error) as error:
        temporary.unlink(missing_ok=True)
        staging.unlink(missing_ok=True)
        set_state(ready=False, error=str(error))
        print(
            f"CVE database initialization failed: {error}", file=sys.stderr, flush=True
        )


def parse_bounded_int(
    params: dict[str, list[str]], name: str, default: int, minimum: int, maximum: int
) -> int:
    raw = params.get(name, [str(default)])[0]
    try:
        value = int(raw)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def where_clause(params: dict[str, list[str]]) -> tuple[str, list[str]]:
    clauses: list[str] = []
    values: list[str] = []
    severity = params.get("severity", [""])[0].strip().upper()
    query = params.get("q", [""])[0].strip()
    if severity:
        if severity not in VALID_SEVERITIES:
            raise ValueError("severity is invalid")
        clauses.append("severity = ?")
        values.append(severity)
    if len(query) > MAX_QUERY_LENGTH:
        raise ValueError(f"q must not exceed {MAX_QUERY_LENGTH} characters")
    if query:
        pattern = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append(
            "(cve_id LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' "
            "OR affected_vendor LIKE ? ESCAPE '\\' "
            "OR affected_product LIKE ? ESCAPE '\\')"
        )
        values.extend([f"%{pattern}%"] * 4)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", values


class RootHandler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:
        message = fmt % args
        if "favicon" not in message:
            sys.stderr.write(f"{self.address_string()} - {message}\n")

    def end_headers(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/") or path.endswith(("/", ".html")):
            cache_control = "no-store"
        elif path.endswith((".js", ".css", ".json")):
            cache_control = "no-cache"
        else:
            cache_control = "public, max-age=3600"
        self.send_header("Cache-Control", cache_control)
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
        self.send_header(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        super().end_headers()

    def send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            TEXT_ENCODING
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def api_error(self, status: HTTPStatus, message: str) -> None:
        self.send_json({"error": message}, status)

    def require_ready(self) -> bool:
        with STATE_LOCK:
            ready = bool(STATE["ready"])
            error = STATE["error"]
        if ready:
            return True
        self.api_error(
            (
                HTTPStatus.INTERNAL_SERVER_ERROR
                if error
                else HTTPStatus.SERVICE_UNAVAILABLE
            ),
            str(error or "CVE database is initializing"),
        )
        return False

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            super().do_GET()
            return
        try:
            self.handle_api_get(
                parsed.path, parse_qs(parsed.query, keep_blank_values=True)
            )
        except ValueError as error:
            self.api_error(HTTPStatus.BAD_REQUEST, str(error))
        except sqlite3.Error as error:
            self.api_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"database error: {error}")

    def handle_api_get(self, path: str, params: dict[str, list[str]]) -> None:
        if path in {"/api/health", "/api/cves/status"}:
            with STATE_LOCK:
                state = dict(STATE)
            status = (
                HTTPStatus.OK
                if path.endswith("status") or state["ready"]
                else HTTPStatus.SERVICE_UNAVAILABLE
            )
            self.send_json(state, status)
            return
        if not self.require_ready():
            return
        if path == "/api/cves/counts":
            where, values = where_clause(params)
            with closing(connect()) as database:
                rows = database.execute(
                    f"SELECT severity, COUNT(*) FROM cves{where} GROUP BY severity",
                    values,
                ).fetchall()
            self.send_json(
                {"counts": dict(rows), "total": sum(count for _, count in rows)}
            )
            return
        if path == "/api/cves":
            where, values = where_clause(params)
            limit = parse_bounded_int(params, "limit", 50, 1, MAX_LIMIT)
            offset = parse_bounded_int(params, "offset", 0, 0, 1_000_000)
            with closing(connect()) as database:
                total = database.execute(
                    f"SELECT COUNT(*) FROM cves{where}", values
                ).fetchone()[0]
                rows = database.execute(
                    f"SELECT data FROM cves{where} "
                    "ORDER BY published_at DESC, cve_id DESC LIMIT ? OFFSET ?",
                    [*values, limit, offset],
                ).fetchall()
            self.send_json(
                {"rows": [json.loads(row[0]) for row in rows], "total": total}
            )
            return
        if path.startswith("/api/cves/"):
            cve_id = unquote(path.removeprefix("/api/cves/")).upper()
            if not CVE_ID_RE.fullmatch(cve_id):
                raise ValueError("invalid CVE ID")
            with closing(connect()) as database:
                row = database.execute(
                    "SELECT data FROM cves WHERE cve_id = ?", (cve_id,)
                ).fetchone()
            if row is None:
                self.api_error(HTTPStatus.NOT_FOUND, "CVE not found")
            else:
                self.send_json(json.loads(row[0]))
            return
        self.api_error(HTTPStatus.NOT_FOUND, "API endpoint not found")

    def do_POST(self) -> None:
        if urlparse(self.path).path.startswith("/api/"):
            self.api_error(HTTPStatus.METHOD_NOT_ALLOWED, "read-only API")
            return
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)


def main() -> None:
    configure_stdio()
    host = os.environ.get("ROOT_HOST", DEFAULT_HOST)
    raw_port = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.environ.get("ROOT_PORT", str(DEFAULT_PORT))
    )
    try:
        port = int(raw_port)
    except ValueError as error:
        raise SystemExit(f"Invalid port: {raw_port}") from error
    if not 1 <= port <= 65_535:
        raise SystemExit("Port must be between 1 and 65535")
    threading.Thread(target=build_cve_db, daemon=True).start()
    server = ThreadingHTTPServer((host, port), RootHandler)
    print(f"RØOT http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstop", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
