#!/usr/bin/env python3
"""Serve RØOT and its read-only SQLite CVE API."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import threading
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
SEED_PATH = DATA_DIR / "cves_public.json"
DB_PATH = Path(os.environ.get("ROOT_DB_PATH", str(DATA_DIR / "cves.sqlite3")))
TEXT_ENCODING = "utf-8"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
MAX_LIMIT = 100
MAX_QUERY_LENGTH = 200
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
STATE: dict[str, Any] = {"imported": 0, "total": 0, "ready": False, "error": None}
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
        raise ValueError(f"{seed} must contain a JSON array")
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(payload):
        if not isinstance(row, dict) or not CVE_ID_RE.fullmatch(
            str(row.get("cve_id", ""))
        ):
            raise ValueError(f"Invalid CVE record at index {index}")
        rows.append(row)
    return rows


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
        CREATE INDEX cves_published_idx ON cves(published_at DESC);
        CREATE INDEX cves_severity_idx ON cves(severity);
        """
    )


def build_cve_db() -> None:
    temporary = DB_PATH.with_suffix(".tmp.sqlite3")
    try:
        rows = load_seed()
        set_state(imported=0, total=len(rows), ready=False, error=None)
        temporary.unlink(missing_ok=True)
        database = connect(temporary)
        try:
            create_schema(database)
            for start in range(0, len(rows), 100):
                batch = rows[start : start + 100]
                database.executemany(
                    """
                    INSERT INTO cves
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
                            json.dumps(row, ensure_ascii=False, separators=(",", ":")),
                        )
                        for row in batch
                    ],
                )
                database.commit()
                set_state(imported=min(start + len(batch), len(rows)))
        finally:
            database.close()
        temporary.replace(DB_PATH)
        set_state(imported=len(rows), ready=True)
    except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error) as error:
        temporary.unlink(missing_ok=True)
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
        clauses.append(
            "(cve_id LIKE ? OR title LIKE ? OR affected_vendor LIKE ? "
            "OR affected_product LIKE ?)"
        )
        values.extend([f"%{query}%"] * 4)
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
        cache_control = (
            "no-store" if path.endswith(("/", ".html")) else "public, max-age=3600"
        )
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
            with connect() as database:
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
            with connect() as database:
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
            with connect() as database:
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
