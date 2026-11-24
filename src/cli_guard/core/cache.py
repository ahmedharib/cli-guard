"""SQLite verdict cache, local malware blocklist, and user allowlist."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from cli_guard.models import FinalReport, VerdictLabel

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS verdicts (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    integrity TEXT NOT NULL,
    verdict TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    report_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (ecosystem, name, version, integrity)
);

CREATE TABLE IF NOT EXISTS blocklist (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '*',
    advisory_id TEXT NOT NULL DEFAULT 'LOCAL',
    reason TEXT NOT NULL DEFAULT '',
    updated_at REAL NOT NULL,
    PRIMARY KEY (ecosystem, name, version)
);

CREATE TABLE IF NOT EXISTS allowlist (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '*',
    reason TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    PRIMARY KEY (ecosystem, name, version)
);

CREATE TABLE IF NOT EXISTS scanned_packages (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    integrity TEXT NOT NULL DEFAULT '',
    published_at TEXT NOT NULL DEFAULT '',
    scanned_at TEXT NOT NULL,
    scan_source TEXT NOT NULL DEFAULT 'check',
    verdict TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    layers_json TEXT NOT NULL DEFAULT '[]',
    summary TEXT NOT NULL DEFAULT '',
    finding_id TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (ecosystem, name, version)
);

CREATE TABLE IF NOT EXISTS monitor_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS osv_vulns (
    id TEXT PRIMARY KEY,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    summary TEXT NOT NULL DEFAULT '',
    refs_json TEXT NOT NULL DEFAULT '[]',
    updated_at REAL NOT NULL
);
"""


class VerdictCache:
    """Content-addressed local SQLite cache keyed by (ecosystem, name, version, integrity)."""

    def __init__(self, db_path: Path, ttl_seconds: float = 7 * 86400.0) -> None:
        self.db_path = db_path
        self.ttl_seconds = ttl_seconds
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    def get(
        self,
        ecosystem: str,
        name: str,
        version: str,
        integrity: str,
    ) -> FinalReport | None:
        if not integrity:
            return None
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT report_json, created_at FROM verdicts
                WHERE ecosystem = ? AND name = ? AND version = ? AND integrity = ?
                """,
                (ecosystem, name, version, integrity),
            ).fetchone()
        if not row:
            return None
        if (time.time() - float(row["created_at"])) > self.ttl_seconds:
            return None
        try:
            report = FinalReport.model_validate_json(row["report_json"])
            report.from_cache = True
            return report
        except Exception:
            return None

    def put(self, report: FinalReport) -> None:
        if not report.integrity:
            return
        payload = report.model_dump_json()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO verdicts
                (ecosystem, name, version, integrity, verdict, risk_score, report_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.ecosystem,
                    report.name,
                    report.version,
                    report.integrity,
                    report.verdict.value,
                    report.risk_score,
                    payload,
                    time.time(),
                ),
            )

    def is_allowlisted(self, ecosystem: str, name: str, version: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM allowlist
                WHERE ecosystem = ? AND name = ? AND (version = ? OR version = '*')
                LIMIT 1
                """,
                (ecosystem, name, version),
            ).fetchone()
        return row is not None

    def add_allowlist(
        self, ecosystem: str, name: str, version: str = "*", reason: str = ""
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO allowlist
                (ecosystem, name, version, reason, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (ecosystem, name, version, reason, time.time()),
            )

    def check_blocklist(
        self, ecosystem: str, name: str, version: str
    ) -> list[tuple[str, str]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT advisory_id, reason FROM blocklist
                WHERE ecosystem = ? AND name = ? AND (version = ? OR version = '*')
                """,
                (ecosystem, name, version),
            ).fetchall()
        return [(str(r["advisory_id"]), str(r["reason"])) for r in rows]

    def upsert_blocklist(
        self,
        entries: list[tuple[str, str, str, str, str]],
    ) -> int:
        """Bulk insert (ecosystem, name, version, advisory_id, reason) rows."""
        now = time.time()
        rows = [(eco, name, ver, adv_id, reason, now) for eco, name, ver, adv_id, reason in entries]
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO blocklist
                (ecosystem, name, version, advisory_id, reason, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def clear_verdicts(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM verdicts")
            return cur.rowcount

    def stats(self) -> dict[str, int]:
        with self._connect() as conn:
            v_count = conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
            b_count = conn.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0]
            a_count = conn.execute("SELECT COUNT(*) FROM allowlist").fetchone()[0]
            mal_count = conn.execute(
                "SELECT COUNT(*) FROM verdicts WHERE verdict = ?",
                (VerdictLabel.MALICIOUS.value,),
            ).fetchone()[0]
        return {
            "cached_verdicts": int(v_count),
            "cached_malicious": int(mal_count),
            "blocklist_entries": int(b_count),
            "allowlist_entries": int(a_count),
        }

    def export_verdicts(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ecosystem, name, version, verdict, risk_score, report_json FROM verdicts"
            ).fetchall()
        return [
            {
                "ecosystem": r["ecosystem"],
                "name": r["name"],
                "version": r["version"],
                "verdict": r["verdict"],
                "risk_score": r["risk_score"],
                "report": json.loads(r["report_json"]),
            }
            for r in rows
        ]

    def record_scan(
        self,
        *,
        ecosystem: str,
        name: str,
        version: str,
        integrity: str,
        published_at: str,
        scanned_at: str,
        scan_source: str,
        verdict: str,
        risk_score: int,
        layers_run: list[str],
        summary: str,
        finding_id: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scanned_packages
                (ecosystem, name, version, integrity, published_at, scanned_at, scan_source,
                 verdict, risk_score, layers_json, summary, finding_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ecosystem,
                    name,
                    version,
                    integrity,
                    published_at,
                    scanned_at,
                    scan_source,
                    verdict,
                    risk_score,
                    json.dumps(layers_run),
                    summary[:400],
                    finding_id,
                ),
            )

    def record_scan_if_missing(
        self,
        *,
        ecosystem: str,
        name: str,
        version: str,
        integrity: str,
        published_at: str,
        scanned_at: str,
        scan_source: str,
        verdict: str,
        risk_score: int,
        layers_run: list[str],
        summary: str,
        finding_id: str = "",
    ) -> bool:
        """Insert a scanned_packages row only if (ecosystem, name, version) does not already exist."""
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO scanned_packages
                (ecosystem, name, version, integrity, published_at, scanned_at, scan_source,
                 verdict, risk_score, layers_json, summary, finding_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ecosystem,
                    name,
                    version,
                    integrity,
                    published_at,
                    scanned_at,
                    scan_source,
                    verdict,
                    risk_score,
                    json.dumps(layers_run),
                    summary[:400],
                    finding_id,
                ),
            )
            return cur.rowcount > 0

    def has_scanned(self, ecosystem: str, name: str, version: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM scanned_packages WHERE ecosystem = ? AND name = ? AND version = ? LIMIT 1",
                (ecosystem, name, version),
            ).fetchone()
        return row is not None

    def list_scanned_packages(
        self,
        *,
        ecosystem: str = "npm",
        verdicts: list[str] | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        query = "SELECT * FROM scanned_packages WHERE ecosystem = ?"
        params: list[object] = [ecosystem]
        if verdicts:
            placeholders = ",".join("?" for _ in verdicts)
            query += f" AND verdict IN ({placeholders})"
            params.extend(verdicts)
        query += " ORDER BY scanned_at DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "ecosystem": r["ecosystem"],
                "name": r["name"],
                "version": r["version"],
                "integrity": r["integrity"],
                "published_at": r["published_at"],
                "scanned_at": r["scanned_at"],
                "scan_source": r["scan_source"],
                "verdict": r["verdict"],
                "risk_score": r["risk_score"],
                "layers_run": json.loads(r["layers_json"] or "[]"),
                "summary": r["summary"],
                "finding_id": r["finding_id"],
            }
            for r in rows
        ]

    def get_state(self, key: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM monitor_state WHERE key = ?",
                (key,),
            ).fetchone()
        return str(row["value"]) if row else None

    def set_state(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO monitor_state (key, value, updated_at) VALUES (?, ?, ?)",
                (key, value, time.time()),
            )

    def count_scanned_by_verdict(self, *, ecosystem: str = "npm") -> dict[str, int]:
        """Return exact all-time counts grouped by verdict without row limits."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT verdict, COUNT(*) AS cnt FROM scanned_packages WHERE ecosystem = ? GROUP BY verdict",
                (ecosystem,),
            ).fetchall()
        return {str(r["verdict"]): int(r["cnt"]) for r in rows}

    def get_osv_vuln(
        self, adv_id: str, *, ttl_seconds: float = 86400.0
    ) -> dict[str, object] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT aliases_json, summary, refs_json, updated_at FROM osv_vulns WHERE id = ?",
                (adv_id,),
            ).fetchone()
        if not row or (time.time() - float(row["updated_at"])) > ttl_seconds:
            return None
        return {
            "aliases": json.loads(row["aliases_json"] or "[]"),
            "summary": str(row["summary"] or ""),
            "references": json.loads(row["refs_json"] or "[]"),
        }

    def put_osv_vuln(
        self,
        adv_id: str,
        *,
        aliases: list[str],
        summary: str,
        references: list[str],
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO osv_vulns (id, aliases_json, summary, refs_json, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    adv_id,
                    json.dumps(aliases),
                    summary[:500],
                    json.dumps(references[:5]),
                    time.time(),
                ),
            )
