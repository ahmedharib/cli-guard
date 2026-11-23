"""Live HTTP dashboard server (`cg dashboard serve`) and GitHub Pages exporter (`cg dashboard export`)."""

from __future__ import annotations

import http.server
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cli_guard import __version__
from cli_guard.config import Settings
from cli_guard.core.advisories import AdvisoryClient
from cli_guard.core.cache import VerdictCache
from cli_guard.core.pipeline import SecurityPipeline
from cli_guard.dashboard.ui import DASHBOARD_HTML
from cli_guard.ecosystems.npm.resolver import NpmAdapter
from cli_guard.ledger.store import FindingsLedgerStore
from cli_guard.llm.factory import create_provider


def build_dashboard_snapshot(settings: Settings) -> dict[str, Any]:
    """Assemble a 100% real JSON snapshot from SQLite cache, findings store, ledger, and monitor logs."""
    cache = VerdictCache(settings.cache_db_path)
    ledger = FindingsLedgerStore(settings.data_dir)

    scanned = cache.list_scanned_packages(ecosystem="npm", limit=300)
    findings = ledger.list_findings()[:50]
    ledger_entries = ledger.list_ledger_entries()[-200:]
    last_seq = cache.get_state("npm_last_seq") or ""

    logs: list[dict[str, Any]] = []
    log_file = settings.logs_dir / "monitor.jsonl"
    if log_file.exists():
        raw_lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-150:]
        for line in reversed(raw_lines):
            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    # Attach latest OTS confirmation state onto findings
    ledger_by_id = {e.get("finding_id"): e for e in ledger_entries}
    seen_finding_pkgs: set[tuple[str, str]] = set()
    for f in findings:
        rep = f.get("report") or {}
        seen_finding_pkgs.add((str(rep.get("name", "")), str(rep.get("version", ""))))
        entry = ledger_by_id.get(f.get("finding_id"))
        if entry:
            f["ots_status"] = entry.get("ots_status")
            if entry.get("bitcoin_block_height"):
                f["bitcoin_block_height"] = entry.get("bitcoin_block_height")

    # Also surface real cached benign/cleared inspection reports (e.g. from `cg check` / `cg monitor`)
    # so Verified Inspection Reports reflect real scans without inventing any fake demo entries.
    cached_verdicts = cache.export_verdicts()
    for item in cached_verdicts[:25]:
        key = (str(item.get("name", "")), str(item.get("version", "")))
        if key in seen_finding_pkgs:
            continue
        seen_finding_pkgs.add(key)
        rep = item.get("report") or {}
        findings.append(
            {
                "finding_id": f"cached_{key[0]}@{key[1]}",
                "detected_at_utc": "",
                "commitment_sha256": rep.get("integrity", ""),
                "ots_status": "verified_cache",
                "report": rep,
            }
        )

    mal = sum(1 for r in scanned if r["verdict"] == "malicious")
    susp = sum(1 for r in scanned if r["verdict"] == "suspicious")
    ben = sum(1 for r in scanned if r["verdict"] == "benign")
    ots_conf = sum(1 for e in ledger_entries if e.get("ots_status") == "confirmed")
    ots_pend = sum(1 for e in ledger_entries if e.get("ots_status") == "pending")
    ots_err = sum(1 for e in ledger_entries if e.get("ots_status") in {"stamp_failed", "error"})

    return {
        "version": __version__,
        "repo_url": os.environ.get("CG_REPO_URL", "").strip(),
        "ledger_repo": settings.ledger_repo or "",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "provider": settings.llm_provider,
        "model": settings.effective_triage_model,
        "last_seq": last_seq,
        "metrics": {
            "total_scanned": len(scanned),
            "malicious": mal,
            "suspicious": susp,
            "benign": ben,
            "ledger_commitments": len(ledger_entries),
            "ots_confirmed": ots_conf,
            "ots_pending": ots_pend,
            "ots_errors": ots_err,
        },
        "findings": findings,
        "ledger": list(reversed(ledger_entries)),
        "scanned_packages": scanned,
        "logs": logs,
    }


def export_static_dashboard(
    settings: Settings,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Export static GitHub-Pages-ready dashboard (`index.html` + `snapshot.json`) from real data."""
    output_dir.mkdir(parents=True, exist_ok=True)
    snap = build_dashboard_snapshot(settings)

    html_path = output_dir / "index.html"
    json_path = output_dir / "snapshot.json"
    html_path.write_text(DASHBOARD_HTML, encoding="utf-8")
    json_path.write_text(json.dumps(snap, indent=2), encoding="utf-8")
    return html_path, json_path


def create_dashboard_server(
    settings: Settings,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
) -> http.server.ThreadingHTTPServer:
    """Create a live ThreadingHTTPServer serving the cli-guard web dashboard and JSON APIs."""

    class _DashboardHandler(http.server.BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path in {"/", "/index.html"}:
                self._send(200, DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            if path == "/api/snapshot":
                snap = build_dashboard_snapshot(settings)
                self._send(200, json.dumps(snap).encode("utf-8"), "application/json")
                return
            if path == "/api/health":
                self._send(200, b'{"status":"ok"}', "application/json")
                return
            self._send(404, b'{"error":"not found"}', "application/json")

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw_body = self.rfile.read(min(length, 65536)) if length > 0 else b"{}"

            if path == "/api/ots/upgrade":
                ledger = FindingsLedgerStore(settings.data_dir)
                statuses = ledger.upgrade_all_ots(verify_bitcoin_header=True)
                payload = [
                    {
                        "ots_file": s.ots_path.name,
                        "state": s.state,
                        "blocks": [a.height for a in s.bitcoin_anchors],
                    }
                    for s in statuses
                ]
                self._send(200, json.dumps(payload).encode("utf-8"), "application/json")
                return

            if path == "/api/check":
                try:
                    req = json.loads(raw_body.decode("utf-8"))
                    pkg = str(req.get("package", "")).strip()
                    if not pkg:
                        raise ValueError("Missing `package` field.")
                    cache = VerdictCache(settings.cache_db_path)
                    advisories = AdvisoryClient(osv_api_url=settings.osv_api_url, cache=cache)
                    adapter = NpmAdapter(settings)
                    pipeline = SecurityPipeline(
                        settings=settings,
                        adapter=adapter,
                        cache=cache,
                        advisories=advisories,
                        llm_provider=create_provider(settings),
                    )
                    spec = adapter.parse_spec(pkg)
                    report = pipeline.evaluate(
                        spec,
                        use_cache=True,
                        enable_diff=True,
                        enable_llm=True,
                        scan_source="dashboard",
                    )
                    self._send(200, report.model_dump_json().encode("utf-8"), "application/json")
                except Exception as exc:
                    self._send(400, json.dumps({"error": str(exc)}).encode("utf-8"), "application/json")
                return

            self._send(404, b'{"error":"not found"}', "application/json")

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    return http.server.ThreadingHTTPServer((host, port), _DashboardHandler)
