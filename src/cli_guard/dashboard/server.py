"""Live HTTP dashboard server (`cg dashboard serve`), public rate-limited API, and GitHub Pages exporter."""

from __future__ import annotations

import http.server
import json
import os
import threading
import time
from collections import defaultdict, deque
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


def _is_publicly_disclosable_finding(finding: dict[str, Any]) -> bool:
    """Return True if a finding is safe to show by name on a public showcase.

    Unconfirmed `suspicious` / `malicious` findings stay hidden behind salted hashes
    in `ledger.jsonl` until revealed or confirmed via OSV/npm ground truth.
    """
    rep = finding.get("report") or {}
    verdict = str(rep.get("verdict") or "").lower()
    if verdict == "benign":
        return True
    if finding.get("revealed") is True:
        return True
    gt = finding.get("ground_truth") or {}
    if isinstance(gt, dict) and str(gt.get("classification") or "").startswith("TRUE_POSITIVE"):
        return True
    return False


def build_dashboard_snapshot(
    settings: Settings,
    *,
    public_safe: bool = False,
) -> dict[str, Any]:
    """Assemble a 100% real JSON snapshot from SQLite cache, findings store, ledger, and monitor logs."""
    cache = VerdictCache(settings.cache_db_path)
    ledger = FindingsLedgerStore(settings.data_dir)

    scanned = cache.list_scanned_packages(ecosystem="npm", limit=300)
    raw_findings = ledger.list_findings()[:50]
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
    disclosed_pkg_keys: set[tuple[str, str]] = set()

    findings: list[dict[str, Any]] = []
    for f in raw_findings:
        rep = f.get("report") or {}
        pkg_key = (str(rep.get("name", "")), str(rep.get("version", "")))
        seen_finding_pkgs.add(pkg_key)
        entry = ledger_by_id.get(f.get("finding_id"))
        if entry:
            f["ots_status"] = entry.get("ots_status")
            if entry.get("bitcoin_block_height"):
                f["bitcoin_block_height"] = entry.get("bitcoin_block_height")

        if public_safe and not _is_publicly_disclosable_finding(f):
            continue
        disclosed_pkg_keys.add(pkg_key)
        findings.append(f)

    # Surface real cached benign/cleared inspection reports (skip unconfirmed non-benign in public_safe)
    cached_verdicts = cache.export_verdicts()
    for item in cached_verdicts[:25]:
        key = (str(item.get("name", "")), str(item.get("version", "")))
        if key in seen_finding_pkgs:
            continue
        seen_finding_pkgs.add(key)
        rep = item.get("report") or {}
        verdict = str(rep.get("verdict") or "").lower()
        if public_safe and verdict != "benign":
            continue
        findings.append(
            {
                "finding_id": f"cached_{key[0]}@{key[1]}",
                "detected_at_utc": "",
                "commitment_sha256": rep.get("integrity", ""),
                "ots_status": "verified_cache",
                "report": rep,
            }
        )

    # Compute accurate totals from unredacted counts BEFORE redacting unconfirmed rows
    mal = sum(1 for r in scanned if r["verdict"] == "malicious")
    susp = sum(1 for r in scanned if r["verdict"] == "suspicious")
    ben = sum(1 for r in scanned if r["verdict"] == "benign")
    ots_conf = sum(1 for e in ledger_entries if e.get("ots_status") == "confirmed")
    ots_pend = sum(1 for e in ledger_entries if e.get("ots_status") == "pending")
    ots_err = sum(1 for e in ledger_entries if e.get("ots_status") in {"stamp_failed", "error"})

    if public_safe:
        redacted_scanned: list[dict[str, Any]] = []
        redacted_pkg_names: set[str] = set()
        for row in scanned:
            v = str(row.get("verdict") or "").lower()
            key = (str(row.get("name", "")), str(row.get("version", "")))
            if v in {"malicious", "suspicious"} and key not in disclosed_pkg_keys:
                redacted_pkg_names.add(f"{key[0]}@{key[1]}")
                fid = str(row.get("finding_id") or "")
                redacted_scanned.append(
                    {
                        **row,
                        "name": f"[redacted:{fid or 'pending'}]",
                        "version": "*",
                        "summary": "Salted SHA-256 commitment pending independent OSV/npm confirmation.",
                    }
                )
            else:
                redacted_scanned.append(row)
        scanned = redacted_scanned

        # Redact unconfirmed package names from public logs
        safe_logs: list[dict[str, Any]] = []
        for entry in logs:
            msg = str(entry.get("message") or "")
            pkg_tag = str(entry.get("package") or "")
            if pkg_tag and pkg_tag in redacted_pkg_names:
                fid = str(entry.get("finding_id") or "pending")
                msg = msg.replace(pkg_tag, f"[redacted:{fid}]")
                safe_logs.append({**entry, "package": f"[redacted:{fid}]", "message": msg})
            elif any(p in msg for p in redacted_pkg_names):
                for p in redacted_pkg_names:
                    if p in msg:
                        msg = msg.replace(p, "[redacted:pending]")
                safe_logs.append({**entry, "message": msg})
            else:
                safe_logs.append(entry)
        logs = safe_logs

    return {
        "version": __version__,
        "public_safe": public_safe,
        "repo_url": os.environ.get("CG_REPO_URL", "").strip(),
        "public_api_url": os.environ.get("CG_PUBLIC_API_URL", "").strip().rstrip("/"),
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
    *,
    public_safe: bool = True,
) -> tuple[Path, Path]:
    """Export static GitHub-Pages-ready dashboard (`index.html` + `snapshot.json`)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    snap = build_dashboard_snapshot(settings, public_safe=public_safe)

    html_path = output_dir / "index.html"
    json_path = output_dir / "snapshot.json"
    html_path.write_text(DASHBOARD_HTML, encoding="utf-8")
    json_path.write_text(json.dumps(snap, indent=2), encoding="utf-8")
    return html_path, json_path


class PublicApiLimiter:
    """Rate & LLM credit limiter protecting public `/api/check` deployments from abuse."""

    def __init__(
        self,
        *,
        max_checks_per_ip_hour: int = 15,
        max_llm_per_ip_day: int = 3,
        max_llm_global_day: int = 50,
    ) -> None:
        self.max_checks_per_ip_hour = max(1, max_checks_per_ip_hour)
        self.max_llm_per_ip_day = max(0, max_llm_per_ip_day)
        self.max_llm_global_day = max(0, max_llm_global_day)
        self._lock = threading.Lock()
        self._ip_checks: dict[str, deque[float]] = defaultdict(deque)
        self._ip_llm: dict[str, deque[float]] = defaultdict(deque)
        self._global_llm: deque[float] = deque()

    def _prune(self, q: deque[float], window_seconds: float, now: float) -> None:
        cutoff = now - window_seconds
        while q and q[0] < cutoff:
            q.popleft()

    def allow_check(self, client_ip: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds) for an incoming `/api/check` request."""
        now = time.monotonic()
        with self._lock:
            q = self._ip_checks[client_ip]
            self._prune(q, 3600.0, now)
            if len(q) >= self.max_checks_per_ip_hour:
                retry = max(1, int(3600.0 - (now - q[0])))
                return False, retry
            q.append(now)
            return True, 0

    def allow_llm(self, client_ip: str) -> bool:
        """Return True and consume a daily LLM slot if both IP and global daily budgets permit."""
        if self.max_llm_per_ip_day <= 0 or self.max_llm_global_day <= 0:
            return False
        now = time.monotonic()
        with self._lock:
            self._prune(self._global_llm, 86400.0, now)
            ip_q = self._ip_llm[client_ip]
            self._prune(ip_q, 86400.0, now)
            if len(self._global_llm) >= self.max_llm_global_day:
                return False
            if len(ip_q) >= self.max_llm_per_ip_day:
                return False
            self._global_llm.append(now)
            ip_q.append(now)
            return True


def create_dashboard_server(
    settings: Settings,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    public_api: bool = False,
    cors_origin: str | None = None,
    trust_proxy: bool = False,
    limiter: PublicApiLimiter | None = None,
) -> http.server.ThreadingHTTPServer:
    """Create a ThreadingHTTPServer serving the dashboard and `/api/check` (local or public Option A)."""
    resolved_cors = (
        cors_origin.strip()
        if cors_origin
        else ("*" if public_api else "")
    )
    active_limiter = limiter or (PublicApiLimiter() if public_api else None)

    class _DashboardHandler(http.server.BaseHTTPRequestHandler):
        def _client_ip(self) -> str:
            if trust_proxy:
                xff = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
                if xff:
                    return xff
            return str(self.client_address[0])

        def _send(
            self,
            code: int,
            body: bytes,
            content_type: str,
            *,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if resolved_cors:
                self.send_header("Access-Control-Allow-Origin", resolved_cors)
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self) -> None:  # noqa: N802
            self._send(204, b"", "text/plain")

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path in {"/", "/index.html"}:
                self._send(200, DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            if path == "/api/snapshot":
                snap = build_dashboard_snapshot(settings, public_safe=public_api)
                self._send(200, json.dumps(snap).encode("utf-8"), "application/json")
                return
            if path == "/api/health":
                payload = {
                    "status": "ok",
                    "mode": "public_api" if public_api else "local",
                    "version": __version__,
                }
                self._send(200, json.dumps(payload).encode("utf-8"), "application/json")
                return
            self._send(404, b'{"error":"not found"}', "application/json")

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw_body = self.rfile.read(min(length, 65536)) if length > 0 else b"{}"

            if path == "/api/ots/upgrade":
                if public_api:
                    self._send(
                        403,
                        b'{"error":"Administrative OTS upgrades are disabled in public API mode."}',
                        "application/json",
                    )
                    return
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
                client_ip = self._client_ip()
                if active_limiter is not None:
                    allowed, retry_after = active_limiter.allow_check(client_ip)
                    if not allowed:
                        self._send(
                            429,
                            json.dumps(
                                {
                                    "error": f"Rate limit exceeded. Try again in {retry_after}s.",
                                    "retry_after": retry_after,
                                }
                            ).encode("utf-8"),
                            "application/json",
                            extra_headers={"Retry-After": str(retry_after)},
                        )
                        return

                try:
                    req = json.loads(raw_body.decode("utf-8"))
                    pkg = str(req.get("package", "")).strip()
                    if not pkg or len(pkg) > 220:
                        raise ValueError("Invalid or missing `package` field.")

                    cache = VerdictCache(settings.cache_db_path)
                    advisories = AdvisoryClient(osv_api_url=settings.osv_api_url, cache=cache)
                    adapter = NpmAdapter(settings)
                    spec = adapter.parse_spec(pkg)
                    if spec.spec_kind in {"git", "file", "tarball_url"} and public_api:
                        raise ValueError(
                            "Public API only checks npm registry packages (external URLs/git/file specs disabled)."
                        )

                    meta = adapter.fetch_metadata(spec)
                    cached_hit = (
                        cache.get(meta.ecosystem, meta.name, meta.version, meta.integrity)
                        if meta.integrity
                        else None
                    )
                    if cached_hit is not None:
                        self._send(200, cached_hit.model_dump_json().encode("utf-8"), "application/json")
                        return

                    # Check whether LLM quota permits escalation (otherwise degrade gracefully to static AST)
                    llm_allowed = True
                    if active_limiter is not None:
                        llm_allowed = active_limiter.allow_llm(client_ip)

                    pipeline = SecurityPipeline(
                        settings=settings,
                        adapter=adapter,
                        cache=cache,
                        advisories=advisories,
                        llm_provider=create_provider(settings) if llm_allowed else None,
                    )
                    report = pipeline.evaluate(
                        spec,
                        use_cache=True,
                        enable_diff=True,
                        enable_llm=llm_allowed,
                        prefetched_metadata=meta,
                        scan_source="public_api" if public_api else "dashboard",
                    )
                    if active_limiter is not None and not llm_allowed and report.risk_score >= settings.triage_risk_threshold:
                        report.extra["rate_limit_notice"] = (
                            "Daily public LLM quota reached; completed using static Layer 0 + Layer 1 AST analysis."
                        )
                    self._send(200, report.model_dump_json().encode("utf-8"), "application/json")
                except Exception as exc:
                    self._send(400, json.dumps({"error": str(exc)}).encode("utf-8"), "application/json")
                return

            self._send(404, b'{"error":"not found"}', "application/json")

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    return http.server.ThreadingHTTPServer((host, port), _DashboardHandler)
