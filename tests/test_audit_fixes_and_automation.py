"""Regression tests for audit bug fixes (#1-#12) and hands-off automation Upgrades A, B, C."""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cli_guard.cli import build_daily_schedule_spec
from cli_guard.config import Settings
from cli_guard.core.advisories import AdvisoryClient
from cli_guard.core.cache import VerdictCache
from cli_guard.dashboard.server import build_dashboard_snapshot
from cli_guard.dashboard.ui import DASHBOARD_HTML
from cli_guard.ecosystems.npm.registry import RegistryError, verify_tarball_integrity
from cli_guard.ledger.bitcoin_ots import BitcoinAnchorInfo, OTSStatus
from cli_guard.ledger.github_sync import push_ledger_to_github
from cli_guard.ledger.store import FindingsLedgerStore
from cli_guard.llm.base import ChatMessage, LLMProvider, LLMResponse, ToolSpec
from cli_guard.models import (
    FinalReport,
    PackageMetadata,
    StaticAnalysisReport,
    VerdictLabel,
)
from cli_guard.monitor.ground_truth import NpmOfficialStatus, run_ground_truth_verification
from cli_guard.monitor.npm_feed import LiveNpmMonitor, MonitorStats


def test_osv_querybatch_hydrates_ghsa_malware_alias_and_caches(tmp_path: Path) -> None:
    vuln_hits = {"count": 0}

    class _MockOsvHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length > 0:
                self.rfile.read(length)
            if self.path == "/querybatch":
                body = json.dumps(
                    {
                        "results": [
                            {
                                # Real OSV /querybatch shape: only id + modified (no aliases/summary!)
                                "vulns": [{"id": "GHSA-evil-1234", "modified": "2026-11-24T00:00:00Z"}]
                            }
                        ]
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/vulns/GHSA-evil-1234":
                vuln_hits["count"] += 1
                body = json.dumps(
                    {
                        "id": "GHSA-evil-1234",
                        "aliases": ["MAL-2026-9999"],
                        "summary": "Malicious package exfiltrates ~/.npmrc tokens",
                        "references": [{"url": "https://osv.dev/vulnerability/MAL-2026-9999"}],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), _MockOsvHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        port = server.server_address[1]
        cache = VerdictCache(tmp_path / "cache.sqlite3")
        client = AdvisoryClient(osv_api_url=f"http://127.0.0.1:{port}", cache=cache)

        res1 = client.query_one("npm", "bad-ghsa-pkg", "1.0.0")
        assert len(res1) == 1
        assert res1[0].id == "GHSA-evil-1234"
        assert res1[0].is_malware is True
        assert "MAL-2026-9999" in res1[0].aliases
        assert "exfiltrates" in res1[0].summary
        assert vuln_hits["count"] == 1

        # Second lookup should reuse SQLite `osv_vulns` cache without re-fetching /vulns/GHSA-evil-1234
        res2 = client.query_one("npm", "bad-ghsa-pkg", "1.0.0")
        assert len(res2) == 1
        assert res2[0].is_malware is True
        assert vuln_hits["count"] == 1
    finally:
        server.shutdown()
        server.server_close()


def test_dashboard_kpis_exceed_300_and_exclude_skipped(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    cache = VerdictCache(settings.cache_db_path)
    base = datetime(2026, 11, 20, 0, 0, tzinfo=UTC)

    # Insert 3 older malicious rows BEFORE 320 newer benign rows
    for i in range(3):
        cache.record_scan(
            ecosystem="npm",
            name=f"old-mal-{i}",
            version="1.0.0",
            integrity=f"sha512-m{i}",
            published_at=base.isoformat(),
            scanned_at=(base + timedelta(seconds=i)).isoformat(),
            scan_source="monitor",
            verdict="malicious",
            risk_score=95,
            layers_run=["layer1"],
            summary="Malware",
        )
    for i in range(320):
        cache.record_scan(
            ecosystem="npm",
            name=f"benign-{i}",
            version="1.0.0",
            integrity=f"sha512-b{i}",
            published_at=base.isoformat(),
            scanned_at=(base + timedelta(minutes=10, seconds=i)).isoformat(),
            scan_source="monitor",
            verdict="benign",
            risk_score=0,
            layers_run=["layer1"],
            summary="Clean",
        )
    for i in range(5):
        cache.record_scan(
            ecosystem="npm",
            name=f"oversized-{i}",
            version="1.0.0",
            integrity="",
            published_at="",
            scanned_at=(base + timedelta(hours=1, seconds=i)).isoformat(),
            scan_source="monitor",
            verdict="skipped",
            risk_score=0,
            layers_run=[],
            summary="Tarball exceeds max file count",
        )

    snap = build_dashboard_snapshot(settings, public_safe=True)
    assert snap["metrics"]["total_scanned"] == 323
    assert snap["metrics"]["malicious"] == 3
    assert snap["metrics"]["benign"] == 320
    assert all(r["verdict"] != "skipped" for r in snap["scanned_packages"])


def test_ground_truth_author_unpublish_is_not_confirmed_malware(
    tmp_path: Path, monkeypatch
) -> None:
    now = datetime.now(UTC)
    settings = Settings(data_dir=tmp_path)
    cache = VerdictCache(settings.cache_db_path)
    store = FindingsLedgerStore(settings.data_dir)

    # 1. Flagged suspicious package later unpublished by author (version_removed, NOT 0.0.1-security)
    susp_rep = FinalReport(
        ecosystem="npm",
        name="author-unpub-susp",
        version="0.1.0-beta.1",
        integrity="sha512-s",
        verdict=VerdictLabel.SUSPICIOUS,
        risk_score=55,
        summary="Install script",
    )
    susp_saved = store.record_finding(susp_rep, scan_source="monitor", stamp_bitcoin=False)
    cache.record_scan(
        ecosystem="npm",
        name="author-unpub-susp",
        version="0.1.0-beta.1",
        integrity="sha512-s",
        published_at=(now - timedelta(hours=12)).isoformat(),
        scanned_at=(now - timedelta(hours=11)).isoformat(),
        scan_source="monitor",
        verdict="suspicious",
        risk_score=55,
        layers_run=["layer1"],
        summary="Install script",
        finding_id=susp_saved["finding_id"],
    )

    # 2. Benign package later unpublished by author (must NOT count as FALSE_NEGATIVE_MISSED!)
    cache.record_scan(
        ecosystem="npm",
        name="author-unpub-benign",
        version="1.0.0",
        integrity="sha512-b",
        published_at=(now - timedelta(hours=12)).isoformat(),
        scanned_at=(now - timedelta(hours=11)).isoformat(),
        scan_source="monitor",
        verdict="benign",
        risk_score=0,
        layers_run=["layer1"],
        summary="Clean",
    )

    # 3. Genuine confirmed malware (replaced by 0.0.1-security)
    mal_rep = FinalReport(
        ecosystem="npm",
        name="real-malware",
        version="1.0.0",
        integrity="sha512-m",
        verdict=VerdictLabel.MALICIOUS,
        risk_score=95,
        summary="Exfil",
    )
    mal_saved = store.record_finding(mal_rep, scan_source="monitor", stamp_bitcoin=False)
    cache.record_scan(
        ecosystem="npm",
        name="real-malware",
        version="1.0.0",
        integrity="sha512-m",
        published_at=(now - timedelta(hours=12)).isoformat(),
        scanned_at=(now - timedelta(hours=11)).isoformat(),
        scan_source="monitor",
        verdict="malicious",
        risk_score=95,
        layers_run=["layer1"],
        summary="Exfil",
        finding_id=mal_saved["finding_id"],
    )

    monkeypatch.setattr(
        "cli_guard.monitor.ground_truth.AdvisoryClient.query_batch",
        lambda self, pkgs: {p: [] for p in pkgs},
    )

    def _fake_npm_status(name: str, ver: str, **kw) -> NpmOfficialStatus:
        if name == "author-unpub-susp":
            return NpmOfficialStatus(state="version_removed", reason="Author unpublished beta")
        if name == "author-unpub-benign":
            return NpmOfficialStatus(state="unpublished", reason="Author unpublished")
        return NpmOfficialStatus(
            state="security_holding",
            reason="0.0.1-security",
            takedown_at_utc=(now - timedelta(hours=1)).isoformat(),
        )

    monkeypatch.setattr("cli_guard.monitor.ground_truth.check_npm_official_status", _fake_npm_status)

    gt = run_ground_truth_verification(settings, upgrade_ots=False, auto_reveal=True)
    assert gt["counts"]["TRUE_POSITIVE_EARLY_CATCH"] == 1
    assert gt["counts"]["REMOVED_UNCONFIRMED"] == 2
    assert gt["counts"]["FALSE_NEGATIVE_MISSED"] == 0
    assert gt["recall"] == 1.0
    assert mal_saved["finding_id"] in gt["auto_revealed_finding_ids"]
    assert susp_saved["finding_id"] not in gt["auto_revealed_finding_ids"]


def test_tarball_integrity_verification_pass_and_reject_tampered() -> None:
    raw = b"tarball-payload-bytes"
    sha512_sri = "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode("ascii")
    sha1_hex = hashlib.sha1(raw).hexdigest()

    verify_tarball_integrity(raw, sha512_sri)
    verify_tarball_integrity(raw, sha1_hex)

    with pytest.raises(RegistryError, match="integrity mismatch"):
        verify_tarball_integrity(raw + b"X", sha512_sri)

    with pytest.raises(RegistryError, match="shasum mismatch"):
        verify_tarball_integrity(raw + b"X", sha1_hex)


def test_ledger_merge_preserves_concurrent_appends_and_skips_confirmed_ots(
    tmp_path: Path, monkeypatch
) -> None:
    store = FindingsLedgerStore(tmp_path)
    r1 = FinalReport(ecosystem="npm", name="pkg-1", version="1.0.0", verdict=VerdictLabel.SUSPICIOUS, risk_score=60)
    r2 = FinalReport(ecosystem="npm", name="pkg-2", version="1.0.0", verdict=VerdictLabel.SUSPICIOUS, risk_score=65)
    s1 = store.record_finding(r1, scan_source="monitor", stamp_bitcoin=False)
    s2 = store.record_finding(r2, scan_source="monitor", stamp_bitcoin=False)

    # Mark s1 as already confirmed in ledger.jsonl + create dummy .ots files for s1 and s2
    store._merge_and_write_ledger_updates(
        {s1["finding_id"]: {"ots_status": "confirmed", "bitcoin_block_height": 900001}}
    )
    (store.ots_dir / f"{s1['finding_id']}.ots").write_bytes(b"dummy1")
    (store.ots_dir / f"{s2['finding_id']}.ots").write_bytes(b"dummy2")

    upgraded_calls: list[str] = []

    def _fake_upgrade(ots_path: Path, verify_bitcoin_header: bool = True):
        upgraded_calls.append(ots_path.stem)
        # Simulate a concurrent worker appending a brand-new finding WHILE OTS HTTP call is running!
        r3 = FinalReport(ecosystem="npm", name="pkg-concurrent", version="1.0.0", verdict=VerdictLabel.MALICIOUS, risk_score=95)
        store.record_finding(r3, scan_source="monitor", stamp_bitcoin=False)
        return True, OTSStatus(
            ots_path=ots_path,
            file_digest_hex=s2["commitment_sha256"],
            state="confirmed",
            bitcoin_anchors=[BitcoinAnchorInfo(height=900002, merkle_root_hex="abcd")],
        )

    monkeypatch.setattr("cli_guard.ledger.store.upgrade_ots_file", _fake_upgrade)
    statuses = store.upgrade_all_ots(verify_bitcoin_header=True)

    # Already-confirmed s1 must be skipped; only pending s2 triggers network upgrade
    assert upgraded_calls == [s2["finding_id"]]
    assert len(statuses) == 2

    # All 3 entries (s1, upgraded s2, and concurrently appended r3) must exist intact!
    entries = store.list_ledger_entries()
    assert len(entries) == 3
    by_id = {e["finding_id"]: e for e in entries}
    assert by_id[s2["finding_id"]]["ots_status"] == "confirmed"
    assert by_id[s2["finding_id"]]["bitcoin_block_height"] == 900002


def test_monitor_auto_fast_forward_rate_limit_no_cache_poison_and_skip_registry_err(
    tmp_path: Path, monkeypatch
) -> None:
    class _StubRepClient:
        def __init__(self, head: str, pkgs: list[str]) -> None:
            self.head = head
            self.pkgs = pkgs
            self.since_seen: list[str] = []

        def fetch_head_seq(self) -> str:
            return self.head

        def fetch_changes(self, *, since: str, limit: int = 100) -> tuple[str, list[str]]:
            self.since_seen.append(since)
            return str(int(since) + 10), list(self.pkgs)

    class _DummyLLM(LLMProvider):
        name = "dummy"

        def chat(
            self,
            messages: list[ChatMessage],
            *,
            model: str,
            tools: list[ToolSpec] | None = None,
            json_mode: bool = False,
            max_tokens: int = 512,
            temperature: float = 0.0,
        ) -> LLMResponse:
            return LLMResponse(content="{}")

    settings = Settings(data_dir=tmp_path, llm_provider="static")
    cache = VerdictCache(settings.cache_db_path)
    # Seed a stale checkpoint 400,000 changes behind HEAD
    cache.set_state("npm_last_seq", "100000")

    rep_client = _StubRepClient(head="500000", pkgs=["oversized-pkg", "susp-ratelimited-pkg"])
    monitor = LiveNpmMonitor(
        settings=settings,
        min_llm_risk=40,
        max_llm_rpm=0,  # Force LLM rate-limit skip!
        workers=1,
        stamp_bitcoin=False,
        auto_upgrade_ots=False,
        auto_verify_truth=False,
        rep_client=rep_client,
    )
    monitor.llm_provider = _DummyLLM()

    now_iso = datetime.now(UTC).isoformat()

    def _fake_fetch_packument(self, name: str) -> dict:
        return {
            "name": name,
            "dist-tags": {"latest": "1.0.0"},
            "time": {"1.0.0": now_iso},
            "versions": {"1.0.0": {"name": name, "version": "1.0.0", "dist": {"integrity": "sha512-x"}}},
        }

    def _fake_eval(self, spec, **kw):
        if spec.name == "oversized-pkg":
            raise RegistryError("Tarball exceeds max file count (5000).")
        meta = PackageMetadata(name=spec.name, version="1.0.0", integrity="sha512-susp")
        return FinalReport(
            ecosystem="npm",
            name=spec.name,
            version="1.0.0",
            integrity="sha512-susp",
            verdict=VerdictLabel.SUSPICIOUS,
            risk_score=65,
            layers_run=["layer0_metadata_advisories", "layer1_ast_diff"],
            summary="Install script",
            static_report=StaticAnalysisReport(metadata=meta, risk_score=65),
        )

    monkeypatch.setattr("cli_guard.ecosystems.npm.registry.NpmRegistryClient.fetch_packument", _fake_fetch_packument)
    monkeypatch.setattr("cli_guard.core.pipeline.SecurityPipeline.evaluate", _fake_eval)

    stats = MonitorStats()
    monitor.poll_once(stats, batch_limit=50, enable_llm=True)

    # 1. Stale checkpoint auto-fast-forwarded close to live HEAD instead of crawling seq=100000
    assert int(rep_client.since_seen[0]) >= 499500
    # 2. Oversized tarball counted as skipped (not error) and marked scanned so repeat events skip it
    assert stats.skipped_count == 1
    assert stats.errors == 0
    assert cache.has_scanned("npm", "oversized-pkg", "1.0.0") is True
    # 3. Rate-limited SUSPICIOUS package must NOT poison the 7-day verdicts cache
    assert stats.llm_skipped_rate_limit == 1
    assert cache.get("npm", "susp-ratelimited-pkg", "1.0.0", "sha512-susp") is None


def test_ledger_push_uploads_redacted_public_snapshot_and_schedule_spec(
    tmp_path: Path, monkeypatch
) -> None:
    settings = Settings(data_dir=tmp_path, ledger_repo="ahmedharib/cli-guard-ledger")
    store = FindingsLedgerStore(settings.data_dir)
    cache = VerdictCache(settings.cache_db_path)

    rep = FinalReport(
        ecosystem="npm",
        name="secret-unconfirmed-pkg",
        version="1.0.0",
        integrity="sha512-secret",
        verdict=VerdictLabel.SUSPICIOUS,
        risk_score=70,
        summary="Unconfirmed suspicious flag",
    )
    saved = store.record_finding(rep, scan_source="monitor", stamp_bitcoin=False)
    cache.record_scan(
        ecosystem="npm",
        name="secret-unconfirmed-pkg",
        version="1.0.0",
        integrity="sha512-secret",
        published_at="",
        scanned_at=datetime.now(UTC).isoformat(),
        scan_source="monitor",
        verdict="suspicious",
        risk_score=70,
        layers_run=["layer1"],
        summary="Unconfirmed suspicious flag",
        finding_id=saved["finding_id"],
    )

    uploaded: dict[str, bytes] = {}

    def _fake_put(client, *, repo, path, content_bytes, message, branch=None):
        uploaded[path] = content_bytes
        return {"ok": True}

    monkeypatch.setattr("cli_guard.ledger.github_sync._put_github_file", _fake_put)
    monkeypatch.setattr(
        "cli_guard.ledger.github_sync.ensure_public_ledger_repo",
        lambda token, repo, timeout=20.0: {"full_name": repo},
    )

    res = push_ledger_to_github(
        store,
        repo="ahmedharib/cli-guard-ledger",
        token="ghp_test",
        settings=settings,
        include_public_snapshot=True,
    )
    assert "ledger.jsonl" in res.uploaded_files
    assert "public_snapshot.json" in res.uploaded_files
    snap_text = uploaded["public_snapshot.json"].decode("utf-8")
    assert "secret-unconfirmed-pkg" not in snap_text
    assert '"public_safe": true' in snap_text
    assert "public_snapshot.json" in DASHBOARD_HTML

    # Upgrade C schedule command builder checks
    win_spec = build_daily_schedule_spec(
        daily_time="18:30",
        task_name="cli-guard-daily-sync",
        platform_name="nt",
        python_exe=Path(r"C:\Python313\python.exe"),
        working_dir=tmp_path,
    )
    assert win_spec["platform"] == "windows"
    assert "/Create" in win_spec["cmd"]
    assert "18:30" in win_spec["cmd"]

    posix_spec = build_daily_schedule_spec(
        daily_time="06:15",
        task_name="cli-guard-daily-sync",
        full=True,
        platform_name="posix",
        python_exe=Path("/usr/bin/python3"),
        working_dir=tmp_path,
    )
    assert posix_spec["cron_line"].startswith("15 6 * * *")
    assert "--full" in posix_spec["cron_line"]

    with pytest.raises(ValueError):
        build_daily_schedule_spec(daily_time="25:99")
