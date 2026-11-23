"""Tests for `.npmrc` parsing, GitHub ledger sync & OpenSSF PRs, auto OTS upgrade, and web dashboard."""

import json
import urllib.request
from pathlib import Path

import httpx
import pytest

from cli_guard.config import Settings
from cli_guard.core.cache import VerdictCache
from cli_guard.dashboard.server import (
    PublicApiLimiter,
    build_dashboard_snapshot,
    create_dashboard_server,
    export_static_dashboard,
)
from cli_guard.dashboard.ui import DASHBOARD_HTML
from cli_guard.ecosystems.npm.npmrc import NpmrcConfig
from cli_guard.ecosystems.npm.resolver import (
    load_project_resolution_context,
    resolve_catalog_spec,
)
from cli_guard.ledger.github_sync import (
    build_openssf_pr_artifacts,
    push_ledger_to_github,
    submit_openssf_pr,
)
from cli_guard.ledger.store import FindingsLedgerStore
from cli_guard.models import Citation, FinalReport, VerificationResult, VerdictLabel
from cli_guard.monitor.npm_feed import LiveNpmMonitor, MonitorStats
from cli_guard.monitor.state_sync import hydrate_state_from_snapshot


def test_npmrc_scoped_registries_auth_and_env_expansion(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MY_GH_TOKEN", "ghp_secret_123")
    monkeypatch.delenv("CG_NPM_REGISTRY", raising=False)

    home_dir = tmp_path / "home"
    proj_dir = tmp_path / "project"
    home_dir.mkdir()
    proj_dir.mkdir()

    (home_dir / ".npmrc").write_text(
        "registry=https://registry.npmjs.org/\n"
        "//registry.npmjs.org/:_authToken=npm_user_tok\n",
        encoding="utf-8",
    )
    (proj_dir / ".npmrc").write_text(
        "@acme:registry=https://npm.pkg.github.com\n"
        "//npm.pkg.github.com/:_authToken=${MY_GH_TOKEN}\n"
        "https-proxy=http://proxy.corp.local:8080\n"
        "strict-ssl=false\n",
        encoding="utf-8",
    )

    cfg = NpmrcConfig.load(cwd=proj_dir, user_home=home_dir)
    assert cfg.registry_for_package("lodash") == "https://registry.npmjs.org"
    assert cfg.registry_for_package("@acme/private-sdk") == "https://npm.pkg.github.com"
    assert cfg.httpx_proxy() == "http://proxy.corp.local:8080"
    assert cfg.httpx_verify() is False

    # Project overrides & pnpm-workspace catalog resolution parity
    (proj_dir / "package.json").write_text(
        json.dumps({"overrides": {"lodash": "4.17.21"}, "resolutions": {"foo>bar": "2.0.0"}}),
        encoding="utf-8",
    )
    (proj_dir / "pnpm-workspace.yaml").write_text(
        "catalog:\n  chalk: '^5.3.0'\ncatalogs:\n  react18:\n    react: '^18.3.1'\n",
        encoding="utf-8",
    )
    overrides, catalogs = load_project_resolution_context(proj_dir)
    assert overrides["lodash"] == "4.17.21"
    assert overrides["bar"] == "2.0.0"
    assert resolve_catalog_spec("chalk", "catalog:", catalogs) == "^5.3.0"
    assert resolve_catalog_spec("react", "catalog:react18", catalogs) == "^18.3.1"

    # Auth tokens ONLY attach to matching origins (no cross-origin leakage)
    assert cfg.auth_headers_for_url("https://npm.pkg.github.com/@acme%2fprivate-sdk") == {
        "Authorization": "Bearer ghp_secret_123"
    }
    assert cfg.auth_headers_for_url("https://registry.npmjs.org/lodash") == {
        "Authorization": "Bearer npm_user_tok"
    }
    assert cfg.auth_headers_for_url("https://evil.example.com/tarball.tgz") == {}


def test_github_ledger_push_excludes_secrets_and_openssf_pr_dry_run(
    tmp_path: Path, monkeypatch
) -> None:
    store = FindingsLedgerStore(tmp_path)
    rep = FinalReport(
        ecosystem="npm",
        name="bad-pkg",
        version="1.2.3",
        integrity="sha512-bad",
        verdict=VerdictLabel.MALICIOUS,
        risk_score=98,
        layers_run=["layer0", "layer1", "layer3_investigator"],
        summary="Postinstall exfiltrates ~/.npmrc credentials.",
        verification=VerificationResult(
            valid_citations=[
                Citation(file="install.js", start_line=1, end_line=4, reason="exfil")
            ]
        ),
        extra={
            "cited_excerpts": [
                {"file": "install.js", "start_line": 1, "end_line": 4, "excerpt": "   1: fetch(...)"}
            ]
        },
    )
    saved = store.record_finding(rep, scan_source="monitor", stamp_bitcoin=False)
    fid = saved["finding_id"]
    # Simulate an .ots file present
    (store.ots_dir / f"{fid}.ots").write_bytes(b"fake-ots-bytes")

    uploaded_paths: list[str] = []

    def _fake_put(client, *, repo, path, content_bytes, message, branch=None):
        uploaded_paths.append(path)
        return {"content": {"path": path}}

    monkeypatch.setattr("cli_guard.ledger.github_sync._put_github_file", _fake_put)
    monkeypatch.setattr(
        "cli_guard.ledger.github_sync.ensure_public_ledger_repo",
        lambda token, repo, timeout=20.0: {"full_name": repo},
    )

    sync_res = push_ledger_to_github(
        store,
        repo="ahmed/cli-guard-ledger",
        token="ghp_dummy",
        auto_create=True,
    )
    assert "ledger.jsonl" in sync_res.uploaded_files
    assert f"ots/{fid}.ots" in sync_res.uploaded_files
    # Private secrets MUST NEVER be uploaded
    assert not any("secret" in p for p in uploaded_paths)

    # OpenSSF PR dry-run builds valid OSV path and PR body
    rel_path, title, body, osv_doc = build_openssf_pr_artifacts(store, fid)
    assert rel_path == f"osv/malicious/npm/bad-pkg/MAL-0000-{fid}.json"
    assert "bad-pkg@1.2.3" in title
    assert saved["commitment_sha256"] in body
    assert osv_doc["affected"][0]["package"]["name"] == "bad-pkg"

    pr_dry = submit_openssf_pr(store, fid, token=None, dry_run=True)
    assert pr_dry.dry_run is True
    assert pr_dry.report_path == rel_path


def test_monitor_auto_ots_upgrade_respects_interval(tmp_path: Path, monkeypatch) -> None:
    settings = Settings(data_dir=tmp_path, ots_upgrade_interval_seconds=1800.0)
    monitor = LiveNpmMonitor(
        settings=settings,
        stamp_bitcoin=False,
        auto_upgrade_ots=True,
        ots_upgrade_interval=600.0,
    )
    calls = 0

    def _fake_upgrade(verify_bitcoin_header=True):
        nonlocal calls
        calls += 1
        return []

    monkeypatch.setattr(monitor.ledger, "upgrade_all_ots", _fake_upgrade)
    stats = MonitorStats()

    # First call runs immediately; immediate second call is throttled by interval; force=True runs again
    monitor.maybe_upgrade_ots_and_sync(stats)
    monitor.maybe_upgrade_ots_and_sync(stats)
    assert calls == 1
    monitor.maybe_upgrade_ots_and_sync(stats, force=True)
    assert calls == 2


def test_dashboard_snapshot_static_export_and_live_server(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    # Empty data dir MUST return zero fake/demo entries
    snap = build_dashboard_snapshot(settings)
    assert snap["findings"] == []
    assert snap["scanned_packages"] == []
    assert snap["ledger"] == []
    assert snap["version"] == "0.1.0"

    out_dir = tmp_path / "docs"
    html_p, json_p = export_static_dashboard(settings, out_dir)
    assert html_p.exists() and json_p.exists()
    html_text = html_p.read_text(encoding="utf-8")
    assert "cli-guard Security Dashboard" in html_text
    assert "ots-nav-status" not in html_text
    assert "nav-docs-link" not in html_text
    assert '<section id="view-runner" class="view">' in html_text
    # CLI Runner must be the second nav button right after Inspection Reports
    idx_reports = html_text.index('data-view="findings"')
    idx_runner = html_text.index('data-view="runner"')
    idx_ledger = html_text.index('data-view="ledger"')
    assert idx_reports < idx_runner < idx_ledger
    assert DASHBOARD_HTML == html_text

    # Verify live HTTP server endpoints cleanly in-process
    server = create_dashboard_server(settings, host="127.0.0.1", port=0)
    import threading

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        port = server.server_address[1]
        # Use urllib with empty proxy handler so local sandbox proxies don't intercept loopback
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/api/health", timeout=5) as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode("utf-8"))["status"] == "ok"
        with opener.open(f"http://127.0.0.1:{port}/api/snapshot", timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "metrics" in data and "findings" in data
    finally:
        server.shutdown()
        server.server_close()


def test_baseline_snapshot_hydration_cold_start_and_merge(tmp_path: Path) -> None:
    snap_path = tmp_path / "baseline_snapshot.json"
    snap_payload = {
        "last_seq": "200",
        "scanned_packages": [
            {
                "ecosystem": "npm",
                "name": "lodash",
                "version": "4.17.21",
                "integrity": "sha512-lodash",
                "published_at": "2021-02-20T00:00:00+00:00",
                "scanned_at": "2026-11-23T18:00:00+00:00",
                "scan_source": "monitor",
                "verdict": "benign",
                "risk_score": 0,
                "layers_run": ["layer0_metadata_advisories", "layer1_ast_diff"],
                "summary": "Clean.",
                "finding_id": "",
            },
            {
                "ecosystem": "npm",
                "name": "evil-prev",
                "version": "1.0.0",
                "integrity": "sha512-evil",
                "published_at": "2026-11-23T17:50:00+00:00",
                "scanned_at": "2026-11-23T18:01:00+00:00",
                "scan_source": "monitor",
                "verdict": "suspicious",
                "risk_score": 70,
                "layers_run": ["layer0_metadata_advisories", "layer1_ast_diff"],
                "summary": "Suspicious postinstall.",
                "finding_id": "20261123T180100Z_abc123",
            },
        ],
        "findings": [
            {
                "finding_id": "20261123T180100Z_abc123",
                "detected_at_utc": "2026-11-23T18:01:00+00:00",
                "commitment_sha256": "deadbeef" * 8,
                "report": {
                    "ecosystem": "npm",
                    "name": "evil-prev",
                    "version": "1.0.0",
                    "integrity": "sha512-evil",
                    "verdict": "suspicious",
                    "risk_score": 70,
                    "layers_run": ["layer0_metadata_advisories", "layer1_ast_diff"],
                    "summary": "Suspicious postinstall.",
                },
            },
            {
                "finding_id": "cached_lodash@4.17.21",
                "report": {
                    "ecosystem": "npm",
                    "name": "lodash",
                    "version": "4.17.21",
                    "integrity": "sha512-lodash",
                    "verdict": "benign",
                    "risk_score": 0,
                    "layers_run": ["layer0_metadata_advisories", "layer1_ast_diff"],
                    "summary": "Clean.",
                },
            },
        ],
        "ledger": [
            {
                "finding_id": "20261123T180100Z_abc123",
                "commitment_sha256": "deadbeef" * 8,
                "verdict": "suspicious",
                "risk_score": 70,
                "ots_status": "pending",
                "status": "committed",
            }
        ],
        "logs": [
            {
                "ts_utc": "2026-11-23T18:01:00+00:00",
                "level": "warning",
                "message": "FLAGGED SUSPICIOUS evil-prev@1.0.0",
            }
        ],
    }
    snap_path.write_text(json.dumps(snap_payload), encoding="utf-8")

    data_dir = tmp_path / "data"
    settings = Settings(data_dir=data_dir)

    # 1. Cold-start hydration populates seq, scanned_packages, verdict cache, findings, ledger, and logs
    h1 = hydrate_state_from_snapshot(settings, [str(snap_path)])
    assert h1.seq_restored == "200"
    assert h1.scanned_added == 2
    assert h1.findings_added == 1
    assert h1.ledger_added == 1
    assert h1.logs_added == 1

    cache = VerdictCache(settings.cache_db_path)
    ledger = FindingsLedgerStore(settings.data_dir)
    assert cache.get_state("npm_last_seq") == "200"
    assert cache.has_scanned("npm", "lodash", "4.17.21") is True
    assert cache.get("npm", "lodash", "4.17.21", "sha512-lodash") is not None
    assert (ledger.findings_dir / "20261123T180100Z_abc123.json").exists()
    assert not (ledger.findings_dir / "cached_lodash@4.17.21.json").exists()
    assert len(ledger.list_ledger_entries()) == 1

    # 2. Newer local state (seq=250 + extra scan) MUST NOT be downgraded or duplicated by older snapshot
    cache.set_state("npm_last_seq", "250")
    cache.record_scan(
        ecosystem="npm",
        name="chalk",
        version="5.3.0",
        integrity="sha512-chalk",
        published_at="2023-01-01T00:00:00+00:00",
        scanned_at="2026-11-23T19:00:00+00:00",
        scan_source="monitor",
        verdict="benign",
        risk_score=0,
        layers_run=["layer0_metadata_advisories", "layer1_ast_diff"],
        summary="Clean.",
    )
    h2 = hydrate_state_from_snapshot(settings, [str(snap_path)])
    assert h2.seq_restored is None
    assert h2.scanned_added == 0
    assert h2.ledger_added == 0
    assert h2.logs_added == 0
    assert cache.get_state("npm_last_seq") == "250"
    assert len(cache.list_scanned_packages(ecosystem="npm")) == 3
    assert len(ledger.list_ledger_entries()) == 1


def test_public_safe_redacts_unconfirmed_findings_and_keeps_confirmed_and_benign(
    tmp_path: Path,
) -> None:
    settings = Settings(data_dir=tmp_path)
    cache = VerdictCache(settings.cache_db_path)
    store = FindingsLedgerStore(settings.data_dir)

    # 1. Unconfirmed suspicious finding (must NOT leak package name in public_safe=True)
    unconf_rep = FinalReport(
        ecosystem="npm",
        name="secret-unconfirmed-pkg",
        version="1.0.0",
        integrity="sha512-unconf",
        verdict=VerdictLabel.SUSPICIOUS,
        risk_score=65,
        summary="Flagged suspicious install script.",
    )
    saved_unconf = store.record_finding(unconf_rep, scan_source="monitor", stamp_bitcoin=False)
    cache.record_scan(
        ecosystem="npm",
        name="secret-unconfirmed-pkg",
        version="1.0.0",
        integrity="sha512-unconf",
        published_at="2026-11-23T18:00:00+00:00",
        scanned_at="2026-11-23T18:05:00+00:00",
        scan_source="monitor",
        verdict="suspicious",
        risk_score=65,
        layers_run=["layer0", "layer1"],
        summary="Flagged suspicious install script.",
        finding_id=saved_unconf["finding_id"],
    )

    # 2. Confirmed + revealed malicious finding (MUST appear in public_safe=True)
    conf_rep = FinalReport(
        ecosystem="npm",
        name="confirmed-evil-pkg",
        version="2.0.0",
        integrity="sha512-conf",
        verdict=VerdictLabel.MALICIOUS,
        risk_score=100,
        summary="Confirmed credential stealer.",
    )
    saved_conf = store.record_finding(conf_rep, scan_source="monitor", stamp_bitcoin=False)
    store.update_finding_ground_truth(
        saved_conf["finding_id"], {"classification": "TRUE_POSITIVE_EARLY_CATCH"}
    )
    store.reveal_finding(saved_conf["finding_id"], verify_bitcoin_header=False)
    cache.record_scan(
        ecosystem="npm",
        name="confirmed-evil-pkg",
        version="2.0.0",
        integrity="sha512-conf",
        published_at="2026-11-23T17:00:00+00:00",
        scanned_at="2026-11-23T17:05:00+00:00",
        scan_source="monitor",
        verdict="malicious",
        risk_score=100,
        layers_run=["layer0", "layer1"],
        summary="Confirmed credential stealer.",
        finding_id=saved_conf["finding_id"],
    )

    # 3. Benign cached package (MUST appear in public_safe=True)
    ben_rep = FinalReport(
        ecosystem="npm",
        name="lodash",
        version="4.17.21",
        integrity="sha512-lodash",
        verdict=VerdictLabel.BENIGN,
        risk_score=0,
        summary="Clean.",
    )
    cache.put(ben_rep)
    cache.record_scan(
        ecosystem="npm",
        name="lodash",
        version="4.17.21",
        integrity="sha512-lodash",
        published_at="2021-02-20T00:00:00+00:00",
        scanned_at="2026-11-23T17:06:00+00:00",
        scan_source="monitor",
        verdict="benign",
        risk_score=0,
        layers_run=["layer0", "layer1"],
        summary="Clean.",
    )

    # Monitor log containing unconfirmed package name
    settings.logs_dir.mkdir(parents=True, exist_ok=True)
    (settings.logs_dir / "monitor.jsonl").write_text(
        json.dumps(
            {
                "ts_utc": "2026-11-23T18:05:00+00:00",
                "level": "warning",
                "package": "secret-unconfirmed-pkg@1.0.0",
                "finding_id": saved_unconf["finding_id"],
                "message": "FLAGGED SUSPICIOUS secret-unconfirmed-pkg@1.0.0",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    snap = build_dashboard_snapshot(settings, public_safe=True)
    assert snap["public_safe"] is True
    # Counts remain truthful
    assert snap["metrics"]["total_scanned"] == 3
    assert snap["metrics"]["suspicious"] == 1
    assert snap["metrics"]["malicious"] == 1
    assert snap["metrics"]["benign"] == 1

    finding_names = {f["report"]["name"] for f in snap["findings"]}
    assert "confirmed-evil-pkg" in finding_names
    assert "lodash" in finding_names
    assert "secret-unconfirmed-pkg" not in finding_names
    assert "secret-unconfirmed-pkg" not in json.dumps(snap["findings"])
    assert "secret-unconfirmed-pkg" not in json.dumps(snap["scanned_packages"])
    assert "secret-unconfirmed-pkg" not in json.dumps(snap["logs"])
    # Unconfirmed commitment STILL appears in ledger as an opaque hash
    assert any(
        e["finding_id"] == saved_unconf["finding_id"] and not e.get("name")
        for e in snap["ledger"]
    )


def test_public_api_mode_rate_limiting_cors_and_admin_lockdown(tmp_path: Path) -> None:
    limiter = PublicApiLimiter(
        max_checks_per_ip_hour=2,
        max_llm_per_ip_day=1,
        max_llm_global_day=2,
    )
    assert limiter.allow_check("1.2.3.4") == (True, 0)
    assert limiter.allow_check("1.2.3.4") == (True, 0)
    allowed, retry = limiter.allow_check("1.2.3.4")
    assert allowed is False and retry > 0
    assert limiter.allow_llm("1.2.3.4") is True
    assert limiter.allow_llm("1.2.3.4") is False  # Per-IP daily cap hit
    assert limiter.allow_llm("5.6.7.8") is True
    assert limiter.allow_llm("9.9.9.9") is False  # Global daily cap hit

    settings = Settings(data_dir=tmp_path)
    srv_limiter = PublicApiLimiter(max_checks_per_ip_hour=1, max_llm_per_ip_day=0, max_llm_global_day=0)
    server = create_dashboard_server(
        settings,
        host="127.0.0.1",
        port=0,
        public_api=True,
        cors_origin="https://ahmedharib.github.io",
        limiter=srv_limiter,
    )
    import threading

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        port = server.server_address[1]
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        # CORS preflight
        req_opt = urllib.request.Request(f"http://127.0.0.1:{port}/api/check", method="OPTIONS")
        with opener.open(req_opt, timeout=5) as resp:
            assert resp.status == 204
            assert resp.headers.get("Access-Control-Allow-Origin") == "https://ahmedharib.github.io"

        # /api/ots/upgrade locked down in public_api mode
        req_ots = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/ots/upgrade", data=b"{}", method="POST"
        )
        with pytest.raises(urllib.error.HTTPError) as exc_ots:
            opener.open(req_ots, timeout=5)
        assert exc_ots.value.code == 403

        # 1st /api/check consumes quota (with invalid empty package -> 400); 2nd hits 429 rate limit
        req_c1 = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/check",
            data=b'{"package":""}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_c1:
            opener.open(req_c1, timeout=5)
        assert exc_c1.value.code == 400

        req_c2 = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/check",
            data=b'{"package":"lodash"}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_c2:
            opener.open(req_c2, timeout=5)
        assert exc_c2.value.code == 429
    finally:
        server.shutdown()
        server.server_close()
