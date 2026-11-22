"""Tests for `.npmrc` parsing, GitHub ledger sync & OpenSSF PRs, auto OTS upgrade, and web dashboard."""

import json
import urllib.request
from pathlib import Path

import httpx
import pytest

from cli_guard.config import Settings
from cli_guard.dashboard.server import (
    build_dashboard_snapshot,
    create_dashboard_server,
    export_static_dashboard,
)
from cli_guard.ecosystems.npm.npmrc import NpmrcConfig
from cli_guard.ledger.github_sync import (
    build_openssf_pr_artifacts,
    push_ledger_to_github,
    submit_openssf_pr,
)
from cli_guard.ledger.store import FindingsLedgerStore
from cli_guard.models import Citation, FinalReport, VerificationResult, VerdictLabel
from cli_guard.monitor.npm_feed import LiveNpmMonitor, MonitorStats


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
        "//npm.pkg.github.com/:_authToken=${MY_GH_TOKEN}\n",
        encoding="utf-8",
    )

    cfg = NpmrcConfig.load(cwd=proj_dir, user_home=home_dir)
    assert cfg.registry_for_package("lodash") == "https://registry.npmjs.org"
    assert cfg.registry_for_package("@acme/private-sdk") == "https://npm.pkg.github.com"

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
    snap = build_dashboard_snapshot(settings, include_demo_if_empty=True)
    assert snap["findings"]
    assert snap["findings"][0]["is_demo"] is True

    out_dir = tmp_path / "docs"
    html_p, json_p = export_static_dashboard(settings, out_dir)
    assert html_p.exists() and json_p.exists()
    assert "cli-guard Security Dashboard" in html_p.read_text(encoding="utf-8")

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
