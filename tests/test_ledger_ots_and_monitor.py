"""Tests for salted commit-reveal ledger, Bitcoin OpenTimestamps, live npm feed, and ground-truth verifier."""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from cli_guard.config import Settings
from cli_guard.core.cache import VerdictCache
from cli_guard.ledger.bitcoin_ots import inspect_ots_file, serialize_detached
from cli_guard.ledger.store import FindingsLedgerStore, verify_commitment_reveal
from cli_guard.models import (
    Citation,
    FinalReport,
    LLMVerdict,
    PackageMetadata,
    StaticAnalysisReport,
    VerificationResult,
    VerdictLabel,
)
from cli_guard.monitor.ground_truth import (
    NpmOfficialStatus,
    classify_outcome,
    run_ground_truth_verification,
)
from cli_guard.monitor.npm_feed import pick_new_versions_to_scan


def test_salted_commit_reveal_and_showcase_storage(tmp_path: Path) -> None:
    store = FindingsLedgerStore(tmp_path)
    meta = PackageMetadata(
        name="evil-demo",
        version="1.0.2",
        integrity="sha512-deadbeef",
        published_at=datetime.now(UTC) - timedelta(minutes=10),
    )
    rep = FinalReport(
        ecosystem="npm",
        name="evil-demo",
        version="1.0.2",
        integrity="sha512-deadbeef",
        verdict=VerdictLabel.MALICIOUS,
        risk_score=95,
        layers_run=["layer0", "layer1", "layer3_investigator"],
        summary="Postinstall exfiltrates ~/.npmrc to external host.",
        static_report=StaticAnalysisReport(metadata=meta, risk_score=95),
        llm_verdict=LLMVerdict(
            verdict=VerdictLabel.MALICIOUS,
            confidence=0.98,
            summary="Exfiltrates npmrc",
            citations=[Citation(file="steal.js", start_line=1, end_line=3, reason="exfil")],
        ),
        verification=VerificationResult(
            valid_citations=[Citation(file="steal.js", start_line=1, end_line=3, reason="exfil")]
        ),
        extra={"cited_excerpts": [{"file": "steal.js", "start_line": 1, "end_line": 3, "excerpt": "   1: fetch(...)"}]},
    )

    saved = store.record_finding(rep, scan_source="monitor", stamp_bitcoin=False)
    fid = saved["finding_id"]

    # Public ledger entry MUST NOT leak the package name prior to reveal
    public_entries = store.list_ledger_entries()
    assert len(public_entries) == 1
    assert "evil-demo" not in json.dumps(public_entries[0])
    assert public_entries[0]["commitment_sha256"] == saved["commitment_sha256"]

    # Showcase file preserves exact code excerpts
    showcase = store.load_finding(fid)
    assert showcase is not None
    assert showcase["report"]["extra"]["cited_excerpts"][0]["file"] == "steal.js"

    # Reveal reproduces exact commitment hash & detects tampering
    reveal = store.reveal_finding(fid, verify_bitcoin_header=False)
    assert reveal["hash_verified"] is True
    assert reveal["payload"]["name"] == "evil-demo"

    tampered_payload = dict(reveal["payload"])
    tampered_payload["version"] = "9.9.9"
    assert (
        verify_commitment_reveal(
            commitment_sha256=reveal["commitment_sha256"],
            salt_hex=reveal["salt_hex"],
            payload=tampered_payload,
        )
        is False
    )

    # OpenSSF export contains schema_version + affected + cited_excerpts
    osv_doc = store.export_openssf_malicious_package(fid)
    assert osv_doc["affected"][0]["package"]["name"] == "evil-demo"
    assert osv_doc["database_specific"]["cited_excerpts"]


def test_ots_proof_serialization_pending_and_bitcoin_verification(
    tmp_path: Path, monkeypatch
) -> None:
    digest = os.urandom(32)
    root_ts = Timestamp(digest)
    nonce_ts = root_ts.ops.add(OpAppend(b"\x01" * 16))
    hashed_ts = nonce_ts.ops.add(OpSHA256())

    # Pending attestation
    hashed_ts.attestations.add(PendingAttestation("https://a.pool.opentimestamps.org"))
    pending_path = tmp_path / "pending.ots"
    pending_path.write_bytes(serialize_detached(DetachedTimestampFile(OpSHA256(), root_ts)))

    st_pending = inspect_ots_file(pending_path, expected_digest_hex=digest.hex())
    assert st_pending.state == "pending"
    assert st_pending.pending_calendars == ["https://a.pool.opentimestamps.org"]
    assert st_pending.errors == []

    # Confirmed Bitcoin attestation with mocked block header matching derived msg[::-1]
    btc_height = 912345
    hashed_ts.attestations.add(BitcoinBlockHeaderAttestation(btc_height))
    confirmed_path = tmp_path / "confirmed.ots"
    confirmed_path.write_bytes(serialize_detached(DetachedTimestampFile(OpSHA256(), root_ts)))

    expected_merkle_be = hashed_ts.msg[::-1].hex()
    monkeypatch.setattr(
        "cli_guard.ledger.bitcoin_ots._fetch_bitcoin_block",
        lambda h: {
            "id": "0000000000000000000abc",
            "merkle_root": expected_merkle_be,
            "timestamp": 1795300000,
        },
    )
    st_conf = inspect_ots_file(
        confirmed_path,
        expected_digest_hex=digest.hex(),
        verify_bitcoin_header=True,
    )
    assert st_conf.state == "confirmed"
    assert st_conf.bitcoin_anchors[0].height == btc_height
    assert st_conf.bitcoin_anchors[0].merkle_verified is True
    assert st_conf.errors == []


def test_pick_new_versions_skips_security_placeholders_and_old_releases() -> None:
    now = datetime.now(UTC)
    packument = {
        "dist-tags": {"latest": "1.0.1"},
        "time": {
            "created": (now - timedelta(days=30)).isoformat(),
            "1.0.0": (now - timedelta(days=10)).isoformat(),
            "1.0.1": (now - timedelta(minutes=5)).isoformat(),
            "0.0.1-security": (now - timedelta(minutes=1)).isoformat(),
        },
        "versions": {
            "1.0.0": {},
            "1.0.1": {},
            "0.0.1-security": {},
        },
    }
    picked = pick_new_versions_to_scan(packument, fresh_window_hours=2.0)
    assert picked == ["1.0.1"]


def test_ground_truth_classification_and_retrospective_report(
    tmp_path: Path, monkeypatch
) -> None:
    now = datetime.now(UTC)
    cls_early, lead = classify_outcome(
        our_verdict="malicious",
        our_scanned_at=(now - timedelta(hours=10)).isoformat(),
        official_confirmed_malware=True,
        official_confirmed_at=(now - timedelta(hours=2)).isoformat(),
        age_since_scan_hours=10.0,
    )
    assert cls_early == "TRUE_POSITIVE_EARLY_CATCH"
    assert lead == 8.0

    cls_fn, _ = classify_outcome(
        our_verdict="benign",
        our_scanned_at=(now - timedelta(hours=10)).isoformat(),
        official_confirmed_malware=True,
        official_confirmed_at=now.isoformat(),
        age_since_scan_hours=10.0,
    )
    assert cls_fn == "FALSE_NEGATIVE_MISSED"

    # End-to-end mocked ground-truth verification run
    settings = Settings(data_dir=tmp_path)
    cache = VerdictCache(settings.cache_db_path)
    store = FindingsLedgerStore(settings.data_dir)

    rep = FinalReport(
        ecosystem="npm",
        name="early-catch-pkg",
        version="1.0.0",
        integrity="sha512-x",
        verdict=VerdictLabel.MALICIOUS,
        risk_score=90,
        summary="Credential theft",
    )
    saved = store.record_finding(rep, scan_source="monitor", stamp_bitcoin=False)
    cache.record_scan(
        ecosystem="npm",
        name="early-catch-pkg",
        version="1.0.0",
        integrity="sha512-x",
        published_at=(now - timedelta(hours=12)).isoformat(),
        scanned_at=(now - timedelta(hours=11)).isoformat(),
        scan_source="monitor",
        verdict="malicious",
        risk_score=90,
        layers_run=["layer1"],
        summary="Credential theft",
        finding_id=saved["finding_id"],
    )
    cache.record_scan(
        ecosystem="npm",
        name="safe-pkg",
        version="2.0.0",
        integrity="sha512-y",
        published_at=(now - timedelta(hours=12)).isoformat(),
        scanned_at=(now - timedelta(hours=11)).isoformat(),
        scan_source="monitor",
        verdict="benign",
        risk_score=0,
        layers_run=["layer1"],
        summary="Clean",
    )

    monkeypatch.setattr(
        "cli_guard.monitor.ground_truth.AdvisoryClient.query_batch",
        lambda self, pkgs: {p: [] for p in pkgs},
    )
    monkeypatch.setattr(
        "cli_guard.monitor.ground_truth.check_npm_official_status",
        lambda name, ver, **kw: (
            NpmOfficialStatus(
                state="security_holding",
                reason="Replaced by 0.0.1-security",
                takedown_at_utc=(now - timedelta(hours=1)).isoformat(),
            )
            if name == "early-catch-pkg"
            else NpmOfficialStatus(state="live", reason="Live")
        ),
    )

    gt = run_ground_truth_verification(
        settings,
        upgrade_ots=False,
        auto_reveal=True,
    )
    assert gt["counts"]["TRUE_POSITIVE_EARLY_CATCH"] == 1
    assert gt["counts"]["TRUE_NEGATIVE"] == 1
    assert saved["finding_id"] in gt["auto_revealed_finding_ids"]
    assert Path(gt["markdown_report_path"]).exists()
    assert Path(gt["json_report_path"]).exists()
