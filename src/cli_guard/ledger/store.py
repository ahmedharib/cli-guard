"""Detailed showcase findings store + salted SHA-256 commit-reveal ledger + OpenSSF export."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cli_guard.ledger.bitcoin_ots import (
    OTSStatus,
    inspect_ots_file,
    stamp_digest_hex,
    upgrade_ots_file,
)
from cli_guard.models import FinalReport


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize payload deterministically so commitment verification is byte-exact."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_salted_commitment(salt_hex: str, payload: dict[str, Any]) -> str:
    """Compute SHA-256(salt_bytes || canonical_json_bytes)."""
    salt_bytes = bytes.fromhex(salt_hex)
    return hashlib.sha256(salt_bytes + canonical_json_bytes(payload)).hexdigest()


def verify_commitment_reveal(
    *,
    commitment_sha256: str,
    salt_hex: str,
    payload: dict[str, Any],
) -> bool:
    """Return True iff `salt_hex` + `payload` reproduce `commitment_sha256`."""
    try:
        actual = compute_salted_commitment(salt_hex, payload)
        return actual.lower() == commitment_sha256.lower()
    except Exception:
        return False


class FindingsLedgerStore:
    """Manages detailed showcase findings, private salted secrets, public ledger.jsonl, and .ots proofs."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.findings_dir = data_dir / "findings"
        self.secrets_dir = data_dir / "ledger_secrets"
        self.ots_dir = data_dir / "ots"
        self.reveals_dir = data_dir / "reveals"
        self.ledger_path = data_dir / "ledger.jsonl"

        for d in (
            self.data_dir,
            self.findings_dir,
            self.secrets_dir,
            self.ots_dir,
            self.reveals_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

    def _next_finding_id(self, detected_dt: datetime) -> str:
        # Opaque random ID so public `ledger.jsonl` and `.ots` filenames never leak package names pre-reveal
        ts = detected_dt.strftime("%Y%m%dT%H%M%SZ")
        short_rand = secrets.token_hex(6)
        return f"{ts}_{short_rand}"

    def record_finding(
        self,
        report: FinalReport,
        *,
        scan_source: str = "monitor",
        stamp_bitcoin: bool = True,
    ) -> dict[str, Any]:
        """Save full showcase details, create salted SHA-256 commitment, and optionally stamp in Bitcoin."""
        detected_dt = datetime.now(UTC)
        detected_iso = detected_dt.isoformat()
        finding_id = self._next_finding_id(detected_dt)

        sr = report.static_report
        meta = sr.metadata if sr else None

        # Canonical commitment payload (what gets revealed later to prove early detection)
        citations_list: list[dict[str, Any]] = []
        if report.verification and report.verification.valid_citations:
            citations_list = [c.model_dump() for c in report.verification.valid_citations]
        elif report.llm_verdict and report.llm_verdict.citations:
            citations_list = [c.model_dump() for c in report.llm_verdict.citations]

        commitment_payload: dict[str, Any] = {
            "commitment_version": 1,
            "finding_id": finding_id,
            "ecosystem": report.ecosystem,
            "name": report.name,
            "version": report.version,
            "integrity": report.integrity,
            "published_at_utc": meta.published_at.isoformat() if meta and meta.published_at else "",
            "detected_at_utc": detected_iso,
            "verdict": report.verdict.value,
            "risk_score": report.risk_score,
            "summary": report.summary,
            "citations": citations_list,
        }

        salt_hex = secrets.token_hex(32)
        commitment_sha256 = compute_salted_commitment(salt_hex, commitment_payload)

        # Save rich showcase artifact (exact code excerpts, AST, diff, LLM trace, metadata)
        showcase_record: dict[str, Any] = {
            "finding_id": finding_id,
            "scan_source": scan_source,
            "detected_at_utc": detected_iso,
            "commitment_sha256": commitment_sha256,
            "ots_file": str((self.ots_dir / f"{finding_id}.ots").name),
            "revealed": False,
            "ground_truth": None,
            "report": report.model_dump(mode="json"),
        }
        finding_path = self.findings_dir / f"{finding_id}.json"
        finding_path.write_text(json.dumps(showcase_record, indent=2), encoding="utf-8")

        # Save private secret (kept off public ledger until responsible reveal)
        secret_record = {
            "finding_id": finding_id,
            "commitment_sha256": commitment_sha256,
            "salt_hex": salt_hex,
            "payload": commitment_payload,
        }
        secret_path = self.secrets_dir / f"{finding_id}.secret.json"
        secret_path.write_text(json.dumps(secret_record, indent=2), encoding="utf-8")

        ots_status_str = "unstamped"
        ots_errors: list[str] = []
        ots_path = self.ots_dir / f"{finding_id}.ots"
        if stamp_bitcoin:
            try:
                status = stamp_digest_hex(commitment_sha256, ots_path)
                ots_status_str = status.state
                ots_errors = status.errors
            except Exception as exc:
                ots_status_str = "stamp_failed"
                ots_errors = [str(exc)]

        # Append public commitment entry (contains ZERO package identifiers)
        public_entry = {
            "finding_id": finding_id,
            "commitment_sha256": commitment_sha256,
            "detected_at_utc": detected_iso,
            "verdict": report.verdict.value,
            "risk_score": report.risk_score,
            "ots_file": ots_path.name if ots_path.exists() else "",
            "ots_status": ots_status_str,
            "status": "committed",
        }
        with self.ledger_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(public_entry) + "\n")

        return {
            "finding_id": finding_id,
            "finding_path": str(finding_path),
            "commitment_sha256": commitment_sha256,
            "ots_path": str(ots_path) if ots_path.exists() else "",
            "ots_status": ots_status_str,
            "ots_errors": ots_errors,
        }

    def list_ledger_entries(self) -> list[dict[str, Any]]:
        if not self.ledger_path.exists():
            return []
        entries: list[dict[str, Any]] = []
        for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries

    def _rewrite_ledger_entries(self, entries: list[dict[str, Any]]) -> None:
        self.ledger_path.write_text(
            "".join(json.dumps(e) + "\n" for e in entries),
            encoding="utf-8",
        )

    def load_finding(self, finding_id: str) -> dict[str, Any] | None:
        path = self.findings_dir / f"{finding_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def list_findings(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for path in sorted(self.findings_dir.glob("*.json"), reverse=True):
            try:
                out.append(json.loads(path.read_text(encoding="utf-8")))
            except Exception:
                continue
        return out

    def update_finding_ground_truth(
        self, finding_id: str, ground_truth: dict[str, Any]
    ) -> None:
        path = self.findings_dir / f"{finding_id}.json"
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        data["ground_truth"] = ground_truth
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def stamp_missing(self) -> list[dict[str, Any]]:
        """Stamp any committed ledger entries that do not yet have an `.ots` file."""
        entries = self.list_ledger_entries()
        results: list[dict[str, Any]] = []
        changed = False

        for entry in entries:
            fid = entry.get("finding_id", "")
            commit_hex = entry.get("commitment_sha256", "")
            if not fid or not commit_hex:
                continue
            ots_path = self.ots_dir / f"{fid}.ots"
            if ots_path.exists():
                continue
            try:
                status = stamp_digest_hex(commit_hex, ots_path)
                entry["ots_file"] = ots_path.name
                entry["ots_status"] = status.state
                changed = True
                results.append(
                    {"finding_id": fid, "status": status.state, "ots_path": str(ots_path)}
                )
            except Exception as exc:
                results.append({"finding_id": fid, "status": "error", "error": str(exc)})

        if changed:
            self._rewrite_ledger_entries(entries)
        return results

    def upgrade_all_ots(self, *, verify_bitcoin_header: bool = True) -> list[OTSStatus]:
        """Upgrade all pending `.ots` files to Bitcoin block attestations once mined."""
        entries = self.list_ledger_entries()
        entry_by_id = {e.get("finding_id"): e for e in entries}
        statuses: list[OTSStatus] = []
        ledger_dirty = False

        for ots_path in sorted(self.ots_dir.glob("*.ots")):
            fid = ots_path.stem
            try:
                _, status = upgrade_ots_file(
                    ots_path, verify_bitcoin_header=verify_bitcoin_header
                )
                statuses.append(status)
                if fid in entry_by_id:
                    entry = entry_by_id[fid]
                    if entry.get("ots_status") != status.state:
                        entry["ots_status"] = status.state
                        ledger_dirty = True
                    if status.bitcoin_anchors:
                        anchor = status.bitcoin_anchors[0]
                        entry["bitcoin_block_height"] = anchor.height
                        entry["bitcoin_block_time_utc"] = anchor.block_time_utc
                        entry["bitcoin_merkle_verified"] = anchor.merkle_verified
                        ledger_dirty = True
            except Exception as exc:
                statuses.append(
                    OTSStatus(
                        ots_path=ots_path,
                        file_digest_hex="",
                        state="error",
                        errors=[str(exc)],
                    )
                )

        if ledger_dirty:
            self._rewrite_ledger_entries(entries)
        return statuses

    def reveal_finding(
        self, finding_id: str, *, verify_bitcoin_header: bool = True
    ) -> dict[str, Any]:
        """Reveal salted secret + payload alongside its `.ots` proof and verify integrity."""
        secret_path = self.secrets_dir / f"{finding_id}.secret.json"
        if not secret_path.exists():
            raise FileNotFoundError(f"Secret commitment file not found for `{finding_id}`.")

        secret_data = json.loads(secret_path.read_text(encoding="utf-8"))
        commitment = secret_data["commitment_sha256"]
        salt_hex = secret_data["salt_hex"]
        payload = secret_data["payload"]

        hash_valid = verify_commitment_reveal(
            commitment_sha256=commitment,
            salt_hex=salt_hex,
            payload=payload,
        )

        ots_path = self.ots_dir / f"{finding_id}.ots"
        ots_info: dict[str, Any] | None = None
        if ots_path.exists():
            st = inspect_ots_file(
                ots_path,
                expected_digest_hex=commitment,
                verify_bitcoin_header=verify_bitcoin_header,
            )
            ots_info = {
                "ots_file": str(ots_path),
                "state": st.state,
                "pending_calendars": st.pending_calendars,
                "bitcoin_anchors": [
                    {
                        "height": a.height,
                        "merkle_root_hex": a.merkle_root_hex,
                        "block_hash": a.block_hash,
                        "block_time_utc": a.block_time_utc,
                        "merkle_verified": a.merkle_verified,
                    }
                    for a in st.bitcoin_anchors
                ],
                "errors": st.errors,
            }

        reveal_doc = {
            "finding_id": finding_id,
            "commitment_sha256": commitment,
            "hash_verified": hash_valid,
            "salt_hex": salt_hex,
            "payload": payload,
            "ots_proof": ots_info,
            "revealed_at_utc": datetime.now(UTC).isoformat(),
        }
        reveal_path = self.reveals_dir / f"{finding_id}.reveal.json"
        reveal_path.write_text(json.dumps(reveal_doc, indent=2), encoding="utf-8")

        # Update ledger & showcase record
        entries = self.list_ledger_entries()
        for e in entries:
            if e.get("finding_id") == finding_id:
                e["status"] = "revealed"
                e["name"] = payload.get("name")
                e["version"] = payload.get("version")
                e["revealed_at_utc"] = reveal_doc["revealed_at_utc"]
        self._rewrite_ledger_entries(entries)

        fpath = self.findings_dir / f"{finding_id}.json"
        if fpath.exists():
            fdata = json.loads(fpath.read_text(encoding="utf-8"))
            fdata["revealed"] = True
            fdata["reveal_path"] = str(reveal_path)
            fpath.write_text(json.dumps(fdata, indent=2), encoding="utf-8")

        return {**reveal_doc, "reveal_path": str(reveal_path)}

    def export_openssf_malicious_package(self, finding_id: str) -> dict[str, Any]:
        """Export finding in OpenSSF `malicious-packages` OSV JSON format."""
        fdata = self.load_finding(finding_id)
        if not fdata:
            raise FileNotFoundError(f"Finding `{finding_id}` not found.")
        rep = fdata["report"]
        return {
            "schema_version": "1.6.0",
            "id": f"CG-{finding_id}",
            "summary": f"Malicious behavior in {rep['name']}@{rep['version']}: {rep['summary']}",
            "details": rep["summary"],
            "affected": [
                {
                    "package": {
                        "ecosystem": "npm",
                        "name": rep["name"],
                    },
                    "versions": [rep["version"]],
                }
            ],
            "database_specific": {
                "cli_guard_finding_id": finding_id,
                "detected_at_utc": fdata["detected_at_utc"],
                "commitment_sha256": fdata["commitment_sha256"],
                "risk_score": rep["risk_score"],
                "cited_excerpts": (rep.get("extra") or {}).get("cited_excerpts", []),
            },
        }
