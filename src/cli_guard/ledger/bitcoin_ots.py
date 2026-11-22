"""OpenTimestamps (Bitcoin blockchain) stamping, upgrading, and verification."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import httpx
from opentimestamps.calendar import CommitmentNotFoundError, RemoteCalendar
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import (
    BytesDeserializationContext,
    BytesSerializationContext,
)
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

DEFAULT_OTS_CALENDARS: tuple[str, ...] = (
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
)

BITCOIN_API_BASES: tuple[str, ...] = (
    "https://blockstream.info/api",
    "https://mempool.space/api",
)


@dataclass(slots=True)
class BitcoinAnchorInfo:
    height: int
    merkle_root_hex: str
    block_hash: str | None = None
    block_time_utc: str | None = None
    merkle_verified: bool | None = None


@dataclass(slots=True)
class OTSStatus:
    ots_path: Path
    file_digest_hex: str
    state: str  # "pending" | "confirmed" | "empty"
    pending_calendars: list[str] = field(default_factory=list)
    bitcoin_anchors: list[BitcoinAnchorInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def serialize_detached(detached: DetachedTimestampFile) -> bytes:
    ctx = BytesSerializationContext()
    detached.serialize(ctx)
    return ctx.getbytes()


def deserialize_detached(raw_bytes: bytes) -> DetachedTimestampFile:
    ctx = BytesDeserializationContext(raw_bytes)
    return DetachedTimestampFile.deserialize(ctx)


def _fetch_bitcoin_block(height: int, timeout: float = 12.0) -> dict | None:
    """Query public Bitcoin explorers for block hash, merkle_root, and timestamp."""
    for base in BITCOIN_API_BASES:
        try:
            with httpx.Client(timeout=timeout) as client:
                h_resp = client.get(f"{base}/block-height/{height}")
                if h_resp.status_code != 200:
                    continue
                block_hash = h_resp.text.strip()
                b_resp = client.get(f"{base}/block/{block_hash}")
                if b_resp.status_code != 200:
                    continue
                data = b_resp.json()
                return {
                    "id": data.get("id") or block_hash,
                    "merkle_root": data.get("merkle_root"),
                    "timestamp": data.get("timestamp"),
                }
        except Exception:
            continue
    return None


def inspect_ots_file(
    ots_path: Path,
    *,
    expected_digest_hex: str | None = None,
    verify_bitcoin_header: bool = False,
) -> OTSStatus:
    """Inspect and optionally verify an `.ots` proof against Bitcoin block headers."""
    raw = ots_path.read_bytes()
    detached = deserialize_detached(raw)
    digest_hex = detached.file_digest.hex()

    errors: list[str] = []
    if expected_digest_hex and digest_hex.lower() != expected_digest_hex.lower():
        errors.append(
            f"Digest mismatch: .ots commits to {digest_hex}, expected {expected_digest_hex}"
        )

    pending: list[str] = []
    anchors: list[BitcoinAnchorInfo] = []

    for msg_bytes, att in detached.timestamp.all_attestations():
        if isinstance(att, PendingAttestation):
            if att.uri not in pending:
                pending.append(att.uri)
        elif isinstance(att, BitcoinBlockHeaderAttestation):
            # OTS msg_bytes are little-endian internal Bitcoin merkle root bytes
            merkle_be = msg_bytes[::-1].hex()
            info = BitcoinAnchorInfo(height=int(att.height), merkle_root_hex=merkle_be)
            if verify_bitcoin_header:
                blk = _fetch_bitcoin_block(info.height)
                if blk and blk.get("merkle_root"):
                    info.block_hash = str(blk["id"])
                    ts_val = blk.get("timestamp")
                    if isinstance(ts_val, (int, float)):
                        info.block_time_utc = datetime.fromtimestamp(
                            ts_val, tz=UTC
                        ).isoformat()
                    info.merkle_verified = (
                        str(blk["merkle_root"]).lower() == merkle_be.lower()
                    )
                    if not info.merkle_verified:
                        errors.append(
                            f"Bitcoin block #{info.height} merkle_root mismatch: "
                            f"proof={merkle_be} vs block={blk['merkle_root']}"
                        )
            anchors.append(info)

    state = "confirmed" if anchors else ("pending" if pending else "empty")
    return OTSStatus(
        ots_path=ots_path,
        file_digest_hex=digest_hex,
        state=state,
        pending_calendars=pending,
        bitcoin_anchors=anchors,
        errors=errors,
    )


def stamp_digest_hex(
    digest_hex: str,
    ots_path: Path,
    *,
    calendars: tuple[str, ...] = DEFAULT_OTS_CALENDARS,
    timeout: float = 12.0,
) -> OTSStatus:
    """Stamp a SHA-256 hex digest with public OpenTimestamps calendars and save `.ots`."""
    digest_bytes = bytes.fromhex(digest_hex)
    if len(digest_bytes) != 32:
        raise ValueError(f"Expected 32-byte SHA-256 hex digest, got {len(digest_bytes)} bytes.")

    # Standard OTS privacy pattern: append 16-byte random nonce and hash before sending to calendars
    root_ts = Timestamp(digest_bytes)
    nonce_op = OpAppend(os.urandom(16))
    nonce_ts = root_ts.ops.add(nonce_op)
    hashed_ts = nonce_ts.ops.add(OpSHA256())

    successes = 0
    errors: list[str] = []
    for cal_url in calendars:
        try:
            cal = RemoteCalendar(cal_url)
            cal_ts = cal.submit(hashed_ts.msg, timeout=timeout)
            hashed_ts.merge(cal_ts)
            successes += 1
        except Exception as exc:
            errors.append(f"{cal_url}: {exc}")

    if successes == 0:
        raise RuntimeError(
            "Failed to submit digest to any OpenTimestamps calendar: " + "; ".join(errors)
        )

    detached = DetachedTimestampFile(OpSHA256(), root_ts)
    ots_path.parent.mkdir(parents=True, exist_ok=True)
    ots_path.write_bytes(serialize_detached(detached))

    status = inspect_ots_file(ots_path, expected_digest_hex=digest_hex)
    status.errors.extend(errors)
    return status


def _upgrade_node(node: Timestamp, timeout: float = 12.0) -> tuple[bool, list[str]]:
    changed = False
    errors: list[str] = []

    has_btc = any(isinstance(a, BitcoinBlockHeaderAttestation) for a in node.attestations)
    if not has_btc:
        for att in list(node.attestations):
            if isinstance(att, PendingAttestation):
                try:
                    cal = RemoteCalendar(att.uri)
                    upgraded = cal.get_timestamp(node.msg, timeout=timeout)
                    node.merge(upgraded)
                    changed = True
                except CommitmentNotFoundError:
                    pass
                except Exception as exc:
                    errors.append(f"{att.uri}: {exc}")

    for child in list(node.ops.values()):
        child_changed, child_errs = _upgrade_node(child, timeout=timeout)
        if child_changed:
            changed = True
        errors.extend(child_errs)

    return changed, errors


def upgrade_ots_file(
    ots_path: Path,
    *,
    timeout: float = 12.0,
    verify_bitcoin_header: bool = True,
) -> tuple[bool, OTSStatus]:
    """Poll OpenTimestamps calendars to upgrade pending attestations to Bitcoin block proofs."""
    detached = deserialize_detached(ots_path.read_bytes())
    changed, errs = _upgrade_node(detached.timestamp, timeout=timeout)
    if changed:
        ots_path.write_bytes(serialize_detached(detached))

    status = inspect_ots_file(
        ots_path,
        verify_bitcoin_header=verify_bitcoin_header,
    )
    status.errors.extend(errs)
    return changed, status
