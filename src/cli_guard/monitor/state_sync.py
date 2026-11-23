"""Baseline state hydration from a prior live `snapshot.json` (URL or local file).

Ensures `cg monitor start --once` never behaves like a cold start when `actions/cache`
misses or expires: it restores `npm_last_seq`, scanned package history, findings,
public ledger entries, and monitor logs without overwriting newer local state.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from cli_guard.config import Settings
from cli_guard.core.cache import VerdictCache
from cli_guard.ledger.store import FindingsLedgerStore
from cli_guard.models import FinalReport


@dataclass(slots=True)
class HydrationResult:
    source: str | None = None
    seq_restored: str | None = None
    scanned_added: int = 0
    findings_added: int = 0
    ledger_added: int = 0
    logs_added: int = 0


def _load_snapshot_source(source: str, timeout: float = 15.0) -> dict[str, Any] | None:
    cleaned = source.strip()
    if not cleaned:
        return None
    if cleaned.startswith(("http://", "https://")):
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(cleaned, headers={"Accept": "application/json"})
            if resp.status_code != 200:
                return None
            data = resp.json()
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    path = Path(cleaned).expanduser()
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _is_newer_seq(candidate: str, current: str | None) -> bool:
    if not candidate:
        return False
    if not current:
        return True
    try:
        return int(candidate) > int(current)
    except ValueError:
        return False


def hydrate_state_from_snapshot(
    settings: Settings,
    sources: Sequence[str],
    *,
    timeout: float = 15.0,
) -> HydrationResult:
    """Hydrate `~/.cli-guard` from the first reachable `snapshot.json` URL or file path.

    Merges non-destructively: existing newer local SQLite rows, findings, ledger entries,
    and `npm_last_seq` are always preserved.
    """
    snapshot: dict[str, Any] | None = None
    used_source: str | None = None
    for src in sources:
        loaded = _load_snapshot_source(src, timeout=timeout)
        if loaded is not None:
            snapshot = loaded
            used_source = src
            break

    res = HydrationResult(source=used_source)
    if snapshot is None:
        return res

    cache = VerdictCache(settings.cache_db_path)
    ledger = FindingsLedgerStore(settings.data_dir)

    # 1. Restore npm_last_seq if missing locally or behind the live snapshot
    snap_seq = str(snapshot.get("last_seq") or "").strip()
    local_seq = cache.get_state("npm_last_seq")
    if _is_newer_seq(snap_seq, local_seq):
        cache.set_state("npm_last_seq", snap_seq)
        res.seq_restored = snap_seq

    # 2. Merge scanned_packages (INSERT OR IGNORE keeps newer local records intact)
    for row in snapshot.get("scanned_packages") or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        version = str(row.get("version") or "").strip()
        if not name or not version:
            continue
        inserted = cache.record_scan_if_missing(
            ecosystem=str(row.get("ecosystem") or "npm"),
            name=name,
            version=version,
            integrity=str(row.get("integrity") or ""),
            published_at=str(row.get("published_at") or ""),
            scanned_at=str(row.get("scanned_at") or ""),
            scan_source=str(row.get("scan_source") or "monitor"),
            verdict=str(row.get("verdict") or "benign"),
            risk_score=int(row.get("risk_score") or 0),
            layers_run=list(row.get("layers_run") or []),
            summary=str(row.get("summary") or ""),
            finding_id=str(row.get("finding_id") or ""),
        )
        if inserted:
            res.scanned_added += 1

    # 3. Restore real findings JSON files and cached verdicts if missing locally
    for item in snapshot.get("findings") or []:
        if not isinstance(item, dict):
            continue
        fid = str(item.get("finding_id") or "").strip()
        rep_dict = item.get("report")
        if not fid or not isinstance(rep_dict, dict):
            continue

        # Hydrate SQLite verdict cache for cached reports so repeat runs skip rescanning
        try:
            rep = FinalReport.model_validate(rep_dict)
            if rep.integrity and cache.get(rep.ecosystem, rep.name, rep.version, rep.integrity) is None:
                cache.put(rep)
        except Exception:
            pass

        if fid.startswith("cached_"):
            continue
        fpath = ledger.findings_dir / f"{fid}.json"
        if not fpath.exists():
            fpath.write_text(json.dumps(item, indent=2), encoding="utf-8")
            res.findings_added += 1

    # 4. Merge public ledger entries (preserving chronological order and deduplicating by finding_id)
    existing_entries = ledger.list_ledger_entries()
    existing_ids = {str(e.get("finding_id")) for e in existing_entries if e.get("finding_id")}
    # snapshot["ledger"] is newest-first; reverse to restore chronological append order
    snap_ledger = list(reversed(snapshot.get("ledger") or []))
    new_ledger_rows: list[dict[str, Any]] = []
    for entry in snap_ledger:
        if not isinstance(entry, dict):
            continue
        fid = str(entry.get("finding_id") or "").strip()
        if not fid or fid in existing_ids:
            continue
        existing_ids.add(fid)
        new_ledger_rows.append(entry)

    if new_ledger_rows:
        combined = new_ledger_rows + existing_entries
        ledger.ledger_path.write_text(
            "".join(json.dumps(e) + "\n" for e in combined),
            encoding="utf-8",
        )
        res.ledger_added = len(new_ledger_rows)

    # 5. Merge monitor logs (preserving chronological order, deduped by (ts_utc, message))
    settings.logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = settings.logs_dir / "monitor.jsonl"
    existing_logs: list[dict[str, Any]] = []
    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                existing_logs.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    existing_log_keys = {
        (str(e.get("ts_utc", "")), str(e.get("message", ""))) for e in existing_logs
    }
    snap_logs = list(reversed(snapshot.get("logs") or []))
    new_logs: list[dict[str, Any]] = []
    for entry in snap_logs:
        if not isinstance(entry, dict):
            continue
        key = (str(entry.get("ts_utc", "")), str(entry.get("message", "")))
        if not key[1] or key in existing_log_keys:
            continue
        existing_log_keys.add(key)
        new_logs.append(entry)

    if new_logs:
        merged_logs = new_logs + existing_logs
        log_path.write_text(
            "".join(json.dumps(e) + "\n" for e in merged_logs[-500:]),
            encoding="utf-8",
        )
        res.logs_added = len(new_logs)

    return res
