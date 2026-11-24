"""Retrospective ground-truth verifier against official npm registry & OSV/OpenSSF advisories."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from cli_guard.config import Settings
from cli_guard.core.advisories import AdvisoryClient
from cli_guard.core.cache import VerdictCache
from cli_guard.ledger.store import FindingsLedgerStore
from cli_guard.models import VerdictLabel


def _parse_iso(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


@dataclass(slots=True)
class NpmOfficialStatus:
    state: str  # "live" | "removed_404" | "unpublished" | "security_holding" | "version_removed" | "error"
    reason: str = ""
    takedown_at_utc: str | None = None
    latest_version: str | None = None


@dataclass(slots=True)
class PackageVerificationRow:
    name: str
    version: str
    our_verdict: str
    our_risk_score: int
    our_scanned_at: str
    finding_id: str
    npm_status: str
    npm_reason: str
    osv_malware_ids: list[str] = field(default_factory=list)
    official_confirmed_malware: bool = False
    official_confirmed_at_utc: str | None = None
    lead_time_hours: float | None = None
    classification: str = "PENDING"
    ots_state: str = ""
    bitcoin_block_height: int | None = None


def check_npm_official_status(
    name: str,
    version: str,
    *,
    registry_url: str = "https://registry.npmjs.org",
    timeout: float = 12.0,
) -> NpmOfficialStatus:
    """Query official npm registry to see if a package/version is live, unpublished, or security-removed."""
    encoded = quote(name, safe="@")
    url = f"{registry_url.rstrip('/')}/{encoded}"
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        return NpmOfficialStatus(state="error", reason=f"HTTP error: {exc}")

    if resp.status_code == 404:
        return NpmOfficialStatus(
            state="removed_404",
            reason="Package returns HTTP 404 on official npm registry (deleted/taken down).",
        )
    if resp.status_code >= 400:
        return NpmOfficialStatus(state="error", reason=f"Registry HTTP {resp.status_code}")

    doc = resp.json()
    times = doc.get("time") or {}
    unpub = times.get("unpublished")
    if isinstance(unpub, dict):
        unpub_time = unpub.get("time")
        return NpmOfficialStatus(
            state="unpublished",
            reason="Package marked unpublished in official npm registry.",
            takedown_at_utc=str(unpub_time) if unpub_time else None,
        )

    versions = doc.get("versions") or {}
    dist_tags = doc.get("dist-tags") or {}
    latest = str(dist_tags.get("latest") or "")

    # Detect npm's official security-holding placeholder package
    latest_doc = versions.get(latest, {}) if latest else {}
    desc = str(latest_doc.get("description") or doc.get("description") or "").lower()
    if (
        latest in {"0.0.1-security", "0.0.0-security"}
        or "0.0.1-security" in versions
        or "security holding package" in desc
        or "removed by npm security" in desc
    ):
        sec_time = times.get("0.0.1-security") or times.get(latest)
        return NpmOfficialStatus(
            state="security_holding",
            reason="Replaced by official npm `0.0.1-security` holding package.",
            takedown_at_utc=str(sec_time) if sec_time else None,
            latest_version=latest,
        )

    if version not in versions:
        return NpmOfficialStatus(
            state="version_removed",
            reason=f"Version `{version}` no longer present on npm (latest={latest}).",
            latest_version=latest,
        )

    return NpmOfficialStatus(
        state="live",
        reason="Version still live on official npm registry.",
        latest_version=latest,
    )


def fetch_osv_published_time(
    vuln_id: str,
    *,
    osv_api_url: str = "https://api.osv.dev/v1",
    timeout: float = 12.0,
) -> str | None:
    """Fetch exact `published` timestamp of an OSV/OpenSSF MAL-* advisory."""
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"{osv_api_url.rstrip('/')}/vulns/{vuln_id}")
            if resp.status_code != 200:
                return None
            data = resp.json()
            pub = data.get("published")
            return str(pub) if pub else None
    except httpx.HTTPError:
        return None


def classify_outcome(
    *,
    our_verdict: str,
    our_scanned_at: str,
    official_confirmed_malware: bool,
    official_confirmed_at: str | None,
    age_since_scan_hours: float | None,
    npm_removed_unconfirmed: bool = False,
) -> tuple[str, float | None]:
    """Classify accuracy and compute lead time (official_time - our_time in hours)."""
    lead_hours: float | None = None
    our_dt = _parse_iso(our_scanned_at)
    off_dt = _parse_iso(official_confirmed_at)
    if our_dt is not None and off_dt is not None:
        lead_hours = round((off_dt - our_dt).total_seconds() / 3600.0, 2)

    flagged = our_verdict in {VerdictLabel.MALICIOUS.value, VerdictLabel.SUSPICIOUS.value}

    if flagged and official_confirmed_malware:
        if lead_hours is None or lead_hours >= 0:
            return "TRUE_POSITIVE_EARLY_CATCH", lead_hours
        return "TRUE_POSITIVE_POST_DISCLOSURE", lead_hours
    if not flagged and official_confirmed_malware:
        return "FALSE_NEGATIVE_MISSED", lead_hours
    if npm_removed_unconfirmed:
        # Author unpublish / plain 404 without OSV MAL-* or npm 0.0.1-security holding:
        # keep separate so routine developer unpublishes never trigger false public reveals or false recall drops.
        return "REMOVED_UNCONFIRMED", None
    if flagged and not official_confirmed_malware:
        if age_since_scan_hours is not None and age_since_scan_hours >= 168.0:
            return "LIKELY_FALSE_POSITIVE", None
        return "PENDING_FLAG", None
    return "TRUE_NEGATIVE", None


def run_ground_truth_verification(
    settings: Settings,
    *,
    only_flagged: bool = False,
    limit: int | None = None,
    upgrade_ots: bool = True,
    auto_reveal: bool = False,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    """Verify all scanned packages against OSV MAL-* and official npm registry status."""
    cache = VerdictCache(settings.cache_db_path)
    advisories = AdvisoryClient(osv_api_url=settings.osv_api_url, cache=cache)
    ledger = FindingsLedgerStore(settings.data_dir)

    verdicts_filter = (
        [VerdictLabel.MALICIOUS.value, VerdictLabel.SUSPICIOUS.value]
        if only_flagged
        else None
    )
    scanned_rows = cache.list_scanned_packages(
        ecosystem="npm",
        verdicts=verdicts_filter,
        limit=limit,
    )

    # Include any saved findings not yet in scanned_packages (e.g. imported findings)
    seen_keys = {(r["name"], r["version"]) for r in scanned_rows}
    for fdata in ledger.list_findings():
        rep = fdata.get("report") or {}
        key = (rep.get("name", ""), rep.get("version", ""))
        if key[0] and key[1] and key not in seen_keys:
            seen_keys.add(key)
            scanned_rows.append(
                {
                    "ecosystem": rep.get("ecosystem", "npm"),
                    "name": key[0],
                    "version": key[1],
                    "integrity": rep.get("integrity", ""),
                    "published_at": "",
                    "scanned_at": fdata.get("detected_at_utc", ""),
                    "scan_source": fdata.get("scan_source", "unknown"),
                    "verdict": rep.get("verdict", "suspicious"),
                    "risk_score": rep.get("risk_score", 0),
                    "layers_run": rep.get("layers_run", []),
                    "summary": rep.get("summary", ""),
                    "finding_id": fdata.get("finding_id", ""),
                }
            )

    if upgrade_ots:
        ledger.upgrade_all_ots(verify_bitcoin_header=True)

    ledger_by_id = {e.get("finding_id"): e for e in ledger.list_ledger_entries()}

    # Batch query OSV across all scanned packages
    osv_queries = [("npm", r["name"], r["version"]) for r in scanned_rows]
    osv_map = advisories.query_batch(osv_queries)
    osv_time_cache: dict[str, str | None] = {}

    now_dt = datetime.now(UTC)
    verified_rows: list[PackageVerificationRow] = []
    summary_counts: dict[str, int] = {
        "TRUE_POSITIVE_EARLY_CATCH": 0,
        "TRUE_POSITIVE_POST_DISCLOSURE": 0,
        "PENDING_FLAG": 0,
        "REMOVED_UNCONFIRMED": 0,
        "LIKELY_FALSE_POSITIVE": 0,
        "FALSE_NEGATIVE_MISSED": 0,
        "TRUE_NEGATIVE": 0,
    }
    revealed_ids: list[str] = []

    for row in scanned_rows:
        name = row["name"]
        version = row["version"]
        fid = row.get("finding_id") or ""
        osv_hits = [a for a in osv_map.get(("npm", name, version), []) if a.is_malware]
        osv_ids = [a.id for a in osv_hits]

        npm_st = check_npm_official_status(
            name,
            version,
            registry_url=settings.npm_registry_url,
            timeout=min(12.0, settings.http_timeout_seconds),
        )

        # Hard confirmation requires OSV MAL-* OR official npm `0.0.1-security` holding.
        # Plain author unpublishes / 404s stay `REMOVED_UNCONFIRMED` (never auto-revealed as malware).
        confirmed = bool(osv_ids) or npm_st.state == "security_holding"
        removed_unconfirmed = (not confirmed) and npm_st.state in {
            "removed_404",
            "unpublished",
            "version_removed",
        }

        official_times: list[str] = []
        for adv_id in osv_ids[:3]:
            if adv_id not in osv_time_cache:
                osv_time_cache[adv_id] = fetch_osv_published_time(
                    adv_id, osv_api_url=settings.osv_api_url
                )
            if osv_time_cache[adv_id]:
                official_times.append(str(osv_time_cache[adv_id]))
        if confirmed and npm_st.takedown_at_utc:
            official_times.append(npm_st.takedown_at_utc)
        earliest_official = min(official_times) if official_times else None

        scan_dt = _parse_iso(row.get("scanned_at"))
        age_hours = (
            (now_dt - scan_dt).total_seconds() / 3600.0 if scan_dt is not None else None
        )

        cls_label, lead_h = classify_outcome(
            our_verdict=row["verdict"],
            our_scanned_at=row.get("scanned_at", ""),
            official_confirmed_malware=confirmed,
            official_confirmed_at=earliest_official,
            age_since_scan_hours=age_hours,
            npm_removed_unconfirmed=removed_unconfirmed,
        )
        summary_counts[cls_label] = summary_counts.get(cls_label, 0) + 1

        ledger_entry = ledger_by_id.get(fid, {})
        ots_state = str(ledger_entry.get("ots_status") or "")
        btc_height = ledger_entry.get("bitcoin_block_height")

        v_row = PackageVerificationRow(
            name=name,
            version=version,
            our_verdict=row["verdict"],
            our_risk_score=int(row.get("risk_score") or 0),
            our_scanned_at=row.get("scanned_at", ""),
            finding_id=fid,
            npm_status=npm_st.state,
            npm_reason=npm_st.reason,
            osv_malware_ids=osv_ids,
            official_confirmed_malware=confirmed,
            official_confirmed_at_utc=earliest_official,
            lead_time_hours=lead_h,
            classification=cls_label,
            ots_state=ots_state,
            bitcoin_block_height=btc_height,
        )
        verified_rows.append(v_row)

        if fid:
            gt_payload = {
                "checked_at_utc": now_dt.isoformat(),
                "classification": cls_label,
                "npm_status": npm_st.state,
                "npm_reason": npm_st.reason,
                "osv_malware_ids": osv_ids,
                "official_confirmed_at_utc": earliest_official,
                "lead_time_hours": lead_h,
            }
            ledger.update_finding_ground_truth(fid, gt_payload)
            if auto_reveal and confirmed and cls_label.startswith("TRUE_POSITIVE"):
                try:
                    ledger.reveal_finding(fid, verify_bitcoin_header=True)
                    revealed_ids.append(fid)
                except Exception:
                    pass

    tp = summary_counts["TRUE_POSITIVE_EARLY_CATCH"] + summary_counts["TRUE_POSITIVE_POST_DISCLOSURE"]
    fp = summary_counts["LIKELY_FALSE_POSITIVE"]
    fn = summary_counts["FALSE_NEGATIVE_MISSED"]
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else None
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else None

    report_dict = {
        "generated_at_utc": now_dt.isoformat(),
        "total_checked": len(verified_rows),
        "counts": summary_counts,
        "precision_excluding_pending": precision,
        "recall": recall,
        "auto_revealed_finding_ids": revealed_ids,
        "results": [
            {
                "name": r.name,
                "version": r.version,
                "our_verdict": r.our_verdict,
                "our_risk_score": r.our_risk_score,
                "our_scanned_at": r.our_scanned_at,
                "finding_id": r.finding_id,
                "npm_status": r.npm_status,
                "npm_reason": r.npm_reason,
                "osv_malware_ids": r.osv_malware_ids,
                "official_confirmed_malware": r.official_confirmed_malware,
                "official_confirmed_at_utc": r.official_confirmed_at_utc,
                "lead_time_hours": r.lead_time_hours,
                "classification": r.classification,
                "ots_state": r.ots_state,
                "bitcoin_block_height": r.bitcoin_block_height,
            }
            for r in verified_rows
        ],
    }

    target_dir = output_dir or (settings.data_dir / "reports")
    target_dir.mkdir(parents=True, exist_ok=True)
    ts_tag = now_dt.strftime("%Y%m%dT%H%M%SZ")
    json_path = target_dir / f"ground_truth_{ts_tag}.json"
    md_path = target_dir / f"ground_truth_{ts_tag}.md"
    json_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown_showcase(report_dict), encoding="utf-8")

    report_dict["json_report_path"] = str(json_path)
    report_dict["markdown_report_path"] = str(md_path)
    return report_dict


def _render_markdown_showcase(report: dict[str, Any]) -> str:
    lines = [
        "# cli-guard Ground-Truth Showcase Report",
        "",
        f"- **Generated (UTC):** {report['generated_at_utc']}",
        f"- **Total Packages Verified:** {report['total_checked']}",
        f"- **Early Catches (True Positive before official advisory/takedown):** {report['counts']['TRUE_POSITIVE_EARLY_CATCH']}",
        f"- **Post-Disclosure Catches:** {report['counts']['TRUE_POSITIVE_POST_DISCLOSURE']}",
        f"- **Pending Flags (awaiting OSV/npm confirmation):** {report['counts']['PENDING_FLAG']}",
        f"- **Removed / Unpublished (unconfirmed by OSV or 0.0.1-security):** {report['counts'].get('REMOVED_UNCONFIRMED', 0)}",
        f"- **Likely False Positives (>7d live):** {report['counts']['LIKELY_FALSE_POSITIVE']}",
        f"- **Missed (False Negatives):** {report['counts']['FALSE_NEGATIVE_MISSED']}",
        f"- **True Negatives:** {report['counts']['TRUE_NEGATIVE']}",
        f"- **Precision (excl. pending):** {report['precision_excluding_pending']}",
        f"- **Recall:** {report['recall']}",
        "",
        "## Detailed Package Outcomes",
        "",
        "| Package | Our Verdict | Risk | Official npm | OSV MAL-* | Lead Time (h) | Bitcoin OTS | Classification |",
        "| :--- | :--- | ---: | :--- | :--- | ---: | :--- | :--- |",
    ]
    for r in report["results"]:
        osv_str = ", ".join(r["osv_malware_ids"]) if r["osv_malware_ids"] else "-"
        lead_str = f"{r['lead_time_hours']:+.2f}" if r["lead_time_hours"] is not None else "-"
        btc_str = (
            f"{r['ots_state']} (blk #{r['bitcoin_block_height']})"
            if r["bitcoin_block_height"]
            else (r["ots_state"] or "-")
        )
        lines.append(
            f"| `{r['name']}@{r['version']}` | {r['our_verdict']} | {r['our_risk_score']} | "
            f"{r['npm_status']} | {osv_str} | {lead_str} | {btc_str} | {r['classification']} |"
        )
    lines.append("")
    return "\n".join(lines)
