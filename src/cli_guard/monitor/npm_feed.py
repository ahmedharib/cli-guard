"""Live npm registry monitor consuming `replicate.npmjs.com/registry/_changes`."""

from __future__ import annotations

import concurrent.futures
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

import httpx

from cli_guard.config import Settings
from cli_guard.core.advisories import AdvisoryClient
from cli_guard.core.cache import VerdictCache
from cli_guard.core.pipeline import SecurityPipeline
from cli_guard.ecosystems.npm.registry import NpmRegistryClient, RegistryError
from cli_guard.ecosystems.npm.resolver import NpmAdapter
from cli_guard.ledger.github_sync import push_ledger_to_github, submit_openssf_pr
from cli_guard.ledger.store import FindingsLedgerStore
from cli_guard.llm.factory import create_provider
from cli_guard.models import FinalReport, PackageSpec, VerdictLabel
from cli_guard.monitor.ground_truth import run_ground_truth_verification
from cli_guard.monitor.state_sync import hydrate_state_from_snapshot

REPLICATE_BASE_URL = "https://replicate.npmjs.com"
SECURITY_PLACEHOLDER_VERSIONS: frozenset[str] = frozenset(
    {"0.0.1-security", "0.0.0-security"}
)


def _parse_npm_time(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


class TokenBucketRateLimiter:
    """Thread-safe sliding-window RPM limiter to cap LLM API credit burn."""

    def __init__(self, max_per_minute: int) -> None:
        self.max_per_minute = max(0, max_per_minute)
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        if self.max_per_minute <= 0:
            return False
        with self._lock:
            now = time.monotonic()
            cutoff = now - 60.0
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()
            if len(self._timestamps) >= self.max_per_minute:
                return False
            self._timestamps.append(now)
            return True


@dataclass(slots=True)
class MonitorStats:
    started_at_utc: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_seq: str = ""
    batches_polled: int = 0
    changes_seen: int = 0
    new_versions_scanned: int = 0
    benign_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    llm_escalations: int = 0
    llm_skipped_rate_limit: int = 0
    ots_upgraded_count: int = 0
    ledger_pushes: int = 0
    openssf_prs_opened: int = 0
    truth_checks_run: int = 0
    skipped_count: int = 0
    errors: int = 0
    findings_recorded: list[dict[str, Any]] = field(default_factory=list)


class NpmReplicationClient:
    """Compliant client for npm's May 2025+ `replicate.npmjs.com/registry/_changes` API."""

    def __init__(self, base_url: str = REPLICATE_BASE_URL, timeout: float = 20.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def fetch_head_seq(self) -> str:
        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            resp = client.get(f"{self.base_url}/")
            resp.raise_for_status()
            data = resp.json()
            seq = data.get("update_seq")
            if seq is None:
                raise RuntimeError(f"Missing `update_seq` in {self.base_url}/ response: {data}")
            return str(seq)

    def fetch_changes(self, *, since: str, limit: int = 100) -> tuple[str, list[str]]:
        """Return (new_last_seq, deduplicated_package_names) using only supported params."""
        params = {"since": since, "limit": str(max(1, min(1000, limit)))}
        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            resp = client.get(f"{self.base_url}/registry/_changes", params=params)
            resp.raise_for_status()
            data = resp.json()

        last_seq = str(data.get("last_seq") or since)
        results = data.get("results") or []
        names: list[str] = []
        seen: set[str] = set()
        for row in results:
            if not isinstance(row, dict):
                continue
            if row.get("deleted"):
                continue
            pkg_id = str(row.get("id") or "").strip()
            if not pkg_id or pkg_id.startswith("_design/") or pkg_id in seen:
                continue
            seen.add(pkg_id)
            names.append(pkg_id)

        return last_seq, names


def pick_new_versions_to_scan(
    packument: dict[str, Any],
    *,
    fresh_window_hours: float = 2.0,
    max_per_pkg: int = 2,
) -> list[str]:
    """Identify newly published versions from a packument's `time` map, skipping security placeholders."""
    versions_map = packument.get("versions") or {}
    times_map = packument.get("time") or {}
    if not versions_map:
        return []

    cutoff = datetime.now(UTC) - timedelta(hours=fresh_window_hours)
    recent: list[tuple[datetime, str]] = []
    for ver, ts_raw in times_map.items():
        if ver in {"created", "modified", "unpublished"}:
            continue
        if ver in SECURITY_PLACEHOLDER_VERSIONS or ver not in versions_map:
            continue
        dt = _parse_npm_time(str(ts_raw))
        if dt is not None and dt >= cutoff:
            recent.append((dt, ver))

    if recent:
        recent.sort(reverse=True)
        return [ver for _, ver in recent[:max_per_pkg]]

    # Fallback: if no `time` matches window (e.g., clock skew or manual backfill), inspect `latest` only
    latest = (packument.get("dist-tags") or {}).get("latest")
    if latest and latest in versions_map and latest not in SECURITY_PLACEHOLDER_VERSIONS:
        dt = _parse_npm_time(str(times_map.get(latest, "")))
        if dt is None or dt >= cutoff:
            return [str(latest)]
    return []


class LiveNpmMonitor:
    """Polls live npm changes, runs Layer 0+1 on all new versions, gates LLM calls, and stamps Bitcoin OTS."""

    def __init__(
        self,
        *,
        settings: Settings,
        min_llm_risk: int = 40,
        max_llm_rpm: int = 10,
        workers: int = 8,
        stamp_bitcoin: bool = True,
        auto_upgrade_ots: bool = True,
        ots_upgrade_interval: float | None = None,
        auto_push_ledger: bool | None = None,
        auto_openssf_pr: bool | None = None,
        auto_verify_truth: bool = True,
        truth_check_interval: float = 6 * 3600.0,
        from_head: bool = False,
        backfill: bool = False,
        fresh_window_hours: float = 2.0,
        baseline_snapshots: list[str] | None = None,
        rep_client: NpmReplicationClient | None = None,
        registry_client: NpmRegistryClient | None = None,
    ) -> None:
        self.settings = settings
        self.min_llm_risk = min_llm_risk
        self.workers = max(1, min(32, workers))
        self.stamp_bitcoin = stamp_bitcoin
        self.auto_upgrade_ots = auto_upgrade_ots
        self.ots_upgrade_interval = (
            ots_upgrade_interval
            if ots_upgrade_interval is not None
            else settings.ots_upgrade_interval_seconds
        )
        self.auto_push_ledger = (
            auto_push_ledger if auto_push_ledger is not None else settings.auto_push_ledger
        )
        self.auto_openssf_pr = (
            auto_openssf_pr if auto_openssf_pr is not None else settings.auto_openssf_pr
        )
        self.auto_verify_truth = auto_verify_truth
        self.truth_check_interval = max(300.0, truth_check_interval)
        self.from_head = from_head
        self.backfill = backfill
        self.fresh_window_hours = fresh_window_hours
        self.baseline_snapshots = list(baseline_snapshots or [])
        self._hydrated_baseline = False
        self._checked_startup_lag = False
        self._last_ots_upgrade_ts: float = 0.0
        self._last_truth_check_ts: float = 0.0
        self._state_lock = threading.Lock()

        self.cache = VerdictCache(settings.cache_db_path)
        self.advisories = AdvisoryClient(
            osv_api_url=settings.osv_api_url,
            cache=self.cache,
            timeout=min(15.0, settings.http_timeout_seconds),
        )
        self.registry = registry_client or NpmRegistryClient(
            registry_url=settings.npm_registry_url,
            timeout=settings.http_timeout_seconds,
            max_tarball_bytes=settings.max_tarball_bytes,
            max_extracted_bytes=settings.max_extracted_bytes,
            max_extracted_files=settings.max_extracted_files,
        )
        self.adapter = NpmAdapter(settings, registry=self.registry)
        self.llm_provider = create_provider(settings)
        self.ledger = FindingsLedgerStore(settings.data_dir)
        self.rep_client = rep_client or NpmReplicationClient()
        self.llm_limiter = TokenBucketRateLimiter(max_llm_rpm)
        self.log_path = settings.logs_dir / "monitor.jsonl"
        settings.logs_dir.mkdir(parents=True, exist_ok=True)

    def _log_event(
        self,
        level: str,
        message: str,
        *,
        extra: dict[str, Any] | None = None,
        on_event: Callable[[str], None] | None = None,
    ) -> None:
        entry = {
            "ts_utc": datetime.now(UTC).isoformat(),
            "level": level,
            "message": message,
            **(extra or {}),
        }
        try:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass
        if on_event:
            on_event(message)

    def maybe_upgrade_ots_and_sync(
        self,
        stats: MonitorStats,
        *,
        force: bool = False,
        on_event: Callable[[str], None] | None = None,
    ) -> int:
        """Automatically upgrade pending Bitcoin `.ots` proofs on schedule and sync ledger to GitHub."""
        if not self.auto_upgrade_ots:
            return 0
        now = time.monotonic()
        if not force and self._last_ots_upgrade_ts > 0 and (now - self._last_ots_upgrade_ts) < self.ots_upgrade_interval:
            return 0
        self._last_ots_upgrade_ts = now

        try:
            statuses = self.ledger.upgrade_all_ots(verify_bitcoin_header=True)
        except Exception as exc:
            stats.errors += 1
            self._log_event("error", f"Auto OTS upgrade error: {exc}", on_event=on_event)
            return 0

        confirmed = [s for s in statuses if s.state == "confirmed"]
        if confirmed:
            stats.ots_upgraded_count = len(confirmed)
            self._log_event(
                "info",
                f"[green]Auto OTS upgrade:[/green] {len(confirmed)}/{len(statuses)} proof(s) confirmed in Bitcoin.",
                extra={"confirmed": len(confirmed), "total": len(statuses)},
                on_event=on_event,
            )
            self._maybe_push_ledger(stats, on_event=on_event)
        return len(confirmed)

    def maybe_verify_ground_truth(
        self,
        stats: MonitorStats,
        *,
        force: bool = False,
        on_event: Callable[[str], None] | None = None,
    ) -> dict[str, Any] | None:
        """Periodically check flagged packages against OSV MAL-* and npm 0.0.1-security and auto-reveal confirmed TPs."""
        if not self.auto_verify_truth:
            return None
        now = time.monotonic()
        if (
            not force
            and self._last_truth_check_ts > 0
            and (now - self._last_truth_check_ts) < self.truth_check_interval
        ):
            return None
        self._last_truth_check_ts = now

        # Skip if no flagged findings exist yet
        if not self.ledger.list_ledger_entries():
            return None

        try:
            res = run_ground_truth_verification(
                self.settings,
                only_flagged=True,
                upgrade_ots=False,
                auto_reveal=True,
            )
            stats.truth_checks_run += 1
            revealed = res.get("auto_revealed_finding_ids") or []
            if revealed:
                self._log_event(
                    "alert",
                    f"[bold green]Ground-truth auto-reveal:[/bold green] {len(revealed)} confirmed True Positive(s).",
                    extra={"revealed": revealed},
                    on_event=on_event,
                )
                self._maybe_push_ledger(stats, on_event=on_event)
            return res
        except Exception as exc:
            stats.errors += 1
            self._log_event("error", f"Scheduled ground-truth check failed: {exc}", on_event=on_event)
            return None

    def _maybe_push_ledger(
        self,
        stats: MonitorStats,
        *,
        on_event: Callable[[str], None] | None = None,
    ) -> None:
        if not (self.auto_push_ledger and self.settings.github_token and self.settings.ledger_repo):
            return
        try:
            sync_res = push_ledger_to_github(
                self.ledger,
                repo=self.settings.ledger_repo,
                token=self.settings.github_token,
                auto_create=True,
                settings=self.settings,
            )
            if sync_res.uploaded_files:
                stats.ledger_pushes += 1
                self._log_event(
                    "info",
                    f"[cyan]Ledger pushed[/cyan] to `{sync_res.repo}` ({len(sync_res.uploaded_files)} file(s)).",
                    extra={"repo": sync_res.repo, "uploaded": sync_res.uploaded_files},
                    on_event=on_event,
                )
        except Exception as exc:
            stats.errors += 1
            self._log_event("error", f"Ledger GitHub sync failed: {exc}", on_event=on_event)

    def _maybe_submit_openssf_pr(
        self,
        finding_id: str,
        report: FinalReport,
        stats: MonitorStats,
        *,
        on_event: Callable[[str], None] | None = None,
    ) -> None:
        if not (
            self.auto_openssf_pr
            and self.settings.github_token
            and report.verdict == VerdictLabel.MALICIOUS
        ):
            return
        try:
            pr_res = submit_openssf_pr(
                self.ledger,
                finding_id,
                token=self.settings.github_token,
                upstream_repo=self.settings.openssf_repo,
                fork_repo=self.settings.openssf_fork,
                dry_run=False,
            )
            stats.openssf_prs_opened += 1
            self._log_event(
                "alert",
                f"[bold magenta]OpenSSF PR opened:[/bold magenta] {pr_res.pr_url}",
                extra={"finding_id": finding_id, "pr_url": pr_res.pr_url},
                on_event=on_event,
            )
        except Exception as exc:
            stats.errors += 1
            self._log_event("error", f"OpenSSF PR submission failed: {exc}", on_event=on_event)

    def _process_package_change(
        self,
        pkg_name: str,
        stats: MonitorStats,
        *,
        enable_llm: bool,
        on_event: Callable[[str], None] | None,
    ) -> list[FinalReport]:
        """Worker function: fetches packument & evaluates newly published versions for one package."""
        pkg_reports: list[FinalReport] = []
        # Each worker uses its own registry client instance so packument cache is thread-safe
        worker_registry = NpmRegistryClient(
            registry_url=self.settings.npm_registry_url,
            npmrc=self.registry.npmrc,
            timeout=self.settings.http_timeout_seconds,
            max_tarball_bytes=self.settings.max_tarball_bytes,
            max_extracted_bytes=self.settings.max_extracted_bytes,
            max_extracted_files=self.settings.max_extracted_files,
        )
        worker_adapter = NpmAdapter(self.settings, registry=worker_registry)
        custom_settings = replace(
            self.settings,
            triage_risk_threshold=self.min_llm_risk,
            investigator_risk_threshold=max(self.min_llm_risk + 15, 55),
        )
        static_pipe = SecurityPipeline(
            settings=custom_settings,
            adapter=worker_adapter,
            cache=self.cache,
            advisories=self.advisories,
            llm_provider=None,
        )
        llm_pipe = SecurityPipeline(
            settings=custom_settings,
            adapter=worker_adapter,
            cache=self.cache,
            advisories=self.advisories,
            llm_provider=self.llm_provider if (enable_llm and self.llm_provider is not None) else None,
        )

        try:
            packument = worker_registry.fetch_packument(pkg_name)
            new_versions = pick_new_versions_to_scan(
                packument, fresh_window_hours=self.fresh_window_hours
            )
        except RegistryError:
            return []
        except Exception as exc:
            with self._state_lock:
                stats.errors += 1
                self._log_event("error", f"[yellow]Error fetching {pkg_name}:[/yellow] {exc}", on_event=on_event)
            return []

        for ver in new_versions:
            if self.cache.has_scanned("npm", pkg_name, ver):
                continue
            spec = PackageSpec(ecosystem="npm", name=pkg_name, version=ver, raw_spec=f"{pkg_name}@{ver}")
            try:
                # Run Layer 0 + Layer 1 without prematurely caching static-only results
                report = static_pipe.evaluate(
                    spec,
                    use_cache=True,
                    write_cache=False,
                    record_scan=False,
                    enable_diff=True,
                    enable_llm=False,
                    scan_source="monitor",
                )

                needs_llm = (
                    enable_llm
                    and self.llm_provider is not None
                    and not (report.static_report and report.static_report.deterministic_block)
                    and report.risk_score >= self.min_llm_risk
                )
                rate_limited_llm = False
                if needs_llm:
                    if self.llm_limiter.allow():
                        with self._state_lock:
                            stats.llm_escalations += 1
                        report = llm_pipe.evaluate(
                            spec,
                            use_cache=False,
                            write_cache=True,
                            record_scan=False,
                            enable_diff=True,
                            enable_llm=True,
                            scan_source="monitor",
                        )
                    else:
                        rate_limited_llm = True
                        with self._state_lock:
                            stats.llm_skipped_rate_limit += 1
                elif not report.from_cache:
                    # Final deterministic/benign verdict (no pending LLM escalation): safe to cache
                    self.cache.put(report)

                pkg_reports.append(report)
                finding_id = ""
                with self._state_lock:
                    stats.new_versions_scanned += 1
                    if report.verdict == VerdictLabel.MALICIOUS:
                        stats.malicious_count += 1
                    elif report.verdict == VerdictLabel.SUSPICIOUS:
                        stats.suspicious_count += 1
                    else:
                        stats.benign_count += 1

                    if report.verdict in {VerdictLabel.MALICIOUS, VerdictLabel.SUSPICIOUS}:
                        saved = self.ledger.record_finding(
                            report,
                            scan_source="monitor",
                            stamp_bitcoin=self.stamp_bitcoin,
                        )
                        finding_id = saved["finding_id"]
                        stats.findings_recorded.append(
                            {
                                "finding_id": finding_id,
                                "package": f"{report.name}@{report.version}",
                                "verdict": report.verdict.value,
                                "risk_score": report.risk_score,
                                "commitment_sha256": saved["commitment_sha256"],
                                "ots_status": saved["ots_status"],
                            }
                        )
                        self._log_event(
                            "alert" if report.verdict == VerdictLabel.MALICIOUS else "warning",
                            f"FLAGGED {report.verdict.value.upper()} "
                            f"{report.name}@{report.version} (risk={report.risk_score}"
                            f"{', static-only: RPM cap' if rate_limited_llm else ''}) -> "
                            f"commit={saved['commitment_sha256'][:12]}... ots={saved['ots_status']}",
                            extra={
                                "finding_id": finding_id,
                                "package": f"{report.name}@{report.version}",
                                "verdict": report.verdict.value,
                                "risk_score": report.risk_score,
                                "ots_status": saved["ots_status"],
                            },
                            on_event=on_event,
                        )
                        self._maybe_push_ledger(stats, on_event=on_event)
                        self._maybe_submit_openssf_pr(
                            finding_id, report, stats, on_event=on_event
                        )

                    self.cache.record_scan(
                        ecosystem=report.ecosystem,
                        name=report.name,
                        version=report.version,
                        integrity=report.integrity,
                        published_at=(
                            report.static_report.metadata.published_at.isoformat()
                            if report.static_report and report.static_report.metadata.published_at
                            else ""
                        ),
                        scanned_at=datetime.now(UTC).isoformat(),
                        scan_source="monitor",
                        verdict=report.verdict.value,
                        risk_score=report.risk_score,
                        layers_run=report.layers_run,
                        summary=report.summary,
                        finding_id=finding_id,
                    )
            except RegistryError as exc:
                # Oversized tarballs (>5000 files / >100MiB) or 404 races: mark skipped so repeat edits don't re-download
                with self._state_lock:
                    stats.skipped_count += 1
                    self.cache.record_scan(
                        ecosystem="npm",
                        name=pkg_name,
                        version=ver,
                        integrity="",
                        published_at="",
                        scanned_at=datetime.now(UTC).isoformat(),
                        scan_source="monitor",
                        verdict="skipped",
                        risk_score=0,
                        layers_run=[],
                        summary=str(exc)[:300],
                    )
                    self._log_event(
                        "info",
                        f"[dim]Skipped {pkg_name}@{ver}: {exc}[/dim]",
                        on_event=on_event,
                    )
            except Exception as exc:
                with self._state_lock:
                    stats.errors += 1
                    self._log_event(
                        "error",
                        f"Scan failed for {pkg_name}@{ver}: {exc}",
                        on_event=on_event,
                    )
        return pkg_reports

    def poll_once(
        self,
        stats: MonitorStats,
        *,
        batch_limit: int = 50,
        enable_llm: bool = True,
        on_event: Callable[[str], None] | None = None,
    ) -> list[FinalReport]:
        """Poll one `_changes` batch from checkpoint and scan new versions concurrently."""
        if not self._hydrated_baseline and self.baseline_snapshots:
            self._hydrated_baseline = True
            h_res = hydrate_state_from_snapshot(self.settings, self.baseline_snapshots)
            if h_res.source and (
                h_res.seq_restored or h_res.scanned_added or h_res.findings_added or h_res.ledger_added
            ):
                self._log_event(
                    "info",
                    f"Hydrated baseline state from {h_res.source} "
                    f"(seq={h_res.seq_restored or 'kept'}, scanned=+{h_res.scanned_added}, "
                    f"findings=+{h_res.findings_added}, ledger=+{h_res.ledger_added})",
                    on_event=on_event,
                )

        seq = self.cache.get_state("npm_last_seq")
        if not seq:
            head = self.rep_client.fetch_head_seq()
            try:
                head_int = int(head)
                # Start slightly behind live HEAD so Batch 1 immediately scans fresh packages
                seq = str(max(0, head_int - min(500, batch_limit * 5))) if head_int > 1000 else head
            except ValueError:
                seq = head
            self.cache.set_state("npm_last_seq", seq)
            stats.last_seq = seq
            self._checked_startup_lag = True
            self._log_event(
                "info",
                f"Initialized live npm checkpoint at update_seq={seq}",
                on_event=on_event,
            )
        elif not self._checked_startup_lag:
            self._checked_startup_lag = True
            if self.from_head or (not self.backfill and self.fresh_window_hours <= 6.0):
                try:
                    head_str = self.rep_client.fetch_head_seq()
                    head_int = int(head_str)
                    seq_int = int(seq)
                    lag = head_int - seq_int
                    if self.from_head or lag > 10_000:
                        target_seq = str(max(seq_int, head_int - min(500, batch_limit * 5)))
                        if target_seq != seq:
                            self.cache.set_state("npm_last_seq", target_seq)
                            self._log_event(
                                "info",
                                f"Fast-forwarded stale checkpoint from seq={seq} to live seq={target_seq} "
                                f"(was {lag:,} changes behind HEAD={head_int}; pass --backfill to crawl old history).",
                                on_event=on_event,
                            )
                            seq = target_seq
                except Exception:
                    pass

        new_seq, pkg_names = self.rep_client.fetch_changes(since=seq, limit=batch_limit)
        stats.batches_polled += 1
        stats.changes_seen += len(pkg_names)

        reports: list[FinalReport] = []
        if pkg_names:
            worker_count = min(self.workers, len(pkg_names))
            if worker_count == 1:
                for pkg_name in pkg_names:
                    reports.extend(
                        self._process_package_change(
                            pkg_name, stats, enable_llm=enable_llm, on_event=on_event
                        )
                    )
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as pool:
                    futures = [
                        pool.submit(
                            self._process_package_change,
                            pkg_name,
                            stats,
                            enable_llm=enable_llm,
                            on_event=on_event,
                        )
                        for pkg_name in pkg_names
                    ]
                    for fut in concurrent.futures.as_completed(futures):
                        try:
                            reports.extend(fut.result())
                        except Exception as exc:
                            with self._state_lock:
                                stats.errors += 1
                                self._log_event("error", f"Monitor worker error: {exc}", on_event=on_event)

        if new_seq != seq:
            self.cache.set_state("npm_last_seq", new_seq)
            stats.last_seq = new_seq

        # Periodically upgrade pending Bitcoin `.ots` proofs and run flagged ground-truth checks
        self.maybe_upgrade_ots_and_sync(stats, on_event=on_event)
        self.maybe_verify_ground_truth(stats, on_event=on_event)
        return reports
