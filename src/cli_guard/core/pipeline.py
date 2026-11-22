"""4-layer zero-execution security pipeline: Cache/OSV -> AST+Diff -> Triage LLM -> Investigator."""

from __future__ import annotations

from datetime import UTC, datetime

from cli_guard.agent.investigator import run_investigator_agent
from cli_guard.agent.triage_llm import run_triage_llm
from cli_guard.config import Settings
from cli_guard.core.advisories import AdvisoryClient
from cli_guard.core.cache import VerdictCache
from cli_guard.core.verifier import verify_llm_verdict
from cli_guard.ecosystems.base import EcosystemAdapter, InMemoryArchive
from cli_guard.ecosystems.npm.ast_scanner import INSTALL_HOOK_NAMES
from cli_guard.llm.base import LLMError, LLMProvider
from cli_guard.models import (
    CapabilityKind,
    FinalReport,
    LLMVerdict,
    PackageMetadata,
    PackageSpec,
    Severity,
    StaticAnalysisReport,
    VerdictLabel,
)


def score_static_report(
    report: StaticAnalysisReport,
    *,
    is_exec_target: bool = False,
    cooldown_hours: float = 24.0,
) -> None:
    """Compute deterministic risk score (0-100), risk reasons, and non-bypassable floors."""
    score = 0
    reasons: list[str] = []
    det_block = False
    det_floor = False

    meta = report.metadata
    caps = report.capabilities
    diff = report.version_diff

    # 1. Known malware advisories (OSV MAL-* or local blocklist)
    malware_advs = [a for a in report.advisories if a.is_malware]
    if malware_advs:
        score += 100
        det_block = True
        ids = ", ".join(a.id for a in malware_advs[:3])
        reasons.append(f"Matched known malware advisory: {ids}")

    # 2. Release age cooldown
    if meta.age_hours is not None and cooldown_hours > 0 and meta.age_hours < cooldown_hours:
        report.cooldown_triggered = True
        score += 15
        reasons.append(
            f"Newly published release ({meta.age_hours:.1f}h old < {cooldown_hours:.0f}h cooldown)"
        )

    # 3. Typosquatting / phantom deps / external URLs
    if report.typosquat_targets:
        score += 30
        det_floor = True
        reasons.append(
            f"Potential typosquat of popular package(s): {', '.join(report.typosquat_targets)}"
        )
    if report.phantom_dependencies:
        score += 35
        det_floor = True
        reasons.append(
            f"Phantom/unpublished dependency gap: {', '.join(report.phantom_dependencies[:3])}"
        )
    if report.external_dependencies:
        score += 25
        reasons.append(
            f"Non-registry external dependency: {', '.join(report.external_dependencies[:3])}"
        )

    # 4. Deterministic critical findings (e.g. curl|sh, obfuscated child_process, heavy invisible unicode)
    for f in caps.findings:
        if f.deterministic_critical:
            score += 65
            det_block = True
            reasons.append(f"Critical pattern in {f.file}:{f.line} — {f.detail}")

    # 5. Install-time & immediate bin-execution reachability analysis
    install_kinds: set[CapabilityKind] = set()
    bin_kinds: set[CapabilityKind] = set()
    all_kinds: set[CapabilityKind] = set()

    for f in caps.findings:
        all_kinds.add(f.kind)
        if "install" in f.reachable_from or any(r.startswith("script:") for r in f.reachable_from):
            install_kinds.add(f.kind)
        if "bin" in f.reachable_from:
            bin_kinds.add(f.kind)

    if caps.has_install_scripts:
        score += 15
        reasons.append("Package defines install lifecycle script(s)")

    if CapabilityKind.EXEC in install_kinds and (
        CapabilityKind.NETWORK in install_kinds or CapabilityKind.SENSITIVE_READ in install_kinds
    ):
        score += 45
        reasons.append("Install-reachable execution combined with network/credential access")
    elif CapabilityKind.EXEC in install_kinds:
        score += 25
        reasons.append("Install-reachable process/shell execution")

    if CapabilityKind.NETWORK in install_kinds and CapabilityKind.SENSITIVE_READ in install_kinds:
        score += 40
        reasons.append("Install-reachable sensitive/env read combined with outbound network")

    if CapabilityKind.COMPUTED_REQUIRE in install_kinds or CapabilityKind.DYNAMIC_EXEC in install_kinds:
        score += 35
        reasons.append("Install-reachable dynamic eval/Function or computed require()")
    elif CapabilityKind.COMPUTED_REQUIRE in all_kinds:
        score += 20
        reasons.append("Contains computed/dynamic require() hiding import graph")

    if is_exec_target:
        if CapabilityKind.EXEC in bin_kinds and (
            CapabilityKind.NETWORK in bin_kinds or CapabilityKind.SENSITIVE_READ in bin_kinds
        ):
            score += 40
            reasons.append("Immediate `bin` target combines execution with network/credential access")
        if CapabilityKind.DYNAMIC_EXEC in bin_kinds or CapabilityKind.COMPUTED_REQUIRE in bin_kinds:
            score += 30
            reasons.append("Immediate `bin` target uses dynamic eval or computed require()")

    # Runtime-only sensitive credential + network + obfuscation combo
    high_sev_sensitive = any(
        f.kind == CapabilityKind.SENSITIVE_READ and f.severity == Severity.HIGH
        for f in caps.findings
    )
    if high_sev_sensitive and CapabilityKind.NETWORK in all_kinds:
        score += 30
        reasons.append("References sensitive credential paths (.npmrc/.ssh/.aws/wallets) alongside network code")

    if caps.has_invisible_unicode:
        score += 40
        det_floor = True
        reasons.append("Contains invisible/bidi Unicode characters (Trojan Source / steganography)")

    if caps.has_prompt_injection_pattern:
        score += 35
        det_floor = True
        reasons.append("Contains reviewer-targeted prompt-injection text inside package")

    if CapabilityKind.OBFUSCATION in install_kinds or (
        is_exec_target and CapabilityKind.OBFUSCATION in bin_kinds
    ):
        score += 20
        reasons.append("Encoded/obfuscated payload decoding in executable entrypoint")

    # 6. Version diff signals (catch compromised patch releases!)
    if diff is not None:
        added_install_hooks = [k for k in diff.added_scripts if k in INSTALL_HOOK_NAMES]
        mod_install_hooks = [k for k in diff.modified_scripts if k in INSTALL_HOOK_NAMES]
        if added_install_hooks:
            score += 30
            det_floor = True
            reasons.append(
                f"Version {diff.current_version} newly added install hook(s): {', '.join(added_install_hooks)}"
            )
        elif mod_install_hooks:
            score += 20
            reasons.append(
                f"Version {diff.current_version} modified install hook(s): {', '.join(mod_install_hooks)}"
            )

        if diff.provenance_dropped:
            score += 25
            det_floor = True
            reasons.append(
                f"SLSA/npm provenance DROPPED between {diff.previous_version} and {diff.current_version}"
            )

        new_high_caps = [
            f
            for f in diff.new_capabilities
            if f.severity in {Severity.HIGH, Severity.CRITICAL}
            or f.kind in {CapabilityKind.EXEC, CapabilityKind.NETWORK, CapabilityKind.DYNAMIC_EXEC, CapabilityKind.COMPUTED_REQUIRE}
        ]
        if new_high_caps:
            score += 25
            kinds_str = ", ".join(sorted({f.kind.value for f in new_high_caps})[:4])
            reasons.append(
                f"New risky capability class(es) introduced since {diff.previous_version}: {kinds_str}"
            )
            if diff.maintainer_changed:
                score += 20
                det_floor = True
                reasons.append(
                    f"New maintainer(s) ({', '.join(diff.added_maintainers[:3])}) coincided with new risky capabilities"
                )
        elif diff.maintainer_changed:
            score += 10
            reasons.append(
                f"Maintainer list changed since {diff.previous_version}: +{', '.join(diff.added_maintainers[:3])}"
            )

    # Small trust reduction for verified SLSA provenance when no severe anomalies exist
    if meta.has_provenance and not det_block and not det_floor and score > 0:
        score = max(0, score - 10)
        reasons.append("Verified npm SLSA provenance attestation present (-10 risk)")

    report.risk_score = min(100, score)
    report.risk_reasons = reasons
    report.deterministic_block = det_block
    report.deterministic_floor_suspicious = det_floor


def _extract_cited_excerpts(
    report: StaticAnalysisReport,
    llm_verdict: LLMVerdict | None,
    text_files: dict[str, str],
) -> list[dict[str, object]]:
    """Snapshot exact line excerpts for cited/high-risk findings before the in-memory tarball is discarded."""
    excerpts: list[dict[str, object]] = []
    seen: set[tuple[str, int, int]] = set()

    def _slice(file_path: str, start: int, end: int, reason: str, source: str) -> None:
        norm = file_path.lstrip("./")
        text = text_files.get(norm)
        if text is None:
            return
        lines = text.splitlines()
        if not lines:
            return
        s = max(1, start - 2)
        e = min(len(lines), end + 2)
        if e - s > 35:
            e = s + 35
        key = (norm, s, e)
        if key in seen:
            return
        seen.add(key)
        numbered = "\n".join(f"{ln:>4}: {lines[ln - 1][:240]}" for ln in range(s, e + 1))
        excerpts.append(
            {
                "file": norm,
                "start_line": start,
                "end_line": end,
                "source": source,
                "reason": reason[:200],
                "excerpt": numbered,
            }
        )

    if llm_verdict is not None:
        for cit in llm_verdict.citations[:10]:
            _slice(cit.file, cit.start_line, cit.end_line, cit.reason, "llm_citation")

    for finding in report.capabilities.findings:
        if finding.deterministic_critical or finding.severity in {Severity.CRITICAL, Severity.HIGH}:
            _slice(finding.file, finding.line, finding.end_line, finding.detail, "ast_finding")
        if len(excerpts) >= 15:
            break

    return excerpts


class SecurityPipeline:
    """Orchestrates Layer 0 (Cache/OSV/Age) -> Layer 1 (AST+Diff) -> Layer 2 (Triage) -> Layer 3 (Investigator)."""

    def __init__(
        self,
        *,
        settings: Settings,
        adapter: EcosystemAdapter,
        cache: VerdictCache,
        advisories: AdvisoryClient,
        llm_provider: LLMProvider | None = None,
    ) -> None:
        self.settings = settings
        self.adapter = adapter
        self.cache = cache
        self.advisories = advisories
        self.llm_provider = llm_provider

    def evaluate(
        self,
        spec: PackageSpec,
        *,
        use_cache: bool = True,
        enable_diff: bool = True,
        enable_llm: bool = True,
        force_investigate: bool = False,
        prefetched_metadata: PackageMetadata | None = None,
        scan_source: str = "check",
    ) -> FinalReport:
        layers_run: list[str] = ["layer0_metadata_advisories"]

        meta = prefetched_metadata or self.adapter.fetch_metadata(spec)

        # User explicit allowlist bypass
        if self.cache.is_allowlisted(meta.ecosystem, meta.name, meta.version):
            return FinalReport(
                ecosystem=meta.ecosystem,
                name=meta.name,
                version=meta.version,
                integrity=meta.integrity,
                verdict=VerdictLabel.BENIGN,
                risk_score=0,
                from_cache=True,
                layers_run=["allowlist"],
                summary="Explicitly allowlisted by user.",
            )

        # Layer 0a: Content-addressed SQLite cache hit (skip when forcing deep investigation)
        if use_cache and not force_investigate and meta.integrity:
            cached = self.cache.get(meta.ecosystem, meta.name, meta.version, meta.integrity)
            if cached is not None:
                return cached

        # Layer 0b: OSV + local blocklist advisories
        adv_matches = self.advisories.query_one(meta.ecosystem, meta.name, meta.version)

        # Layer 1: In-memory archive unpack + Tree-sitter AST + Version Diff + Typosquat + Phantom deps
        layers_run.append("layer1_ast_diff")
        archive: InMemoryArchive = self.adapter.download_archive(meta)
        caps = self.adapter.scan_archive(meta, archive, is_exec_target=spec.is_exec_target)
        typosquats = self.adapter.detect_typosquat(meta.name)
        phantom_deps, external_deps = self.adapter.detect_phantom_and_external_deps(meta)

        version_diff = None
        if enable_diff and meta.previous_version:
            version_diff = self.adapter.compute_version_diff(meta, archive, caps)

        static_report = StaticAnalysisReport(
            metadata=meta,
            advisories=adv_matches,
            capabilities=caps,
            version_diff=version_diff,
            typosquat_targets=typosquats,
            phantom_dependencies=phantom_deps,
            external_dependencies=external_deps,
        )
        score_static_report(
            static_report,
            is_exec_target=spec.is_exec_target,
            cooldown_hours=self.settings.cooldown_hours,
        )

        # Fast-exit deterministic block (unless user explicitly wants forensic investigation)
        if static_report.deterministic_block and not force_investigate:
            extra_block: dict[str, object] = {}
            excerpts = _extract_cited_excerpts(static_report, None, archive.text_files)
            if excerpts:
                extra_block["cited_excerpts"] = excerpts
            report = FinalReport(
                ecosystem=meta.ecosystem,
                name=meta.name,
                version=meta.version,
                integrity=meta.integrity,
                verdict=VerdictLabel.MALICIOUS,
                risk_score=static_report.risk_score,
                layers_run=layers_run,
                summary="; ".join(static_report.risk_reasons[:3]) or "Blocked by deterministic rule.",
                static_report=static_report,
                extra=extra_block,
            )
            self.cache.put(report)
            self._record_scan_row(meta, report, scan_source)
            return report

        # Fast-exit benign (0 LLM calls!)
        if (
            not force_investigate
            and static_report.risk_score < self.settings.triage_risk_threshold
            and not static_report.deterministic_floor_suspicious
        ):
            report = FinalReport(
                ecosystem=meta.ecosystem,
                name=meta.name,
                version=meta.version,
                integrity=meta.integrity,
                verdict=VerdictLabel.BENIGN,
                risk_score=static_report.risk_score,
                layers_run=layers_run,
                summary="Clean static AST, metadata, and advisory check.",
                static_report=static_report,
            )
            self.cache.put(report)
            self._record_scan_row(meta, report, scan_source)
            return report

        # Layer 2 & Layer 3: Pluggable LLM escalation (when enabled and provider configured)
        llm_verdict: LLMVerdict | None = None
        verification = None
        extra: dict[str, object] = {}

        if enable_llm and self.llm_provider is not None:
            try:
                if force_investigate:
                    layers_run.append("layer3_investigator")
                    llm_verdict, trace = run_investigator_agent(
                        self.llm_provider,
                        self.settings.effective_investigator_model,
                        static_report,
                        archive.text_files,
                        archive.file_sizes,
                        max_turns=self.settings.max_investigator_turns,
                    )
                    extra["investigator_trace"] = trace
                else:
                    layers_run.append("layer2_triage_llm")
                    llm_verdict = run_triage_llm(
                        self.llm_provider,
                        self.settings.effective_triage_model,
                        static_report,
                        archive.text_files,
                    )
                    needs_deep_dive = (
                        static_report.risk_score >= self.settings.investigator_risk_threshold
                        or llm_verdict.verdict == VerdictLabel.SUSPICIOUS
                        or llm_verdict.confidence < 0.75
                    )
                    if needs_deep_dive:
                        layers_run.append("layer3_investigator")
                        llm_verdict, trace = run_investigator_agent(
                            self.llm_provider,
                            self.settings.effective_investigator_model,
                            static_report,
                            archive.text_files,
                            archive.file_sizes,
                            max_turns=self.settings.max_investigator_turns,
                        )
                        extra["investigator_trace"] = trace

                verification = verify_llm_verdict(
                    llm_verdict,
                    static_report,
                    archive.line_counts,
                )
            except LLMError as exc:
                extra["llm_error"] = str(exc)

        # Finalize verdict
        if llm_verdict is not None and verification is not None:
            final_verdict = verification.overridden_verdict or llm_verdict.verdict
            summary = llm_verdict.summary or "; ".join(static_report.risk_reasons[:3])
            if verification.override_reason:
                summary = f"{summary} [Verifier: {verification.override_reason}]"
        else:
            # Static-only verdict (no API key or LLM error): only deterministic critical threats
            # auto-classify as MALICIOUS; pure heuristics cap at SUSPICIOUS to avoid false blocks
            # on legitimate native installers (e.g. esbuild, sharp) when AI is unavailable.
            if static_report.deterministic_block:
                final_verdict = VerdictLabel.MALICIOUS
            elif (
                static_report.deterministic_floor_suspicious
                or static_report.risk_score >= self.settings.triage_risk_threshold
            ):
                final_verdict = VerdictLabel.SUSPICIOUS
            else:
                final_verdict = VerdictLabel.BENIGN
            summary = "; ".join(static_report.risk_reasons[:3]) or "Static analysis completed."

        if final_verdict != VerdictLabel.BENIGN or force_investigate:
            excerpts = _extract_cited_excerpts(static_report, llm_verdict, archive.text_files)
            if excerpts:
                extra["cited_excerpts"] = excerpts

        report = FinalReport(
            ecosystem=meta.ecosystem,
            name=meta.name,
            version=meta.version,
            integrity=meta.integrity,
            verdict=final_verdict,
            risk_score=static_report.risk_score,
            layers_run=layers_run,
            summary=summary,
            static_report=static_report,
            llm_verdict=llm_verdict,
            verification=verification,
            extra=extra,
        )
        if not force_investigate and not extra.get("llm_error"):
            self.cache.put(report)
        self._record_scan_row(meta, report, scan_source)
        return report

    def _record_scan_row(
        self,
        meta: PackageMetadata,
        report: FinalReport,
        scan_source: str,
    ) -> None:
        self.cache.record_scan(
            ecosystem=meta.ecosystem,
            name=meta.name,
            version=meta.version,
            integrity=meta.integrity,
            published_at=meta.published_at.isoformat() if meta.published_at else "",
            scanned_at=datetime.now(UTC).isoformat(),
            scan_source=scan_source,
            verdict=report.verdict.value,
            risk_score=report.risk_score,
            layers_run=report.layers_run,
            summary=report.summary,
        )
