"""Deterministic verification of LLM verdicts, line citations, and prompt-injection floors."""

from __future__ import annotations

from cli_guard.models import (
    Citation,
    LLMVerdict,
    StaticAnalysisReport,
    VerificationResult,
    VerdictLabel,
)


def verify_llm_verdict(
    llm_verdict: LLMVerdict,
    static_report: StaticAnalysisReport,
    file_line_counts: dict[str, int],
) -> VerificationResult:
    """Validate LLM citations against real files and enforce deterministic security floors."""
    valid_citations: list[Citation] = []
    invalid_citations: list[Citation] = []
    warnings: list[str] = []

    for cit in llm_verdict.citations:
        norm_file = cit.file.lstrip("./")
        line_count = file_line_counts.get(norm_file)
        if line_count is None:
            invalid_citations.append(cit)
            warnings.append(f"Hallucinated file citation: '{cit.file}' does not exist in tarball.")
            continue
        if cit.start_line < 1 or cit.end_line < cit.start_line or cit.start_line > line_count:
            invalid_citations.append(cit)
            warnings.append(
                f"Out-of-range citation in '{norm_file}': lines {cit.start_line}-{cit.end_line} (file has {line_count} lines)."
            )
            continue
        clamped_end = min(cit.end_line, line_count)
        valid_citations.append(
            Citation(
                file=norm_file,
                start_line=cit.start_line,
                end_line=clamped_end,
                reason=cit.reason,
            )
        )

    overridden: VerdictLabel | None = None
    override_reason: str | None = None

    # 1. If model claims MALICIOUS with zero valid citations (or only hallucinated ones),
    #    downgrade from malicious -> suspicious so human reviews instead of blind false alarm.
    if llm_verdict.verdict == VerdictLabel.MALICIOUS and not valid_citations:
        if not static_report.deterministic_block:
            overridden = VerdictLabel.SUSPICIOUS
            override_reason = (
                "Model claimed malicious without any valid in-tarball file/line citation; "
                "downgraded to suspicious for human review."
            )
            warnings.append(override_reason)

    # 2. Check install-time reachability claim against AST reachability graph
    reach = static_report.capabilities.reachability
    if llm_verdict.claims_install_execution and valid_citations:
        reachable_set = set(reach.reachable_at_install) | {"package.json", "binding.gyp"}
        cited_files = {c.file for c in valid_citations}
        if not (cited_files & reachable_set):
            if static_report.capabilities.has_computed_require:
                warnings.append(
                    "Cited file is not statically linked from install hooks, "
                    "but package contains computed/dynamic require() so reachability cannot be ruled out."
                )
            else:
                warnings.append(
                    "Model claimed install-time execution, but cited file(s) are not statically "
                    "reachable from install scripts (may be runtime-only)."
                )

    # 3. Non-bypassable deterministic floor (prevents prompt injection forcing `benign`)
    if static_report.deterministic_block:
        if llm_verdict.verdict != VerdictLabel.MALICIOUS:
            overridden = VerdictLabel.MALICIOUS
            override_reason = (
                "Deterministic critical threat (known malware advisory or high-confidence "
                "malicious pattern) cannot be downgraded by LLM."
            )
            warnings.append(override_reason)
    elif static_report.deterministic_floor_suspicious and llm_verdict.verdict == VerdictLabel.BENIGN:
        overridden = VerdictLabel.SUSPICIOUS
        override_reason = (
            "LLM returned benign despite high-risk deterministic signals "
            "(possible prompt injection or missed obfuscation); clamped to suspicious."
        )
        warnings.append(override_reason)

    return VerificationResult(
        valid_citations=valid_citations,
        invalid_citations=invalid_citations,
        warnings=warnings,
        overridden_verdict=overridden,
        override_reason=override_reason,
    )
