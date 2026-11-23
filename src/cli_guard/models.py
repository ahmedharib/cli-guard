"""Core data models shared across ecosystems, triage, LLM layers, and CLI."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class VerdictLabel(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CapabilityKind(StrEnum):
    INSTALL_SCRIPT = "install_script"
    BIN_ENTRYPOINT = "bin_entrypoint"
    NETWORK = "network"
    EXEC = "exec"
    SENSITIVE_READ = "sensitive_read"
    DYNAMIC_EXEC = "dynamic_exec"
    COMPUTED_REQUIRE = "computed_require"
    OBFUSCATION = "obfuscation"
    INVISIBLE_UNICODE = "invisible_unicode"
    NATIVE_BINARY = "native_binary"
    EXTERNAL_DEP = "external_dep"
    PHANTOM_DEP = "phantom_dep"
    PROMPT_INJECTION = "prompt_injection"


class PackageSpec(BaseModel):
    ecosystem: str = "npm"
    name: str
    version: str | None = None
    raw_spec: str = ""
    direct: bool = True
    is_exec_target: bool = False  # True for npx / pnpm dlx / yarn dlx / bunx
    spec_kind: str = "registry"  # registry | alias | git | tarball_url | file


class AdvisoryMatch(BaseModel):
    id: str
    source: str  # "osv" | "local_blocklist"
    summary: str = ""
    is_malware: bool = False
    aliases: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class PackageMetadata(BaseModel):
    ecosystem: str = "npm"
    name: str
    version: str
    tarball_url: str = ""
    integrity: str = ""  # sha512-...
    published_at: datetime | None = None
    age_hours: float | None = None
    previous_version: str | None = None
    previous_tarball_url: str | None = None
    maintainers: list[str] = Field(default_factory=list)
    previous_maintainers: list[str] = Field(default_factory=list)
    publisher: str | None = None
    has_provenance: bool = False
    previous_has_provenance: bool = False
    repository_url: str | None = None
    scripts: dict[str, str] = Field(default_factory=dict)
    bin_entries: dict[str, str] = Field(default_factory=dict)
    dependencies: dict[str, str] = Field(default_factory=dict)
    optional_dependencies: dict[str, str] = Field(default_factory=dict)
    peer_dependencies: dict[str, str] = Field(default_factory=dict)
    deprecated: str | None = None


class CapabilityFinding(BaseModel):
    kind: CapabilityKind
    severity: Severity
    file: str
    line: int = 1
    end_line: int = 1
    symbol: str = ""
    snippet: str = ""
    detail: str = ""
    reachable_from: list[str] = Field(default_factory=list)
    deterministic_critical: bool = False


class ReachabilityGraph(BaseModel):
    install_entrypoints: list[str] = Field(default_factory=list)
    bin_entrypoints: list[str] = Field(default_factory=list)
    main_entrypoints: list[str] = Field(default_factory=list)
    reachable_at_install: list[str] = Field(default_factory=list)
    reachable_at_bin: list[str] = Field(default_factory=list)
    computed_require_files: list[str] = Field(default_factory=list)
    edges: dict[str, list[str]] = Field(default_factory=dict)


class CapabilitySummary(BaseModel):
    total_files: int = 0
    js_ts_files: int = 0
    binary_files: list[str] = Field(default_factory=list)
    reachability: ReachabilityGraph = Field(default_factory=ReachabilityGraph)
    findings: list[CapabilityFinding] = Field(default_factory=list)
    capability_counts: dict[str, int] = Field(default_factory=dict)
    has_install_scripts: bool = False
    has_computed_require: bool = False
    has_invisible_unicode: bool = False
    has_prompt_injection_pattern: bool = False


class VersionDiff(BaseModel):
    previous_version: str
    current_version: str
    added_files: list[str] = Field(default_factory=list)
    removed_files: list[str] = Field(default_factory=list)
    modified_files: list[str] = Field(default_factory=list)
    added_scripts: dict[str, str] = Field(default_factory=dict)
    modified_scripts: dict[str, tuple[str, str]] = Field(default_factory=dict)
    new_capabilities: list[CapabilityFinding] = Field(default_factory=list)
    provenance_dropped: bool = False
    maintainer_changed: bool = False
    added_maintainers: list[str] = Field(default_factory=list)
    unified_diff_excerpt: str = ""


class StaticAnalysisReport(BaseModel):
    metadata: PackageMetadata
    advisories: list[AdvisoryMatch] = Field(default_factory=list)
    capabilities: CapabilitySummary = Field(default_factory=CapabilitySummary)
    version_diff: VersionDiff | None = None
    typosquat_targets: list[str] = Field(default_factory=list)
    phantom_dependencies: list[str] = Field(default_factory=list)
    external_dependencies: list[str] = Field(default_factory=list)
    cooldown_triggered: bool = False
    risk_score: int = 0
    risk_reasons: list[str] = Field(default_factory=list)
    deterministic_block: bool = False
    deterministic_floor_suspicious: bool = False


class Citation(BaseModel):
    file: str
    start_line: int
    end_line: int
    reason: str = ""


class LLMVerdict(BaseModel):
    verdict: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    summary: str = ""
    claims_install_execution: bool = False
    citations: list[Citation] = Field(default_factory=list)
    attack_categories: list[str] = Field(default_factory=list)
    model_used: str = ""
    layer: str = ""  # "triage_llm" | "investigator"


class VerificationResult(BaseModel):
    valid_citations: list[Citation] = Field(default_factory=list)
    invalid_citations: list[Citation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    overridden_verdict: VerdictLabel | None = None
    override_reason: str | None = None


class FinalReport(BaseModel):
    ecosystem: str = "npm"
    name: str
    version: str
    integrity: str = ""
    verdict: VerdictLabel
    risk_score: int
    from_cache: bool = False
    layers_run: list[str] = Field(default_factory=list)
    summary: str = ""
    static_report: StaticAnalysisReport | None = None
    llm_verdict: LLMVerdict | None = None
    verification: VerificationResult | None = None
    extra: dict[str, Any] = Field(default_factory=dict)
