"""Runtime configuration for cli-guard (`cg`)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


def default_data_dir() -> Path:
    """Return user-scoped data directory for cache, shims, and advisories."""
    override = os.environ.get("CG_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / ".cli-guard").resolve()


@dataclass(slots=True)
class ProviderPreset:
    name: str
    kind: str  # "openai_compat" | "anthropic" | "gemini"
    base_url: str
    api_key_envs: tuple[str, ...]
    default_triage_model: str
    default_investigator_model: str


PROVIDER_PRESETS: dict[str, ProviderPreset] = {
    "meta": ProviderPreset(
        name="meta",
        kind="openai_compat",
        base_url="https://api.meta.ai/v1",
        api_key_envs=("MODEL_API_KEY", "META_API_KEY"),
        default_triage_model="muse-spark-1.3",
        default_investigator_model="muse-spark-1.3",
    ),
    "openai": ProviderPreset(
        name="openai",
        kind="openai_compat",
        base_url="https://api.openai.com/v1",
        api_key_envs=("OPENAI_API_KEY",),
        default_triage_model="gpt-4o-mini",
        default_investigator_model="gpt-4o",
    ),
    "anthropic": ProviderPreset(
        name="anthropic",
        kind="anthropic",
        base_url="https://api.anthropic.com/v1",
        api_key_envs=("ANTHROPIC_API_KEY",),
        default_triage_model="claude-3-5-haiku-latest",
        default_investigator_model="claude-sonnet-4-20250514",
    ),
    "gemini": ProviderPreset(
        name="gemini",
        kind="gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        api_key_envs=("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        default_triage_model="gemini-2.5-flash",
        default_investigator_model="gemini-2.5-pro",
    ),
    "ollama": ProviderPreset(
        name="ollama",
        kind="openai_compat",
        base_url="http://localhost:11434/v1",
        api_key_envs=("OLLAMA_API_KEY",),
        default_triage_model="qwen2.5-coder:7b",
        default_investigator_model="qwen2.5-coder:32b",
    ),
    "custom": ProviderPreset(
        name="custom",
        kind="openai_compat",
        base_url="http://localhost:8000/v1",
        api_key_envs=("CG_LLM_API_KEY", "MODEL_API_KEY", "OPENAI_API_KEY"),
        default_triage_model="default",
        default_investigator_model="default",
    ),
}


@dataclass(slots=True)
class Settings:
    data_dir: Path = field(default_factory=default_data_dir)
    llm_provider: str = "meta"
    llm_base_url: str | None = None
    llm_api_key: str | None = None
    triage_model: str | None = None
    investigator_model: str | None = None
    cooldown_hours: float = 24.0
    fail_open: bool = False
    max_investigator_turns: int = 8
    npm_registry_url: str = "https://registry.npmjs.org"
    osv_api_url: str = "https://api.osv.dev/v1"
    http_timeout_seconds: float = 30.0
    max_tarball_bytes: int = 50 * 1024 * 1024
    max_extracted_bytes: int = 100 * 1024 * 1024
    max_extracted_files: int = 5000
    triage_risk_threshold: int = 25
    investigator_risk_threshold: int = 55
    ots_upgrade_interval_seconds: float = 1800.0
    github_token: str | None = None
    ledger_repo: str | None = None  # e.g. "owner/cli-guard-ledger"
    openssf_repo: str = "ossf/malicious-packages"
    openssf_fork: str | None = None
    auto_push_ledger: bool = False
    auto_openssf_pr: bool = False

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def cache_db_path(self) -> Path:
        return self.data_dir / "cache.sqlite3"

    @property
    def shims_dir(self) -> Path:
        return self.data_dir / "shims"

    @property
    def resolved_preset(self) -> ProviderPreset:
        key = self.llm_provider.lower().strip()
        return PROVIDER_PRESETS.get(key, PROVIDER_PRESETS["custom"])

    @property
    def effective_base_url(self) -> str:
        return (self.llm_base_url or self.resolved_preset.base_url).rstrip("/")

    @property
    def effective_triage_model(self) -> str:
        return self.triage_model or self.resolved_preset.default_triage_model

    @property
    def effective_investigator_model(self) -> str:
        return self.investigator_model or self.resolved_preset.default_investigator_model

    @property
    def effective_api_key(self) -> str | None:
        if self.llm_api_key:
            return self.llm_api_key
        for env_name in self.resolved_preset.api_key_envs:
            val = os.environ.get(env_name, "").strip()
            if val and val != ".":
                return val
        return None

    @classmethod
    def from_env(
        cls,
        *,
        provider: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        env_file: Path | None = None,
    ) -> Settings:
        if env_file and env_file.exists():
            load_dotenv(env_file, override=False)
        else:
            load_dotenv(override=False)

        chosen_provider = (
            provider or os.environ.get("CG_LLM_PROVIDER", "meta")
        ).strip().lower()

        raw_cooldown = os.environ.get("CG_COOLDOWN_HOURS", "24")
        try:
            cooldown_hours = float(raw_cooldown)
        except ValueError:
            cooldown_hours = 24.0

        raw_turns = os.environ.get("CG_MAX_INVESTIGATOR_TURNS", "8")
        try:
            max_turns = max(1, int(raw_turns))
        except ValueError:
            max_turns = 8

        triage_model = model or os.environ.get("CG_TRIAGE_MODEL") or os.environ.get("CG_MODEL") or None
        investigator_model = (
            model or os.environ.get("CG_INVESTIGATOR_MODEL") or os.environ.get("CG_MODEL") or None
        )

        raw_ots_interval = os.environ.get("CG_OTS_UPGRADE_INTERVAL", "1800")
        try:
            ots_interval = max(60.0, float(raw_ots_interval))
        except ValueError:
            ots_interval = 1800.0

        gh_token = (
            os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        ).strip() or None

        return cls(
            data_dir=default_data_dir(),
            llm_provider=chosen_provider,
            llm_base_url=base_url or os.environ.get("CG_LLM_BASE_URL") or None,
            llm_api_key=os.environ.get("CG_LLM_API_KEY") or None,
            triage_model=triage_model,
            investigator_model=investigator_model,
            cooldown_hours=cooldown_hours,
            fail_open=os.environ.get("CG_FAIL_OPEN", "false").lower() in {"1", "true", "yes"},
            max_investigator_turns=max_turns,
            npm_registry_url=os.environ.get("CG_NPM_REGISTRY", "https://registry.npmjs.org").rstrip("/"),
            ots_upgrade_interval_seconds=ots_interval,
            github_token=gh_token,
            ledger_repo=os.environ.get("CG_LEDGER_REPO", "").strip() or None,
            openssf_repo=os.environ.get("CG_OPENSSF_REPO", "ossf/malicious-packages").strip(),
            openssf_fork=os.environ.get("CG_OPENSSF_FORK", "").strip() or None,
            auto_push_ledger=os.environ.get("CG_AUTO_PUSH_LEDGER", "false").lower() in {"1", "true", "yes"},
            auto_openssf_pr=os.environ.get("CG_AUTO_OPENSSF_PR", "false").lower() in {"1", "true", "yes"},
        )
