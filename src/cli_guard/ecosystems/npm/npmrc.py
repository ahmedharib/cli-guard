"""npm `.npmrc` parser supporting default/scoped registries, auth tokens, and `${ENV}` expansion."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: str) -> str:
    return _ENV_VAR_RE.sub(lambda m: os.environ.get(m.group(1), ""), value).strip()


def _normalize_auth_prefix(raw_prefix: str) -> str:
    """Normalize `//registry.host/path/` style keys for safe host+path prefix matching."""
    cleaned = raw_prefix.strip()
    if cleaned.startswith(("http://", "https://")):
        parsed = urlparse(cleaned)
        cleaned = f"//{parsed.netloc}{parsed.path}"
    if not cleaned.startswith("//"):
        cleaned = f"//{cleaned.lstrip('/')}"
    return cleaned.rstrip("/") + "/"


@dataclass(slots=True)
class NpmrcConfig:
    default_registry: str = "https://registry.npmjs.org"
    scoped_registries: dict[str, str] = field(default_factory=dict)  # "@scope" -> "https://..."
    auth_tokens: dict[str, str] = field(default_factory=dict)  # "//host/path/" -> Bearer token
    basic_auth: dict[str, str] = field(default_factory=dict)  # "//host/path/" -> Base64 basic auth
    loaded_files: list[str] = field(default_factory=list)

    def registry_for_package(self, package_name: str) -> str:
        """Return the configured registry URL for a scoped or unscoped package."""
        if package_name.startswith("@") and "/" in package_name:
            scope = package_name.split("/", 1)[0].lower()
            if scope in self.scoped_registries:
                return self.scoped_registries[scope].rstrip("/")
        return self.default_registry.rstrip("/")

    def auth_headers_for_url(self, url: str) -> dict[str, str]:
        """Return Authorization header ONLY if `url` matches a configured host+path prefix."""
        parsed = urlparse(url)
        if not parsed.netloc:
            return {}
        target = f"//{parsed.netloc.lower()}{(parsed.path or '/')}".rstrip("/") + "/"

        # Match longest prefix first (most specific registry path wins)
        best_token: tuple[int, str] | None = None
        for prefix, token in self.auth_tokens.items():
            if token and target.startswith(prefix.lower()):
                if best_token is None or len(prefix) > best_token[0]:
                    best_token = (len(prefix), token)
        if best_token:
            return {"Authorization": f"Bearer {best_token[1]}"}

        best_basic: tuple[int, str] | None = None
        for prefix, b64 in self.basic_auth.items():
            if b64 and target.startswith(prefix.lower()):
                if best_basic is None or len(prefix) > best_basic[0]:
                    best_basic = (len(prefix), b64)
        if best_basic:
            return {"Authorization": f"Basic {best_basic[1]}"}

        return {}

    def apply_text(self, text: str, source_label: str = "") -> None:
        """Parse `.npmrc` content and overlay onto this config (higher precedence overwrites)."""
        if source_label:
            self.loaded_files.append(source_label)

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")) or "=" not in line:
                continue
            key, raw_val = line.split("=", 1)
            key = key.strip()
            val = _expand_env(raw_val.strip().strip('"').strip("'"))
            if not key or not val:
                continue

            if key == "registry":
                self.default_registry = val.rstrip("/")
            elif key.startswith("@") and key.endswith(":registry"):
                scope = key[: -len(":registry")].lower()
                self.scoped_registries[scope] = val.rstrip("/")
            elif ":_authToken" in key:
                prefix = _normalize_auth_prefix(key.split(":_authToken", 1)[0])
                self.auth_tokens[prefix] = val
            elif ":_auth" in key:
                prefix = _normalize_auth_prefix(key.split(":_auth", 1)[0])
                self.basic_auth[prefix] = val

    @classmethod
    def load(
        cls,
        *,
        cwd: Path | None = None,
        user_home: Path | None = None,
        registry_override: str | None = None,
    ) -> NpmrcConfig:
        """Load `.npmrc` files in npm precedence order (user -> NPM_CONFIG_USERCONFIG -> project -> env override)."""
        cfg = cls()
        home = (user_home or Path.home()).resolve()
        work_dir = (cwd or Path.cwd()).resolve()

        candidates: list[Path] = [home / ".npmrc"]
        env_usercfg = os.environ.get("NPM_CONFIG_USERCONFIG", "").strip()
        if env_usercfg:
            candidates.append(Path(env_usercfg).expanduser())
        candidates.append(work_dir / ".npmrc")

        seen: set[Path] = set()
        for path in candidates:
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if resolved in seen or not resolved.is_file():
                continue
            seen.add(resolved)
            try:
                cfg.apply_text(resolved.read_text(encoding="utf-8", errors="replace"), str(resolved))
            except OSError:
                continue

        # Explicit CLI/env override (`CG_NPM_REGISTRY`) takes highest precedence for default registry
        if registry_override and registry_override.strip():
            cfg.default_registry = registry_override.strip().rstrip("/")
        elif os.environ.get("CG_NPM_REGISTRY", "").strip():
            cfg.default_registry = os.environ["CG_NPM_REGISTRY"].strip().rstrip("/")

        return cfg
