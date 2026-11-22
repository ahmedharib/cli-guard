"""npm spec parsing, safe transitive dependency resolution, and EcosystemAdapter implementation."""

from __future__ import annotations

import re
from collections import deque

from cli_guard.config import Settings
from cli_guard.core.typosquat import find_typosquat_targets
from cli_guard.ecosystems.base import EcosystemAdapter, InMemoryArchive
from cli_guard.ecosystems.npm.ast_scanner import scan_npm_archive
from cli_guard.ecosystems.npm.differ import compute_npm_version_diff
from cli_guard.ecosystems.npm.registry import NpmRegistryClient, RegistryError
from cli_guard.ecosystems.npm.top_packages import TOP_NPM_PACKAGES
from cli_guard.models import (
    CapabilitySummary,
    PackageMetadata,
    PackageSpec,
    VersionDiff,
)

_EXTERNAL_PREFIXES = (
    "http://",
    "https://",
    "git+",
    "git://",
    "github:",
    "gitlab:",
    "bitbucket:",
    "file:",
    "link:",
    "portal:",
)
_GITHUB_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#.+)?$")


def is_external_dep_spec(spec_val: str) -> bool:
    s = spec_val.strip()
    if s.startswith(_EXTERNAL_PREFIXES):
        return True
    if not s.startswith("@") and _GITHUB_SHORTHAND_RE.match(s):
        return True
    return False


def parse_npm_spec(raw: str, *, is_exec_target: bool = False) -> PackageSpec:
    """Parse an npm/pnpm/yarn/bun package specifier without invoking npm."""
    cleaned = raw.strip().strip("'\"")
    if not cleaned:
        raise ValueError("Empty package specifier.")

    # External tarball URL or git/github URL
    if cleaned.startswith(("http://", "https://")):
        return PackageSpec(
            ecosystem="npm",
            name=cleaned,
            version=None,
            raw_spec=cleaned,
            is_exec_target=is_exec_target,
            spec_kind="tarball_url",
        )
    if cleaned.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:")):
        return PackageSpec(
            ecosystem="npm",
            name=cleaned,
            version=None,
            raw_spec=cleaned,
            is_exec_target=is_exec_target,
            spec_kind="git",
        )
    if cleaned.startswith(("file:", "link:", "./", "../", "/")):
        return PackageSpec(
            ecosystem="npm",
            name=cleaned,
            version=None,
            raw_spec=cleaned,
            is_exec_target=is_exec_target,
            spec_kind="file",
        )

    # npm: alias syntax (e.g. `my-alias@npm:real-pkg@^1.0.0` or `npm:real-pkg@1.0.0`)
    if "@npm:" in cleaned:
        _, target = cleaned.split("@npm:", 1)
        inner = parse_npm_spec(target, is_exec_target=is_exec_target)
        inner.raw_spec = cleaned
        inner.spec_kind = "alias"
        return inner
    if cleaned.startswith("npm:"):
        inner = parse_npm_spec(cleaned[4:], is_exec_target=is_exec_target)
        inner.raw_spec = cleaned
        inner.spec_kind = "alias"
        return inner

    # Standard scoped or unscoped package: `@scope/name@version` or `name@version`
    if cleaned.startswith("@"):
        if "/" not in cleaned:
            raise ValueError(f"Invalid scoped npm package spec: {cleaned}")
        slash_idx = cleaned.index("/")
        rest = cleaned[slash_idx + 1 :]
        if "@" in rest:
            pkg_part, ver_part = rest.split("@", 1)
            name = cleaned[: slash_idx + 1] + pkg_part
            version = ver_part or None
        else:
            name = cleaned
            version = None
    else:
        if "@" in cleaned:
            name, ver_part = cleaned.split("@", 1)
            version = ver_part or None
        else:
            name = cleaned
            version = None

    return PackageSpec(
        ecosystem="npm",
        name=name.strip(),
        version=version.strip() if version else None,
        raw_spec=cleaned,
        is_exec_target=is_exec_target,
        spec_kind="registry",
    )


class NpmAdapter(EcosystemAdapter):
    """Complete npm ecosystem adapter supporting npm, npx, pnpm, yarn, and bun."""

    ecosystem_name = "npm"

    def __init__(
        self,
        settings: Settings,
        registry: NpmRegistryClient | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry or NpmRegistryClient(
            registry_url=settings.npm_registry_url,
            timeout=settings.http_timeout_seconds,
            max_tarball_bytes=settings.max_tarball_bytes,
            max_extracted_bytes=settings.max_extracted_bytes,
            max_extracted_files=settings.max_extracted_files,
        )

    def parse_spec(self, raw: str, *, is_exec_target: bool = False) -> PackageSpec:
        return parse_npm_spec(raw, is_exec_target=is_exec_target)

    def fetch_metadata(self, spec: PackageSpec) -> PackageMetadata:
        if spec.spec_kind == "tarball_url":
            return PackageMetadata(
                ecosystem="npm",
                name=spec.name,
                version="external-url",
                tarball_url=spec.name,
                integrity="",
            )
        return self.registry.fetch_metadata(spec)

    def download_archive(self, metadata: PackageMetadata) -> InMemoryArchive:
        return self.registry.download_tarball(metadata.tarball_url)

    def scan_archive(
        self,
        metadata: PackageMetadata,
        archive: InMemoryArchive,
        *,
        is_exec_target: bool = False,
    ) -> CapabilitySummary:
        return scan_npm_archive(metadata, archive, is_exec_target=is_exec_target)

    def compute_version_diff(
        self,
        metadata: PackageMetadata,
        current_archive: InMemoryArchive,
        current_caps: CapabilitySummary,
    ) -> VersionDiff | None:
        if not metadata.previous_version or not metadata.previous_tarball_url:
            return None
        try:
            prev_archive = self.registry.download_tarball(metadata.previous_tarball_url)
        except RegistryError:
            return None
        return compute_npm_version_diff(metadata, current_archive, current_caps, prev_archive)

    def detect_typosquat(self, name: str) -> list[str]:
        return find_typosquat_targets(name, TOP_NPM_PACKAGES)

    def detect_phantom_and_external_deps(
        self, metadata: PackageMetadata
    ) -> tuple[list[str], list[str]]:
        """Detect phantom/private dependencies (unpublished on public npm) and external URLs/git deps."""
        phantom: list[str] = []
        external: list[str] = []
        combined = {**metadata.dependencies, **metadata.optional_dependencies}

        checked = 0
        for dep_name, dep_spec in combined.items():
            if is_external_dep_spec(dep_spec):
                external.append(f"{dep_name} -> {dep_spec}")
                continue
            if dep_spec.startswith("npm:"):
                inner = parse_npm_spec(dep_spec)
                target_name = inner.name
            else:
                target_name = dep_name

            # Cap network HEAD checks per package to keep guard latency predictable
            if checked >= 25:
                continue
            checked += 1
            exists = self.registry.package_exists(target_name)
            if exists is False:
                phantom.append(f"{dep_name} ({dep_spec})")

        return phantom, external

    def resolve_transitive(
        self,
        roots: list[PackageSpec],
        *,
        max_packages: int = 80,
        max_depth: int = 4,
    ) -> tuple[list[tuple[PackageSpec, PackageMetadata]], list[str]]:
        """Resolve direct and transitive npm dependencies strictly from registry metadata."""
        resolved: list[tuple[PackageSpec, PackageMetadata]] = []
        warnings: list[str] = []
        visited: set[tuple[str, str]] = set()
        queue: deque[tuple[PackageSpec, int]] = deque((spec, 0) for spec in roots)

        while queue and len(resolved) < max_packages:
            spec, depth = queue.popleft()
            if spec.spec_kind in {"git", "file"}:
                warnings.append(
                    f"Non-registry specifier `{spec.raw_spec}` ({spec.spec_kind}) cannot be verified via npm registry."
                )
                continue
            try:
                meta = self.fetch_metadata(spec)
            except RegistryError as exc:
                warnings.append(str(exc))
                continue

            key = (meta.name, meta.version)
            if key in visited:
                continue
            visited.add(key)
            resolved.append((spec, meta))

            if depth >= max_depth:
                continue

            for dep_name, dep_range in meta.dependencies.items():
                if is_external_dep_spec(dep_range):
                    warnings.append(
                        f"{meta.name}@{meta.version} declares non-registry dependency `{dep_name}: {dep_range}`"
                    )
                    continue
                if dep_range.startswith("npm:"):
                    child_spec = parse_npm_spec(dep_range)
                    child_spec.direct = False
                else:
                    child_spec = PackageSpec(
                        ecosystem="npm",
                        name=dep_name,
                        version=dep_range,
                        raw_spec=f"{dep_name}@{dep_range}",
                        direct=False,
                    )
                queue.append((child_spec, depth + 1))

        return resolved, warnings
