"""npm spec parsing, safe transitive dependency resolution, and EcosystemAdapter implementation."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import deque
from pathlib import Path
from typing import Any

import yaml

from cli_guard.config import Settings
from cli_guard.core.typosquat import find_typosquat_targets
from cli_guard.ecosystems.base import EcosystemAdapter, InMemoryArchive
from cli_guard.ecosystems.npm.ast_scanner import scan_npm_archive
from cli_guard.ecosystems.npm.differ import compute_npm_version_diff
from cli_guard.ecosystems.npm.lockfile import parse_package_lock_json
from cli_guard.ecosystems.npm.registry import NpmRegistryClient, RegistryError
from cli_guard.ecosystems.npm.shims import find_real_executable
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
_WORKSPACE_PREFIXES = ("workspace:", "catalog:")
_GITHUB_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#.+)?$")


def is_external_dep_spec(spec_val: str) -> bool:
    s = spec_val.strip()
    if s.startswith(_EXTERNAL_PREFIXES):
        return True
    if not s.startswith("@") and _GITHUB_SHORTHAND_RE.match(s):
        return True
    return False


def load_project_resolution_context(cwd: Path | None) -> tuple[dict[str, str], dict[str, str]]:
    """Load npm `overrides`/`resolutions` and pnpm `catalog` mappings from project root."""
    overrides: dict[str, str] = {}
    catalogs: dict[str, str] = {}
    if cwd is None:
        return overrides, catalogs

    pkg_path = cwd / "package.json"
    if pkg_path.is_file():
        try:
            doc = json.loads(pkg_path.read_text(encoding="utf-8"))
            for field in ("overrides", "resolutions"):
                mapping = doc.get(field)
                if isinstance(mapping, dict):
                    for k, v in mapping.items():
                        if isinstance(v, str):
                            # Strip nested parent selectors like `foo>bar` -> `bar`
                            leaf = str(k).split(">")[-1].strip()
                            overrides[leaf] = v.strip()
            pnpm_block = doc.get("pnpm")
            if isinstance(pnpm_block, dict) and isinstance(pnpm_block.get("overrides"), dict):
                for k, v in pnpm_block["overrides"].items():
                    if isinstance(v, str):
                        leaf = str(k).split(">")[-1].strip()
                        overrides[leaf] = v.strip()
        except Exception:
            pass

    ws_yaml = cwd / "pnpm-workspace.yaml"
    if ws_yaml.is_file():
        try:
            ws_doc = yaml.safe_load(ws_yaml.read_text(encoding="utf-8"))
            if isinstance(ws_doc, dict):
                default_cat = ws_doc.get("catalog")
                if isinstance(default_cat, dict):
                    for k, v in default_cat.items():
                        if isinstance(v, str):
                            catalogs[f":{k}"] = v.strip()
                named_cats = ws_doc.get("catalogs")
                if isinstance(named_cats, dict):
                    for cat_name, cat_map in named_cats.items():
                        if isinstance(cat_map, dict):
                            for k, v in cat_map.items():
                                if isinstance(v, str):
                                    catalogs[f"{cat_name}:{k}"] = v.strip()
        except Exception:
            pass

    return overrides, catalogs


def resolve_catalog_spec(pkg_name: str, spec_val: str, catalogs: dict[str, str]) -> str | None:
    """Resolve pnpm `catalog:` / `catalog:<name>` specifier using `pnpm-workspace.yaml`."""
    cleaned = spec_val.strip()
    if not cleaned.startswith("catalog:"):
        return cleaned
    cat_name = cleaned[len("catalog:") :].strip()
    return catalogs.get(f"{cat_name}:{pkg_name}")


def resolve_via_npm_lock_only(
    specs: list[PackageSpec],
    *,
    shims_dir: Path,
    cwd: Path | None = None,
    timeout: float = 45.0,
) -> list[tuple[str, str, str]] | None:
    """Zero-execution npm Arborist parity resolver using `npm install --package-lock-only --ignore-scripts`.

    Runs in an isolated temp directory (never touches user `node_modules` and never runs scripts).
    Returns list of `(name, version, integrity)` or None if npm CLI is unavailable/fails.
    """
    npm_bin = find_real_executable("npm", shims_dir)
    if not npm_bin:
        return None
    registry_specs = [s for s in specs if s.spec_kind == "registry"]
    if not registry_specs:
        return None

    with tempfile.TemporaryDirectory(prefix="cg-arborist-") as tmp:
        tmp_path = Path(tmp)
        deps = {s.name: (s.version or "latest") for s in registry_specs}
        pkg_doc: dict[str, Any] = {"name": "cg-resolve-scratch", "version": "0.0.0", "dependencies": deps}
        # Carry over project overrides & .npmrc if present
        if cwd:
            src_pkg = cwd / "package.json"
            if src_pkg.is_file():
                try:
                    existing = json.loads(src_pkg.read_text(encoding="utf-8"))
                    if isinstance(existing.get("overrides"), dict):
                        pkg_doc["overrides"] = existing["overrides"]
                except Exception:
                    pass
            src_npmrc = cwd / ".npmrc"
            if src_npmrc.is_file():
                shutil.copy2(src_npmrc, tmp_path / ".npmrc")
        (tmp_path / "package.json").write_text(json.dumps(pkg_doc), encoding="utf-8")

        env = dict(os.environ)
        env["CG_BYPASS"] = "1"
        try:
            proc = subprocess.run(
                [npm_bin, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
                cwd=str(tmp_path),
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            lock_path = tmp_path / "package-lock.json"
            if proc.returncode != 0 or not lock_path.is_file():
                return None
            locked = parse_package_lock_json(lock_path)
            return [(p.name, p.version, p.integrity) for p in locked]
        except Exception:
            return None


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
        return self.registry.download_tarball(
            metadata.tarball_url,
            expected_integrity=metadata.integrity,
        )

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
        max_packages: int = 500,
        max_depth: int = 12,
        cwd: Path | None = None,
        use_npm_arborist: bool = False,
    ) -> tuple[list[tuple[PackageSpec, PackageMetadata]], list[str]]:
        """Resolve direct and transitive npm dependencies (incl. peerDependencies, overrides, catalogs) without running scripts."""
        resolved: list[tuple[PackageSpec, PackageMetadata]] = []
        warnings: list[str] = []
        visited: set[tuple[str, str]] = set()
        overrides, catalogs = load_project_resolution_context(cwd)

        # Optional exact npm Arborist lock-only resolution when explicitly requested
        if use_npm_arborist:
            arb = resolve_via_npm_lock_only(
                roots, shims_dir=self.settings.shims_dir, cwd=cwd
            )
            if arb:
                direct_names = {r.name for r in roots}
                exec_names = {r.name for r in roots if r.is_exec_target}
                for name, ver, _ in arb[:max_packages]:
                    spec = PackageSpec(
                        ecosystem="npm",
                        name=name,
                        version=ver,
                        raw_spec=f"{name}@{ver}",
                        direct=(name in direct_names),
                        is_exec_target=(name in exec_names),
                    )
                    try:
                        meta = self.fetch_metadata(spec)
                        if (meta.name, meta.version) not in visited:
                            visited.add((meta.name, meta.version))
                            resolved.append((spec, meta))
                    except RegistryError as exc:
                        warnings.append(str(exc))
                if resolved:
                    return resolved, warnings

        queue: deque[tuple[PackageSpec, int]] = deque((spec, 0) for spec in roots)

        while queue and len(resolved) < max_packages:
            spec, depth = queue.popleft()
            if spec.spec_kind in {"git", "file"}:
                warnings.append(
                    f"Non-registry specifier `{spec.raw_spec}` ({spec.spec_kind}) cannot be verified via npm registry."
                )
                continue
            if spec.version and spec.version.startswith("workspace:"):
                continue
            if spec.version and spec.version.startswith("catalog:"):
                mapped = resolve_catalog_spec(spec.name, spec.version, catalogs)
                if not mapped:
                    warnings.append(f"Unresolved pnpm catalog specifier `{spec.name}@{spec.version}`.")
                    continue
                spec = spec.model_copy(update={"version": mapped})

            # Apply project `overrides` / `resolutions` for transitive & direct deps
            if spec.name in overrides:
                ov = overrides[spec.name]
                if not ov.startswith("$"):
                    spec = spec.model_copy(update={"version": ov})

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

            # Resolve dependencies + optionalDependencies + non-optional peerDependencies (npm v7+ parity)
            child_maps = (
                meta.dependencies,
                meta.optional_dependencies,
                meta.peer_dependencies,
            )
            for dep_map in child_maps:
                for dep_name, dep_range in dep_map.items():
                    if dep_range.startswith("workspace:"):
                        continue
                    if dep_range.startswith("catalog:"):
                        mapped = resolve_catalog_spec(dep_name, dep_range, catalogs)
                        if not mapped:
                            continue
                        dep_range = mapped
                    if is_external_dep_spec(dep_range):
                        warnings.append(
                            f"{meta.name}@{meta.version} declares non-registry dependency `{dep_name}: {dep_range}`"
                        )
                        continue
                    if dep_name in overrides and not overrides[dep_name].startswith("$"):
                        dep_range = overrides[dep_name]
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
