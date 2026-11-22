"""Lockfile parsers for npm (`package-lock.json`), pnpm (`pnpm-lock.yaml`), yarn (`yarn.lock`), and bun (`bun.lock`)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

STANDARD_NPM_HOSTS: frozenset[str] = frozenset(
    {
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "npm.pkg.github.com",
    }
)


@dataclass(slots=True)
class LockedPackage:
    name: str
    version: str
    integrity: str = ""
    resolved_url: str = ""
    has_install_script: bool = False
    source_file: str = ""
    warnings: list[str] = field(default_factory=list)


def _check_resolved_url(url: str) -> str | None:
    if not url:
        return None
    if url.startswith(("git+", "git://", "github:", "file:")):
        return f"Non-registry resolved spec in lockfile: {url}"
    if url.startswith(("http://", "https://")):
        host = (urlparse(url).hostname or "").lower()
        if host and host not in STANDARD_NPM_HOSTS:
            return f"Non-standard registry host in lockfile: {host} ({url})"
    return None


def parse_package_lock_json(path: Path) -> list[LockedPackage]:
    """Parse npm `package-lock.json` (lockfileVersion 1, 2, and 3)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    results: list[LockedPackage] = []
    seen: set[tuple[str, str]] = set()

    # v2 / v3 format (`packages` map keyed by `node_modules/...`)
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, entry in packages.items():
            if not pkg_path or not isinstance(entry, dict):
                continue
            if entry.get("link"):
                continue
            version = str(entry.get("version") or "").strip()
            if not version:
                continue
            name = str(entry.get("name") or "").strip()
            if not name:
                # Extract package name from last `node_modules/` segment
                marker = "node_modules/"
                if marker in pkg_path:
                    name = pkg_path.rsplit(marker, 1)[1]
                else:
                    continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)

            resolved = str(entry.get("resolved") or "")
            warnings: list[str] = []
            url_warn = _check_resolved_url(resolved)
            if url_warn:
                warnings.append(url_warn)

            results.append(
                LockedPackage(
                    name=name,
                    version=version,
                    integrity=str(entry.get("integrity") or ""),
                    resolved_url=resolved,
                    has_install_script=bool(entry.get("hasInstallScript", False)),
                    source_file=path.name,
                    warnings=warnings,
                )
            )
        if results:
            return results

    # v1 fallback (`dependencies` recursive tree)
    def _walk_v1(deps_map: dict[str, Any]) -> None:
        for name, entry in deps_map.items():
            if not isinstance(entry, dict):
                continue
            version = str(entry.get("version") or "").strip()
            if version and (name, version) not in seen:
                seen.add((name, version))
                resolved = str(entry.get("resolved") or "")
                warnings = []
                url_warn = _check_resolved_url(resolved)
                if url_warn:
                    warnings.append(url_warn)
                results.append(
                    LockedPackage(
                        name=name,
                        version=version,
                        integrity=str(entry.get("integrity") or ""),
                        resolved_url=resolved,
                        source_file=path.name,
                        warnings=warnings,
                    )
                )
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                _walk_v1(nested)

    if isinstance(data.get("dependencies"), dict):
        _walk_v1(data["dependencies"])

    return results


def _parse_pnpm_pkg_key(key: str) -> tuple[str, str] | None:
    """Parse pnpm lockfile package keys across v5/v6/v9 formats.

    Examples:
      - `lodash@4.17.21`
      - `@scope/pkg@1.2.3(react@18.2.0)`
      - `/@scope/pkg@1.2.3`
      - `/lodash/4.17.21`
    """
    cleaned = key.strip().strip("'\"")
    if "(" in cleaned:
        cleaned = cleaned.split("(", 1)[0]
    cleaned = cleaned.lstrip("/")
    if not cleaned:
        return None

    # v6/v9 format: `name@version` or `@scope/name@version`
    if cleaned.startswith("@"):
        if "/" in cleaned:
            slash_idx = cleaned.index("/")
            rest = cleaned[slash_idx + 1 :]
            if "@" in rest:
                pkg_part, ver = rest.split("@", 1)
                return cleaned[: slash_idx + 1] + pkg_part, ver
            if "/" in rest:
                pkg_part, ver = rest.split("/", 1)
                return cleaned[: slash_idx + 1] + pkg_part, ver
    else:
        if "@" in cleaned:
            name, ver = cleaned.split("@", 1)
            return name, ver
        if "/" in cleaned:
            name, ver = cleaned.split("/", 1)
            return name, ver
    return None


def parse_pnpm_lock_yaml(path: Path) -> list[LockedPackage]:
    """Parse pnpm `pnpm-lock.yaml` (v5, v6, and v9)."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []

    packages = data.get("packages") or {}
    if not isinstance(packages, dict):
        return []

    results: list[LockedPackage] = []
    seen: set[tuple[str, str]] = set()
    for raw_key, entry in packages.items():
        parsed = _parse_pnpm_pkg_key(str(raw_key))
        if not parsed:
            continue
        name, version = parsed
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)

        entry_dict = entry if isinstance(entry, dict) else {}
        resolution = entry_dict.get("resolution")
        res_dict = resolution if isinstance(resolution, dict) else {}
        integrity = str(res_dict.get("integrity") or "")
        tarball = str(res_dict.get("tarball") or "")
        warnings: list[str] = []
        url_warn = _check_resolved_url(tarball)
        if url_warn:
            warnings.append(url_warn)

        results.append(
            LockedPackage(
                name=name,
                version=version,
                integrity=integrity,
                resolved_url=tarball,
                has_install_script=bool(entry_dict.get("requiresBuild", False)),
                source_file=path.name,
                warnings=warnings,
            )
        )
    return results


def _extract_yarn_pkg_name(header_spec: str) -> str | None:
    """Extract package name from Yarn header key like `lodash@^4.17.0` or `@scope/pkg@npm:^1.0.0`."""
    first = header_spec.split(",", 1)[0].strip().strip("'\"")
    if not first:
        return None
    if first.startswith("@"):
        if "/" not in first:
            return None
        slash = first.index("/")
        rest = first[slash + 1 :]
        if "@" in rest:
            return first[: slash + 1] + rest.split("@", 1)[0]
        return first
    if "@" in first:
        return first.split("@", 1)[0]
    return first


def parse_yarn_lock(path: Path) -> list[LockedPackage]:
    """Parse both Yarn Classic (v1) and Yarn Berry (v2+/YAML) `yarn.lock` files."""
    text = path.read_text(encoding="utf-8")
    results: list[LockedPackage] = []
    seen: set[tuple[str, str]] = set()

    # Detect Yarn Berry YAML format (`__metadata:`)
    if "__metadata:" in text[:500]:
        try:
            doc = yaml.safe_load(text)
            if isinstance(doc, dict):
                for raw_key, entry in doc.items():
                    if raw_key == "__metadata" or not isinstance(entry, dict):
                        continue
                    version = str(entry.get("version") or "").strip()
                    resolution = str(entry.get("resolution") or "")
                    name = _extract_yarn_pkg_name(resolution) or _extract_yarn_pkg_name(str(raw_key))
                    if not name or not version or (name, version) in seen:
                        continue
                    seen.add((name, version))
                    warnings: list[str] = []
                    if "@http" in resolution or "@git" in resolution:
                        warnings.append(f"Non-registry Yarn resolution: {resolution}")
                    results.append(
                        LockedPackage(
                            name=name,
                            version=version,
                            integrity=str(entry.get("checksum") or ""),
                            resolved_url=resolution,
                            source_file=path.name,
                            warnings=warnings,
                        )
                    )
                return results
        except yaml.YAMLError:
            pass

    # Yarn Classic v1 parser
    current_name: str | None = None
    current_version: str = ""
    current_resolved: str = ""
    current_integrity: str = ""

    def _flush() -> None:
        if current_name and current_version and (current_name, current_version) not in seen:
            seen.add((current_name, current_version))
            warnings = []
            url_warn = _check_resolved_url(current_resolved)
            if url_warn:
                warnings.append(url_warn)
            results.append(
                LockedPackage(
                    name=current_name,
                    version=current_version,
                    integrity=current_integrity,
                    resolved_url=current_resolved,
                    source_file=path.name,
                    warnings=warnings,
                )
            )

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and stripped.endswith(":"):
            _flush()
            current_name = _extract_yarn_pkg_name(stripped[:-1])
            current_version = ""
            current_resolved = ""
            current_integrity = ""
        elif current_name:
            if stripped.startswith("version "):
                current_version = stripped.split(" ", 1)[1].strip().strip('"')
            elif stripped.startswith("resolved "):
                current_resolved = stripped.split(" ", 1)[1].strip().strip('"')
            elif stripped.startswith("integrity "):
                current_integrity = stripped.split(" ", 1)[1].strip().strip('"')

    _flush()
    return results


def _strip_jsonc(text: str) -> str:
    """Safely strip // comments, /* */ comments, and trailing commas from JSONC (`bun.lock`)."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_str = False
    escaped = False

    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            i += 1
            continue

        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1

    no_comments = "".join(out)
    # Remove trailing commas before } or ] outside strings (safe regex on JSONC tokens)
    return re.sub(r",(\s*[}\]])", r"\1", no_comments)


def parse_bun_lock(path: Path) -> list[LockedPackage]:
    """Parse Bun text lockfile (`bun.lock` JSONC format)."""
    raw = path.read_text(encoding="utf-8")
    data = json.loads(_strip_jsonc(raw))
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return []

    results: list[LockedPackage] = []
    seen: set[tuple[str, str]] = set()
    for _key, tuple_val in packages.items():
        if not isinstance(tuple_val, list) or not tuple_val:
            continue
        ident = str(tuple_val[0]).strip()
        if not ident:
            continue
        parsed = _parse_pnpm_pkg_key(ident)
        if not parsed:
            continue
        name, version = parsed
        if (name, version) in seen:
            continue
        seen.add((name, version))

        resolved = str(tuple_val[1]) if len(tuple_val) > 1 and isinstance(tuple_val[1], str) else ""
        integrity = str(tuple_val[3]) if len(tuple_val) > 3 and isinstance(tuple_val[3], str) else ""
        warnings: list[str] = []
        url_warn = _check_resolved_url(resolved)
        if url_warn:
            warnings.append(url_warn)

        results.append(
            LockedPackage(
                name=name,
                version=version,
                integrity=integrity,
                resolved_url=resolved,
                source_file=path.name,
                warnings=warnings,
            )
        )
    return results


LOCKFILE_CANDIDATES: tuple[str, ...] = (
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
)


def discover_and_parse_lockfiles(target: Path) -> tuple[list[Path], list[LockedPackage]]:
    """Find lockfile(s) at `target` (file or directory) and parse all locked npm packages."""
    files: list[Path] = []
    if target.is_file():
        files = [target]
    elif target.is_dir():
        for name in LOCKFILE_CANDIDATES:
            cand = target / name
            if cand.exists():
                files.append(cand)

    packages: list[LockedPackage] = []
    for lf in files:
        lname = lf.name.lower()
        if lname == "package-lock.json":
            packages.extend(parse_package_lock_json(lf))
        elif lname == "pnpm-lock.yaml":
            packages.extend(parse_pnpm_lock_yaml(lf))
        elif lname == "yarn.lock":
            packages.extend(parse_yarn_lock(lf))
        elif lname == "bun.lock":
            packages.extend(parse_bun_lock(lf))

    return files, packages
