"""Security-only scanner for currently installed npm packages (local `node_modules` & global `npm -g`)."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from cli_guard.ecosystems.npm.ast_scanner import INSTALL_HOOK_NAMES
from cli_guard.ecosystems.npm.shims import find_real_executable


@dataclass(slots=True)
class InstalledPackage:
    name: str
    version: str
    location: str
    has_install_script: bool = False
    install_scripts: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def _read_installed_pkg_json(pkg_json: Path, root_label: str) -> InstalledPackage | None:
    try:
        doc = json.loads(pkg_json.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    name = str(doc.get("name") or "").strip()
    version = str(doc.get("version") or "").strip()
    if not name or not version:
        return None

    scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
    install_hooks = {
        str(k): str(v)
        for k, v in scripts.items()
        if k in INSTALL_HOOK_NAMES and isinstance(v, str) and v.strip()
    }
    warnings: list[str] = []
    resolved = str(doc.get("_resolved") or "")
    if resolved.startswith(("git+", "git://", "http://")):
        warnings.append(f"Installed from insecure/external origin: {resolved}")

    return InstalledPackage(
        name=name,
        version=version,
        location=root_label,
        has_install_script=bool(install_hooks),
        install_scripts=install_hooks,
        warnings=warnings,
    )


def scan_installed_node_modules(project_dir: Path) -> list[InstalledPackage]:
    """Walk `node_modules/` directories under `project_dir` without executing any code."""
    nm_root = project_dir / "node_modules"
    if not nm_root.is_dir():
        return []

    results: list[InstalledPackage] = []
    seen: set[tuple[str, str]] = set()

    def _walk_nm(nm_dir: Path) -> None:
        try:
            entries = sorted(nm_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for entry in entries:
            if not entry.is_dir() or entry.name.startswith("."):
                continue
            if entry.name.startswith("@"):
                try:
                    scoped_children = sorted(entry.iterdir(), key=lambda p: p.name)
                except OSError:
                    continue
                for child in scoped_children:
                    if child.is_dir():
                        _inspect_pkg_dir(child)
            else:
                _inspect_pkg_dir(entry)

    def _inspect_pkg_dir(pkg_dir: Path) -> None:
        pkg_json = pkg_dir / "package.json"
        if pkg_json.is_file():
            try:
                rel = str(pkg_dir.relative_to(project_dir))
            except ValueError:
                rel = str(pkg_dir)
            item = _read_installed_pkg_json(pkg_json, rel)
            if item and (item.name, item.version) not in seen:
                seen.add((item.name, item.version))
                results.append(item)
        nested_nm = pkg_dir / "node_modules"
        if nested_nm.is_dir():
            _walk_nm(nested_nm)

    _walk_nm(nm_root)
    return results


def scan_global_npm_packages(shims_dir: Path) -> tuple[str | None, list[InstalledPackage]]:
    """Locate the global `node_modules` directory (bypassing shims) and inspect installed packages."""
    npm_bin = find_real_executable("npm", shims_dir)
    if not npm_bin:
        return None, []
    env = dict(os.environ)
    env["CG_BYPASS"] = "1"
    try:
        proc = subprocess.run(
            [npm_bin, "root", "-g"],
            env=env,
            capture_output=True,
            text=True,
            timeout=15.0,
        )
        if proc.returncode != 0:
            return None, []
        global_nm = Path(proc.stdout.strip())
        if not global_nm.is_dir():
            return None, []
        # Reuse `scan_installed_node_modules` by passing `global_nm.parent` when named `node_modules`
        if global_nm.name == "node_modules":
            return str(global_nm), scan_installed_node_modules(global_nm.parent)
        return str(global_nm), []
    except Exception:
        return None, []
