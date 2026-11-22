"""Cross-platform PATH shim generator (Windows `.cmd` safe under Restricted ExecutionPolicy + POSIX)."""

from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

SHIM_TARGETS: tuple[str, ...] = ("npm", "npx", "pnpm", "yarn", "bun", "bunx")


def _normalize_dir(path: Path | str) -> str:
    return os.path.normcase(os.path.normpath(str(Path(path).resolve())))


def find_real_executable(manager: str, shims_dir: Path) -> str | None:
    """Locate the real package-manager executable on PATH while excluding `shims_dir` (no recursion)."""
    shim_norm = _normalize_dir(shims_dir)
    raw_path = os.environ.get("PATH", "")
    filtered_dirs = [
        entry
        for entry in raw_path.split(os.pathsep)
        if entry and _normalize_dir(entry) != shim_norm
    ]
    cleaned_path = os.pathsep.join(filtered_dirs)

    if os.name == "nt":
        # Prefer .cmd / .exe over .ps1 on Windows so PowerShell Restricted ExecutionPolicy never breaks
        for candidate in (f"{manager}.cmd", f"{manager}.exe", manager):
            found = shutil.which(candidate, path=cleaned_path)
            if found and not found.lower().endswith(".ps1"):
                return found
    return shutil.which(manager, path=cleaned_path)


def render_windows_cmd_shim(manager: str, python_exe: Path) -> str:
    """Render a Windows `.cmd` shim that works in both cmd.exe and PowerShell (even when Restricted)."""
    return (
        "@echo off\r\n"
        f'"{python_exe}" -m cli_guard guard intercept {manager} -- %*\r\n'
        "exit /b %ERRORLEVEL%\r\n"
    )


def render_posix_shim(manager: str, python_exe: Path) -> str:
    """Render a POSIX `/usr/bin/env sh` shim for macOS and Linux."""
    return (
        "#!/usr/bin/env sh\n"
        f'exec "{python_exe}" -m cli_guard guard intercept {manager} -- "$@"\n'
    )


def install_shims(
    shims_dir: Path,
    *,
    managers: tuple[str, ...] = SHIM_TARGETS,
    python_exe: Path | None = None,
    platform_name: str | None = None,
) -> dict[str, Path]:
    """Generate and write guard shims into `shims_dir`. Returns {manager: shim_path}."""
    shims_dir.mkdir(parents=True, exist_ok=True)
    py_path = (python_exe or Path(sys.executable)).resolve()
    is_windows = (platform_name or os.name) == "nt"

    written: dict[str, Path] = {}
    for manager in managers:
        if is_windows:
            shim_path = shims_dir / f"{manager}.cmd"
            shim_path.write_text(render_windows_cmd_shim(manager, py_path), encoding="utf-8")
        else:
            shim_path = shims_dir / manager
            shim_path.write_text(render_posix_shim(manager, py_path), encoding="utf-8")
            mode = shim_path.stat().st_mode
            shim_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        written[manager] = shim_path

    return written


def build_guarded_env(shims_dir: Path, base_env: dict[str, str] | None = None) -> dict[str, str]:
    """Return an environment mapping with `shims_dir` prepended first on PATH."""
    env = dict(base_env or os.environ)
    shim_str = str(shims_dir.resolve())
    shim_norm = _normalize_dir(shims_dir)
    current = env.get("PATH", "")
    parts = [p for p in current.split(os.pathsep) if p and _normalize_dir(p) != shim_norm]
    env["PATH"] = os.pathsep.join([shim_str, *parts])
    env["CG_GUARD_ACTIVE"] = "1"
    return env
