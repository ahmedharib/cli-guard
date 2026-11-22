"""CLI command parser for npm, npx, pnpm, yarn, bun, and bunx install/exec interception."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from cli_guard.ecosystems.npm.resolver import parse_npm_spec
from cli_guard.models import PackageSpec

SUPPORTED_MANAGERS: frozenset[str] = frozenset({"npm", "npx", "pnpm", "yarn", "bun", "bunx"})

# Flags across npm/pnpm/yarn/bun that consume the immediately following token as a value
_FLAGS_WITH_VALUE: frozenset[str] = frozenset(
    {
        "--registry",
        "--prefix",
        "-C",
        "--dir",
        "--cwd",
        "--workspace",
        "-w",
        "--filter",
        "-F",
        "--cache",
        "--userconfig",
        "--tag",
        "--loglevel",
        "--config",
        "--store-dir",
        "--virtual-store-dir",
    }
)

_NPX_PKG_FLAGS: frozenset[str] = frozenset({"-p", "--package"})

_NPM_INSTALL_CMDS: frozenset[str] = frozenset(
    {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "add", "ci", "update", "up", "upgrade"}
)
_PNPM_INSTALL_CMDS: frozenset[str] = frozenset({"install", "i", "add", "up", "update"})
_YARN_INSTALL_CMDS: frozenset[str] = frozenset({"install", "add", "up", "upgrade"})
_BUN_INSTALL_CMDS: frozenset[str] = frozenset({"install", "i", "add", "update"})


@dataclass(slots=True)
class InterceptedCommand:
    manager: str
    action: str  # "passthrough" | "install" | "exec"
    specs: list[PackageSpec] = field(default_factory=list)
    use_project_manifest: bool = False
    ignore_scripts: bool = False
    raw_args: list[str] = field(default_factory=list)


def _extract_positional_args(
    args: list[str],
    *,
    capture_pkg_flags: bool = False,
    stop_after_first_positional: bool = False,
    allow_target_after_double_dash: bool = False,
) -> tuple[list[str], bool]:
    """Return (positional_specs, ignore_scripts_flag)."""
    positionals: list[str] = []
    explicit_pkg_flags: list[str] = []
    ignore_scripts = False
    after_double_dash = False

    i = 0
    n = len(args)
    while i < n:
        tok = args[i]
        if tok == "--" and not after_double_dash:
            if allow_target_after_double_dash and not positionals and not explicit_pkg_flags:
                after_double_dash = True
                i += 1
                continue
            break
        if not after_double_dash:
            if tok == "--ignore-scripts":
                ignore_scripts = True
                i += 1
                continue
            if capture_pkg_flags and tok in _NPX_PKG_FLAGS and i + 1 < n:
                explicit_pkg_flags.append(args[i + 1])
                i += 2
                continue
            if capture_pkg_flags and tok.startswith("--package="):
                explicit_pkg_flags.append(tok.split("=", 1)[1])
                i += 1
                continue
            if tok in _FLAGS_WITH_VALUE and i + 1 < n:
                i += 2
                continue
            if tok.startswith("-"):
                i += 1
                continue
        positionals.append(tok)
        if stop_after_first_positional:
            break
        i += 1

    if explicit_pkg_flags:
        return explicit_pkg_flags, ignore_scripts
    return positionals, ignore_scripts


def load_specs_from_package_json(cwd: Path) -> list[PackageSpec]:
    """Read direct dependencies from local `package.json` for bare `npm install` / `pnpm i`."""
    pkg_path = cwd / "package.json"
    if not pkg_path.exists():
        return []
    try:
        doc = json.loads(pkg_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    specs: list[PackageSpec] = []
    seen: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        mapping = doc.get(section)
        if not isinstance(mapping, dict):
            continue
        for name, ver in mapping.items():
            if not isinstance(ver, str) or name in seen:
                continue
            seen.add(name)
            raw = f"{name}@{ver}" if not ver.startswith(("npm:", "http", "git", "file:", "link:")) else ver
            try:
                spec = parse_npm_spec(raw)
                specs.append(spec)
            except ValueError:
                continue
    return specs


def parse_package_manager_command(
    manager: str,
    args: list[str],
    *,
    cwd: Path | None = None,
) -> InterceptedCommand:
    """Determine whether a package-manager invocation installs/executes packages or passes through."""
    pm = manager.lower().strip()
    if pm not in SUPPORTED_MANAGERS:
        return InterceptedCommand(manager=pm, action="passthrough", raw_args=args)

    # Direct runners: `npx <pkg> ...` and `bunx <pkg> ...`
    if pm in {"npx", "bunx"}:
        if not args or any(a in {"-h", "--help", "-v", "--version"} for a in args[:2]):
            return InterceptedCommand(manager=pm, action="passthrough", raw_args=args)
        raw_specs, ignore_scripts = _extract_positional_args(
            args,
            capture_pkg_flags=True,
            stop_after_first_positional=True,
            allow_target_after_double_dash=True,
        )
        specs = [parse_npm_spec(s, is_exec_target=True) for s in raw_specs]
        return InterceptedCommand(
            manager=pm,
            action="exec" if specs else "passthrough",
            specs=specs,
            ignore_scripts=ignore_scripts,
            raw_args=args,
        )

    # Locate subcommand (skipping leading global flags like `--cwd dir`)
    subcmd: str | None = None
    subcmd_idx = 0
    i = 0
    while i < len(args):
        tok = args[i]
        if tok in _FLAGS_WITH_VALUE and i + 1 < len(args):
            i += 2
            continue
        if tok.startswith("-"):
            if tok in {"-v", "--version", "-h", "--help"}:
                return InterceptedCommand(manager=pm, action="passthrough", raw_args=args)
            i += 1
            continue
        subcmd = tok.lower()
        subcmd_idx = i
        break

    # Bare `yarn` with no subcommand runs `yarn install`!
    if pm == "yarn" and subcmd is None:
        manifest_specs = load_specs_from_package_json(cwd or Path.cwd())
        return InterceptedCommand(
            manager=pm,
            action="install",
            specs=manifest_specs,
            use_project_manifest=True,
            raw_args=args,
        )

    if subcmd is None:
        return InterceptedCommand(manager=pm, action="passthrough", raw_args=args)

    rest = args[subcmd_idx + 1 :]

    # `npm exec`, `pnpm dlx`, `yarn dlx`, `bun x` -> immediate bin execution
    if (
        (pm == "npm" and subcmd == "exec")
        or (pm in {"pnpm", "yarn"} and subcmd == "dlx")
        or (pm == "bun" and subcmd == "x")
    ):
        raw_specs, ignore_scripts = _extract_positional_args(
            rest,
            capture_pkg_flags=True,
            stop_after_first_positional=True,
            allow_target_after_double_dash=True,
        )
        specs = [parse_npm_spec(s, is_exec_target=True) for s in raw_specs]
        return InterceptedCommand(
            manager=pm,
            action="exec" if specs else "passthrough",
            specs=specs,
            ignore_scripts=ignore_scripts,
            raw_args=args,
        )

    # `npm create <foo>` / `pnpm create <foo>` / `yarn create <foo>` / `bun create <foo>`
    if subcmd == "create":
        raw_specs, ignore_scripts = _extract_positional_args(
            rest, stop_after_first_positional=True
        )
        specs: list[PackageSpec] = []
        for s in raw_specs:
            # npm `create foo` resolves to `create-foo` (or `@scope/create-foo`)
            if s.startswith("@") and "/" in s:
                scope, tail = s.split("/", 1)
                prefixed = f"{scope}/create-{tail}" if not tail.startswith("create-") else s
            else:
                prefixed = f"create-{s}" if not s.startswith("create-") else s
            specs.append(parse_npm_spec(prefixed, is_exec_target=True))
        return InterceptedCommand(
            manager=pm,
            action="exec" if specs else "passthrough",
            specs=specs,
            ignore_scripts=ignore_scripts,
            raw_args=args,
        )

    # Standard install / add / ci commands
    install_map = {
        "npm": _NPM_INSTALL_CMDS,
        "pnpm": _PNPM_INSTALL_CMDS,
        "yarn": _YARN_INSTALL_CMDS,
        "bun": _BUN_INSTALL_CMDS,
    }
    if subcmd in install_map.get(pm, set()):
        raw_specs, ignore_scripts = _extract_positional_args(rest)
        if raw_specs:
            specs = [parse_npm_spec(s, is_exec_target=False) for s in raw_specs]
            return InterceptedCommand(
                manager=pm,
                action="install",
                specs=specs,
                use_project_manifest=False,
                ignore_scripts=ignore_scripts,
                raw_args=args,
            )
        manifest_specs = load_specs_from_package_json(cwd or Path.cwd())
        return InterceptedCommand(
            manager=pm,
            action="install",
            specs=manifest_specs,
            use_project_manifest=True,
            ignore_scripts=ignore_scripts,
            raw_args=args,
        )

    return InterceptedCommand(manager=pm, action="passthrough", raw_args=args)
