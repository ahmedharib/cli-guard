"""Model Context Protocol (MCP) stdio server so AI coding agents can call `cli-guard` natively."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, TextIO

from cli_guard import __version__
from cli_guard.config import Settings
from cli_guard.core.advisories import AdvisoryClient
from cli_guard.core.cache import VerdictCache
from cli_guard.core.pipeline import SecurityPipeline
from cli_guard.ecosystems.npm.installed import (
    scan_global_npm_packages,
    scan_installed_node_modules,
)
from cli_guard.ecosystems.npm.lockfile import discover_and_parse_lockfiles
from cli_guard.ecosystems.npm.resolver import NpmAdapter
from cli_guard.llm.factory import create_provider

MCP_PROTOCOL_VERSION = "2024-11-05"

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "check_package",
        "description": (
            "Statically analyze an npm package (zero code execution) before installing or running it with npx. "
            "Runs Layer 0 (OSV MAL-*, cache, cooldown) -> Layer 1 (Tree-sitter AST + version diff) -> optional LLM triage/investigator."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {
                    "type": "string",
                    "description": "npm package spec (e.g. 'lodash@4.17.21' or '@scope/pkg').",
                },
                "as_exec": {
                    "type": "boolean",
                    "description": "Set true when checking an `npx` / `dlx` / `bunx` binary target.",
                    "default": False,
                },
                "no_llm": {
                    "type": "boolean",
                    "description": "Run deterministic Layer 0 + Layer 1 static analysis only (0 LLM calls).",
                    "default": False,
                },
            },
            "required": ["package"],
        },
    },
    {
        "name": "investigate_package",
        "description": (
            "Run a deep forensic investigation over an npm package tarball in memory (including AST, version diff, and deobfuscation)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {
                    "type": "string",
                    "description": "npm package spec (e.g. 'esbuild@0.25.0').",
                }
            },
            "required": ["package"],
        },
    },
    {
        "name": "audit_lockfiles",
        "description": (
            "Audit package-lock.json, pnpm-lock.yaml, yarn.lock, or bun.lock in a directory against OSV/OpenSSF malware advisories and poisoned URLs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Project directory or lockfile path (default '.').",
                    "default": ".",
                }
            },
        },
    },
    {
        "name": "audit_installed",
        "description": (
            "Security-only scan of currently installed npm packages (local node_modules and/or global npm -g) against OSV MAL-* advisories and external origins."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Project directory containing node_modules (default '.').",
                    "default": ".",
                },
                "global_packages": {
                    "type": "boolean",
                    "description": "If true, scan globally installed `npm -g` packages instead of local node_modules.",
                    "default": False,
                },
            },
        },
    },
]


def _make_runtime(settings: Settings) -> tuple[VerdictCache, AdvisoryClient, NpmAdapter, SecurityPipeline]:
    cache = VerdictCache(settings.cache_db_path)
    advisories = AdvisoryClient(
        osv_api_url=settings.osv_api_url,
        cache=cache,
        timeout=min(15.0, settings.http_timeout_seconds),
    )
    adapter = NpmAdapter(settings)
    pipeline = SecurityPipeline(
        settings=settings,
        adapter=adapter,
        cache=cache,
        advisories=advisories,
        llm_provider=create_provider(settings),
    )
    return cache, advisories, adapter, pipeline


def execute_mcp_tool(
    name: str,
    arguments: dict[str, Any],
    *,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Execute a cli-guard MCP tool synchronously and return JSON-serializable payload."""
    cfg = settings or Settings.from_env()
    _, advisories, adapter, pipeline = _make_runtime(cfg)

    if name == "check_package":
        pkg = str(arguments.get("package", "")).strip()
        if not pkg:
            raise ValueError("Missing required argument `package`.")
        spec = adapter.parse_spec(pkg, is_exec_target=bool(arguments.get("as_exec", False)))
        report = pipeline.evaluate(
            spec,
            use_cache=True,
            enable_diff=True,
            enable_llm=not bool(arguments.get("no_llm", False)),
            force_investigate=False,
            scan_source="mcp",
        )
        return report.model_dump(mode="json")

    if name == "investigate_package":
        pkg = str(arguments.get("package", "")).strip()
        if not pkg:
            raise ValueError("Missing required argument `package`.")
        spec = adapter.parse_spec(pkg)
        report = pipeline.evaluate(
            spec,
            use_cache=False,
            enable_diff=True,
            enable_llm=True,
            force_investigate=True,
            scan_source="mcp",
        )
        return report.model_dump(mode="json")

    if name == "audit_lockfiles":
        target = Path(str(arguments.get("path") or ".")).expanduser()
        lockfiles, locked_pkgs = discover_and_parse_lockfiles(target)
        if not lockfiles:
            return {"lockfiles": [], "scanned_packages": 0, "malware": [], "lockfile_warnings": []}
        adv_map = advisories.query_batch([("npm", p.name, p.version) for p in locked_pkgs])
        malware = []
        warnings = []
        for p in locked_pkgs:
            for adv in adv_map.get(("npm", p.name, p.version), []):
                if adv.is_malware:
                    malware.append(
                        {
                            "package": f"{p.name}@{p.version}",
                            "lockfile": p.source_file,
                            "id": adv.id,
                            "summary": adv.summary,
                        }
                    )
            for w in p.warnings:
                warnings.append({"package": f"{p.name}@{p.version}", "lockfile": p.source_file, "warning": w})
        return {
            "lockfiles": [str(f) for f in lockfiles],
            "scanned_packages": len(locked_pkgs),
            "malware": malware,
            "lockfile_warnings": warnings,
        }

    if name == "audit_installed":
        use_global = bool(arguments.get("global_packages", False))
        if use_global:
            root_label, installed = scan_global_npm_packages(cfg.shims_dir)
        else:
            target = Path(str(arguments.get("path") or ".")).expanduser()
            root_label = str(target / "node_modules")
            installed = scan_installed_node_modules(target)

        adv_map = advisories.query_batch([("npm", p.name, p.version) for p in installed])
        malware = []
        warnings = []
        install_hook_pkgs = []
        for p in installed:
            for adv in adv_map.get(("npm", p.name, p.version), []):
                if adv.is_malware:
                    malware.append(
                        {
                            "package": f"{p.name}@{p.version}",
                            "location": p.location,
                            "id": adv.id,
                            "summary": adv.summary,
                        }
                    )
            for w in p.warnings:
                warnings.append({"package": f"{p.name}@{p.version}", "location": p.location, "warning": w})
            if p.has_install_script:
                install_hook_pkgs.append(
                    {
                        "package": f"{p.name}@{p.version}",
                        "location": p.location,
                        "hooks": sorted(p.install_scripts.keys()),
                    }
                )
        return {
            "root": root_label,
            "scanned_installed": len(installed),
            "malware": malware,
            "warnings": warnings,
            "packages_with_install_scripts": install_hook_pkgs,
        }

    raise ValueError(f"Unknown MCP tool: {name}")


def handle_mcp_request(
    msg: dict[str, Any],
    *,
    settings: Settings | None = None,
) -> dict[str, Any] | None:
    """Handle one parsed JSON-RPC 2.0 MCP message. Returns response dict or None for notifications."""
    method = msg.get("method")
    req_id = msg.get("id")

    # Notifications (no id) get no JSON-RPC response
    if req_id is None:
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "cli-guard", "version": __version__},
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}

    if method == "tools/call":
        params = msg.get("params") or {}
        tool_name = str(params.get("name") or "")
        args = params.get("arguments") or {}
        try:
            out = execute_mcp_tool(tool_name, args, settings=settings)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(out, indent=2)}],
                    "isError": False,
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error executing {tool_name}: {exc}"}],
                    "isError": True,
                },
            }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def serve_mcp_stdio(
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    settings: Settings | None = None,
) -> None:
    """Run newline-delimited JSON-RPC 2.0 MCP stdio loop."""
    in_stream = stdin or sys.stdin
    out_stream = stdout or sys.stdout
    cfg = settings or Settings.from_env()

    for raw_line in in_stream:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            out_stream.write(json.dumps(resp) + "\n")
            out_stream.flush()
            continue

        resp = handle_mcp_request(msg, settings=cfg)
        if resp is not None:
            out_stream.write(json.dumps(resp) + "\n")
            out_stream.flush()


def build_agent_mcp_config(python_exe: Path | None = None) -> dict[str, Any]:
    """Return ready-to-paste `mcpServers` JSON snippet for AI coding agents."""
    py = str((python_exe or Path(sys.executable)).resolve())
    return {
        "mcpServers": {
            "cli-guard": {
                "command": py,
                "args": ["-m", "cli_guard", "mcp"],
            }
        }
    }
