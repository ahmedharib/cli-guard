"""Tests for npm/pnpm/yarn/bun lockfile parsers and command-line interception parser."""

import json
from pathlib import Path

from cli_guard.ecosystems.npm.command_parser import parse_package_manager_command
from cli_guard.ecosystems.npm.lockfile import (
    discover_and_parse_lockfiles,
    parse_bun_lock,
    parse_package_lock_json,
    parse_pnpm_lock_yaml,
    parse_yarn_lock,
)


def test_parse_all_four_lockfile_formats(tmp_path: Path) -> None:
    # 1. npm package-lock.json (v3) with a poisoned custom host
    pkg_lock = tmp_path / "package-lock.json"
    pkg_lock.write_text(
        json.dumps(
            {
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo", "version": "1.0.0"},
                    "node_modules/lodash": {
                        "version": "4.17.21",
                        "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                        "integrity": "sha512-abc",
                    },
                    "node_modules/poison": {
                        "version": "1.0.0",
                        "resolved": "https://evil-mirror.invalid/poison-1.0.0.tgz",
                        "hasInstallScript": True,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    npm_pkgs = parse_package_lock_json(pkg_lock)
    assert {(p.name, p.version) for p in npm_pkgs} == {("lodash", "4.17.21"), ("poison", "1.0.0")}
    poison = next(p for p in npm_pkgs if p.name == "poison")
    assert poison.warnings and "evil-mirror.invalid" in poison.warnings[0]

    # 2. pnpm-lock.yaml (v9)
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        "  '@scope/lib@2.3.4':\n"
        "    resolution: {integrity: sha512-xyz}\n"
        "  'chalk@5.3.0(supports-color@9.0.0)':\n"
        "    resolution: {integrity: sha512-123}\n",
        encoding="utf-8",
    )
    pnpm_pkgs = parse_pnpm_lock_yaml(pnpm_lock)
    assert {(p.name, p.version) for p in pnpm_pkgs} == {("@scope/lib", "2.3.4"), ("chalk", "5.3.0")}

    # 3. yarn.lock (Classic v1)
    yarn_v1 = tmp_path / "yarn.lock"
    yarn_v1.write_text(
        '# yarn lockfile v1\n\n'
        'express@^4.18.0:\n'
        '  version "4.19.2"\n'
        '  resolved "https://registry.yarnpkg.com/express/-/express-4.19.2.tgz"\n'
        '  integrity sha512-exp\n',
        encoding="utf-8",
    )
    y1_pkgs = parse_yarn_lock(yarn_v1)
    assert [(p.name, p.version) for p in y1_pkgs] == [("express", "4.19.2")]

    # 4. yarn.lock (Berry YAML)
    yarn_berry = tmp_path / "yarn.berry.lock"
    yarn_berry.write_text(
        "__metadata:\n"
        "  version: 8\n"
        '"zod@npm:^3.23.0":\n'
        "  version: 3.23.8\n"
        '  resolution: "zod@npm:3.23.8"\n'
        "  checksum: abc123\n",
        encoding="utf-8",
    )
    yb_pkgs = parse_yarn_lock(yarn_berry)
    assert [(p.name, p.version) for p in yb_pkgs] == [("zod", "3.23.8")]

    # 5. bun.lock (JSONC with comment + trailing comma)
    bun_lock = tmp_path / "bun.lock"
    bun_lock.write_text(
        '{\n'
        '  // bun text lockfile\n'
        '  "lockfileVersion": 1,\n'
        '  "packages": {\n'
        '    "hono": ["hono@4.6.0", "", {}, "sha512-hono",],\n'
        '  },\n'
        '}\n',
        encoding="utf-8",
    )
    bun_pkgs = parse_bun_lock(bun_lock)
    assert [(p.name, p.version) for p in bun_pkgs] == [("hono", "4.6.0")]

    # Auto-discovery picks up all 4 standard lockfiles in directory
    files, all_pkgs = discover_and_parse_lockfiles(tmp_path)
    assert len(files) == 4
    assert len(all_pkgs) == 6


def test_command_parser_npm_npx_pnpm_yarn_bun(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"chalk": "^5.3.0"}}),
        encoding="utf-8",
    )

    c1 = parse_package_manager_command("npm", ["i", "-D", "--registry", "https://r.test", "lodash@4.17.21"])
    assert c1.action == "install"
    assert [(s.name, s.version, s.is_exec_target) for s in c1.specs] == [("lodash", "4.17.21", False)]

    c2 = parse_package_manager_command("npx", ["-y", "cowsay@1.6.0", "hello"])
    assert c2.action == "exec"
    assert [(s.name, s.version, s.is_exec_target) for s in c2.specs] == [("cowsay", "1.6.0", True)]

    c3 = parse_package_manager_command("pnpm", ["dlx", "@evil/runner@1.0.0", "--flag"])
    assert c3.action == "exec"
    assert c3.specs[0].name == "@evil/runner" and c3.specs[0].is_exec_target is True

    c4 = parse_package_manager_command("yarn", [], cwd=tmp_path)
    assert c4.action == "install" and c4.use_project_manifest is True
    assert c4.specs[0].name == "chalk"

    c5 = parse_package_manager_command("bun", ["add", "hono"])
    assert c5.action == "install" and c5.specs[0].name == "hono"

    c6 = parse_package_manager_command("bunx", ["vite"])
    assert c6.action == "exec" and c6.specs[0].name == "vite" and c6.specs[0].is_exec_target is True

    c7 = parse_package_manager_command("npm", ["create", "next-app@latest"])
    assert c7.action == "exec" and c7.specs[0].name == "create-next-app"

    c8 = parse_package_manager_command("npm", ["run", "test"])
    assert c8.action == "passthrough"

    # Double-dash bypass attempt (`npm exec -- evil-pkg` / `npx -- evil-pkg`) must still be caught!
    c9 = parse_package_manager_command("npm", ["exec", "--", "evil-pkg@1.0.0", "--flag"])
    assert c9.action == "exec" and c9.specs[0].name == "evil-pkg" and c9.specs[0].is_exec_target is True

    c10 = parse_package_manager_command("npx", ["--", "evil-runner"])
    assert c10.action == "exec" and c10.specs[0].name == "evil-runner"
