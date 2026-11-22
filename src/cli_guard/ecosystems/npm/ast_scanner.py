"""Tree-sitter JS/TS AST capability scanner and static install/bin reachability analyzer."""

from __future__ import annotations

import json
import posixpath
import re
from collections import deque
from typing import Any

from cli_guard.core.deobfuscate import (
    detect_invisible_unicode,
    shannon_entropy,
    static_deobfuscate,
)
from cli_guard.ecosystems.base import InMemoryArchive
from cli_guard.models import (
    CapabilityFinding,
    CapabilityKind,
    CapabilitySummary,
    PackageMetadata,
    ReachabilityGraph,
    Severity,
)

try:
    import tree_sitter_javascript as _tsjs
    import tree_sitter_typescript as _tsts
    from tree_sitter import Language, Parser

    _JS_LANG = Language(_tsjs.language())
    _TS_LANG = Language(_tsts.language_typescript())
    _TSX_LANG = Language(_tsts.language_tsx())
    TREE_SITTER_AVAILABLE = True
except Exception:
    TREE_SITTER_AVAILABLE = False
    _JS_LANG = None
    _TS_LANG = None
    _TSX_LANG = None

INSTALL_HOOK_NAMES: tuple[str, ...] = (
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "preprepare",
    "postprepare",
)

JS_EXTENSIONS: tuple[str, ...] = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")

EXEC_MODULES: frozenset[str] = frozenset({"child_process", "node:child_process"})
NETWORK_MODULES: frozenset[str] = frozenset(
    {
        "http",
        "node:http",
        "https",
        "node:https",
        "net",
        "node:net",
        "tls",
        "node:tls",
        "dgram",
        "node:dgram",
        "dns",
        "node:dns",
        "http2",
        "node:http2",
        "axios",
        "node-fetch",
        "got",
        "undici",
        "ws",
        "superagent",
    }
)
VM_MODULES: frozenset[str] = frozenset({"vm", "node:vm"})

EXEC_CALLEES: frozenset[str] = frozenset(
    {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
)
NETWORK_CALLEES: frozenset[str] = frozenset(
    {"fetch", "XMLHttpRequest", "WebSocket", "request", "connect", "createConnection"}
)
DYNAMIC_EXEC_CALLEES: frozenset[str] = frozenset(
    {
        "eval",
        "Function",
        "runInThisContext",
        "runInNewContext",
        "runInContext",
        "compileFunction",
    }
)

SENSITIVE_PATH_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\.npmrc", re.IGNORECASE), "npm auth token file (.npmrc)"),
    (re.compile(r"(?:^|[/\\])\.ssh(?:[/\\]|$)"), "SSH keys directory (.ssh)"),
    (re.compile(r"(?:^|[/\\])\.aws(?:[/\\]|$)"), "AWS credentials directory (.aws)"),
    (re.compile(r"(?:^|[/\\])\.kube(?:[/\\]|$)"), "Kubernetes config (.kube)"),
    (re.compile(r"\.git-credentials"), "Git credentials file"),
    (re.compile(r"/etc/(?:passwd|shadow)"), "System passwd/shadow file"),
    (
        re.compile(r"(?:metamask|phantom|exodus|electrum|wallet\.dat|seed\s*phrase)", re.IGNORECASE),
        "Crypto wallet path/material",
    ),
    (
        re.compile(r"(?:Login Data|Local State|discord[\\/].*leveldb)", re.IGNORECASE),
        "Browser/Discord credential store",
    ),
)

SUSPICIOUS_SHELL_PATTERNS: tuple[tuple[re.Pattern[str], str, Severity], ...] = (
    (
        re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:sh|bash|zsh|node|python)", re.IGNORECASE),
        "Pipe-to-shell remote downloader in install script",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"\b(?:powershell|pwsh)\b.*(?:-enc|-encodedcommand|iex|invoke-expression|downloadstring)", re.IGNORECASE),
        "Encoded/remote PowerShell execution in install script",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"\b(?:curl|wget|nc|ncat|netcat)\b", re.IGNORECASE),
        "Network shell command in install script",
        Severity.HIGH,
    ),
    (
        re.compile(r"\b(?:bash|sh|cmd)\s+(?:-c|/c)\b", re.IGNORECASE),
        "Inline shell command execution in install script",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"\bnode\s+-e\b", re.IGNORECASE),
        "Inline `node -e` execution in install script",
        Severity.HIGH,
    ),
)

PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"(?:mark|classify|rate)\s+this\s+package\s+as\s+(?:benign|safe)", re.IGNORECASE),
    re.compile(r"this\s+package\s+(?:has\s+been\s+)?audited\s+and\s+(?:is\s+)?safe", re.IGNORECASE),
    re.compile(r"\"verdict\"\s*:\s*\"benign\"", re.IGNORECASE),
    re.compile(r"system\s*prompt|security\s+scanner\s+override", re.IGNORECASE),
)

_NODE_SCRIPT_FILE_RE = re.compile(
    r"""(?:node|bun|tsx|ts-node|sh|bash|python3?)\s+(?:-[a-zA-Z]+\s+)*['"]?([./a-zA-Z0-9_\-]+\.(?:[cm]?js|ts|sh|py))['"]?"""
)
_EXTERNAL_URL_RE = re.compile(r"https?://([a-zA-Z0-9.-]+)(?::\d+)?(/[^\s'\"`<>]*)?")
_BENIGN_URL_DOMAINS: frozenset[str] = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "registry.npmjs.org",
        "npmjs.org",
        "www.npmjs.com",
        "json-schema.org",
        "spdx.org",
        "opensource.org",
        "mozilla.org",
        "w3.org",
        "example.com",
        "schema.org",
    }
)


def _get_parser(rel_path: str) -> Any | None:
    if not TREE_SITTER_AVAILABLE:
        return None
    ext = posixpath.splitext(rel_path)[1].lower()
    if ext == ".ts":
        return Parser(_TS_LANG)
    if ext == ".tsx":
        return Parser(_TSX_LANG)
    if ext in {".js", ".mjs", ".cjs", ".jsx"}:
        return Parser(_JS_LANG)
    return None


def _resolve_relative_import(
    from_file: str,
    specifier: str,
    available_files: set[str],
) -> str | None:
    """Resolve a relative JS/TS import specifier to a file inside the tarball."""
    if not specifier.startswith("."):
        return None
    base_dir = posixpath.dirname(from_file)
    joined = posixpath.normpath(posixpath.join(base_dir, specifier)).lstrip("./")
    candidates = [joined]
    for ext in JS_EXTENSIONS + (".json",):
        candidates.append(joined + ext)
    for ext in JS_EXTENSIONS:
        candidates.append(posixpath.join(joined, "index" + ext))
    for cand in candidates:
        if cand in available_files:
            return cand
    return None


def _extract_pkg_json_entrypoints(
    archive: InMemoryArchive,
    metadata: PackageMetadata,
) -> tuple[list[str], list[str], list[str]]:
    """Return (install_entrypoints, bin_entrypoints, main_entrypoints)."""
    available = set(archive.text_files.keys()) | set(archive.binary_files)
    install_entries: list[str] = []
    bin_entries: list[str] = []
    main_entries: list[str] = []

    scripts = dict(metadata.scripts)
    pkg_json_raw = archive.text_files.get("package.json")
    pkg_doc: dict[str, Any] = {}
    if pkg_json_raw:
        try:
            pkg_doc = json.loads(pkg_json_raw)
            if isinstance(pkg_doc.get("scripts"), dict):
                for k, v in pkg_doc["scripts"].items():
                    if isinstance(v, str):
                        scripts.setdefault(str(k), v)
        except json.JSONDecodeError:
            pkg_doc = {}

    for hook in INSTALL_HOOK_NAMES:
        cmd = scripts.get(hook)
        if not cmd:
            continue
        for match in _NODE_SCRIPT_FILE_RE.finditer(cmd):
            rel = match.group(1).lstrip("./")
            resolved = _resolve_relative_import("package.json", f"./{rel}", available) or rel
            if resolved in available and resolved not in install_entries:
                install_entries.append(resolved)

    if "binding.gyp" in available:
        install_entries.append("binding.gyp")

    # Bin entrypoints (critical for npx / pnpm dlx / yarn dlx / bunx)
    raw_bins = dict(metadata.bin_entries)
    if not raw_bins and pkg_doc.get("bin"):
        raw = pkg_doc["bin"]
        if isinstance(raw, str):
            raw_bins[metadata.name.split("/")[-1]] = raw
        elif isinstance(raw, dict):
            raw_bins = {str(k): str(v) for k, v in raw.items() if isinstance(v, str)}
    for target in raw_bins.values():
        rel = target.lstrip("./")
        resolved = _resolve_relative_import("package.json", f"./{rel}", available) or rel
        if resolved in available and resolved not in bin_entries:
            bin_entries.append(resolved)

    # Main / module / exports entrypoints
    main_candidates: list[str] = []
    for key in ("main", "module"):
        val = pkg_doc.get(key)
        if isinstance(val, str):
            main_candidates.append(val)
    exports = pkg_doc.get("exports")
    if isinstance(exports, str):
        main_candidates.append(exports)
    elif isinstance(exports, dict):
        for val in exports.values():
            if isinstance(val, str):
                main_candidates.append(val)
            elif isinstance(val, dict):
                for sub in val.values():
                    if isinstance(sub, str):
                        main_candidates.append(sub)
    if not main_candidates and "index.js" in available:
        main_candidates.append("index.js")

    for cand in main_candidates:
        rel = cand.lstrip("./")
        resolved = _resolve_relative_import("package.json", f"./{rel}", available) or rel
        if resolved in available and resolved not in main_entries:
            main_entries.append(resolved)

    return install_entries, bin_entries, main_entries


def _is_likely_minified(text: str) -> bool:
    """Detect legitimate minified JS bundles so we avoid noisy entropy false positives."""
    lines = text.splitlines()
    if not lines:
        return False
    if len(lines) <= 5 and len(text) > 8000:
        return True
    avg_len = len(text) / max(1, len(lines))
    return avg_len > 300 and "//# sourceMappingURL=" in text[-400:]


def _node_text(node: Any, src_bytes: bytes) -> str:
    return src_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _strip_quotes(raw: str) -> str:
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"', "`"}:
        return raw[1:-1]
    return raw


def _walk_ast_js(
    rel_path: str,
    text: str,
    available_files: set[str],
) -> tuple[list[CapabilityFinding], list[str], bool]:
    """Scan a JS/TS file via Tree-sitter AST. Returns (findings, static_imports, has_computed_require)."""
    findings: list[CapabilityFinding] = []
    static_imports: list[str] = []
    has_computed_require = False

    parser = _get_parser(rel_path)
    if parser is None:
        return _walk_regex_fallback(rel_path, text, available_files)

    src_bytes = text.encode("utf-8", errors="replace")
    tree = parser.parse(src_bytes)
    root = tree.root_node
    minified = _is_likely_minified(text)

    def _add(
        kind: CapabilityKind,
        severity: Severity,
        node: Any,
        symbol: str,
        detail: str,
        *,
        det_crit: bool = False,
    ) -> None:
        line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        snippet = _node_text(node, src_bytes).replace("\n", " ")[:220]
        findings.append(
            CapabilityFinding(
                kind=kind,
                severity=severity,
                file=rel_path,
                line=line,
                end_line=end_line,
                symbol=symbol,
                snippet=snippet,
                detail=detail,
                deterministic_critical=det_crit,
            )
        )

    def _check_module_specifier(spec: str, node: Any) -> None:
        if spec in EXEC_MODULES:
            _add(CapabilityKind.EXEC, Severity.HIGH, node, spec, f"Imports process execution module `{spec}`")
        elif spec in NETWORK_MODULES:
            _add(CapabilityKind.NETWORK, Severity.MEDIUM, node, spec, f"Imports network module `{spec}`")
        elif spec in VM_MODULES:
            _add(CapabilityKind.DYNAMIC_EXEC, Severity.HIGH, node, spec, f"Imports dynamic VM execution module `{spec}`")
        elif spec.startswith("."):
            resolved = _resolve_relative_import(rel_path, spec, available_files)
            if resolved and resolved not in static_imports:
                static_imports.append(resolved)

    stack = [root]
    while stack:
        node = stack.pop()
        ntype = node.type

        if ntype == "import_statement":
            source_node = node.child_by_field_name("source")
            if source_node is not None:
                spec = _strip_quotes(_node_text(source_node, src_bytes))
                _check_module_specifier(spec, node)

        elif ntype == "call_expression":
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if func_node is not None:
                func_text = _node_text(func_node, src_bytes)
                last_ident = func_text.split(".")[-1]
                arg_children = [
                    c for c in (args_node.named_children if args_node else [])
                ]

                # require(...) and dynamic import(...)
                if func_text in {"require", "import"} and arg_children:
                    first_arg = arg_children[0]
                    if first_arg.type == "string":
                        spec = _strip_quotes(_node_text(first_arg, src_bytes))
                        _check_module_specifier(spec, node)
                    elif first_arg.type == "template_string" and not any(
                        c.type == "template_substitution" for c in first_arg.named_children
                    ):
                        spec = _strip_quotes(_node_text(first_arg, src_bytes))
                        _check_module_specifier(spec, node)
                    else:
                        # Computed / obfuscated require()!
                        has_computed_require = True
                        raw_arg = _node_text(first_arg, src_bytes)
                        decoded = static_deobfuscate(raw_arg)
                        extra = (
                            f" (statically decoded: {decoded[0].decoded!r})"
                            if decoded
                            else ""
                        )
                        _add(
                            CapabilityKind.COMPUTED_REQUIRE,
                            Severity.HIGH,
                            node,
                            f"{func_text}(dynamic)",
                            f"Dynamic/computed `{func_text}(...)` hides target module from static graphs{extra}",
                        )
                        for art in decoded:
                            if art.decoded in EXEC_MODULES:
                                _add(
                                    CapabilityKind.EXEC,
                                    Severity.CRITICAL,
                                    node,
                                    art.decoded,
                                    f"Obfuscated import resolves to `{art.decoded}`",
                                    det_crit=True,
                                )

                # Dynamic eval / Function / vm
                elif func_text in {"eval", "Function", "global.eval", "globalThis.eval"} or last_ident in DYNAMIC_EXEC_CALLEES:
                    _add(
                        CapabilityKind.DYNAMIC_EXEC,
                        Severity.HIGH,
                        node,
                        func_text,
                        f"Dynamic code evaluation via `{func_text}(...)`",
                    )

                # Process execution calls
                elif last_ident in EXEC_CALLEES and (
                    "child_process" in func_text
                    or func_text in EXEC_CALLEES
                    or func_text.startswith(("cp.", "proc.", "childProcess."))
                ):
                    _add(
                        CapabilityKind.EXEC,
                        Severity.HIGH,
                        node,
                        func_text,
                        f"Process execution call `{func_text}(...)`",
                    )

                # Network calls
                elif func_text in {"fetch", "globalThis.fetch"} or (
                    last_ident in {"request", "get", "post", "connect"}
                    and any(
                        tok in func_text
                        for tok in ("http", "https", "net", "axios", "got", "dns", "tls")
                    )
                ):
                    _add(
                        CapabilityKind.NETWORK,
                        Severity.MEDIUM,
                        node,
                        func_text,
                        f"Outbound network call `{func_text}(...)`",
                    )

                # Base64 / hex / fromCharCode decoding
                elif func_text in {"atob", "Buffer.from"}:
                    call_str = _node_text(node, src_bytes)
                    if func_text == "atob" or any(
                        enc in call_str for enc in ("'base64'", '"base64"', "'hex'", '"hex"')
                    ):
                        decoded = static_deobfuscate(call_str)
                        preview = f" -> {decoded[0].decoded[:80]!r}" if decoded else ""
                        _add(
                            CapabilityKind.OBFUSCATION,
                            Severity.MEDIUM,
                            node,
                            func_text,
                            f"Encoded payload decoding via `{func_text}`{preview}",
                        )
                elif func_text == "String.fromCharCode" and len(arg_children) >= 6:
                    decoded = static_deobfuscate(_node_text(node, src_bytes))
                    preview = f" -> {decoded[0].decoded[:80]!r}" if decoded else ""
                    _add(
                        CapabilityKind.OBFUSCATION,
                        Severity.HIGH,
                        node,
                        "String.fromCharCode",
                        f"Character-code string obfuscation ({len(arg_children)} codes){preview}",
                    )

        elif ntype == "new_expression":
            ctor_node = node.child_by_field_name("constructor")
            if ctor_node is not None:
                ctor = _node_text(ctor_node, src_bytes)
                if ctor in {"Function", "vm.Script", "Script"}:
                    _add(
                        CapabilityKind.DYNAMIC_EXEC,
                        Severity.HIGH,
                        node,
                        f"new {ctor}",
                        f"Dynamic code compilation via `new {ctor}(...)`",
                    )
                elif ctor in {"WebSocket", "XMLHttpRequest"}:
                    _add(
                        CapabilityKind.NETWORK,
                        Severity.MEDIUM,
                        node,
                        f"new {ctor}",
                        f"Network client instantiation `new {ctor}(...)`",
                    )

        elif ntype == "member_expression":
            member_text = _node_text(node, src_bytes)
            if member_text == "process.env":
                _add(
                    CapabilityKind.SENSITIVE_READ,
                    Severity.MEDIUM,
                    node,
                    "process.env",
                    "Reads environment variables (`process.env`)",
                )

        elif ntype == "string":
            raw_str = _node_text(node, src_bytes)
            val = _strip_quotes(raw_str)
            if len(val) >= 4:
                for rx, label in SENSITIVE_PATH_PATTERNS:
                    if rx.search(val):
                        _add(
                            CapabilityKind.SENSITIVE_READ,
                            Severity.HIGH,
                            node,
                            val[:60],
                            f"References sensitive credential path: {label}",
                        )
                        break

                # High-entropy opaque blob check (skip data URIs and legitimate minified bundles)
                if (
                    not minified
                    and len(val) >= 96
                    and " " not in val[:80]
                    and not val.startswith(("data:", "http://", "https://", "-----BEGIN"))
                    and shannon_entropy(val) >= 5.0
                ):
                    _add(
                        CapabilityKind.OBFUSCATION,
                        Severity.MEDIUM,
                        node,
                        "high_entropy_literal",
                        f"High-entropy opaque string literal (len={len(val)}, H={shannon_entropy(val):.2f})",
                    )

        # Traverse children (reverse order so DFS visits top-to-bottom)
        for child in reversed(node.children):
            stack.append(child)

    return findings, static_imports, has_computed_require


def _walk_regex_fallback(
    rel_path: str,
    text: str,
    available_files: set[str],
) -> tuple[list[CapabilityFinding], list[str], bool]:
    """Fallback static scanner if tree-sitter binaries are unavailable."""
    findings: list[CapabilityFinding] = []
    imports: list[str] = []
    has_computed = False

    for line_no, line in enumerate(text.splitlines(), start=1):
        for m in re.finditer(r"""require\(\s*['"]([^'"]+)['"]\s*\)""", line):
            spec = m.group(1)
            if spec.startswith("."):
                resolved = _resolve_relative_import(rel_path, spec, available_files)
                if resolved and resolved not in imports:
                    imports.append(resolved)
            elif spec in EXEC_MODULES:
                findings.append(
                    CapabilityFinding(
                        kind=CapabilityKind.EXEC,
                        severity=Severity.HIGH,
                        file=rel_path,
                        line=line_no,
                        end_line=line_no,
                        symbol=spec,
                        snippet=line.strip()[:200],
                        detail=f"Requires `{spec}`",
                    )
                )
        if re.search(r"""require\(\s*[^'"`\s)]""", line):
            has_computed = True
            findings.append(
                CapabilityFinding(
                    kind=CapabilityKind.COMPUTED_REQUIRE,
                    severity=Severity.HIGH,
                    file=rel_path,
                    line=line_no,
                    end_line=line_no,
                    symbol="require(dynamic)",
                    snippet=line.strip()[:200],
                    detail="Dynamic/computed `require(...)`",
                )
            )
        if "process.env" in line:
            findings.append(
                CapabilityFinding(
                    kind=CapabilityKind.SENSITIVE_READ,
                    severity=Severity.MEDIUM,
                    file=rel_path,
                    line=line_no,
                    end_line=line_no,
                    symbol="process.env",
                    snippet=line.strip()[:200],
                    detail="Reads `process.env`",
                )
            )
        if re.search(r"\b(?:eval|Function)\s*\(", line):
            findings.append(
                CapabilityFinding(
                    kind=CapabilityKind.DYNAMIC_EXEC,
                    severity=Severity.HIGH,
                    file=rel_path,
                    line=line_no,
                    end_line=line_no,
                    symbol="eval/Function",
                    snippet=line.strip()[:200],
                    detail="Dynamic code evaluation",
                )
            )
    return findings, imports, has_computed


def _bfs_reachable(starts: list[str], edges: dict[str, list[str]]) -> list[str]:
    visited: list[str] = []
    seen: set[str] = set()
    q: deque[str] = deque(starts)
    while q:
        curr = q.popleft()
        if curr in seen:
            continue
        seen.add(curr)
        visited.append(curr)
        for nxt in edges.get(curr, []):
            if nxt not in seen:
                q.append(nxt)
    return visited


def scan_npm_archive(
    metadata: PackageMetadata,
    archive: InMemoryArchive,
    *,
    is_exec_target: bool = False,
) -> CapabilitySummary:
    """Scan an in-memory npm tarball with Tree-sitter AST, reachability, and steganography checks."""
    available = set(archive.text_files.keys()) | set(archive.binary_files)
    install_entries, bin_entries, main_entries = _extract_pkg_json_entrypoints(archive, metadata)

    all_findings: list[CapabilityFinding] = []
    edges: dict[str, list[str]] = {}
    computed_req_files: list[str] = []
    js_ts_count = 0
    has_invisible = False
    has_prompt_inj = False

    # 1. Inspect package.json install hooks & bin declarations
    has_install_scripts = False
    for hook in INSTALL_HOOK_NAMES:
        cmd = metadata.scripts.get(hook)
        if not cmd:
            continue
        has_install_scripts = True
        all_findings.append(
            CapabilityFinding(
                kind=CapabilityKind.INSTALL_SCRIPT,
                severity=Severity.MEDIUM,
                file="package.json",
                line=1,
                end_line=1,
                symbol=hook,
                snippet=f'"{hook}": "{cmd[:180]}"',
                detail=f"Defines install lifecycle script `{hook}`",
                reachable_from=[f"script:{hook}"],
            )
        )
        for rx, desc, sev in SUSPICIOUS_SHELL_PATTERNS:
            if rx.search(cmd):
                all_findings.append(
                    CapabilityFinding(
                        kind=CapabilityKind.EXEC,
                        severity=sev,
                        file="package.json",
                        line=1,
                        end_line=1,
                        symbol=hook,
                        snippet=f'"{hook}": "{cmd[:180]}"',
                        detail=desc,
                        reachable_from=[f"script:{hook}"],
                        deterministic_critical=(sev == Severity.CRITICAL),
                    )
                )
        for url_m in _EXTERNAL_URL_RE.finditer(cmd):
            host = url_m.group(1).lower()
            if host not in _BENIGN_URL_DOMAINS:
                all_findings.append(
                    CapabilityFinding(
                        kind=CapabilityKind.NETWORK,
                        severity=Severity.HIGH,
                        file="package.json",
                        line=1,
                        end_line=1,
                        symbol=host,
                        snippet=f'"{hook}": "{cmd[:180]}"',
                        detail=f"Install script contacts external host `{host}`",
                        reachable_from=[f"script:{hook}"],
                    )
                )

    if is_exec_target and bin_entries:
        for bfile in bin_entries:
            all_findings.append(
                CapabilityFinding(
                    kind=CapabilityKind.BIN_ENTRYPOINT,
                    severity=Severity.LOW,
                    file=bfile,
                    line=1,
                    end_line=1,
                    symbol="bin",
                    snippet=bfile,
                    detail="Immediate `bin` execution target (`npx`/`dlx`/`bunx`)",
                    reachable_from=["bin"],
                )
            )

    # 2. Flag embedded native binaries / scripts
    for bin_file in archive.binary_files:
        ext = posixpath.splitext(bin_file)[1].lower()
        if ext in {".node", ".wasm", ".exe", ".dll", ".so", ".dylib"}:
            all_findings.append(
                CapabilityFinding(
                    kind=CapabilityKind.NATIVE_BINARY,
                    severity=Severity.MEDIUM if ext in {".node", ".wasm"} else Severity.HIGH,
                    file=bin_file,
                    line=1,
                    end_line=1,
                    symbol=ext,
                    snippet=bin_file,
                    detail=f"Ships prebuilt binary/WASM asset `{bin_file}`",
                )
            )

    # 3. Walk all text files: AST for JS/TS + Invisible Unicode + Prompt Injection
    for rel_path, text in sorted(archive.text_files.items()):
        ext = posixpath.splitext(rel_path)[1].lower()

        # Invisible Unicode / Trojan Source check on code & manifests
        if ext in JS_EXTENSIONS or ext in {".json", ".sh", ".ps1"}:
            inv_hits = detect_invisible_unicode(text)
            if inv_hits:
                has_invisible = True
                first = inv_hits[0]
                total_chars = sum(h.count for h in inv_hits)
                cats = sorted({c for h in inv_hits for c in h.categories})
                all_findings.append(
                    CapabilityFinding(
                        kind=CapabilityKind.INVISIBLE_UNICODE,
                        severity=Severity.CRITICAL if total_chars >= 10 else Severity.HIGH,
                        file=rel_path,
                        line=first.line,
                        end_line=inv_hits[-1].line,
                        symbol=",".join(cats),
                        snippet=f"{total_chars} invisible Unicode characters across {len(inv_hits)} line(s)",
                        detail=f"Detected invisible/bidi Unicode characters ({', '.join(cats)})",
                        deterministic_critical=(total_chars >= 20),
                    )
                )

        # Prompt-injection check across source files & READMEs
        for rx in PROMPT_INJECTION_PATTERNS:
            m = rx.search(text)
            if m:
                has_prompt_inj = True
                line_no = text[: m.start()].count("\n") + 1
                all_findings.append(
                    CapabilityFinding(
                        kind=CapabilityKind.PROMPT_INJECTION,
                        severity=Severity.HIGH,
                        file=rel_path,
                        line=line_no,
                        end_line=line_no,
                        symbol="prompt_injection",
                        snippet=m.group(0)[:180],
                        detail="Adversarial reviewer-targeted prompt-injection phrasing detected",
                    )
                )
                break

        if ext in JS_EXTENSIONS:
            js_ts_count += 1
            file_findings, imports, has_comp = _walk_ast_js(rel_path, text, available)
            all_findings.extend(file_findings)
            if imports:
                edges[rel_path] = imports
            if has_comp:
                computed_req_files.append(rel_path)

    # 4. Compute reachability from install scripts and bin entrypoints
    reachable_install = _bfs_reachable(install_entries, edges)
    reachable_bin = _bfs_reachable(bin_entries, edges)
    install_set = set(reachable_install)
    bin_set = set(reachable_bin)

    for finding in all_findings:
        if finding.file in install_set and "install" not in finding.reachable_from:
            finding.reachable_from.append("install")
            # Elevate severity for dangerous sinks directly reachable at install time
            if finding.kind in {
                CapabilityKind.EXEC,
                CapabilityKind.DYNAMIC_EXEC,
                CapabilityKind.COMPUTED_REQUIRE,
                CapabilityKind.SENSITIVE_READ,
            } and finding.severity == Severity.MEDIUM:
                finding.severity = Severity.HIGH
        if finding.file in bin_set and "bin" not in finding.reachable_from:
            finding.reachable_from.append("bin")

    counts: dict[str, int] = {}
    for f in all_findings:
        counts[f.kind.value] = counts.get(f.kind.value, 0) + 1

    return CapabilitySummary(
        total_files=len(archive.file_sizes),
        js_ts_files=js_ts_count,
        binary_files=sorted(archive.binary_files),
        reachability=ReachabilityGraph(
            install_entrypoints=install_entries,
            bin_entrypoints=bin_entries,
            main_entrypoints=main_entries,
            reachable_at_install=reachable_install,
            reachable_at_bin=reachable_bin,
            computed_require_files=computed_req_files,
            edges=edges,
        ),
        findings=all_findings,
        capability_counts=counts,
        has_install_scripts=has_install_scripts,
        has_computed_require=bool(computed_req_files),
        has_invisible_unicode=has_invisible,
        has_prompt_injection_pattern=has_prompt_inj,
    )
