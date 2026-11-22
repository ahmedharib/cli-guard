"""Version-diff engine: compares current npm tarball against previous published version."""

from __future__ import annotations

import difflib
import json

from cli_guard.core.advisories import is_shared_ci_publisher
from cli_guard.ecosystems.base import InMemoryArchive
from cli_guard.ecosystems.npm.ast_scanner import INSTALL_HOOK_NAMES, scan_npm_archive
from cli_guard.models import (
    CapabilityFinding,
    CapabilitySummary,
    PackageMetadata,
    VersionDiff,
)


def _extract_scripts_from_archive(archive: InMemoryArchive) -> dict[str, str]:
    raw = archive.text_files.get("package.json")
    if not raw:
        return {}
    try:
        doc = json.loads(raw)
        scripts = doc.get("scripts")
        if isinstance(scripts, dict):
            return {str(k): str(v) for k, v in scripts.items() if isinstance(v, str)}
    except json.JSONDecodeError:
        pass
    return {}


def compute_npm_version_diff(
    metadata: PackageMetadata,
    current_archive: InMemoryArchive,
    current_caps: CapabilitySummary,
    previous_archive: InMemoryArchive,
) -> VersionDiff:
    """Compute file, script, AST capability, provenance, and maintainer deltas."""
    prev_ver = metadata.previous_version or "unknown"
    prev_scripts = _extract_scripts_from_archive(previous_archive)
    prev_meta = PackageMetadata(
        ecosystem="npm",
        name=metadata.name,
        version=prev_ver,
        scripts=prev_scripts,
    )
    prev_caps = scan_npm_archive(prev_meta, previous_archive)

    cur_files = set(current_archive.file_sizes.keys())
    prev_files = set(previous_archive.file_sizes.keys())

    added_files = sorted(cur_files - prev_files)
    removed_files = sorted(prev_files - cur_files)
    common_files = sorted(cur_files & prev_files)

    modified_files: list[str] = []
    for path in common_files:
        cur_txt = current_archive.text_files.get(path)
        prev_txt = previous_archive.text_files.get(path)
        if cur_txt is not None and prev_txt is not None:
            if cur_txt != prev_txt:
                modified_files.append(path)
        elif current_archive.file_sizes.get(path) != previous_archive.file_sizes.get(path):
            modified_files.append(path)

    # Script diffs (focus on install & lifecycle scripts plus any newly added scripts)
    added_scripts: dict[str, str] = {}
    modified_scripts: dict[str, tuple[str, str]] = {}
    for k, cur_cmd in metadata.scripts.items():
        if k not in prev_scripts:
            added_scripts[k] = cur_cmd
        elif prev_scripts[k] != cur_cmd:
            modified_scripts[k] = (prev_scripts[k], cur_cmd)

    # AST capability delta: identify (kind, symbol, file) capabilities newly introduced
    prev_sig_set = {(f.kind, f.symbol, f.file) for f in prev_caps.findings}
    prev_kind_set = {f.kind for f in prev_caps.findings}

    new_capabilities: list[CapabilityFinding] = []
    for f in current_caps.findings:
        sig = (f.kind, f.symbol, f.file)
        if sig not in prev_sig_set:
            # Prioritize genuinely new capability classes or new files/install hooks
            if f.kind not in prev_kind_set or f.file in added_files or f.file in modified_files or f.file == "package.json":
                new_capabilities.append(f)

    # Provenance & maintainer takeover detection (respecting shared CI publisher safeguards)
    provenance_dropped = metadata.previous_has_provenance and not metadata.has_provenance

    prev_maint_set = {m.lower() for m in metadata.previous_maintainers}
    added_maintainers = [
        m
        for m in metadata.maintainers
        if prev_maint_set
        and m.lower() not in prev_maint_set
        and not is_shared_ci_publisher(m)
    ]
    maintainer_changed = bool(added_maintainers)

    # Build a compact unified diff excerpt focusing on package.json + highest-risk changed files
    diff_chunks: list[str] = []
    prioritized_diff_files: list[str] = []
    if "package.json" in modified_files:
        prioritized_diff_files.append("package.json")

    risky_files = {f.file for f in new_capabilities}
    for path in modified_files + added_files:
        if path in risky_files and path not in prioritized_diff_files:
            prioritized_diff_files.append(path)
    for path in modified_files:
        if path not in prioritized_diff_files and len(prioritized_diff_files) < 6:
            prioritized_diff_files.append(path)

    total_diff_chars = 0
    for path in prioritized_diff_files[:6]:
        cur_txt = current_archive.text_files.get(path)
        if cur_txt is None:
            continue
        prev_txt = previous_archive.text_files.get(path, "")
        # Skip huge single-line minified files in diff output
        if len(cur_txt) > 80_000 and cur_txt.count("\n") < 20:
            diff_chunks.append(f"--- {path} (minified bundle modified, {len(cur_txt)} bytes)")
            continue
        diff_lines = list(
            difflib.unified_diff(
                prev_txt.splitlines(),
                cur_txt.splitlines(),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                n=2,
                lineterm="",
            )
        )
        if not diff_lines:
            continue
        block = "\n".join(diff_lines[:80])
        if total_diff_chars + len(block) > 4500:
            break
        diff_chunks.append(block)
        total_diff_chars += len(block)

    # Highlight newly added install hooks explicitly
    _ = INSTALL_HOOK_NAMES

    return VersionDiff(
        previous_version=prev_ver,
        current_version=metadata.version,
        added_files=added_files,
        removed_files=removed_files,
        modified_files=modified_files,
        added_scripts=added_scripts,
        modified_scripts=modified_scripts,
        new_capabilities=new_capabilities,
        provenance_dropped=provenance_dropped,
        maintainer_changed=maintainer_changed,
        added_maintainers=added_maintainers,
        unified_diff_excerpt="\n\n".join(diff_chunks),
    )
