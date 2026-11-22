"""Tests for pure-static deobfuscation, invisible Unicode detection, and typosquatting."""

from cli_guard.core.deobfuscate import (
    detect_invisible_unicode,
    shannon_entropy,
    static_deobfuscate,
)
from cli_guard.core.typosquat import damerau_levenshtein, find_typosquat_targets
from cli_guard.ecosystems.npm.top_packages import TOP_NPM_PACKAGES


def test_static_deobfuscate_concat_base64_hex_charcode() -> None:
    snippet = """
    const a = 'ch' + 'ild_' + 'process';
    const b = Buffer.from('aHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tL2V4Zmls', 'base64').toString();
    const c = Buffer.from('6368696c645f70726f63657373', 'hex').toString();
    const d = String.fromCharCode(101, 120, 101, 99, 83, 121, 110, 99);
    """
    artifacts = static_deobfuscate(snippet)
    decoded_values = {a.decoded for a in artifacts}
    assert "child_process" in decoded_values
    assert "https://evil.example.com/exfil" in decoded_values
    assert "execSync" in decoded_values


def test_detect_invisible_unicode_bidi_and_variation_selectors() -> None:
    trojan = "const ok = true;\nconst hidden = '\u202e\u200b\u200c\U000e0100\U000e0101';"
    hits = detect_invisible_unicode(trojan)
    assert len(hits) == 1
    assert hits[0].line == 2
    assert hits[0].count == 5
    assert "bidi-override-trojan-source" in hits[0].categories
    assert "variation-selector-supplement" in hits[0].categories


def test_shannon_entropy_distinguishes_plain_vs_encoded() -> None:
    assert shannon_entropy("aaaaaaaaaaaa") == 0.0
    assert shannon_entropy("aB3$kP9!zQ2@mX7#vL5%nR8^wT1&yF4*cJ6(hD0)") > 5.0


def test_typosquat_detection() -> None:
    assert damerau_levenshtein("lodash", "lodahs") == 1
    assert "lodash" in find_typosquat_targets("lodahs", TOP_NPM_PACKAGES)
    assert "lodash" in find_typosquat_targets("1odash", TOP_NPM_PACKAGES)
    assert "chalk" in find_typosquat_targets("chalk-js", TOP_NPM_PACKAGES)
    assert "lodash" in find_typosquat_targets("@evilscope/lodash", TOP_NPM_PACKAGES)
    # Exact popular package should NOT flag itself
    assert find_typosquat_targets("lodash", TOP_NPM_PACKAGES) == []
