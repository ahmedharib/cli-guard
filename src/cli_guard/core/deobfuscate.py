"""Pure static, zero-eval deobfuscation, entropy, and invisible Unicode detectors."""

from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass, field

# Invisible / Trojan Source / variation-selector code points abused in JS malware
INVISIBLE_RANGES: tuple[tuple[int, int, str], ...] = (
    (0x200B, 0x200F, "zero-width/direction-mark"),
    (0x202A, 0x202E, "bidi-override-trojan-source"),
    (0x2060, 0x206F, "invisible-format-char"),
    (0xFE00, 0xFE0F, "variation-selector-bmp"),
    (0xE0100, 0xE01EF, "variation-selector-supplement"),
)

_CONCAT_STR_RE = re.compile(
    r"""(?P<seq>(?:['"`][^'"`\n\\]{0,120}['"`]\s*\+\s*)+['"`][^'"`\n\\]{0,120}['"`])"""
)
_QUOTED_LIT_RE = re.compile(r"""['"`]([^'"`\n\\]{0,120})['"`]""")
_FROM_CHAR_CODE_RE = re.compile(
    r"""String\.fromCharCode\(\s*([0-9xXa-fA-F,\s]{3,500})\s*\)"""
)
_BASE64_CALL_RE = re.compile(
    r"""(?:Buffer\.from\(\s*['"]([A-Za-z0-9+/=]{12,4096})['"]\s*,\s*['"]base64['"]\s*\)|atob\(\s*['"]([A-Za-z0-9+/=]{12,4096})['"]\s*\))"""
)
_HEX_CALL_RE = re.compile(
    r"""Buffer\.from\(\s*['"]([0-9a-fA-F]{12,4096})['"]\s*,\s*['"]hex['"]\s*\)"""
)
_HEX_ESCAPE_RE = re.compile(r"""(?:\\x([0-9a-fA-F]{2}))""")
_UNI_ESCAPE_RE = re.compile(r"""(?:\\u([0-9a-fA-F]{4})|\\u\{([0-9a-fA-F]{1,6})\})""")


@dataclass(slots=True)
class DecodedArtifact:
    technique: str
    raw: str
    decoded: str


@dataclass(slots=True)
class InvisibleUnicodeHit:
    line: int
    count: int
    categories: list[str] = field(default_factory=list)


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def detect_invisible_unicode(text: str) -> list[InvisibleUnicodeHit]:
    """Detect zero-width, Bidi override (Trojan Source), and variation-selector steganography."""
    hits: list[InvisibleUnicodeHit] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        cats: set[str] = set()
        count = 0
        for ch in line:
            cp = ord(ch)
            # Allow a single BOM at the very start of line 1
            if line_no == 1 and cp == 0xFEFF:
                continue
            for lo, hi, label in INVISIBLE_RANGES:
                if lo <= cp <= hi:
                    count += 1
                    cats.add(label)
                    break
        if count > 0:
            hits.append(
                InvisibleUnicodeHit(line=line_no, count=count, categories=sorted(cats))
            )
    return hits


def _is_printable_text(raw_bytes: bytes) -> str | None:
    try:
        decoded = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded:
        return None
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\r\n\t")
    if (printable / len(decoded)) < 0.85:
        return None
    return decoded


def decode_js_escapes(text: str) -> str:
    """Statically decode \\xNN and \\uNNNN escapes inside a string snippet."""

    def _hex_sub(m: re.Match[str]) -> str:
        return chr(int(m.group(1), 16))

    def _uni_sub(m: re.Match[str]) -> str:
        val = m.group(1) or m.group(2)
        cp = int(val, 16)
        return chr(cp) if 0 <= cp <= 0x10FFFF else m.group(0)

    out = _HEX_ESCAPE_RE.sub(_hex_sub, text)
    out = _UNI_ESCAPE_RE.sub(_uni_sub, out)
    return out


def static_deobfuscate(snippet: str, max_artifacts: int = 25) -> list[DecodedArtifact]:
    """Safely extract and decode common JS obfuscation constructs without executing code."""
    artifacts: list[DecodedArtifact] = []
    seen: set[tuple[str, str]] = set()

    def _add(technique: str, raw: str, decoded: str) -> None:
        cleaned = decoded.strip()
        if not cleaned or len(artifacts) >= max_artifacts:
            return
        key = (technique, cleaned[:200])
        if key in seen:
            return
        seen.add(key)
        artifacts.append(
            DecodedArtifact(technique=technique, raw=raw[:200], decoded=cleaned[:1000])
        )

    # 1. String literal concatenation folding: 'ch' + 'ild_' + 'process'
    for match in _CONCAT_STR_RE.finditer(snippet):
        parts = _QUOTED_LIT_RE.findall(match.group("seq"))
        if len(parts) >= 2:
            joined = decode_js_escapes("".join(parts))
            _add("string_concat", match.group("seq"), joined)

    # 2. String.fromCharCode(...)
    for match in _FROM_CHAR_CODE_RE.finditer(snippet):
        raw_nums = [tok.strip() for tok in match.group(1).split(",") if tok.strip()]
        chars: list[str] = []
        valid = True
        for tok in raw_nums:
            try:
                cp = int(tok, 0)
                if 0 <= cp <= 0x10FFFF:
                    chars.append(chr(cp))
                else:
                    valid = False
                    break
            except ValueError:
                valid = False
                break
        if valid and chars:
            _add("fromCharCode", match.group(0), "".join(chars))

    # 3. Buffer.from(..., 'base64') / atob(...)
    for match in _BASE64_CALL_RE.finditer(snippet):
        b64_str = match.group(1) or match.group(2)
        if not b64_str:
            continue
        try:
            padded = b64_str + "=" * (-len(b64_str) % 4)
            raw_bytes = base64.b64decode(padded, validate=False)
            decoded = _is_printable_text(raw_bytes)
            if decoded:
                _add("base64", b64_str, decoded)
        except Exception:
            continue

    # 4. Buffer.from(..., 'hex')
    for match in _HEX_CALL_RE.finditer(snippet):
        hex_str = match.group(1)
        try:
            raw_bytes = bytes.fromhex(hex_str)
            decoded = _is_printable_text(raw_bytes)
            if decoded:
                _add("hex", hex_str, decoded)
        except Exception:
            continue

    # 5. Direct hex/unicode escape sequences (when dense: >= 4 escapes)
    if len(_HEX_ESCAPE_RE.findall(snippet)) + len(_UNI_ESCAPE_RE.findall(snippet)) >= 4:
        unescaped = decode_js_escapes(snippet)
        if unescaped != snippet:
            _add("escape_decode", snippet[:200], unescaped)

    # 6. Raw standalone base64 candidate if the caller passed just a base64 string directly
    stripped = snippet.strip().strip("'\"")
    if (
        len(stripped) >= 12
        and len(stripped) <= 4096
        and re.fullmatch(r"[A-Za-z0-9+/=]+", stripped)
        and not artifacts
    ):
        try:
            padded = stripped + "=" * (-len(stripped) % 4)
            raw_bytes = base64.b64decode(padded, validate=True)
            decoded = _is_printable_text(raw_bytes)
            if decoded:
                _add("raw_base64", stripped, decoded)
        except Exception:
            pass

    return artifacts
