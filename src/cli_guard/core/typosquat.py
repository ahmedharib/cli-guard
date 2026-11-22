"""Typosquatting detection using Damerau-Levenshtein and name normalization."""

from __future__ import annotations

import re
from collections.abc import Iterable

_HOMOGLYPH_TABLE = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "@": "a",
    }
)

_COMMON_SUFFIXES = ("-js", ".js", "js", "-node", "-cli", "-core", "-utils", "-sdk")


def damerau_levenshtein(a: str, b: str) -> int:
    """Compute optimal string alignment (Damerau-Levenshtein) edit distance."""
    la, lb = len(a), len(b)
    if a == b:
        return 0
    if la == 0:
        return lb
    if lb == 0:
        return la
    if abs(la - lb) > 2:
        return abs(la - lb)

    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j

    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,
                d[i][j - 1] + 1,
                d[i - 1][j - 1] + cost,
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def _normalize(name: str) -> str:
    bare = name.lower().strip()
    if bare.startswith("@") and "/" in bare:
        bare = bare.split("/", 1)[1]
    bare = bare.translate(_HOMOGLYPH_TABLE)
    return re.sub(r"[-_.]", "", bare)


def find_typosquat_targets(
    package_name: str,
    popular_packages: Iterable[str],
    max_results: int = 3,
) -> list[str]:
    """Return high-impact packages that `package_name` appears to impersonate."""
    raw = package_name.lower().strip()
    pop_set = {p.lower() for p in popular_packages}
    if raw in pop_set:
        return []

    bare = raw.split("/", 1)[1] if raw.startswith("@") and "/" in raw else raw
    if len(bare) < 4:
        return []

    norm = _normalize(raw)
    matches: list[tuple[int, str]] = []

    for target in pop_set:
        t_bare = target.split("/", 1)[1] if target.startswith("@") and "/" in target else target
        if len(t_bare) < 4:
            continue

        # Exact match after stripping scope (e.g., @evil/lodash vs lodash)
        if bare == t_bare and raw != target:
            matches.append((0, target))
            continue

        # Exact match after stripping separators or homoglyphs (e.g., 1odash, react_dom)
        t_norm = _normalize(target)
        if norm == t_norm:
            matches.append((1, target))
            continue

        # Suffix stuffing (e.g., chalk-js, lodash-utils)
        for suffix in _COMMON_SUFFIXES:
            if bare == f"{t_bare}{suffix}":
                matches.append((1, target))
                break
        else:
            max_dist = 1 if len(t_bare) <= 6 else 2
            dist = damerau_levenshtein(bare, t_bare)
            if 1 <= dist <= max_dist:
                matches.append((dist, target))

    matches.sort(key=lambda item: (item[0], item[1]))
    seen: list[str] = []
    for _, target in matches:
        if target not in seen:
            seen.append(target)
        if len(seen) >= max_results:
            break
    return seen
