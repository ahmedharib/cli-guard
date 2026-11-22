"""Pure-Python npm SemVer parser and range evaluator (zero external dependencies)."""

from __future__ import annotations

import re
from dataclasses import dataclass

_SEMVER_RE = re.compile(
    r"^[v=]*\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$"
)


@dataclass(frozen=True, slots=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[int | str, ...] = ()
    raw: str = ""

    def _cmp_key(self) -> tuple[int, int, int, int, tuple[tuple[int, int | str], ...]]:
        # Stable release (1) sorts higher than prerelease (0)
        is_stable = 1 if not self.prerelease else 0
        pre_key = tuple(
            (0, item) if isinstance(item, int) else (1, item) for item in self.prerelease
        )
        return (self.major, self.minor, self.patch, is_stable, pre_key)

    def __lt__(self, other: SemVer) -> bool:
        return self._cmp_key() < other._cmp_key()

    def __le__(self, other: SemVer) -> bool:
        return self._cmp_key() <= other._cmp_key()

    def __gt__(self, other: SemVer) -> bool:
        return self._cmp_key() > other._cmp_key()

    def __ge__(self, other: SemVer) -> bool:
        return self._cmp_key() >= other._cmp_key()


def parse_semver(version: str) -> SemVer | None:
    m = _SEMVER_RE.match(version.strip())
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) is not None else 0
    patch = int(m.group(3)) if m.group(3) is not None else 0
    pre_str = m.group(4)
    pre: tuple[int | str, ...] = ()
    if pre_str:
        parts: list[int | str] = []
        for tok in pre_str.split("."):
            parts.append(int(tok) if tok.isdigit() else tok)
        pre = tuple(parts)
    return SemVer(major=major, minor=minor, patch=patch, prerelease=pre, raw=version.strip())


def _is_wildcard(tok: str) -> bool:
    return tok.lower() in {"*", "x"}


def _parse_partial(raw: str) -> tuple[int | None, int | None, int | None, tuple[int | str, ...]]:
    cleaned = raw.strip().lstrip("v=")
    if not cleaned or cleaned in {"*", "x", "X"}:
        return (None, None, None, ())
    pre: tuple[int | str, ...] = ()
    if "+" in cleaned:
        cleaned = cleaned.split("+", 1)[0]
    if "-" in cleaned:
        cleaned, pre_str = cleaned.split("-", 1)
        pre = tuple(int(p) if p.isdigit() else p for p in pre_str.split("."))
    parts = cleaned.split(".")
    nums: list[int | None] = []
    for idx in range(3):
        if idx >= len(parts) or _is_wildcard(parts[idx]):
            nums.append(None)
        elif parts[idx].isdigit():
            nums.append(int(parts[idx]))
        else:
            nums.append(None)
    return (nums[0], nums[1], nums[2], pre)


def _expand_comparator(token: str) -> list[tuple[str, SemVer]]:
    tok = token.strip()
    if not tok or tok in {"*", "x", "X", "latest"}:
        return []

    if tok.startswith("^"):
        maj, mn, pt, pre = _parse_partial(tok[1:])
        if maj is None:
            return []
        lo = SemVer(maj, mn or 0, pt or 0, pre)
        if maj > 0:
            hi = SemVer(maj + 1, 0, 0, (0,))
        elif mn is not None and mn > 0:
            hi = SemVer(0, mn + 1, 0, (0,))
        elif mn is None:
            hi = SemVer(1, 0, 0, (0,))
        else:
            hi = SemVer(0, 0, (pt or 0) + 1, (0,))
        return [(">=", lo), ("<", hi)]

    if tok.startswith("~"):
        maj, mn, pt, pre = _parse_partial(tok[1:])
        if maj is None:
            return []
        lo = SemVer(maj, mn or 0, pt or 0, pre)
        if mn is None:
            hi = SemVer(maj + 1, 0, 0, (0,))
        else:
            hi = SemVer(maj, mn + 1, 0, (0,))
        return [(">=", lo), ("<", hi)]

    for op in (">=", "<=", ">", "<", "="):
        if tok.startswith(op):
            maj, mn, pt, pre = _parse_partial(tok[len(op) :])
            if maj is None:
                return []
            if op == "<=" and (mn is None or pt is None):
                hi = SemVer(maj + 1, 0, 0, (0,)) if mn is None else SemVer(maj, mn + 1, 0, (0,))
                return [("<", hi)]
            if op == ">" and (mn is None or pt is None):
                lo = SemVer(maj + 1, 0, 0) if mn is None else SemVer(maj, mn + 1, 0)
                return [(">=", lo)]
            return [(op, SemVer(maj, mn or 0, pt or 0, pre))]

    # Bare version or X-range (e.g., 1.2.x, 1.x, 1.2.3)
    maj, mn, pt, pre = _parse_partial(tok)
    if maj is None:
        return []
    if mn is None:
        return [(">=", SemVer(maj, 0, 0)), ("<", SemVer(maj + 1, 0, 0, (0,)))]
    if pt is None:
        return [(">=", SemVer(maj, mn, 0)), ("<", SemVer(maj, mn + 1, 0, (0,)))]
    return [("=", SemVer(maj, mn, pt, pre))]


def _matches_comparator(ver: SemVer, op: str, target: SemVer) -> bool:
    if op == "=":
        return ver == target
    if op == ">=":
        return ver >= target
    if op == "<=":
        return ver <= target
    if op == ">":
        return ver > target
    if op == "<":
        return ver < target
    return False


def satisfies(version: str, range_expr: str) -> bool:
    """Return True if `version` satisfies npm semver `range_expr`."""
    ver = parse_semver(version)
    if ver is None:
        return version.strip() == range_expr.strip()

    expr = range_expr.strip()
    if not expr or expr in {"*", "x", "X", "latest"}:
        return not ver.prerelease

    for clause in expr.split("||"):
        clause = clause.strip()
        if not clause:
            continue

        # Normalize spaced operators (`>= 1.0.0` -> `>=1.0.0`)
        clause = re.sub(r"(>=|<=|>|<|=|\^|~)\s+", r"\1", clause)

        comparators: list[tuple[str, SemVer]] = []
        if " - " in clause:
            left, right = clause.split(" - ", 1)
            comparators.extend(_expand_comparator(f">={left.strip()}"))
            comparators.extend(_expand_comparator(f"<={right.strip()}"))
        else:
            for tok in clause.split():
                comparators.extend(_expand_comparator(tok))

        # npm prerelease rule: prereleases only match if a comparator in this clause
        # explicitly specifies a prerelease on the same (major, minor, patch) tuple.
        if ver.prerelease:
            allowed_pre = any(
                t.prerelease and (t.major, t.minor, t.patch) == (ver.major, ver.minor, ver.patch)
                for _, t in comparators
            )
            if not allowed_pre:
                continue

        if all(_matches_comparator(ver, op, target) for op, target in comparators):
            return True

    return False


def resolve_version(
    available_versions: list[str],
    dist_tags: dict[str, str],
    spec: str | None,
) -> str | None:
    """Resolve an npm version spec (exact, dist-tag, or semver range) to the highest matching version."""
    if not available_versions:
        return None

    clean = (spec or "").strip()
    if not clean or clean == "latest":
        if "latest" in dist_tags and dist_tags["latest"] in available_versions:
            return dist_tags["latest"]
    if clean in dist_tags and dist_tags[clean] in available_versions:
        return dist_tags[clean]
    if clean in available_versions:
        return clean

    matching: list[tuple[SemVer, str]] = []
    for raw_v in available_versions:
        if satisfies(raw_v, clean or "*"):
            parsed = parse_semver(raw_v)
            if parsed is not None:
                matching.append((parsed, raw_v))

    if matching:
        matching.sort(key=lambda item: item[0])
        return matching[-1][1]

    # Fallback to latest dist-tag if range is '*' or empty
    if not clean and "latest" in dist_tags:
        return dist_tags["latest"]
    return None


def find_previous_version(
    available_versions: list[str],
    current_version: str,
    publish_times: dict[str, str] | None = None,
) -> str | None:
    """Find the most relevant prior published stable/matching version for security diffing."""
    cur_sv = parse_semver(current_version)
    candidates: list[tuple[SemVer, str]] = []
    for raw_v in available_versions:
        if raw_v == current_version:
            continue
        sv = parse_semver(raw_v)
        if sv is None:
            continue
        if cur_sv is not None and sv < cur_sv:
            # Prefer non-prerelease predecessors unless current itself is prerelease
            if sv.prerelease and not cur_sv.prerelease:
                continue
            candidates.append((sv, raw_v))

    if candidates:
        candidates.sort(key=lambda item: item[0])
        return candidates[-1][1]

    # Fallback: chronological predecessor from `time` map
    if publish_times and current_version in publish_times:
        cur_time = publish_times[current_version]
        earlier = [
            (ts, v)
            for v, ts in publish_times.items()
            if v in available_versions and v != current_version and ts < cur_time
        ]
        if earlier:
            earlier.sort()
            return earlier[-1][1]

    return None
