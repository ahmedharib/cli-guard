"""OSV / OpenSSF malicious-packages advisory client and publisher safeguards."""

from __future__ import annotations

from collections.abc import Sequence

import httpx

from cli_guard.core.cache import VerdictCache
from cli_guard.models import AdvisoryMatch

# Shared automated CI / trusted-publishing identities that must NEVER be auto-banned
# as "bad publishers" when a single repo using them gets compromised (known Gatekeeper pitfall).
SHARED_CI_PUBLISHERS: frozenset[str] = frozenset(
    {
        "github-actions",
        "github actions",
        "npm-bot",
        "semantic-release-bot",
        "renovate-bot",
        "dependabot",
        "gitlab-ci",
        "changeset-bot",
        "verdaccio",
    }
)

OSV_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
}


def is_shared_ci_publisher(publisher: str | None) -> bool:
    if not publisher:
        return False
    norm = publisher.strip().lower()
    return norm in SHARED_CI_PUBLISHERS or norm.endswith("[bot]")


class AdvisoryClient:
    """Queries OSV (including OpenSSF MAL-* malware advisories) and local blocklist."""

    def __init__(
        self,
        osv_api_url: str = "https://api.osv.dev/v1",
        cache: VerdictCache | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.osv_api_url = osv_api_url.rstrip("/")
        self.cache = cache
        self.timeout = timeout

    def query_batch(
        self,
        packages: Sequence[tuple[str, str, str]],
    ) -> dict[tuple[str, str, str], list[AdvisoryMatch]]:
        """Query a batch of (ecosystem, name, version) tuples against local blocklist + OSV."""
        results: dict[tuple[str, str, str], list[AdvisoryMatch]] = {
            pkg: [] for pkg in packages
        }

        if self.cache is not None:
            for pkg in packages:
                eco, name, ver = pkg
                for adv_id, reason in self.cache.check_blocklist(eco, name, ver):
                    results[pkg].append(
                        AdvisoryMatch(
                            id=adv_id,
                            source="local_blocklist",
                            summary=reason or "Matched local malicious-package blocklist",
                            is_malware=True,
                        )
                    )

        # Chunk OSV batch queries (max 500 per request)
        unique_pkgs = list(dict.fromkeys(packages))
        chunk_size = 500
        is_loopback = self.osv_api_url.startswith(("http://127.0.0.1", "http://localhost"))
        try:
            with httpx.Client(timeout=self.timeout, trust_env=not is_loopback) as client:
                for i in range(0, len(unique_pkgs), chunk_size):
                    chunk = unique_pkgs[i : i + chunk_size]
                    queries = [
                        {
                            "version": ver,
                            "package": {
                                "name": name,
                                "ecosystem": OSV_ECOSYSTEM_MAP.get(eco, eco),
                            },
                        }
                        for eco, name, ver in chunk
                    ]
                    resp = client.post(
                        f"{self.osv_api_url}/querybatch",
                        json={"queries": queries},
                    )
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
                    batch_results = data.get("results", [])
                    detail_cache: dict[str, dict[str, object]] = {}

                    for pkg, entry in zip(chunk, batch_results, strict=False):
                        vulns = entry.get("vulns") or []
                        for vuln in vulns:
                            adv_id = str(vuln.get("id", ""))
                            if not adv_id:
                                continue
                            aliases = [str(a) for a in vuln.get("aliases", [])]
                            summary = str(vuln.get("summary", ""))
                            refs = [
                                str(r.get("url", ""))
                                for r in vuln.get("references", [])
                                if isinstance(r, dict) and r.get("url")
                            ]

                            # OSV `/querybatch` returns minimal `{id, modified}` without aliases/summary;
                            # hydrate matched IDs via `/vulns/{id}` (cached in SQLite) so GHSA-* malware
                            # aliases (`MAL-*`) and summaries are never missed.
                            if not aliases and not summary and not refs:
                                details = detail_cache.get(adv_id)
                                if details is None and self.cache is not None:
                                    details = self.cache.get_osv_vuln(adv_id)
                                if details is None:
                                    try:
                                        v_resp = client.get(f"{self.osv_api_url}/vulns/{adv_id}")
                                        if v_resp.status_code == 200:
                                            v_data = v_resp.json()
                                            details = {
                                                "aliases": [str(a) for a in v_data.get("aliases", [])],
                                                "summary": str(
                                                    v_data.get("summary")
                                                    or (v_data.get("details") or "").splitlines()[0]
                                                    if v_data.get("summary") or v_data.get("details")
                                                    else ""
                                                ),
                                                "references": [
                                                    str(r.get("url", ""))
                                                    for r in v_data.get("references", [])
                                                    if isinstance(r, dict) and r.get("url")
                                                ][:5],
                                            }
                                            if self.cache is not None:
                                                self.cache.put_osv_vuln(
                                                    adv_id,
                                                    aliases=list(details["aliases"]),
                                                    summary=str(details["summary"]),
                                                    references=list(details["references"]),
                                                )
                                    except httpx.HTTPError:
                                        details = {}
                                if details is None:
                                    details = {}
                                detail_cache[adv_id] = details
                                aliases = [str(a) for a in details.get("aliases", [])]
                                summary = str(details.get("summary", ""))
                                refs = [str(u) for u in details.get("references", [])]

                            is_mal = adv_id.startswith("MAL-") or any(
                                a.startswith("MAL-") for a in aliases
                            )
                            if not summary and is_mal:
                                summary = "OpenSSF Malicious Packages advisory"
                            results[pkg].append(
                                AdvisoryMatch(
                                    id=adv_id,
                                    source="osv",
                                    summary=summary,
                                    is_malware=is_mal,
                                    aliases=aliases,
                                    references=refs[:3],
                                )
                            )
        except httpx.HTTPError:
            # Offline or transient OSV failure: fall back cleanly to local blocklist + static AST.
            pass

        return results

    def query_one(self, ecosystem: str, name: str, version: str) -> list[AdvisoryMatch]:
        key = (ecosystem, name, version)
        return self.query_batch([key]).get(key, [])
