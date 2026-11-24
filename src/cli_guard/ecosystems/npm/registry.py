"""Zero-execution npm registry client and safe in-memory tarball unpacker."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import posixpath
import tarfile
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from cli_guard.ecosystems.base import InMemoryArchive
from cli_guard.ecosystems.npm.npmrc import NpmrcConfig
from cli_guard.ecosystems.npm.semver_npm import find_previous_version, resolve_version
from cli_guard.models import PackageMetadata, PackageSpec

TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".json",
        ".gyp",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".cmd",
        ".bat",
        ".py",
        ".rb",
        ".pl",
        ".md",
        ".txt",
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
        ".cfg",
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
        ".rs",
        ".go",
    }
)

BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".node",
        ".wasm",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".o",
        ".a",
        ".lib",
        ".pyc",
        ".jar",
    }
)


class RegistryError(RuntimeError):
    """Raised when registry lookup or safe archive extraction fails."""


def _parse_iso_datetime(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        cleaned = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def _extract_maintainers(obj: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for entry in obj.get("maintainers") or []:
        if isinstance(entry, dict):
            name = entry.get("name") or entry.get("email") or ""
            if name:
                out.append(str(name))
        elif isinstance(entry, str):
            out.append(entry)
    return out


def _normalize_bin(pkg_name: str, raw_bin: Any) -> dict[str, str]:
    if isinstance(raw_bin, str):
        short = pkg_name.split("/")[-1]
        return {short: raw_bin.lstrip("./")}
    if isinstance(raw_bin, dict):
        return {str(k): str(v).lstrip("./") for k, v in raw_bin.items() if v}
    return {}


def _extract_repo_url(raw_repo: Any) -> str | None:
    if isinstance(raw_repo, str):
        return raw_repo
    if isinstance(raw_repo, dict):
        url = raw_repo.get("url")
        return str(url) if url else None
    return None


def _has_provenance(ver_doc: dict[str, Any]) -> bool:
    dist = ver_doc.get("dist") or {}
    if dist.get("attestations"):
        return True
    # Older / alternate field layouts
    if ver_doc.get("_attestations"):
        return True
    return False


def unpack_tarball_bytes(
    raw_bytes: bytes,
    *,
    max_extracted_bytes: int = 100 * 1024 * 1024,
    max_files: int = 5000,
) -> InMemoryArchive:
    """Safely extract an npm `.tgz` archive strictly in memory (zip-bomb & traversal safe)."""
    archive = InMemoryArchive()
    total_bytes = 0
    file_count = 0

    try:
        with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    # Ignore symlinks, hardlinks, FIFOs, devices, directories
                    continue

                file_count += 1
                if file_count > max_files:
                    raise RegistryError(f"Tarball exceeds max file count ({max_files}).")

                if member.size < 0 or (total_bytes + member.size) > max_extracted_bytes:
                    raise RegistryError(
                        f"Tarball exceeds max uncompressed size ({max_extracted_bytes} bytes)."
                    )

                raw_name = member.name.replace("\\", "/")
                norm = posixpath.normpath(raw_name).lstrip("/")
                if norm.startswith("..") or "/../" in f"/{norm}/":
                    # Reject path traversal entries silently or raise
                    raise RegistryError(f"Unsafe path traversal entry in tarball: {member.name}")

                # Strip standard npm `package/` root prefix
                if "/" in norm:
                    top, rest = norm.split("/", 1)
                    rel_path = rest if top == "package" else norm
                else:
                    rel_path = norm

                if not rel_path or rel_path == ".":
                    continue

                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                content = extracted.read(member.size + 1)
                total_bytes += len(content)
                archive.file_sizes[rel_path] = len(content)

                ext = posixpath.splitext(rel_path)[1].lower()
                is_known_binary = ext in BINARY_EXTENSIONS or b"\x00" in content[:2048]
                if is_known_binary:
                    archive.binary_files.append(rel_path)
                    continue

                if ext in TEXT_EXTENSIONS or len(content) <= 512 * 1024:
                    try:
                        archive.text_files[rel_path] = content.decode("utf-8", errors="replace")
                    except Exception:
                        archive.binary_files.append(rel_path)
    except tarfile.TarError as exc:
        raise RegistryError(f"Corrupt or unsupported tarball archive: {exc}") from exc

    return archive


def verify_tarball_integrity(raw: bytes, expected_integrity: str) -> None:
    """Verify downloaded tarball bytes match npm SRI (`sha512-...`) or 40-char hex `shasum`."""
    cleaned = expected_integrity.strip()
    if not cleaned:
        return
    # Support space-separated SRI tokens (e.g. `sha512-... sha1-...`) or legacy hex sha1 shasum
    for token in cleaned.split():
        if "-" in token:
            algo, b64_expected = token.split("-", 1)
            algo_l = algo.lower()
            if algo_l in {"sha512", "sha384", "sha256", "sha1"}:
                digest = getattr(hashlib, algo_l)(raw).digest()
                actual_b64 = base64.b64encode(digest).decode("ascii")
                if not hmac.compare_digest(actual_b64, b64_expected):
                    raise RegistryError(
                        f"Tarball integrity mismatch ({algo_l}): expected {token}, got {algo_l}-{actual_b64}"
                    )
                return
        elif len(token) == 40 and all(c in "0123456789abcdefABCDEF" for c in token):
            actual_hex = hashlib.sha1(raw).hexdigest()
            if not hmac.compare_digest(actual_hex.lower(), token.lower()):
                raise RegistryError(
                    f"Tarball shasum mismatch: expected {token}, got {actual_hex}"
                )
            return


class NpmRegistryClient:
    """HTTP client for npm registry packuments and in-memory tarball downloads (with `.npmrc` support)."""

    def __init__(
        self,
        registry_url: str = "https://registry.npmjs.org",
        *,
        npmrc: NpmrcConfig | None = None,
        timeout: float = 30.0,
        max_tarball_bytes: int = 50 * 1024 * 1024,
        max_extracted_bytes: int = 100 * 1024 * 1024,
        max_extracted_files: int = 5000,
    ) -> None:
        self.npmrc = npmrc or NpmrcConfig.load(
            registry_override=(
                registry_url if registry_url.rstrip("/") != "https://registry.npmjs.org" else None
            )
        )
        self.registry_url = self.npmrc.default_registry.rstrip("/")
        self.timeout = timeout
        self.max_tarball_bytes = max_tarball_bytes
        self.max_extracted_bytes = max_extracted_bytes
        self.max_extracted_files = max_extracted_files
        self._packument_cache: dict[str, dict[str, Any]] = {}

    def _package_url(self, name: str) -> str:
        # Honor scoped `@org:registry` mappings from `.npmrc`
        base = self.npmrc.registry_for_package(name)
        encoded = quote(name, safe="@")
        return f"{base}/{encoded}"

    def _headers_for(self, url: str, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = dict(extra or {})
        headers.update(self.npmrc.auth_headers_for_url(url))
        return headers

    def _client(self, *, timeout: float | None = None, url: str = "") -> httpx.Client:
        # Bypass environment proxies for local loopback test registries while honoring `.npmrc` proxy/CA
        is_loopback = url.startswith(("http://127.0.0.1", "http://localhost"))
        kwargs: dict[str, Any] = {
            "timeout": timeout or self.timeout,
            "follow_redirects": True,
            "verify": self.npmrc.httpx_verify(),
        }
        if is_loopback:
            kwargs["trust_env"] = False
        elif self.npmrc.httpx_proxy():
            kwargs["proxy"] = self.npmrc.httpx_proxy()
        return httpx.Client(**kwargs)

    def fetch_packument(self, name: str) -> dict[str, Any]:
        if name in self._packument_cache:
            return self._packument_cache[name]
        url = self._package_url(name)
        try:
            with self._client(url=url) as client:
                resp = client.get(url, headers=self._headers_for(url, {"Accept": "application/json"}))
        except httpx.HTTPError as exc:
            raise RegistryError(f"Failed fetching npm metadata for '{name}': {exc}") from exc

        if resp.status_code == 404:
            raise RegistryError(f"Package '{name}' not found on npm registry.")
        if resp.status_code >= 400:
            raise RegistryError(
                f"Registry error {resp.status_code} for '{name}': {resp.text[:200]}"
            )
        doc = resp.json()
        self._packument_cache[name] = doc
        return doc

    def package_exists(self, name: str) -> bool | None:
        """Check whether a package exists on the configured npm registry (None if network error)."""
        if name in self._packument_cache:
            return True
        url = self._package_url(name)
        try:
            with self._client(timeout=min(10.0, self.timeout), url=url) as client:
                resp = client.head(url, headers=self._headers_for(url))
                if resp.status_code == 405:
                    resp = client.get(
                        url,
                        headers=self._headers_for(
                            url, {"Accept": "application/vnd.npm.install-v1+json"}
                        ),
                    )
            if resp.status_code == 200:
                return True
            if resp.status_code == 404:
                return False
            return None
        except httpx.HTTPError:
            return None

    def fetch_metadata(self, spec: PackageSpec) -> PackageMetadata:
        packument = self.fetch_packument(spec.name)
        versions_map: dict[str, Any] = packument.get("versions") or {}
        dist_tags: dict[str, str] = packument.get("dist-tags") or {}
        times_map: dict[str, str] = packument.get("time") or {}

        resolved_ver = resolve_version(list(versions_map.keys()), dist_tags, spec.version)
        if not resolved_ver or resolved_ver not in versions_map:
            raise RegistryError(
                f"Could not resolve version '{spec.version or 'latest'}' for '{spec.name}'."
            )

        ver_doc: dict[str, Any] = versions_map[resolved_ver]
        dist = ver_doc.get("dist") or {}

        pub_dt = _parse_iso_datetime(times_map.get(resolved_ver))
        age_hours: float | None = None
        if pub_dt is not None:
            age_hours = max(0.0, (datetime.now(UTC) - pub_dt).total_seconds() / 3600.0)

        prev_ver = find_previous_version(list(versions_map.keys()), resolved_ver, times_map)
        prev_doc = versions_map.get(prev_ver, {}) if prev_ver else {}
        prev_dist = prev_doc.get("dist") or {}

        npm_user = ver_doc.get("_npmUser")
        publisher = (
            str(npm_user.get("name"))
            if isinstance(npm_user, dict) and npm_user.get("name")
            else None
        )

        maintainers = _extract_maintainers(ver_doc) or _extract_maintainers(packument)
        prev_maintainers = _extract_maintainers(prev_doc)

        scripts = {
            str(k): str(v)
            for k, v in (ver_doc.get("scripts") or {}).items()
            if isinstance(v, str)
        }
        deps = {
            str(k): str(v)
            for k, v in (ver_doc.get("dependencies") or {}).items()
            if isinstance(v, str)
        }
        opt_deps = {
            str(k): str(v)
            for k, v in (ver_doc.get("optionalDependencies") or {}).items()
            if isinstance(v, str)
        }
        peer_meta = ver_doc.get("peerDependenciesMeta") or {}
        peer_deps = {
            str(k): str(v)
            for k, v in (ver_doc.get("peerDependencies") or {}).items()
            if isinstance(v, str)
            and not (isinstance(peer_meta.get(k), dict) and peer_meta[k].get("optional"))
        }

        return PackageMetadata(
            ecosystem="npm",
            name=spec.name,
            version=resolved_ver,
            tarball_url=str(dist.get("tarball") or ""),
            integrity=str(dist.get("integrity") or dist.get("shasum") or ""),
            published_at=pub_dt,
            age_hours=age_hours,
            previous_version=prev_ver,
            previous_tarball_url=str(prev_dist.get("tarball") or "") or None,
            maintainers=maintainers,
            previous_maintainers=prev_maintainers,
            publisher=publisher,
            has_provenance=_has_provenance(ver_doc),
            previous_has_provenance=_has_provenance(prev_doc) if prev_ver else False,
            repository_url=_extract_repo_url(ver_doc.get("repository") or packument.get("repository")),
            scripts=scripts,
            bin_entries=_normalize_bin(spec.name, ver_doc.get("bin")),
            dependencies=deps,
            optional_dependencies=opt_deps,
            peer_dependencies=peer_deps,
            deprecated=str(ver_doc["deprecated"]) if ver_doc.get("deprecated") else None,
        )

    def download_tarball(
        self,
        tarball_url: str,
        *,
        expected_integrity: str = "",
    ) -> InMemoryArchive:
        if not tarball_url:
            raise RegistryError("Missing tarball URL in package metadata.")
        try:
            with self._client(url=tarball_url) as client:
                with client.stream("GET", tarball_url, headers=self._headers_for(tarball_url)) as resp:
                    if resp.status_code >= 400:
                        raise RegistryError(
                            f"Failed downloading tarball ({resp.status_code}): {tarball_url}"
                        )
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in resp.iter_bytes():
                        total += len(chunk)
                        if total > self.max_tarball_bytes:
                            raise RegistryError(
                                f"Tarball exceeds max download size ({self.max_tarball_bytes} bytes)."
                            )
                        chunks.append(chunk)
                    raw = b"".join(chunks)
        except httpx.HTTPError as exc:
            raise RegistryError(f"HTTP error downloading tarball {tarball_url}: {exc}") from exc

        if expected_integrity:
            verify_tarball_integrity(raw, expected_integrity)

        return unpack_tarball_bytes(
            raw,
            max_extracted_bytes=self.max_extracted_bytes,
            max_files=self.max_extracted_files,
        )
