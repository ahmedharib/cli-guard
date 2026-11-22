"""Abstract ecosystem adapter contract shared across npm and future ecosystems (e.g., PyPI)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from cli_guard.models import (
    CapabilitySummary,
    PackageMetadata,
    PackageSpec,
    VersionDiff,
)


@dataclass(slots=True)
class InMemoryArchive:
    """Strictly in-memory representation of an extracted package archive (never written to disk)."""

    text_files: dict[str, str] = field(default_factory=dict)
    binary_files: list[str] = field(default_factory=list)
    file_sizes: dict[str, int] = field(default_factory=dict)

    @property
    def line_counts(self) -> dict[str, int]:
        return {path: len(text.splitlines()) for path, text in self.text_files.items()}


class EcosystemAdapter(ABC):
    """Base contract implemented by each package ecosystem (`npm`, future `pypi`)."""

    ecosystem_name: str = "base"

    @abstractmethod
    def parse_spec(self, raw: str, *, is_exec_target: bool = False) -> PackageSpec:
        """Parse a raw CLI package spec (e.g. `lodash@^4.17.0`, `@scope/pkg@1.0.0`)."""

    @abstractmethod
    def fetch_metadata(self, spec: PackageSpec) -> PackageMetadata:
        """Fetch registry metadata for the resolved package version without running code."""

    @abstractmethod
    def download_archive(self, metadata: PackageMetadata) -> InMemoryArchive:
        """Download and safely unpack package archive strictly in memory."""

    @abstractmethod
    def scan_archive(
        self,
        metadata: PackageMetadata,
        archive: InMemoryArchive,
        *,
        is_exec_target: bool = False,
    ) -> CapabilitySummary:
        """Run static AST capability & reachability scanning over the archive."""

    @abstractmethod
    def compute_version_diff(
        self,
        metadata: PackageMetadata,
        current_archive: InMemoryArchive,
        current_caps: CapabilitySummary,
    ) -> VersionDiff | None:
        """Compare against the previous published version when available."""

    @abstractmethod
    def detect_typosquat(self, name: str) -> list[str]:
        """Return popular packages that `name` may be impersonating."""

    @abstractmethod
    def detect_phantom_and_external_deps(
        self, metadata: PackageMetadata
    ) -> tuple[list[str], list[str]]:
        """Return (phantom_missing_deps, external_non_registry_deps)."""
