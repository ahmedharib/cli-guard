"""Tests for npm SemVer range evaluation and spec parsing."""

from cli_guard.ecosystems.npm.resolver import is_external_dep_spec, parse_npm_spec
from cli_guard.ecosystems.npm.semver_npm import (
    find_previous_version,
    resolve_version,
    satisfies,
)


def test_semver_satisfies_ranges() -> None:
    assert satisfies("4.17.21", "^4.17.0")
    assert not satisfies("5.0.0", "^4.17.0")
    assert satisfies("0.2.5", "^0.2.1")
    assert not satisfies("0.3.0", "^0.2.1")
    assert satisfies("1.2.9", "~1.2.3")
    assert not satisfies("1.3.0", "~1.2.3")
    assert satisfies("1.5.0", "1.2.0 - 2.0.0")
    assert satisfies("2.1.0", "^1.0.0 || ^2.0.0")
    assert satisfies("3.4.5", "3.4.x")
    assert not satisfies("2.0.0-alpha.1", "^1.0.0 || ^2.0.0")
    assert satisfies("2.0.0-alpha.2", ">=2.0.0-alpha.1")


def test_resolve_and_previous_version() -> None:
    versions = ["1.0.0", "1.1.0", "1.2.0-beta.1", "1.2.0", "1.2.1", "2.0.0"]
    dist_tags = {"latest": "1.2.1", "next": "2.0.0"}
    assert resolve_version(versions, dist_tags, None) == "1.2.1"
    assert resolve_version(versions, dist_tags, "^1.0.0") == "1.2.1"
    assert resolve_version(versions, dist_tags, "next") == "2.0.0"
    assert find_previous_version(versions, "1.2.1") == "1.2.0"
    assert find_previous_version(versions, "1.2.0") == "1.1.0"


def test_parse_npm_specs() -> None:
    s1 = parse_npm_spec("lodash@^4.17.21")
    assert s1.name == "lodash" and s1.version == "^4.17.21" and s1.spec_kind == "registry"

    s2 = parse_npm_spec("@types/node@22.0.0")
    assert s2.name == "@types/node" and s2.version == "22.0.0"

    s3 = parse_npm_spec("my-alias@npm:chalk@5.3.0")
    assert s3.name == "chalk" and s3.version == "5.3.0" and s3.spec_kind == "alias"

    s4 = parse_npm_spec("https://evil.example.com/backdoor.tgz")
    assert s4.spec_kind == "tarball_url"
    assert is_external_dep_spec("git+https://github.com/user/repo.git")
    assert is_external_dep_spec("user/repo#main")
    assert not is_external_dep_spec("^4.17.21")
