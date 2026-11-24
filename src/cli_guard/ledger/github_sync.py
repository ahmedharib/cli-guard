"""GitHub automation: public `cli-guard-ledger` commitment sync & OpenSSF malicious-packages PRs."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from cli_guard import __version__
from cli_guard.ledger.store import FindingsLedgerStore

GITHUB_API_BASE = "https://api.github.com"


class GitHubSyncError(RuntimeError):
    """Raised when GitHub API operations fail or credentials are missing."""


@dataclass(slots=True)
class LedgerSyncResult:
    repo: str
    uploaded_files: list[str] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class OpenSSFPRResult:
    finding_id: str
    package: str
    version: str
    upstream_repo: str
    fork_repo: str
    branch: str
    report_path: str
    dry_run: bool = False
    pr_url: str | None = None
    pr_number: int | None = None
    pr_title: str = ""
    pr_body: str = ""


def _gh_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": f"cli-guard/{__version__}",
    }


def _put_github_file(
    client: httpx.Client,
    *,
    repo: str,
    path: str,
    content_bytes: bytes,
    message: str,
    branch: str | None = None,
) -> dict[str, Any]:
    """Create or update a file via GitHub Contents API (idempotent via existing blob SHA)."""
    url = f"{GITHUB_API_BASE}/repos/{repo}/contents/{path}"
    params = {"ref": branch} if branch else None
    existing_sha: str | None = None

    get_resp = client.get(url, params=params)
    if get_resp.status_code == 200:
        data = get_resp.json()
        existing_sha = data.get("sha")
        existing_b64 = (data.get("content") or "").replace("\n", "")
        if existing_b64 and base64.b64encode(content_bytes).decode("ascii") == existing_b64:
            return {"unchanged": True, "path": path}
    elif get_resp.status_code not in {404}:
        raise GitHubSyncError(
            f"GitHub GET {url} failed ({get_resp.status_code}): {get_resp.text[:300]}"
        )

    payload: dict[str, Any] = {
        "message": message,
        "content": base64.b64encode(content_bytes).decode("ascii"),
    }
    if existing_sha:
        payload["sha"] = existing_sha
    if branch:
        payload["branch"] = branch

    put_resp = client.put(url, json=payload)
    if put_resp.status_code not in {200, 201}:
        raise GitHubSyncError(
            f"GitHub PUT {url} failed ({put_resp.status_code}): {put_resp.text[:300]}"
        )
    return put_resp.json()


def ensure_public_ledger_repo(
    token: str,
    repo: str,
    *,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Verify `owner/cli-guard-ledger` exists on GitHub, creating it publicly under the authed user if missing."""
    headers = _gh_headers(token)
    with httpx.Client(headers=headers, timeout=timeout) as client:
        check = client.get(f"{GITHUB_API_BASE}/repos/{repo}")
        if check.status_code == 200:
            return check.json()
        if check.status_code != 404:
            raise GitHubSyncError(
                f"Could not access repo `{repo}` ({check.status_code}): {check.text[:300]}"
            )

        repo_name = repo.split("/")[-1]
        create_resp = client.post(
            f"{GITHUB_API_BASE}/user/repos",
            json={
                "name": repo_name,
                "description": "Public timestamped salted SHA-256 commitment ledger and Bitcoin OpenTimestamps proofs from cli-guard.",
                "private": False,
                "auto_init": True,
            },
        )
        if create_resp.status_code not in {200, 201}:
            raise GitHubSyncError(
                f"Failed creating public ledger repo `{repo}` ({create_resp.status_code}): {create_resp.text[:300]}"
            )
        return create_resp.json()


def push_ledger_to_github(
    ledger: FindingsLedgerStore,
    *,
    repo: str,
    token: str,
    auto_create: bool = True,
    timeout: float = 25.0,
    settings: Any | None = None,
    include_public_snapshot: bool = True,
) -> LedgerSyncResult:
    """Push ONLY public commitment ledger, `.ots` proofs, revealed proofs, and optional public-safe snapshot to GitHub.

    Hard safety guarantee: NEVER touches `ledger_secrets/` or unrevealed private findings.
    """
    if not token:
        raise GitHubSyncError("GITHUB_TOKEN is required to push commitments to GitHub.")
    if not repo or "/" not in repo:
        raise GitHubSyncError("`repo` must be in `owner/repo` format (e.g. `user/cli-guard-ledger`).")

    if auto_create:
        ensure_public_ledger_repo(token, repo, timeout=timeout)

    result = LedgerSyncResult(repo=repo)
    files_to_sync: list[tuple[str, Path, str]] = []

    if ledger.ledger_path.exists():
        files_to_sync.append(
            ("ledger.jsonl", ledger.ledger_path, "chore(ledger): update salted commitment ledger")
        )
    for ots_file in sorted(ledger.ots_dir.glob("*.ots")):
        files_to_sync.append(
            (f"ots/{ots_file.name}", ots_file, f"chore(ots): add/upgrade Bitcoin proof {ots_file.name}")
        )
    for reveal_file in sorted(ledger.reveals_dir.glob("*.reveal.json")):
        files_to_sync.append(
            (
                f"reveals/{reveal_file.name}",
                reveal_file,
                f"feat(reveal): publish verified disclosure {reveal_file.name}",
            )
        )

    inline_uploads: list[tuple[str, bytes, str]] = []
    if include_public_snapshot and settings is not None:
        from cli_guard.dashboard.server import build_dashboard_snapshot

        snap = build_dashboard_snapshot(settings, public_safe=True)
        # Ensure remote snapshot always links back to this public ledger repo
        if not snap.get("ledger_repo"):
            snap["ledger_repo"] = repo
        inline_uploads.append(
            (
                "public_snapshot.json",
                json.dumps(snap, indent=2).encode("utf-8"),
                "chore(showcase): update public-safe dashboard snapshot",
            )
        )

    headers = _gh_headers(token)
    with httpx.Client(headers=headers, timeout=timeout) as client:
        for remote_path, local_path, commit_msg in files_to_sync:
            # Explicit hard guard against leaking private secrets
            if "ledger_secrets" in str(local_path) or local_path.name.endswith(".secret.json"):
                result.errors.append(f"Blocked unsafe upload attempt: {local_path}")
                continue
            try:
                resp = _put_github_file(
                    client,
                    repo=repo,
                    path=remote_path,
                    content_bytes=local_path.read_bytes(),
                    message=commit_msg,
                )
                if resp.get("unchanged"):
                    result.skipped_files.append(remote_path)
                else:
                    result.uploaded_files.append(remote_path)
            except Exception as exc:
                result.errors.append(f"{remote_path}: {exc}")

        for remote_path, payload_bytes, commit_msg in inline_uploads:
            try:
                resp = _put_github_file(
                    client,
                    repo=repo,
                    path=remote_path,
                    content_bytes=payload_bytes,
                    message=commit_msg,
                )
                if resp.get("unchanged"):
                    result.skipped_files.append(remote_path)
                else:
                    result.uploaded_files.append(remote_path)
            except Exception as exc:
                result.errors.append(f"{remote_path}: {exc}")

    return result


def build_openssf_pr_artifacts(
    ledger: FindingsLedgerStore,
    finding_id: str,
) -> tuple[str, str, str, dict[str, Any]]:
    """Build (repo_relative_path, pr_title, pr_body, osv_dict) for an OpenSSF malicious-packages PR."""
    fdata = ledger.load_finding(finding_id)
    if not fdata:
        raise FileNotFoundError(f"Finding `{finding_id}` not found.")

    osv_doc = ledger.export_openssf_malicious_package(finding_id)
    rep = fdata["report"]
    pkg_name = str(rep["name"])
    version = str(rep["version"])

    # OpenSSF malicious-packages path convention: osv/malicious/npm/<pkg>/MAL-0000-<id>.json
    safe_pkg_dir = pkg_name.strip("/")
    rel_path = f"osv/malicious/npm/{safe_pkg_dir}/MAL-0000-{finding_id}.json"

    pr_title = f"Malicious npm package: {pkg_name}@{version}"

    citations_md = ""
    verif = rep.get("verification") or {}
    valid_cits = verif.get("valid_citations") or []
    if valid_cits:
        citations_md = "\n".join(
            f"- `{c['file']}:{c['start_line']}-{c['end_line']}` — {c.get('reason', '')}"
            for c in valid_cits[:8]
        )
    else:
        citations_md = "- Detected via deterministic Layer 1 AST/static signals."

    excerpts = (rep.get("extra") or {}).get("cited_excerpts") or []
    excerpt_md = ""
    if excerpts:
        first = excerpts[0]
        excerpt_md = (
            f"\n### Key Preserved Excerpt (`{first.get('file')}:{first.get('start_line')}`)\n"
            f"```js\n{str(first.get('excerpt', ''))[:1200]}\n```\n"
        )

    pr_body = (
        f"## Malicious Package Report (cli-guard)\n\n"
        f"- **Ecosystem:** `npm`\n"
        f"- **Package:** `{pkg_name}`\n"
        f"- **Version:** `{version}`\n"
        f"- **Integrity:** `{rep.get('integrity') or 'n/a'}`\n"
        f"- **Detected At (UTC):** `{fdata.get('detected_at_utc')}`\n"
        f"- **Risk Score:** `{rep.get('risk_score')}/100` (`{rep.get('verdict')}`)\n"
        f"- **Salted Commitment (SHA-256 / Bitcoin OTS):** `{fdata.get('commitment_sha256')}`\n\n"
        f"### Summary\n{rep.get('summary')}\n\n"
        f"### Verified Evidence Citations\n{citations_md}\n"
        f"{excerpt_md}\n"
        f"*Generated automatically by `cli-guard` (`cg`) without executing package code.*"
    )
    return rel_path, pr_title, pr_body, osv_doc


def submit_openssf_pr(
    ledger: FindingsLedgerStore,
    finding_id: str,
    *,
    token: str | None,
    upstream_repo: str = "ossf/malicious-packages",
    fork_repo: str | None = None,
    dry_run: bool = False,
    timeout: float = 25.0,
) -> OpenSSFPRResult:
    """Open a Pull Request submitting an OSV malicious-package report to OpenSSF (or configured repo)."""
    rel_path, pr_title, pr_body, osv_doc = build_openssf_pr_artifacts(ledger, finding_id)
    fdata = ledger.load_finding(finding_id)
    assert fdata is not None
    rep = fdata["report"]
    pkg_name = str(rep["name"])
    version = str(rep["version"])
    branch_name = f"cg-report/{finding_id}"

    if dry_run:
        return OpenSSFPRResult(
            finding_id=finding_id,
            package=pkg_name,
            version=version,
            upstream_repo=upstream_repo,
            fork_repo=fork_repo or "<authed-user>/malicious-packages",
            branch=branch_name,
            report_path=rel_path,
            dry_run=True,
            pr_title=pr_title,
            pr_body=pr_body,
        )

    if not token:
        raise GitHubSyncError("GITHUB_TOKEN is required to submit an OpenSSF Pull Request.")

    headers = _gh_headers(token)
    with httpx.Client(headers=headers, timeout=timeout) as client:
        # 1. Identify authenticated GitHub user
        me_resp = client.get(f"{GITHUB_API_BASE}/user")
        if me_resp.status_code != 200:
            raise GitHubSyncError(
                f"Failed authenticating GitHub user ({me_resp.status_code}): {me_resp.text[:250]}"
            )
        username = str(me_resp.json()["login"])

        # 2. Fetch upstream default branch & HEAD SHA
        up_resp = client.get(f"{GITHUB_API_BASE}/repos/{upstream_repo}")
        if up_resp.status_code != 200:
            raise GitHubSyncError(
                f"Could not read upstream repo `{upstream_repo}` ({up_resp.status_code})"
            )
        default_branch = str(up_resp.json().get("default_branch") or "main")

        ref_resp = client.get(
            f"{GITHUB_API_BASE}/repos/{upstream_repo}/git/ref/heads/{default_branch}"
        )
        if ref_resp.status_code != 200:
            raise GitHubSyncError(
                f"Could not read upstream branch `{default_branch}` ({ref_resp.status_code})"
            )
        base_sha = str(ref_resp.json()["object"]["sha"])

        # 3. Determine fork repo (use upstream directly if user owns it, otherwise fork)
        upstream_owner, upstream_name = upstream_repo.split("/", 1)
        target_fork = fork_repo
        if not target_fork:
            if upstream_owner.lower() == username.lower():
                target_fork = upstream_repo
            else:
                target_fork = f"{username}/{upstream_name}"
                fork_check = client.get(f"{GITHUB_API_BASE}/repos/{target_fork}")
                if fork_check.status_code == 404:
                    fork_create = client.post(f"{GITHUB_API_BASE}/repos/{upstream_repo}/forks")
                    if fork_create.status_code not in {200, 201, 202}:
                        raise GitHubSyncError(
                            f"Failed creating fork of `{upstream_repo}` ({fork_create.status_code}): {fork_create.text[:250]}"
                        )

        # 4. Create report branch on fork
        br_resp = client.post(
            f"{GITHUB_API_BASE}/repos/{target_fork}/git/refs",
            json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
        )
        if br_resp.status_code not in {200, 201, 422}:
            raise GitHubSyncError(
                f"Failed creating branch `{branch_name}` on `{target_fork}` ({br_resp.status_code}): {br_resp.text[:250]}"
            )

        # 5. Commit OSV JSON report onto the branch
        _put_github_file(
            client,
            repo=target_fork,
            path=rel_path,
            content_bytes=(json.dumps(osv_doc, indent=2) + "\n").encode("utf-8"),
            message=f"Add malicious package report for npm/{pkg_name}@{version}",
            branch=branch_name,
        )

        # 6. Open PR against upstream
        fork_owner = target_fork.split("/", 1)[0]
        head_ref = branch_name if target_fork == upstream_repo else f"{fork_owner}:{branch_name}"
        pr_resp = client.post(
            f"{GITHUB_API_BASE}/repos/{upstream_repo}/pulls",
            json={
                "title": pr_title,
                "body": pr_body,
                "head": head_ref,
                "base": default_branch,
            },
        )
        if pr_resp.status_code not in {200, 201}:
            raise GitHubSyncError(
                f"Failed opening PR against `{upstream_repo}` ({pr_resp.status_code}): {pr_resp.text[:300]}"
            )
        pr_data = pr_resp.json()

        return OpenSSFPRResult(
            finding_id=finding_id,
            package=pkg_name,
            version=version,
            upstream_repo=upstream_repo,
            fork_repo=target_fork,
            branch=branch_name,
            report_path=rel_path,
            dry_run=False,
            pr_url=str(pr_data.get("html_url") or ""),
            pr_number=int(pr_data["number"]) if pr_data.get("number") is not None else None,
            pr_title=pr_title,
            pr_body=pr_body,
        )
