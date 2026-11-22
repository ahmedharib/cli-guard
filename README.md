# cli-guard (`cg`)

Zero-execution supply-chain malware guard, lockfile auditor, AI investigator, live npm monitor, Bitcoin OpenTimestamps proof ledger, and web dashboard for the JavaScript/npm ecosystem (`npm`, `npx`, `pnpm`, `yarn`, `bun`, `bunx`) — architected with a modular `EcosystemAdapter` layer ready for PyPI (`pip`).

> **Core Security Guarantee:** `cli-guard` unpacks package tarballs strictly **in memory** and **never executes package code** during resolution, static analysis, or AI investigation.

---

## Architecture (4 Layers)

1. **Layer 0 — Instant Gate (`cache.py`, `advisories.py`):**
   * Content-addressed SQLite verdict cache keyed by `(ecosystem, name, version, sha512)`.
   * OSV + OpenSSF `MAL-*` malicious-package batch lookups + local blocklist/allowlist + shared CI publisher safeguards.
   * Configurable release-age cooldown (`CG_COOLDOWN_HOURS=24`).
2. **Layer 1 — Deterministic Tree-sitter AST + Version Diff Engine (`ast_scanner.py`, `differ.py`, `npmrc.py`):**
   * Full `.npmrc` support (default registry, `@scope:registry` mappings, host-scoped `_authToken`/`_auth`, `${ENV_VAR}` expansion without cross-origin token leaks).
   * Tree-sitter JS/TS AST scanner across every file (`exec`, `network`, `sensitive_read`, `dynamic_exec`, `computed_require`, `obfuscation`, `invisible_unicode`, `prompt_injection`, `native_binary`).
   * Static reachability from install scripts (`preinstall`/`install`/`postinstall`/`prepare`), `binding.gyp`, and `bin` entrypoints (`npx`/`pnpm dlx`/`yarn dlx`/`bunx`), explicitly escalating computed `require()`.
   * Automatic previous-version diffing (added install hooks, newly introduced capabilities, maintainer swaps, and SLSA provenance drops).
3. **Layer 2 — Compact Structured LLM Triage (`triage_llm.py`):**
   * Pluggable LLM provider layer defaulting to **Meta Model API** (`https://api.meta.ai/v1`, `muse-spark-1.3`) with drop-in presets for `openai`, `anthropic`, `gemini`, `ollama`, and `custom`.
   * Strict JSON schema output with `<untrusted_package_data>` prompt-injection isolation and automatic reasoning-token retry headroom.
4. **Layer 3 — Read-Only Investigator Agent + Deterministic Claim Verifier (`investigator.py`, `verifier.py`):**
   * Multi-turn analyst agent with read-only tools (`list_files`, `read_lines`, `search_regex`, `get_capabilities`, `get_version_diff`, `static_deobfuscate`, `get_metadata`, `submit_verdict`).
   * Deterministic verifier validates every cited file/line against the in-memory tarball and enforces non-bypassable floors so prompt injections cannot downgrade critical findings to `benign`.

---

## Quick Start

```powershell
# 1. Create virtual environment and install cli-guard
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"

# 2. (Optional) Configure Meta Model API key & GitHub automation
#    Layer 0 + Layer 1 work completely WITHOUT any API key!
Copy-Item .env.example .env
# Edit .env and set MODEL_API_KEY=... (and optionally GITHUB_TOKEN / CG_LEDGER_REPO)

# 3. Inspect configuration & scan packages
.\.venv\Scripts\cg.exe config
.\.venv\Scripts\cg.exe check lodash@4.17.21
.\.venv\Scripts\cg.exe investigate esbuild@0.25.0
.\.venv\Scripts\cg.exe audit .
```

---

## Install Guard (`npm`, `npx`, `pnpm`, `yarn`, `bun`, `bunx`)

```powershell
# Install Windows .cmd (works even under Restricted PowerShell ExecutionPolicy) / POSIX shims
.\.venv\Scripts\cg.exe guard setup

# Safely verify guard blocking using a harmless synthetic local canary
.\.venv\Scripts\cg.exe guard selftest

# Open a guarded shell (shims placed first on PATH)
.\.venv\Scripts\cg.exe guard shell
```

---

## Live npm Monitor, Bitcoin OpenTimestamps Ledger & OpenSSF PRs

`cg monitor` polls `https://replicate.npmjs.com/registry/_changes` (compliant with npm's May 2025 replication API), scans every new publish with Layer 0 + Layer 1, gates LLM escalations by `--min-llm-risk` and `--max-llm-rpm`, preserves cited code excerpts locally before npm deletes malicious tarballs, stamps salted SHA-256 commitments into Bitcoin via **OpenTimestamps**, **automatically upgrades pending `.ots` proofs** on schedule, optionally pushes public commitments to your **`cli-guard-ledger`** GitHub repo, and can automatically open Pull Requests to **`ossf/malicious-packages`**.

```powershell
# Single-batch smoke test
.\.venv\Scripts\cg.exe monitor start --once --batch-limit 10

# Continuous live monitor with auto OTS upgrade, GitHub ledger push, and OpenSSF PRs
.\.venv\Scripts\cg.exe monitor start `
  --min-llm-risk 40 `
  --max-llm-rpm 10 `
  --ots-upgrade-interval 1800 `
  --auto-push-ledger --ledger-repo <owner>/cli-guard-ledger `
  --auto-openssf-pr

# Ledger & proof verification commands
.\.venv\Scripts\cg.exe ledger list
.\.venv\Scripts\cg.exe ledger show <finding_id>
.\.venv\Scripts\cg.exe ledger upgrade
.\.venv\Scripts\cg.exe ledger push --repo <owner>/cli-guard-ledger
.\.venv\Scripts\cg.exe ledger submit-openssf <finding_id> --dry-run
.\.venv\Scripts\cg.exe ledger reveal <finding_id>
.\.venv\Scripts\cg.exe ledger verify <proof.ots> <reveal.json>
```

> **Privacy Guarantee:** `ledger.jsonl` and `.ots` files use opaque finding IDs and salted `SHA-256(salt || canonical_json)` commitments. Private salts in `ledger_secrets/` are **never** pushed to GitHub.

---

## Retrospective Ground-Truth Verification

Run **24h, 72h, and 7 days** after scanning live packages (OSV `MAL-*` advisories and npm `0.0.1-security` takedowns typically lag initial malware publishes by hours to days):

```powershell
.\.venv\Scripts\python.exe scripts\verify_ground_truth.py --auto-reveal
# or equivalently:
.\.venv\Scripts\cg.exe monitor verify-truth --auto-reveal
```

Outputs timestamped JSON and Markdown showcase reports under `~/.cli-guard/reports/` with exact lead times (`official_time - our_detected_at`), precision/recall, and Bitcoin block confirmation status.

---

## Live & Hosted Web Dashboard

View live monitor logs, preserved code excerpts, Bitcoin OpenTimestamps proofs, scanned packages, and run interactive checks:

```powershell
# Start live local dashboard server
.\.venv\Scripts\cg.exe dashboard serve --host 127.0.0.1 --port 8787

# Export static snapshot for GitHub Pages (`docs/index.html` + `docs/snapshot.json`)
.\.venv\Scripts\cg.exe dashboard export --out docs
```

This repository also includes [`.github/workflows/pages.yml`](.github/workflows/pages.yml) so enabling **Settings → Pages → Source: GitHub Actions** automatically hosts the web dashboard on GitHub Pages.

---

## GitHub Action (`action.yml`)

Use `cli-guard` in CI to audit lockfiles, push salted commitments to `cli-guard-ledger`, and automatically open OpenSSF `malicious-packages` PRs when malware is detected:

```yaml
- name: Run cli-guard
  uses: <owner>/cli-guard@main
  with:
    mode: monitor-batch # or `audit` / `check`
    llm-provider: meta
    model-api-key: ${{ secrets.MODEL_API_KEY }}
    github-token: ${{ secrets.CG_GITHUB_TOKEN }}
    ledger-repo: <owner>/cli-guard-ledger
    auto-push-ledger: "true"
    auto-openssf-pr: "true"
    export-dashboard-dir: docs
```

---

## Switching LLM Providers

```powershell
cg check some-pkg --provider meta --model muse-spark-1.3
cg check some-pkg --provider openai --model gpt-4o-mini
cg check some-pkg --provider anthropic --model claude-3-5-haiku-latest
cg check some-pkg --provider gemini --model gemini-2.5-flash
cg check some-pkg --provider ollama --model qwen2.5-coder:7b
```
