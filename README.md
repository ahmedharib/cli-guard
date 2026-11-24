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

## Install Guard, Open-Source / API Setup & AI Agents

```powershell
# Install Windows .cmd (works even under Restricted PowerShell ExecutionPolicy) / POSIX shims
.\.venv\Scripts\cg.exe guard setup

# Plug in an open-source local model, free open-weight API, paid API, or static-only mode:
.\.venv\Scripts\cg.exe config set --provider ollama --model qwen2.5-coder:7b
.\.venv\Scripts\cg.exe config set --provider llamacpp --base-url http://localhost:8080/v1
.\.venv\Scripts\cg.exe config set --provider openrouter --api-key sk-or-...
.\.venv\Scripts\cg.exe config set --provider static
# Or configure interactively while installing shims:
.\.venv\Scripts\cg.exe guard setup --configure

# Safely verify guard blocking using a harmless synthetic local canary
.\.venv\Scripts\cg.exe guard selftest

# Open a guarded shell (shims placed first on PATH)
.\.venv\Scripts\cg.exe guard shell

# Security-audit currently installed packages (no lockfile required)
.\.venv\Scripts\cg.exe audit --installed .
.\.venv\Scripts\cg.exe audit --global

# AI Agent Integration (MCP stdio server for Claude Code, Cursor, Antigravity, Codex)
.\.venv\Scripts\cg.exe agent setup
.\.venv\Scripts\cg.exe mcp
```

---

## Operator npm Monitor, Bitcoin OpenTimestamps Ledger & OpenSSF PRs

`cg monitor` is **operator and research infrastructure** (not an end-user web tool): it polls `https://replicate.npmjs.com/registry/_changes` (compliant with npm's May 2025 replication API), automatically fast-forwards stale checkpoints to live publishes (unless `--backfill` is passed), scans newly published releases with Layer 0 + Layer 1 (verifying tarball SHA-512/SHA-1 integrity in memory), gates LLM escalations by `--min-llm-risk` and `--max-llm-rpm`, preserves cited code excerpts locally before npm deletes malicious tarballs, stamps salted SHA-256 commitments into Bitcoin via **OpenTimestamps**, **automatically upgrades pending `.ots` proofs** and runs periodic **ground-truth checks** inside the loop, pushes public commitments + a redacted `public_snapshot.json` to your **`cli-guard-ledger`** GitHub repo (updating the GitHub Pages showcase live without manual commits to `main`), and submits Pull Requests to **`ossf/malicious-packages`** only for confirmed `malicious` packages.

```powershell
# Single-batch smoke test
.\.venv\Scripts\cg.exe monitor start --once --batch-limit 10

# Continuous live monitor (auto-jumps stale checkpoints, upgrades OTS, checks ground truth, syncs live showcase)
.\.venv\Scripts\cg.exe monitor start `
  --batch-limit 100 `
  --interval 2 `
  --workers 8 `
  --min-llm-risk 45 `
  --max-llm-rpm 6 `
  --auto-push-ledger

# Optional flags:
#   --from-head                 Jump immediately to live npm HEAD on start
#   --backfill                  Crawl historical seq backlog instead of fast-forwarding stale checkpoints
#   --truth-check-interval 21600  Seconds between automatic flagged OSV/npm ground-truth checks (default 6h)

# Hands-off daily maintenance (one-shot OTS upgrade -> ground-truth verify & auto-reveal -> live GitHub sync)
.\.venv\Scripts\cg.exe monitor sync
.\.venv\Scripts\cg.exe monitor sync --full

# Register a user-level daily OS background task (Windows Task Scheduler / POSIX cron — no admin needed)
.\.venv\Scripts\cg.exe monitor schedule --daily 18:00 --dry-run
.\.venv\Scripts\cg.exe monitor schedule --daily 18:00
.\.venv\Scripts\cg.exe monitor schedule --remove

# Ledger & proof verification commands
.\.venv\Scripts\cg.exe monitor status
.\.venv\Scripts\cg.exe ledger list
.\.venv\Scripts\cg.exe ledger show <finding_id>
.\.venv\Scripts\cg.exe ledger upgrade
.\.venv\Scripts\cg.exe ledger push --repo <owner>/cli-guard-ledger
.\.venv\Scripts\cg.exe ledger submit-openssf <finding_id> --dry-run
.\.venv\Scripts\cg.exe ledger reveal <finding_id>
.\.venv\Scripts\cg.exe ledger verify <proof.ots> <reveal.json>
```

> **Privacy Guarantee:** `ledger.jsonl`, `.ots` files, and `public_snapshot.json` use opaque finding IDs and salted `SHA-256(salt || canonical_json)` commitments. Private salts in `ledger_secrets/` and unconfirmed package names are **never** pushed to GitHub.

---

## Retrospective Ground-Truth Verification

Checks scanned packages against **OSV `MAL-*` advisories** (hydrating `/v1/vulns/{id}` aliases and summaries) and **official npm `0.0.1-security` takedowns**. Plain author unpublishes/404s are classified separately as `REMOVED_UNCONFIRMED` so routine developer unpublishes never trigger false public reveals or skew recall.

```powershell
# Quick check of flagged packages (runs automatically inside `cg monitor sync`)
.\.venv\Scripts\cg.exe monitor verify-truth --only-flagged --auto-reveal

# Full check across all scanned packages (e.g. Day 7-10 benchmark)
.\.venv\Scripts\cg.exe monitor verify-truth --auto-reveal
# or equivalently:
.\.venv\Scripts\python.exe scripts\verify_ground_truth.py --auto-reveal
```

Outputs timestamped JSON and Markdown showcase reports under `~/.cli-guard/reports/` with exact lead times (`official_time - our_detected_at`), precision/recall, and Bitcoin block confirmation status.

---

## Live & Hosted Web Dashboard (Option A: Static Showcase + Rate-Limited Public API)

The web dashboard supports two modes in a single unified UI:

1. **GitHub Pages Showcase (`--public-safe` by default + live `cli-guard-ledger` sync):**
   Exports `docs/index.html` + `docs/snapshot.json` with **unconfirmed `SUSPICIOUS` packages automatically redacted** behind their salted SHA-256 commitments + Bitcoin `.ots` entries. When `ledger_repo` is configured, the page automatically loads the freshest redacted `public_snapshot.json` and `ledger.jsonl` directly from `https://raw.githubusercontent.com/<owner>/cli-guard-ledger/main/` on page load—so `cg monitor sync` / `cg ledger push` updates your website automatically without committing snapshot files to `main`.

```powershell
# Export initial/updated public-safe GitHub Pages showcase
.\.venv\Scripts\cg.exe dashboard export --out docs --public-safe

# Run live local dashboard (no redaction, interactive CLI Runner + OTS upgrade button)
.\.venv\Scripts\cg.exe dashboard serve --host 127.0.0.1 --port 8787
```

2. **Public Interactive `CLI Runner` Backend (`Dockerfile` + `--public-api`):**
   Deploy the included [Dockerfile](Dockerfile) to Render, Fly.io, Railway, or Google Cloud Run to power the `CLI Runner` tab on your GitHub Pages site with built-in IP rate limits (`--ip-limit-hour 15`), daily LLM caps (`--ip-llm-day 3`, `--global-llm-day 50`, falling back gracefully to free Layer 0+1 AST analysis when capped), and CORS:

```powershell
# Start public-safe CORS API locally or in container
cg dashboard serve --host 0.0.0.0 --port 8080 --public-api --cors-origin https://<user>.github.io --trust-proxy

# Embed the deployed API URL into GitHub Pages snapshot (or pass ?api=https://... in the browser URL)
$env:CG_PUBLIC_API_URL = "https://cli-guard.onrender.com"
cg dashboard export --out docs --public-safe
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
# Open-source / local (no paid API key required)
cg check some-pkg --provider ollama --model qwen2.5-coder:7b
cg check some-pkg --provider llamacpp --base-url http://localhost:8080/v1
cg check some-pkg --provider static   # Layer 0 + Layer 1 AST/diff only

# Cloud APIs (open-weight & frontier)
cg check some-pkg --provider meta --model muse-spark-1.3
cg check some-pkg --provider openrouter --model qwen/qwen-2.5-coder-32b-instruct:free
cg check some-pkg --provider groq --model llama-3.3-70b-versatile
cg check some-pkg --provider together --model Qwen/Qwen2.5-Coder-32B-Instruct
cg check some-pkg --provider openai --model gpt-4o-mini
cg check some-pkg --provider anthropic --model claude-3-5-haiku-latest
cg check some-pkg --provider gemini --model gemini-2.5-flash
```
