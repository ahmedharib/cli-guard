"""Standalone retrospective ground-truth verification script for cli-guard.

Checks all scanned packages recorded by `cg` (from `cg monitor`, `cg check`, `cg investigate`,
or `cg guard`) against:
  1. OSV / OpenSSF Malicious Packages (`MAL-*` advisories & official published timestamps)
  2. Official npm registry status (live, 404 removed, unpublished, or `0.0.1-security` holding)

Also upgrades pending Bitcoin OpenTimestamps (`.ots`) proofs and saves timestamped JSON +
Markdown showcase reports under `~/.cli-guard/reports/`.

When to run:
  - Run **24h, 72h, and 7 days** after scanning (or as a daily scheduled job), because
    OSV/OpenSSF advisories and npm security takedowns typically lag initial malware publishes
    by hours to several days.
  - Bitcoin `.ots` proofs typically confirm within **1-6 hours** after stamping.
"""

from __future__ import annotations

import argparse
import json

from cli_guard.config import Settings
from cli_guard.monitor.ground_truth import run_ground_truth_verification


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify all cli-guard scanned packages against official npm & OSV ground truth."
    )
    parser.add_argument(
        "--only-flagged",
        action="store_true",
        help="Check only packages flagged as malicious or suspicious.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of recent scanned packages to check.",
    )
    parser.add_argument(
        "--no-ots-upgrade",
        action="store_true",
        help="Skip upgrading pending Bitcoin OpenTimestamps (.ots) proofs.",
    )
    parser.add_argument(
        "--auto-reveal",
        action="store_true",
        help="Automatically reveal salted commit-reveal proofs for confirmed True Positives.",
    )
    args = parser.parse_args()

    settings = Settings.from_env()
    report = run_ground_truth_verification(
        settings,
        only_flagged=args.only_flagged,
        limit=args.limit,
        upgrade_ots=not args.no_ots_upgrade,
        auto_reveal=args.auto_reveal,
    )
    print(json.dumps(report["counts"], indent=2))
    print(f"JSON showcase saved to:     {report['json_report_path']}")
    print(f"Markdown showcase saved to: {report['markdown_report_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
