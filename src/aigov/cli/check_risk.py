"""Evaluate fail-on risk levels against a JSON scan result file.

Exit 0  — no systems match the configured fail-on levels (clean).
Exit 1  — one or more systems match; prints which ones.
Exit 2  — usage or I/O error (bad args, missing file, invalid JSON).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aigov-check",
        description="Check aigov scan results against fail-on risk levels.",
    )
    parser.add_argument(
        "input_file",
        help="JSON file produced by: aigov scan --output json --out-file <file>",
    )
    parser.add_argument(
        "--fail-on",
        default="prohibited",
        metavar="LEVELS",
        help=(
            "Comma-separated risk levels that trigger a failure exit code. "
            "Valid values: prohibited, high_risk, limited_risk, minimal_risk, "
            "needs_review, unknown. Default: prohibited"
        ),
    )
    args = parser.parse_args(argv)

    fail_levels = {lvl.strip().lower() for lvl in args.fail_on.split(",") if lvl.strip()}
    if not fail_levels:
        print("Error: --fail-on must contain at least one risk level.", file=sys.stderr)
        return 2

    try:
        raw = json.loads(Path(args.input_file).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: file not found: {args.input_file}", file=sys.stderr)
        return 2
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Error reading {args.input_file}: {exc}", file=sys.stderr)
        return 2

    findings = raw.get("findings", [])

    triggered: list[dict] = []
    skipped_allowlisted: list[dict] = []
    for finding in findings:
        if (finding.get("risk_classification") or "").lower() not in fail_levels:
            continue
        if _is_allowlisted(finding):
            skipped_allowlisted.append(finding)
            continue
        triggered.append(finding)

    # Always surface allowlist suppressions so reviewers can audit which
    # records were waved through and why — silent allowlisting is a policy
    # footgun.
    if skipped_allowlisted:
        print(f"Suppressed (allowlisted): {len(skipped_allowlisted)} finding(s)")
        for finding in skipped_allowlisted:
            name = finding.get("name") or finding.get("id") or "unknown"
            reason = (finding.get("tags") or {}).get("allowlist_reason") or "no reason recorded"
            print(f"  Suppressed (allowlisted): {name} — {reason}")

    if not triggered:
        label = ", ".join(sorted(fail_levels))
        print(f"aigov check: PASSED — no systems at risk level(s): {label}")
        return 0

    label = ", ".join(sorted(fail_levels))
    print(
        f"aigov check: FAILED — {len(triggered)} system(s) matched "
        f"fail-on level(s): {label}"
    )
    for finding in triggered:
        name = finding.get("name") or finding.get("id") or "unknown"
        risk = finding.get("risk_classification", "unknown")
        loc = finding.get("source_location", "")
        print(f"  [{risk}] {name}  ({loc})")
    return 1


def _is_allowlisted(finding: dict) -> bool:
    """A finding is allowlisted when its tags carry ``allowlisted: "true"``.

    The Allowlist engine writes that tag during classification when a record
    matches an entry in ``.aigov-allowlist.yaml``. Treating it as a CI bypass
    here keeps approved systems from blocking the pipeline while still leaving
    them visible in the underlying scan output.
    """
    tags = finding.get("tags") or {}
    flag = tags.get("allowlisted")
    if isinstance(flag, bool):
        return flag
    if isinstance(flag, str):
        return flag.strip().lower() == "true"
    return False


if __name__ == "__main__":
    sys.exit(main())
