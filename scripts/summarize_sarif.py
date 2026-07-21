#!/usr/bin/env python3
"""Extract focused untrusted-checkout evidence from a CodeQL SARIF file."""

import argparse
import copy
import json
import os
from pathlib import Path


RULES = {
    "actions/untrusted-checkout/critical",
    "actions/untrusted-checkout/high",
}


def result_uri(result):
    return result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def filtered_sarif(sarif, workflow_name):
    filtered = copy.deepcopy(sarif)
    for run in filtered.get("runs", []):
        run["results"] = [
            result
            for result in run.get("results", [])
            if result.get("ruleId") in RULES and result_uri(result).endswith(workflow_name)
        ]
    return filtered


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sarif", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--default-control", default="default-path-positive.yml")
    parser.add_argument("--missing-case", default="nested-quoted-path-candidate.yml")
    args = parser.parse_args()

    sarif = json.loads(args.sarif.read_text(encoding="utf-8"))
    args.output.mkdir(parents=True, exist_ok=True)

    alerts = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            if result.get("ruleId") not in RULES:
                continue
            physical = result["locations"][0]["physicalLocation"]
            alerts.append(
                {
                    "rule_id": result["ruleId"],
                    "uri": physical["artifactLocation"]["uri"],
                    "region": physical.get("region", {}),
                }
            )

    counts = {}
    for alert in alerts:
        counts.setdefault(alert["uri"], {})
        counts[alert["uri"]][alert["rule_id"]] = (
            counts[alert["uri"]].get(alert["rule_id"], 0) + 1
        )

    missing_alerts = [
        alert for alert in alerts if alert["uri"].endswith(args.missing_case)
    ]
    control_alerts = [
        alert for alert in alerts if alert["uri"].endswith(args.default_control)
    ]
    summary = {
        "provenance": {
            "github_repository": os.environ.get("GITHUB_REPOSITORY"),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_sha": os.environ.get("GITHUB_SHA"),
            "codeql_candidate_sha": os.environ.get("CODEQL_CANDIDATE_SHA"),
        },
        "selected_alerts": alerts,
        "counts_by_uri": counts,
        "focused_cases": {
            "expected_critical_but_missing": {
                "workflow": args.missing_case,
                "alerts": missing_alerts,
            },
            "default_path_control": {
                "workflow": args.default_control,
                "alerts": control_alerts,
            },
        },
    }

    (args.output / "selected-alerts.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output / "default-path-control.sarif").write_text(
        json.dumps(filtered_sarif(sarif, args.default_control), indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output / "expected-critical-missing.sarif").write_text(
        json.dumps(filtered_sarif(sarif, args.missing_case), indent=2) + "\n",
        encoding="utf-8",
    )

    if not any(alert["rule_id"] == "actions/untrusted-checkout/critical" for alert in control_alerts):
        raise SystemExit(f"default control did not produce a critical alert: {args.default_control}")
    if missing_alerts:
        raise SystemExit(f"expected current false negative changed: {args.missing_case}")

    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
