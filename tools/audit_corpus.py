"""Report parsing, conversion and SQLite preparation separately from accuracy.

Run with a pinned local SigmaHQ checkout. Preparation uses declared compiler
field requirements, not a SQL scanner or a consumer's accidental event schema.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sigma.backends.sqlite import sqliteBackend
from sigma.backends.sqlite.runtime import ensure_fields, execute_plan
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule


def audit(path, profile):
    pipeline = None
    if profile == "windows-sysmon":
        from sigma.pipelines.sysmon import sysmon_pipeline
        from sigma.pipelines.windows import windows_logsource_pipeline

        pipeline = sysmon_pipeline() + windows_logsource_pipeline()
    elif profile == "windows-audit":
        from sigma.pipelines.windows import (
            windows_audit_pipeline,
            windows_logsource_pipeline,
        )

        pipeline = windows_audit_pipeline() + windows_logsource_pipeline()
    root = path / "rules"
    if profile.startswith("windows-"):
        root /= "windows"
    elif profile == "linux":
        root /= "linux"
    if not root.is_dir():
        raise ValueError(f"No rule directory: {root}")
    stats, errors, rules = Counter(), [], []
    for file in sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml")):
        stats["files"] += 1
        try:
            collection = SigmaCollection.from_yaml(
                file.read_text(), resolve_references=False
            )
            rules.extend(collection.rules)
            stats["parsed_files"] += 1
        except Exception as exc:
            errors.append(dict(stage="parse", path=str(file), error=str(exc)))
    collection = SigmaCollection(rules)
    collection.resolve_rule_references()
    backend = sqliteBackend(pipeline)
    backend.init_processing_pipeline("zircolite")
    for rule in collection:
        title = rule.title
        try:
            output = (
                backend.convert_correlation_rule(rule, "zircolite")
                if isinstance(rule, SigmaCorrelationRule)
                else backend.convert_rule(rule, "zircolite")
            )
            stats["converted_rules"] += 1
            if not output:
                stats["reference_only"] += 1
        except Exception as exc:
            errors.append(dict(stage="conversion", title=title, error=str(exc)))
            continue
        for entry in output:
            stats["queries"] += len(entry["rule"])
            stats["unbounded_channel_entries"] += not bool(entry["channel"])
            connection = sqlite3.connect(":memory:")
            connection.create_function(
                "regexp",
                2,
                lambda pattern, value: bool(value and re.search(pattern, str(value))),
            )
            try:
                connection.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY)")
                if entry.get("correlation_plan"):
                    execute_plan(
                        connection, entry["correlation_plan"], include_events=False
                    )
                    stats["correlations"] += 1
                else:
                    ensure_fields(connection, {"logs": entry["required_fields"]})
                    for query in entry["rule"]:
                        connection.execute("EXPLAIN " + query).fetchall()
                stats["prepared_queries"] += len(entry["rule"])
            except Exception as exc:
                errors.append(dict(stage="preparation", title=title, error=str(exc)))
            finally:
                connection.close()
    return dict(
        profile=profile,
        counts=dict(stats),
        errors=errors,
        sqlite_version=sqlite3.sqlite_version,
        applicability="Profile/logsource dependent; unbounded Channel does not mean inapplicable.",
        semantic_accuracy="Not measured by conversion or preparation. See execution tests and log fixtures.",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument(
        "--profile",
        choices=["raw", "windows-sysmon", "windows-audit", "linux"],
        default="raw",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.corpus, args.profile)
    text = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(text + "\n")
    else:
        print(text)
    # Unsupported keywords remain a visible conversion gap. Invalid generated
    # SQL and invalid corpus documents fail the audit job.
    sys.exit(
        any(
            e["stage"] in ("parse", "preparation")
            or (e["stage"] == "conversion" and not e["error"].startswith("Value-only "))
            for e in result["errors"]
        )
    )
