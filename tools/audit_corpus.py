"""Report parsing, conversion and SQLite preparation separately from accuracy.

Run with a pinned local SigmaHQ checkout. Preparation uses declared compiler
field requirements, not a SQL scanner or a consumer's accidental event schema.
"""

import argparse
import json
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

from sigma.backends.sqlite import sqliteBackend
from sigma.backends.sqlite.runtime import (
    ensure_fields,
    execute_plan,
    register_cidr,
    validate_fulltext,
    validate_sql_functions,
)

KEYWORD_GAP = "Keyword search requires fulltext_field"


def failed(errors):
    """Invalid corpus documents, conversion errors and invalid SQL fail the audit.

    Keyword rules audited without --fulltext-field stay a visible conversion gap.
    """
    return any(
        e["stage"] != "conversion" or not e["error"].startswith(KEYWORD_GAP)
        for e in errors
    )


def audit(path, profile, *, fulltext_field=None, cidr_mode="expanded"):
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
    backend = sqliteBackend(
        pipeline, fulltext_field=fulltext_field, cidr_mode=cidr_mode
    )
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
                lambda pattern, value: (
                    value is not None and re.search(pattern, str(value)) is not None
                ),
            )
            try:
                if "required_sql_functions" in entry:
                    register_cidr(connection)
                    validate_sql_functions(connection, entry["required_sql_functions"])
                    stats["exact_cidr_queries"] += len(entry["rule"])
                connection.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY)")
                fulltext = entry.get("fulltext", [])
                if fulltext:
                    for requirement in fulltext:
                        table = requirement["table"]
                        field = backend.escape_and_quote_field(requirement["field"])
                        # Search text is a consumer prerequisite, not an absent
                        # event field that can be materialized as NULL.
                        connection.execute(
                            f"ALTER TABLE {table} ADD COLUMN {field} "
                            "TEXT NOT NULL DEFAULT ''"
                        )
                    validate_fulltext(connection, fulltext)
                    stats["fulltext_queries"] += len(entry["rule"])
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
        fulltext_field=fulltext_field,
        cidr_mode=cidr_mode,
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
    parser.add_argument(
        "--cidr-mode", choices=["expanded", "exact"], default="expanded"
    )
    parser.add_argument(
        "--fulltext-field",
        help="Provision this searchable TEXT column and enable keyword conversion",
    )
    args = parser.parse_args()
    result = audit(
        args.corpus,
        args.profile,
        fulltext_field=args.fulltext_field,
        cidr_mode=args.cidr_mode,
    )
    text = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(text + "\n")
    else:
        print(text)
    sys.exit(failed(result["errors"]))
