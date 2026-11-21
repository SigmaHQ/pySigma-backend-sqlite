"""Rule builders, an event table and plan execution shared by the test modules."""

import json
import re
import sqlite3

import yaml
from sigma.collection import SigmaCollection

from sigma.backends.sqlite import sqliteBackend
from sigma.backends.sqlite.runtime import execute_plan, register_sqlite_functions


def regexp(pattern, value):
    """Zircolite's REGEXP: false for an absent (NULL) value."""
    return value is not None and re.search(pattern, str(value)) is not None


def detection(name="a", event=1):
    return dict(
        title=name,
        name=name,
        logsource={"category": "test"},
        detection={"s": {"EventID": event}, "condition": "s"},
    )


def correlation(kind="event_count", refs=("a",), condition=None, name="corr", **extra):
    c = dict(type=kind, rules=list(refs), timespan="5s", **{"group-by": ["Host"]})
    if condition is not None:
        c["condition"] = condition
    elif not kind.startswith("temporal"):
        c["condition"] = {"gte": 2}
    c.update(extra)
    return dict(title=name, name=name, correlation=c)


def database(events):
    con = sqlite3.connect(":memory:")
    con.execute(
        "CREATE TABLE logs (row_id INTEGER PRIMARY KEY, timestamp TEXT, Host TEXT COLLATE NOCASE, "
        "EventID INTEGER, User TEXT, OtherUser TEXT, Bytes, event_count INTEGER, OriginalLogfile TEXT)"
    )
    for i, event in enumerate(events, 1):
        row = dict(
            row_id=i,
            Host="h",
            EventID=1,
            User="u",
            OtherUser="u",
            Bytes=10,
            event_count=0,
            OriginalLogfile="input.json",
        )
        row.update(event)
        con.execute(
            "INSERT INTO logs ("
            + ",".join("`" + k + "`" for k in row)
            + ") VALUES ("
            + ",".join("?" for _ in row)
            + ")",
            list(row.values()),
        )
    return con


def event(t, **values):
    return dict(timestamp=f"2024-01-01T00:00:{t:06.3f}", **values)


def execute(docs, events, *, materialized=False, **options):
    """Alert rows of the last rule, from its portable SQL or its materialized plan."""
    b = sqliteBackend(event_id_field="row_id", **options)
    collection = SigmaCollection.from_yaml(yaml.safe_dump_all(docs))
    entry = json.loads(b.convert(collection, "zircolite"))[-1]
    con = database(events)
    try:
        if options.get("sum_mode") == "exact" or options.get("text_mode") == "unicode":
            register_sqlite_functions(con)
        if materialized:
            rows, _ = execute_plan(con, entry["correlation_plan"])
            assert not con.execute(
                "SELECT name FROM sqlite_temp_master WHERE type='table'"
            ).fetchall()
            return rows
        cursor = con.execute(entry["rule"][0])
        keys = [d[0] for d in cursor.description]
        rows = [dict(zip(keys, r)) for r in cursor]
        for row in rows:
            for key in ("group_keys", "event_ids", "child_alert_ids"):
                row[key] = json.loads(row[key])
        return rows
    finally:
        con.close()


def plan_script(plan):
    """The statements a consumer runs to materialize a correlation plan and query it."""
    script = ""
    for stage in plan["prepare"]:
        name = stage["name"]
        script += f"CREATE TEMP TABLE {name} AS {stage['select']};\n"
        for i, columns in enumerate(stage["indexes"]):
            script += f"CREATE INDEX {name}_i{i} ON {name} ({','.join(columns)});\n"
    return script + plan["query"] + ";"
