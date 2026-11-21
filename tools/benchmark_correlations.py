"""Benchmark both sparse and dense windows, with an explicit per-case timeout."""

import argparse
import json
import sqlite3
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sigma.collection import SigmaCollection

from sigma.backends.sqlite import sqliteBackend
from sigma.backends.sqlite.runtime import execute_plan


def benchmark(size, kind, dense, timeout):
    condition = "gte: 2" if kind == "event_count" else "field: User\n    gte: 2"
    text = f"""title: base
name: base
logsource:
  category: test
detection:
  s:
    EventID: 1
  condition: s
---
title: correlation
correlation:
  type: {kind}
  rules: [base]
  group-by: [Host]
  timespan: 5s
  condition:
    {condition}
"""
    backend = sqliteBackend(timestamp_seconds_expression="CAST({field} AS REAL)")
    entry = json.loads(backend.convert(SigmaCollection.from_yaml(text), "zircolite"))[0]
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE logs(timestamp REAL, Host TEXT, EventID INT, User TEXT)"
    )
    connection.executemany(
        "INSERT INTO logs VALUES(?,?,1,?)",
        ((i / 1000 if dense else i, "host", str(i % 100)) for i in range(size)),
    )
    start = time.perf_counter()
    connection.set_progress_handler(
        lambda: time.perf_counter() - start > timeout, 10000
    )
    result = dict(events=size, kind=kind, density="dense" if dense else "sparse")
    try:
        rows, _ = execute_plan(
            connection, entry["correlation_plan"], include_events=False
        )
        result.update(alerts=len(rows), status="ok")
    except sqlite3.OperationalError as exc:
        result.update(
            status="timeout" if "interrupted" in str(exc) else "error", error=str(exc)
        )
    finally:
        connection.set_progress_handler(None, 0)
        connection.close()
    result["seconds"] = round(time.perf_counter() - start, 4)
    return result


def benchmark_ordered(size, references, dense, timeout, repeats):
    names = [f"r{i}" for i in range(references)]
    threshold = (references + 1) // 2 if references != 5 else 2
    docs = [
        dict(
            title=name,
            name=name,
            logsource={"category": "test"},
            detection={"s": {"EventID": i}, "condition": "s"},
        )
        for i, name in enumerate(names)
    ]
    docs.append(
        dict(
            title="ordered",
            correlation={
                "type": "temporal_ordered",
                "rules": names,
                "timespan": "5s",
                "group-by": ["Host"],
                "condition": {"gte": threshold},
            },
        )
    )
    backend = sqliteBackend(timestamp_format="unix")
    entry = json.loads(backend.convert(SigmaCollection.from_dicts(docs), "zircolite"))[
        -1
    ]
    sql, plan = entry["rule"][0], entry["correlation_plan"]
    con = sqlite3.connect(":memory:", cached_statements=0)
    con.execute("CREATE TABLE logs(timestamp REAL, Host TEXT, EventID INT)")
    con.executemany(
        "INSERT INTO logs VALUES(?, 'host', ?)",
        (
            (
                i / 100 if dense else (i // references) * 10 + (i % references) / 10,
                i % references,
            )
            for i in range(size)
        ),
    )
    result = dict(
        events=size,
        kind="temporal_ordered",
        references=references,
        threshold=threshold,
        density="dense" if dense else "sparse",
        sqlite=sqlite3.sqlite_version,
        sql_bytes=len(sql.encode()),
        stages=len(plan["prepare"]),
        repeats=repeats,
    )
    timings = {"prepare_seconds": [], "standalone_seconds": [], "plan_seconds": []}
    try:
        for _ in range(repeats):
            start = time.perf_counter()
            con.set_progress_handler(
                lambda: time.perf_counter() - start > timeout, 10000
            )
            # EXPLAIN compiles the same query without executing it. The standalone
            # timing below includes preparation, as it would on a fresh connection.
            con.execute("EXPLAIN " + sql).fetchone()
            timings["prepare_seconds"].append(time.perf_counter() - start)
            start = time.perf_counter()
            cursor = con.execute(sql)
            columns = [d[0] for d in cursor.description]
            standalone = [dict(zip(columns, row)) for row in cursor]
            timings["standalone_seconds"].append(time.perf_counter() - start)
            start = time.perf_counter()
            materialized, _ = execute_plan(con, plan, include_events=False)
            timings["plan_seconds"].append(time.perf_counter() - start)
            for row in standalone:
                for key in ("event_ids", "child_alert_ids", "group_keys"):
                    row[key] = json.loads(row[key])
            if standalone != materialized:
                raise ValueError("The execution paths disagree on alert rows")
            result["alerts"] = len(standalone)
        result.update(
            {
                key: round(statistics.median(values), 6)
                for key, values in timings.items()
            }
        )
        result["status"] = "ok"
    except sqlite3.OperationalError as exc:
        result.update(
            status="timeout" if "interrupted" in str(exc) else "error", error=str(exc)
        )
    finally:
        con.close()
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000, 10000, 100000])
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument(
        "--ordered",
        action="store_true",
        help="compare both ordered-threshold execution paths",
    )
    parser.add_argument(
        "--repeats", type=int, default=3, help="repetitions per ordered case"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    results = []
    for size in args.sizes:
        for case in (5, 12) if args.ordered else ("event_count", "value_count"):
            for dense in (False, True):
                if args.ordered:
                    result = benchmark_ordered(
                        size, case, dense, args.timeout, args.repeats
                    )
                else:
                    result = benchmark(size, case, dense, args.timeout)
                results.append(result)
                print(json.dumps(result), flush=True)
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n")
