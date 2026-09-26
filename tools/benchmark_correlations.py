"""Benchmark both sparse and dense windows, with an explicit per-case timeout."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sigma.backends.sqlite import sqliteBackend
from sigma.backends.sqlite.runtime import execute_plan
from sigma.collection import SigmaCollection


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
        rows, diagnostics = execute_plan(
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000, 10000, 100000])
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    results = []
    for size in args.sizes:
        for kind in ("event_count", "value_count"):
            for dense in (False, True):
                result = benchmark(size, kind, dense, args.timeout)
                results.append(result)
                print(json.dumps(result), flush=True)
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n")
