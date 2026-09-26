"""Run the actual generated statements on the supported minimum SQLite CLI."""

import json
import os
from pathlib import Path
import runpy
import subprocess

import pytest
import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

sqlite_cli = os.environ.get("SQLITE_MIN_BINARY")
pytestmark = pytest.mark.skipif(
    not sqlite_cli, reason="Set SQLITE_MIN_BINARY to the SQLite 3.38 CLI"
)
helpers = runpy.run_path(str(Path(__file__).with_name("test_correlations.py")))


@pytest.mark.parametrize(
    "kind",
    [
        "event_count",
        "value_count",
        "value_sum",
        "value_avg",
        "value_median",
        "value_percentile",
        "temporal",
        "temporal_ordered",
    ],
)
@pytest.mark.parametrize("materialized", [False, True])
def test_minimum_sqlite_executes_correlations(kind, materialized):
    cond = {"gte": 1}
    if kind.startswith("value_"):
        cond["field"] = "Bytes"
    if kind == "value_percentile":
        cond["percentile"] = 50
    refs = ("a", "b") if kind.startswith("temporal") else ("a",)
    docs = [
        helpers["detection"](),
        helpers["detection"]("b", 2),
        helpers["correlation"](kind, refs, cond),
    ]
    events = [
        helpers["event"](0, Bytes="10"),
        helpers["event"](0.5, Bytes="20"),
        helpers["event"](1, EventID=2),
    ]
    entry = json.loads(
        sqliteBackend(event_id_field="row_id").convert(
            SigmaCollection.from_yaml(yaml.safe_dump_all(docs)), "zircolite"
        )
    )[-1]
    con = helpers["database"](events)
    script = "\n".join(con.iterdump()) + "\n"
    con.close()
    if materialized:
        plan = entry["correlation_plan"]
        for stage in plan["prepare"]:
            script += f'CREATE TEMP TABLE {stage["name"]} AS {stage["select"]};\n'
            for i, columns in enumerate(stage["indexes"]):
                script += f'CREATE INDEX {stage["name"]}_i{i} ON {stage["name"]} ({",".join(columns)});\n'
        script += plan["query"] + ";"
    else:
        script += entry["rule"][0] + ";"
    result = subprocess.run(
        [sqlite_cli, "-json", ":memory:"],
        input=script,
        capture_output=True,
        text=True,
        check=True,
    )
    rows = json.loads(result.stdout)
    expected = helpers["execute"](docs, events)
    assert [r["metric_value"] for r in rows] == [r["metric_value"] for r in expected]
    assert [json.loads(r["event_ids"]) for r in rows] == [
        r["event_ids"] for r in expected
    ]
