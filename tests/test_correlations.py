"""Execute generated SQL and materialized plans; assert observable semantics."""

import json
import random
import sqlite3
import statistics

import pytest
import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.backends.sqlite.runtime import execute_plan
from sigma.collection import SigmaCollection


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
            **{},
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
    b = sqliteBackend(event_id_field="row_id", **options)
    entries = json.loads(
        b.convert(SigmaCollection.from_yaml(yaml.safe_dump_all(docs)), "zircolite")
    )
    entry = entries[-1]
    con = database(events)
    try:
        if materialized:
            rows, diagnostics = execute_plan(con, entry["correlation_plan"])
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


@pytest.mark.parametrize("materialized", [False, True])
def test_count_bursts_keep_occurrences_and_evidence(materialized):
    rows = execute(
        [detection(), correlation()],
        [event(0), event(1), event(20), event(21)],
        materialized=materialized,
    )
    assert [r["metric_value"] for r in rows] == [2, 2]
    assert [r["event_ids"] for r in rows] == [["0:1", "0:2"], ["0:3", "0:4"]]
    assert all(r["event_count"] == 2 for r in rows)
    assert len({r["alert_id"] for r in rows}) == 2
    if materialized:
        assert rows[0]["evidence"][0]["event"]["OriginalLogfile"] == "input.json"


@pytest.mark.parametrize("materialized", [False, True])
def test_overlapping_rules_and_conditions_count_physical_events(materialized):
    a = detection()
    a["detection"].update(s2={"EventID": 1}, condition=["s", "s2"])
    assert (
        execute(
            [a, detection("b"), correlation(refs=("a", "b"))],
            [event(0)],
            materialized=materialized,
        )
        == []
    )


@pytest.mark.parametrize("materialized", [False, True])
def test_aliases_and_order_with_repeated_stage(materialized):
    c = correlation(
        "temporal_ordered",
        ("a", "b", "c"),
        **{
            "group-by": ["identity"],
            "aliases": {"identity": {"a": "User", "b": "OtherUser", "c": "User"}},
        },
    )
    rows = execute(
        [detection(), detection("b", 2), detection("c", 3), c],
        [event(0), event(1, EventID=3), event(2, EventID=2), event(3, EventID=3)],
        materialized=materialized,
    )
    assert len(rows) == 1
    assert rows[0]["group_keys"] == {"identity": "u"}
    assert set(rows[0]["event_ids"]) == {"0:1", "0:3", "0:4"}


@pytest.mark.parametrize("materialized", [False, True])
def test_ordered_ties_and_reversed_are_not_sequences(materialized):
    docs = [detection(), detection("b", 2), correlation("temporal_ordered", ("a", "b"))]
    for events in ([event(0), event(0, EventID=2)], [event(0, EventID=2), event(1)]):
        assert execute(docs, events, materialized=materialized) == []


@pytest.mark.parametrize("materialized", [False, True])
def test_single_reference_temporal(materialized):
    rows = execute(
        [detection(), correlation("temporal")], [event(0)], materialized=materialized
    )
    assert len(rows) == 1


@pytest.mark.parametrize(
    "kind",
    [
        "event_count",
        "value_count",
        "value_sum",
        "value_avg",
        "value_median",
        "value_percentile",
    ],
)
def test_invalid_timestamp_and_missing_groups_never_correlate(kind):
    cond = {"gte": 1}
    if kind != "event_count":
        cond["field"] = "Bytes"
    if kind == "value_percentile":
        cond["percentile"] = 50
    docs = [detection(), correlation(kind, condition=cond)]
    for events in (
        [{"timestamp": None}, {"timestamp": "bad"}],
        [event(0, Host=None), event(1, Host=None)],
    ):
        assert execute(docs, events) == []


def test_fractional_window_boundary():
    docs = [detection(), correlation()]
    assert execute(docs, [event(0.1), event(5.9)]) == []
    assert len(execute(docs, [event(0.1), event(5.1)])) == 1


@pytest.mark.parametrize(
    "kind",
    ["value_sum", "value_avg", "value_median", "value_percentile", "value_count"],
)
@pytest.mark.parametrize("materialized", [False, True])
def test_statistics_numeric_strings_nulls_and_interpolation(kind, materialized):
    cond = {"gte": 0, "field": "Bytes"}
    if kind == "value_percentile":
        cond["percentile"] = 50
    rows = execute(
        [detection(), correlation(kind, condition=cond)],
        [event(0, Bytes=v) for v in ["2", "10", "100", None, "junk"]],
        materialized=materialized,
    )
    expected = {
        "value_sum": 112,
        "value_avg": 112 / 3,
        "value_median": 10,
        "value_percentile": 10,
        "value_count": 4,
    }
    assert rows[0]["metric_value"] == pytest.approx(expected[kind])


@pytest.mark.parametrize(
    "p,expected", [(0, 10), (25, 12.5), (50, 15), (95, 19.5), (100, 20)]
)
def test_percentile_even_sample(p, expected):
    rows = execute(
        [
            detection(),
            correlation(
                "value_percentile",
                condition={"gte": 0, "field": "Bytes", "percentile": p},
            ),
        ],
        [event(0, Bytes=10), event(0, Bytes=20)],
    )
    assert rows[0]["metric_value"] == expected


@pytest.mark.parametrize("kind", ["temporal", "temporal_ordered"])
@pytest.mark.parametrize("materialized", [False, True])
def test_absence_requires_expired_deadline_and_only_orders_positive_stages(
    kind, materialized
):
    docs = [
        detection(),
        detection("b", 2),
        correlation(kind, ("a", "b"), "a and not b"),
    ]
    assert (
        execute(docs, [event(0), event(3, EventID=99)], materialized=materialized) == []
    )
    rows = execute(docs, [event(0), event(5, EventID=99)], materialized=materialized)
    assert len(rows) == 1
    assert rows[0]["occurrence_time"] == 1704067205
    assert (
        execute(
            docs,
            [event(0), event(4, EventID=2), event(6, EventID=99)],
            materialized=materialized,
        )
        == []
    )


@pytest.mark.parametrize("materialized", [False, True])
def test_extended_or_and_nested_not(materialized):
    docs = [
        detection(),
        detection("b", 2),
        detection("c", 3),
        correlation("temporal_ordered", ("a", "b", "c"), "a and not (not b and not c)"),
    ]
    assert execute(docs, [event(0), event(1, EventID=3)], materialized=materialized)


@pytest.mark.parametrize("materialized", [False, True])
def test_chained_count_then_success_preserves_provenance(materialized):
    child = correlation(name="burst")
    parent = correlation("temporal_ordered", ("burst", "success"))
    docs = [detection(), detection("success", 2), child, parent]
    rows = execute(
        docs, [event(0), event(1), event(2, EventID=2)], materialized=materialized
    )
    assert len(rows) == 1
    assert set(rows[0]["event_ids"]) == {"0:1", "0:2", "0:3"}
    assert len(rows[0]["child_alert_ids"]) == 1


@pytest.mark.parametrize("materialized", [False, True])
def test_chained_aggregate_reads_child_metric(materialized):
    child = correlation(name="burst")
    parent = correlation("value_sum", ("burst",), {"gte": 2, "field": "event_count"})
    rows = execute(
        [detection(), child, parent], [event(0), event(1)], materialized=materialized
    )
    assert rows[0]["metric_value"] == 2


@pytest.mark.parametrize(
    "kind",
    [
        "event_count",
        "value_count",
        "value_sum",
        "value_avg",
        "value_median",
        "value_percentile",
    ],
)
def test_random_windows_against_python_reference(kind):
    rng = random.Random(113)
    data = [(t, rng.randrange(1, 15)) for t in sorted(rng.sample(range(59), 20))]
    cond = {"gte": 0}
    if kind != "event_count":
        cond["field"] = "Bytes"
    if kind == "value_percentile":
        cond["percentile"] = 50
    rows = execute(
        [detection(), correlation(kind, condition=cond)],
        [event(t, Bytes=v) for t, v in data],
    )
    assert len(rows) == len(data)
    for row, (t, _) in zip(rows, data):
        sample = [v for s, v in data if t - 5 <= s <= t]
        expected = {
            "event_count": len(sample),
            "value_count": len(set(sample)),
            "value_sum": sum(sample),
            "value_avg": statistics.mean(sample),
            "value_median": statistics.median(sample),
            "value_percentile": statistics.median(sample),
        }[kind]
        assert row["metric_value"] == pytest.approx(expected)


def test_required_fields_and_runtime_cleanup_on_failure():
    c = SigmaCollection.from_yaml(yaml.safe_dump_all([detection(), correlation()]))
    entry = json.loads(sqliteBackend().convert(c, "zircolite"))[0]
    assert set(entry["required_fields"]) == {"Host", "EventID", "timestamp"}
    con = database([event(0)])
    plan = entry["correlation_plan"]
    plan["query"] = "SELECT nonexistent FROM logs"
    with pytest.raises(sqlite3.OperationalError):
        execute_plan(con, plan)
    assert not con.execute(
        "SELECT name FROM sqlite_temp_master WHERE type='table'"
    ).fetchall()
    assert con.execute("SELECT COUNT(*) FROM logs").fetchone() == (1,)
    con.close()


@pytest.mark.parametrize("materialized", [False, True])
@pytest.mark.parametrize("aliased", [False, True])
def test_pure_absence_uses_observed_context(materialized, aliased):
    corr = correlation("temporal", condition="not a")
    if aliased:
        corr["correlation"].update(
            {"group-by": ["identity"], "aliases": {"identity": {"a": "User"}}}
        )
    rows = execute(
        [detection(), corr],
        [event(0, EventID=99), event(5, EventID=99)],
        materialized=materialized,
    )
    assert len(rows) == 1
    assert rows[0]["metric_value"] == 0
    assert rows[0]["event_ids"] == ["0:1"]
    assert rows[0]["group_keys"] == ({"identity": "u"} if aliased else {"Host": "h"})


@pytest.mark.parametrize("materialized", [False, True])
def test_or_branches_merge_one_occurrence(materialized):
    rows = execute(
        [detection(), detection("b", 2), correlation("temporal", ("a", "b"), "a or b")],
        [event(0), event(0, EventID=2)],
        materialized=materialized,
    )
    assert len(rows) == 1
    assert rows[0]["event_ids"] == ["0:1", "0:2"]


def test_generate_true_finalizes_referenced_detection():
    corr = correlation()
    corr["correlation"]["generate"] = True
    entries = json.loads(
        sqliteBackend().convert(
            SigmaCollection.from_yaml(yaml.safe_dump_all([detection(), corr])),
            "zircolite",
        )
    )
    assert len(entries) == 2
    assert entries[0]["rule"] == ["SELECT * FROM logs WHERE EventID=1"]
    assert entries[1]["correlation"] is True


@pytest.mark.parametrize("field", ["Group", "1field", "x`y", "user.name"])
def test_identifiers_and_constructor_options_execute(field):
    rule = detection()
    rule["detection"]["s"] = {field: "a"}
    backend = sqliteBackend(
        table="custom logs", collate_nocase=True, timestamp_field="SystemTime"
    )
    assert backend.timestamp_field == "SystemTime"
    sql = backend.convert(SigmaCollection.from_yaml(yaml.safe_dump(rule)))[0]
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE `custom logs` (`" + field.replace("`", "``") + "` TEXT)")
    con.execute("INSERT INTO `custom logs` VALUES (?)", ("A",))
    assert con.execute(sql).fetchall() == [("A",)]
    con.close()


def test_empty_and_ungrouped_aggregates():
    corr = correlation(**{"group-by": []})
    assert execute([detection(), corr], []) == []
    rows = execute([detection(), corr], [event(0, Host=None), event(1, Host=None)])
    assert rows[0]["group_keys"] == {}
    assert rows[0]["metric_value"] == 2


@pytest.mark.parametrize(
    "kind", ["value_sum", "value_avg", "value_median", "value_percentile"]
)
def test_nonfinite_numbers_are_not_statistics(kind):
    cond = {"field": "Bytes", "gte": 0}
    if kind == "value_percentile":
        cond["percentile"] = 50
    assert not execute(
        [detection(), correlation(kind, condition=cond)],
        [event(0, Bytes="1e999"), event(0, Bytes=float("inf"))],
    )


@pytest.mark.parametrize("materialized", [False, True])
def test_ordered_partial_threshold_does_not_require_all_references(materialized):
    docs = [
        detection(),
        detection("b", 2),
        detection("c", 3),
        correlation("temporal_ordered", ("a", "b", "c"), {"gte": 2}),
    ]
    rows = execute(
        docs,
        [event(0, EventID=3), event(1), event(2, EventID=2)],
        materialized=materialized,
    )
    assert rows
    assert rows[-1]["event_ids"] == ["0:2", "0:3"]


def test_timeout_preserves_original_error_and_removes_temp_relations():
    docs = [
        detection(),
        correlation("value_count", condition={"field": "User", "gte": 1}),
    ]
    entry = json.loads(
        sqliteBackend().convert(
            SigmaCollection.from_yaml(yaml.safe_dump_all(docs)), "zircolite"
        )
    )[-1]
    con = database([event(0) for _ in range(1000)])
    calls = 0

    def interrupt():
        nonlocal calls
        calls += 1
        return calls > 200

    con.set_progress_handler(interrupt, 100)
    with pytest.raises(sqlite3.OperationalError, match="interrupted"):
        execute_plan(con, entry["correlation_plan"])
    con.set_progress_handler(None, 0)
    assert not con.execute(
        "SELECT name FROM sqlite_temp_master WHERE type='table'"
    ).fetchall()
    con.close()


@pytest.mark.parametrize("materialized", [False, True])
def test_grouping_and_value_count_preserve_case_insensitive_semantics(materialized):
    docs = [
        detection(),
        correlation("value_count", condition={"gte": 1, "field": "User"}),
    ]
    rows = execute(
        docs,
        [event(0, Host="HOST", User="Alice"), event(0, Host="host", User="ALICE")],
        materialized=materialized,
    )
    assert len(rows) == 1
    assert rows[0]["group_keys"] == {"Host": "host"}
    assert rows[0]["metric_value"] == 1


@pytest.mark.parametrize(
    "format,scale", [("unix", 1), ("unix_ms", 1000), ("unix_us", 1000000)]
)
def test_explicit_epoch_format_rejects_invalid_values(format, scale):
    rows = execute(
        [detection(), correlation()],
        [
            {"timestamp": 1704067200 * scale},
            {"timestamp": 1704067201 * scale},
            {"timestamp": "invalid"},
            {"timestamp": None},
        ],
        timestamp_format=format,
    )
    assert len(rows) == 1
    assert rows[0]["occurrence_time"] == 1704067201
    assert rows[0]["event_count"] == 2


@pytest.mark.parametrize("materialized", [False, True])
def test_chain_after_absence_deadline(materialized):
    absent = correlation("temporal_ordered", ("a", "b"), "a and not b", name="absent")
    parent = correlation("temporal_ordered", ("absent", "c"))
    rows = execute(
        [detection(), detection("b", 2), detection("c", 3), absent, parent],
        [event(0), event(6, EventID=3)],
        materialized=materialized,
    )
    assert len(rows) == 1
    assert rows[0]["occurrence_time"] == 1704067206
    assert rows[0]["event_ids"] == ["0:1", "0:2"]


@pytest.mark.parametrize("materialized", [False, True])
def test_chain_can_regroup_child_evidence(materialized):
    child = correlation(name="burst")
    parent = correlation(
        "event_count", ("burst",), {"gte": 1}, **{"group-by": ["User"]}
    )
    rows = execute(
        [detection(), child, parent],
        [event(0, User="alice"), event(1, User="bob")],
        materialized=materialized,
    )
    assert {r["group_keys"]["User"] for r in rows} == {"alice", "bob"}
    assert all(r["metric_value"] == 1 for r in rows)


def test_zero_value_count_can_be_chained():
    child = correlation(
        "value_count", condition={"eq": 0, "field": "User"}, name="no_users"
    )
    parent = correlation("event_count", ("no_users",), {"gte": 1})
    rows = execute([detection(), child, parent], [event(0, User=None)])
    assert rows[0]["metric_value"] == 1
    assert rows[0]["event_ids"] == ["0:1"]
