"""Execute generated SQL and materialized plans; assert observable semantics."""

import itertools
import json
import operator
import random
import sqlite3
import statistics
from datetime import UTC, datetime

import pytest
import yaml
from helpers import correlation, database, detection, event, execute
from sigma.collection import SigmaCollection
from sigma.exceptions import (
    SigmaConditionError,
    SigmaCorrelationRuleError,
    SigmaFeatureNotSupportedByBackendError,
)

from sigma.backends.sqlite import sqliteBackend
from sigma.backends.sqlite.runtime import execute_plan


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


@pytest.mark.parametrize("materialized", [False, True])
def test_fractional_thresholds(materialized):
    """pySigma 2 accepts non-integer thresholds; metrics compare against them exactly."""
    count = correlation(condition={"gte": 1.5})
    rows = execute(
        [detection(), count], [event(0), event(1), event(20)], materialized=materialized
    )
    assert [r["metric_value"] for r in rows] == [2]
    avg = correlation("value_avg", condition={"gt": 10.5, "field": "Bytes"})
    rows = execute(
        [detection(), avg],
        [event(0, Bytes=10), event(1, Bytes=12)],
        materialized=materialized,
    )
    assert [r["metric_value"] for r in rows] == [11]
    events = [event(0, Bytes=10), event(1, Bytes=11)]
    assert execute([detection(), avg], events, materialized=materialized) == []


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


@pytest.mark.parametrize("materialized", [False, True])
def test_tuple_value_count_resolves_aliases_and_excludes_incomplete_tuples(
    materialized,
):
    docs = [
        detection(),
        detection("b", 2),
        correlation(
            "value_count",
            ("a", "b"),
            {"gte": 0, "field": ["x", "y"]},
            aliases={
                "x": {"a": "User", "b": "OtherUser"},
                "y": {"a": "OtherUser", "b": "User"},
            },
        ),
    ]
    events = [
        event(0, User="A", OtherUser="1"),
        event(0, User="A", OtherUser="2"),
        event(0, User="B", OtherUser="1"),
        event(0, EventID=2, User="1", OtherUser="a"),
        event(0, OtherUser=None),
        event(0, Host="other", OtherUser=None),
        event(20, User="a|b", OtherUser="c"),
        event(20, User="a", OtherUser="b|c"),
    ]
    rows = execute(docs, events, materialized=materialized)
    assert [
        (r["group_keys"]["Host"], r["metric_value"], r["event_ids"]) for r in rows
    ] == [
        ("h", 3, ["0:1", "0:2", "0:3", "0:4", "0:5"]),
        ("other", 0, ["0:6"]),
        ("h", 2, ["0:7", "0:8"]),
    ]


@pytest.mark.parametrize("materialized", [False, True])
@pytest.mark.parametrize(
    "value", [9007199254740993, "9007199254740993", -9223372036854775808]
)
def test_sum_retains_signed_integers(materialized, value):
    docs = [
        detection(),
        correlation("value_sum", condition={"field": "Bytes", "eq": int(value)}),
    ]
    rows = execute(docs, [event(0, Bytes=value)], materialized=materialized)
    assert [r["metric_value"] for r in rows] == [int(value)]
    assert isinstance(rows[0]["metric_value"], int)
    if int(value) > 0:
        docs[-1]["correlation"]["condition"] = {
            "field": "Bytes",
            "gt": 9007199254740992,
        }
        assert execute(docs, [event(0, Bytes=value)], materialized=materialized)
        docs[-1]["correlation"]["condition"] = {
            "field": "Bytes",
            "eq": 9007199254740992,
        }
        assert not execute(docs, [event(0, Bytes=value)], materialized=materialized)


@pytest.mark.parametrize("materialized", [False, True])
def test_portable_signed_minimum_compares_beyond_int64_threshold(materialized):
    minimum = -(2**63)
    for op, expected in (("eq", []), ("gt", [minimum])):
        docs = [
            detection(),
            correlation("value_sum", condition={"field": "Bytes", op: minimum - 1}),
        ]
        rows = execute(docs, [event(0, Bytes=minimum)], materialized=materialized)
        assert [r["metric_value"] for r in rows] == expected


def ordered_oracle(events, slots, op, threshold):
    compare = {
        "gt": operator.gt,
        "gte": operator.ge,
        "lt": operator.lt,
        "lte": operator.le,
        "eq": operator.eq,
        "neq": operator.ne,
    }[op]
    results = {}
    for host, end in {(h, t) for h, t, _ in events}:
        sample = [
            (i, t, s)
            for i, (h, t, s) in enumerate(events, 1)
            if h == host and end - 5 <= t <= end
        ]
        seen = sorted({s for _, _, s in sample})
        if not compare(len(seen), threshold):
            continue
        subsets = (
            itertools.combinations(range(slots), threshold + (op == "gt"))
            if op in ("gt", "gte")
            else [seen]
        )
        evidence = set()
        for subset in subsets:
            if not subset:
                evidence.update(f"0:{i}" for i, _, _ in sample)
                continue
            after = -float("inf")
            ids = []
            for slot in subset:
                times = [t for _, t, s in sample if s == slot and t > after]
                if not times:
                    break
                after = min(times)
                ids.extend(f"0:{i}" for i, t, s in sample if s == slot and t == after)
            else:
                evidence.update(ids)
        if evidence:
            results[host, end] = len(seen), sorted(evidence)
    return results


@pytest.mark.parametrize("materialized", [False, True])
@pytest.mark.parametrize(
    "op,threshold",
    [
        ("gte", 2),
        ("gte", 5),
        ("gte", 0),
        ("gt", 2),
        ("lt", 2),
        ("lte", 2),
        ("eq", 2),
        ("neq", 2),
    ],
)
def test_ordered_threshold_against_exhaustive_branches(materialized, op, threshold):
    slots = 5
    names = [f"r{i}" for i in range(slots)]
    events = [
        ("a", 0, 3),
        ("a", 1, 2),
        ("a", 1, 1),
        ("a", 3, 3),
        ("a", 0, 0),
        ("a", 2, 1),
        ("a", 2, 1),
        ("b", 0, 1),
        ("b", 4, 2),
        ("a", 8, 4),
        ("a", 2, 2),
        ("a", 4, 4),
    ]
    docs = [detection(n, i) for i, n in enumerate(names)]
    docs.append(correlation("temporal_ordered", names, {op: threshold}))
    rows = execute(
        docs,
        [event(t, Host=h, EventID=s) for h, t, s in events],
        materialized=materialized,
    )
    actual = {
        (r["group_keys"]["Host"], r["occurrence_time"] - 1704067200): (
            r["metric_value"],
            r["event_ids"],
        )
        for r in rows
    }
    assert actual == ordered_oracle(events, slots, op, threshold)


@pytest.mark.parametrize("materialized", [False, True])
def test_ordered_twelve_references_and_half_threshold(materialized):
    names = [f"r{i}" for i in range(12)]
    docs = [detection(n, i) for i, n in enumerate(names)]
    docs.append(correlation("temporal_ordered", names, {"gte": 6}, timespan="30s"))
    rows = execute(
        docs, [event(t, EventID=t) for t in range(12)], materialized=materialized
    )
    assert [r["metric_value"] for r in rows] == list(range(6, 13))
    for row in rows:
        assert row["event_ids"] == sorted(
            f"0:{i + 1}" for i in range(row["metric_value"])
        )


@pytest.mark.parametrize("materialized", [False, True])
def test_wide_ordered_rule_on_one_source(materialized):
    names = [f"r{i}" for i in range(48)]
    docs = [detection(n, i) for i, n in enumerate(names)]
    docs.append(correlation("temporal_ordered", names, {"gte": 24}))
    rows = execute(
        docs, [event(i / 100, EventID=i) for i in range(24)], materialized=materialized
    )
    assert [(r["metric_value"], len(r["event_ids"])) for r in rows] == [(24, 24)]


@pytest.mark.parametrize("materialized", [False, True])
def test_ordered_partial_branches_include_only_participating_child_alerts(materialized):
    first = correlation("event_count", ("a",), {"gte": 1}, name="first")
    parent = correlation("temporal_ordered", ("first", "b", "c"), {"gte": 2})
    docs = [detection(), detection("b", 2), detection("c", 3), first, parent]
    events = [event(0), event(1), event(1, EventID=2), event(2, EventID=3)]
    rows = execute(docs, events, materialized=materialized)
    assert rows[-1]["event_ids"] == ["0:1", "0:3", "0:4"]
    assert len(rows[-1]["child_alert_ids"]) == 1


@pytest.mark.parametrize("materialized", [False, True])
def test_unicode_tuple_and_groups_fold_source_text(materialized):
    docs = [
        detection(),
        correlation(
            "value_count", condition={"gte": 1, "field": ["User", "OtherUser"]}
        ),
    ]
    events = [
        event(0, Host="CAFÉ", User="Straße", OtherUser="É"),
        event(0, Host="café", User="STRASSE", OtherUser="é"),
    ]
    rows = execute(docs, events, materialized=materialized, text_mode="unicode")
    assert [(r["group_keys"], r["metric_value"], r["event_ids"]) for r in rows] == [
        ({"Host": "café"}, 1, ["0:1", "0:2"])
    ]


@pytest.mark.parametrize("sum_mode", ["portable", "exact"])
@pytest.mark.parametrize("materialized", [False, True])
def test_integer_sum_survives_overflow_elsewhere_and_window_eviction(
    sum_mode, materialized
):
    largest = 2**63 - 1
    docs = [
        detection(),
        correlation("value_sum", condition={"field": "Bytes", "gte": 0}),
    ]
    events = [
        event(0, Bytes=largest),
        event(1, Bytes=2),
        event(2, Bytes=-2),
        event(3, Bytes=0.5),
        event(10, Bytes="9007199254740993"),
        event(20, Bytes=None),
        event(25, Bytes="junk"),
    ]
    rows = execute(docs, events, materialized=materialized, sum_mode=sum_mode)
    totals = [r["metric_value"] for r in rows]
    assert totals == [
        largest,
        str(largest + 2) if sum_mode == "exact" else float(largest + 2),
        largest,
        float(largest + 0.5),
        9007199254740993,
    ]
    assert [type(t) for t in totals] == [
        int,
        str if sum_mode == "exact" else float,
        int,
        float,
        int,
    ]


@pytest.mark.parametrize("materialized", [False, True])
@pytest.mark.parametrize("sign", [1, -1])
def test_exact_wide_totals_compare_and_chain_as_integers(materialized, sign):
    wide = sign * (2**63 + 1)
    child = correlation(
        "value_sum", condition={"field": "Bytes", "eq": wide}, name="wide"
    )
    parent = correlation("value_sum", ("wide",), {"field": "sigma_metric", "eq": wide})
    docs = [detection(), child, parent]
    events = [
        event(0, Bytes=str(wide)),
        event(10, Bytes=sign * (2**63 - 1)),
        event(10, Bytes=sign * 2),
    ]
    rows = execute(docs, events, materialized=materialized, sum_mode="exact")
    assert [(r["metric_value"], r["event_ids"]) for r in rows] == [
        (str(wide), ["0:1"]),
        (str(wide), ["0:2", "0:3"]),
    ]
    assert all(len(r["child_alert_ids"]) == 1 for r in rows)
    docs[-1]["correlation"]["condition"]["eq"] = wide + sign
    assert not execute(docs, events, materialized=materialized, sum_mode="exact")


@pytest.mark.parametrize(
    "kind, field",
    [
        ("value_sum", ""),
        ("value_count", ""),
        ("value_avg", 3),
        ("value_median", "metric\x00bad"),
        ("value_count", ["User", None]),
        ("value_count", ["User", "Bytes\x00"]),
        ("value_count", []),
    ],
)
def test_bad_metric_field_does_not_abort_independent_rules(kind, field):
    docs = [
        detection(),
        correlation(kind, condition={"field": field, "gt": 0}),
        detection("independent", 2),
    ]
    backend = sqliteBackend(collect_errors=True)
    entries = json.loads(backend.convert(SigmaCollection.from_dicts(docs), "zircolite"))
    assert [e["title"] for e in entries] == ["independent"]
    [(rule, error)] = backend.errors
    assert rule.title == "corr"
    assert "field" in str(error)


def test_compound_select_limit_is_reported_during_conversion():
    docs = [detection(), correlation("event_count", ["a"] * 501, {"gte": 2})]
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="500"):
        sqliteBackend().convert(SigmaCollection.from_dicts(docs))


@pytest.mark.parametrize("materialized", [False, True])
def test_portable_chain_keeps_int64_metric_precision(materialized):
    value = 9007199254740993
    child = correlation(
        "value_sum", condition={"field": "Bytes", "eq": value}, name="child"
    )
    parent = correlation(
        "value_sum", ("child",), {"field": "value_sum", "gt": value - 1}
    )
    rows = execute(
        [detection(), child, parent],
        [event(0, Bytes=str(value))],
        materialized=materialized,
    )
    assert [(r["metric_value"], r["event_ids"]) for r in rows] == [(value, ["0:1"])]
    assert isinstance(rows[0]["metric_value"], int)


def test_collect_errors_skips_only_failing_correlations():
    keyword = dict(detection("search"), detection={"k": ["needle"], "condition": "k"})
    multi = correlation(
        "value_count", condition={"gte": 2, "field": ["User", "OtherUser"]}
    )
    docs = [
        detection(),
        keyword,
        dict(multi, title="multi", name="multi"),
        correlation(refs=("search",), name="searched"),
        correlation(name="kept"),
    ]
    backend = sqliteBackend(collect_errors=True)
    entries = json.loads(backend.convert(SigmaCollection.from_dicts(docs), "zircolite"))
    assert sorted(entry["title"] for entry in entries) == ["kept", "multi"]
    assert sorted(rule.title for rule, _ in backend.errors) == [
        "search",
        "searched",
    ]


@pytest.mark.parametrize("fulltext_field", [None, "message"])
def test_failed_detection_reports_each_dependent_correlation(fulltext_field):
    broken = detection("broken")
    broken["detection"]["condition"] = "missing"
    docs = [
        broken,
        correlation(refs=("broken",), name="child"),
        correlation(refs=("child",), name="parent"),
        detection("independent"),
    ]
    backend = sqliteBackend(collect_errors=True, fulltext_field=fulltext_field)
    entries = json.loads(backend.convert(SigmaCollection.from_dicts(docs), "zircolite"))
    assert [entry["title"] for entry in entries] == ["independent"]
    errors = {rule.title: error for rule, error in backend.errors}
    assert errors.keys() == {"broken", "child", "parent"}
    assert isinstance(errors["broken"], SigmaConditionError)
    assert "missing" in str(errors["broken"])
    for title in ("child", "parent"):
        assert isinstance(errors[title], SigmaCorrelationRuleError)
        assert str(errors[title]) == (
            f"Correlation {title!r} references 'broken', which has no compiled predicates"
        )


def test_failed_reconversion_invalidates_a_previous_correlation_predicate():
    keyword = dict(detection(), detection={"k": ["needle"], "condition": "k"})
    rules = SigmaCollection.from_dicts([keyword, correlation()])
    assert len(sqliteBackend(fulltext_field="message").convert(rules)) == 1
    backend = sqliteBackend(collect_errors=True)
    assert backend.convert(rules) == []
    assert [rule.title for rule, _ in backend.errors] == ["a", "corr"]
    assert isinstance(backend.errors[-1][1], SigmaCorrelationRuleError)


@pytest.mark.parametrize("result", [None, {}, " "])
def test_correlation_requires_a_nonempty_text_predicate(result):
    backend = sqliteBackend(collect_errors=True)
    rules = SigmaCollection.from_dicts([detection(), correlation()])
    assert backend.convert(rules, callback=lambda *_: result) == []
    [(rule, error)] = backend.errors
    assert rule.title == "corr"
    assert isinstance(error, SigmaCorrelationRuleError)
    assert (
        str(error)
        == "Correlation 'corr' references 'a', which has no compiled predicates"
    )


def test_correlation_requires_conversion_states_for_stored_predicates():
    rules = SigmaCollection.from_dicts([detection(), correlation()])
    rules.resolve_rule_references()
    base, dependent = rules.rules
    base.set_conversion_result(["EventID=1"])
    with pytest.raises(SigmaCorrelationRuleError) as exc:
        sqliteBackend().convert_correlation_rule(dependent)
    assert (
        str(exc.value)
        == "Correlation 'corr' references 'a', which has no compiled predicates"
    )


@pytest.mark.parametrize("value", ["soon", float("inf"), float("nan")])
def test_observation_end_is_validated_at_construction(value):
    with pytest.raises(ValueError, match="observation_end"):
        sqliteBackend(observation_end=value)


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


@pytest.mark.parametrize(
    "change, options, error",
    [
        ({"version": 1}, {}, "plan version"),
        ({"prepare": [{"name": "logs", "select": "SELECT 1"}]}, {}, "relation name"),
        ({}, {"limit": -1}, "limit must be nonnegative"),
    ],
)
def test_execute_plan_rejects_invalid_input(change, options, error):
    c = SigmaCollection.from_dicts([detection(), correlation()])
    plan = json.loads(sqliteBackend().convert(c, "zircolite"))[0]["correlation_plan"]
    con = database([event(0)])
    with pytest.raises(ValueError, match=error):
        execute_plan(con, {**plan, **change}, **options)
    assert con.execute("SELECT COUNT(*) FROM logs").fetchone() == (1,)
    con.close()


def test_execute_plan_requires_sqlite_338(monkeypatch):
    c = SigmaCollection.from_dicts([detection(), correlation()])
    plan = json.loads(sqliteBackend().convert(c, "zircolite"))[0]["correlation_plan"]
    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 37, 2))
    con = database([])
    with pytest.raises(RuntimeError, match="3.38"):
        execute_plan(con, plan)
    con.close()


@pytest.mark.parametrize("materialized", [False, True])
@pytest.mark.parametrize("seconds, starts", [(3, []), (5, [0]), (100, [0, 5])])
def test_observation_end_decides_which_absence_windows_are_complete(
    materialized, seconds, starts
):
    origin = datetime(2024, 1, 1, tzinfo=UTC).timestamp()
    rows = execute(
        [detection(), correlation("temporal", condition="not a")],
        [event(0, EventID=99), event(5, EventID=99)],
        materialized=materialized,
        observation_end=origin + seconds,
    )
    assert [row["window_start"] - origin for row in rows] == pytest.approx(starts)


@pytest.mark.parametrize("materialized", [False, True])
def test_group_by_wider_than_one_json_object(materialized):
    # json_object takes at most 63 pairs on SQLite 3.38.
    fields = [f"F{i:02d}" for i in range(70)]
    docs = [detection(), correlation(**{"group-by": fields})]
    entry = json.loads(
        sqliteBackend().convert(SigmaCollection.from_dicts(docs), "zircolite")
    )[-1]
    con = sqlite3.connect(":memory:")
    con.execute(
        "CREATE TABLE logs (timestamp TEXT, EventID INTEGER, "
        + ", ".join(f"{field} TEXT" for field in fields)
        + ")"
    )
    for t in (0, 1):
        con.execute(
            "INSERT INTO logs VALUES (?, 1, " + ", ".join("?" for _ in fields) + ")",
            [event(t)["timestamp"], *(field.lower() for field in fields)],
        )
    if materialized:
        keys = execute_plan(con, entry["correlation_plan"])[0][0]["group_keys"]
    else:
        keys = json.loads(con.execute(entry["rule"][0]).fetchone()[1])
    con.close()
    assert keys == {field: field.lower() for field in fields}


def test_shared_child_correlation_is_compiled_once():
    docs = [
        detection(),
        detection("b", 2),
        detection("c", 3),
        correlation(condition={"gte": 1}, name="k"),
        correlation("temporal", ("k", "b"), name="c1"),
        correlation("temporal", ("k", "c"), name="c2"),
        correlation("temporal", ("c1", "c2"), name="p"),
    ]
    entry = json.loads(
        sqliteBackend().convert(SigmaCollection.from_dicts(docs), "zircolite")
    )[-1]
    stages = entry["correlation_plan"]["prepare"]
    assert sum(stage["name"].endswith("_alerts") for stage in stages) == 4
    # SQLite 3.54 rejects the single statement of a chain this deep, so run the plan.
    rows = execute(
        docs, [event(0), event(1, EventID=2), event(2, EventID=3)], materialized=True
    )
    assert [(row["metric_value"], row["event_ids"]) for row in rows] == [
        (2, ["0:1", "0:2", "0:3"])
    ]


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


@pytest.mark.parametrize("generate", [None, False, True])
@pytest.mark.parametrize("output_format", ["default", "zircolite"])
def test_chained_generate_controls_child_output(generate, output_format):
    parent = correlation("event_count", ("burst",), {"gte": 1})
    if generate is not None:
        parent["correlation"]["generate"] = generate
    output = sqliteBackend().convert(
        SigmaCollection.from_dicts([detection(), correlation(name="burst"), parent]),
        output_format,
    )
    entries = json.loads(output) if output_format == "zircolite" else output
    assert len(entries) == (2 if generate else 1)
    if output_format == "zircolite":
        assert [entry["title"] for entry in entries] == (
            ["burst", "corr"] if generate else ["corr"]
        )
    else:
        assert all(query.startswith("WITH ") for query in entries)


@pytest.mark.parametrize("materialized", [False, True])
@pytest.mark.parametrize("grouped", [False, True])
def test_overlapping_chained_branches_merge_sorted_evidence(materialized, grouped):
    parent = correlation(
        "temporal",
        ("burst", "success"),
        "burst or (burst and success) or success",
        **{"group-by": ["Host"] if grouped else []},
    )
    docs = [detection(), detection("success", 2), correlation(name="burst"), parent]
    events = [
        event(0),
        event(1),
        event(2),
        event(2, EventID=2),
        event(20, Host="other"),
        event(21, Host="other"),
        event(22, Host="other"),
        event(22, Host="other", EventID=2),
    ]
    rows = execute(docs, events, materialized=materialized)
    assert len(rows) == 4
    for row, ids, host in zip(
        (rows[1], rows[3]),
        (["0:1", "0:2", "0:3", "0:4"], ["0:5", "0:6", "0:7", "0:8"]),
        ("h", "other"),
    ):
        assert row["group_keys"] == ({"Host": host} if grouped else {})
        assert row["event_ids"] == ids
        assert row["event_count"] == 4
        assert row["metric_value"] == 2
        assert len(row["child_alert_ids"]) == 2
        assert row["child_alert_ids"] == sorted(set(row["child_alert_ids"]))


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


def plan_for(docs):
    return json.loads(
        sqliteBackend(event_id_field="row_id").convert(
            SigmaCollection.from_yaml(yaml.safe_dump_all(docs)), "zircolite"
        )
    )[-1]["correlation_plan"]


def test_evidence_is_fetched_with_one_scan_per_source_table():
    # More evidence IDs than the old 400-ID chunking, which scanned once per chunk.
    events = [event(i * 0.05) for i in range(900)]
    con = database(events)
    statements = []
    con.set_trace_callback(statements.append)
    try:
        rows, _ = execute_plan(con, plan_for([detection(), correlation()]))
    finally:
        con.set_trace_callback(None)
        con.close()
    assert len({i for r in rows for i in r["event_ids"]}) == 900
    assert all([e["event_id"] for e in r["evidence"]] == r["event_ids"] for r in rows)
    assert len([s for s in statements if s.startswith("SELECT CAST(")]) == 1


@pytest.mark.parametrize("materialized", [False, True])
def test_alerts_are_ordered_by_occurrence_time(materialized):
    # Alert IDs are numbered by group first, so "a" would precede "b" unordered.
    events = [event(10, Host="a"), event(11, Host="a")]
    events += [event(0, Host="b"), event(1, Host="b")]
    rows = execute([detection(), correlation()], events, materialized=materialized)
    assert [r["group_keys"]["Host"] for r in rows] == ["b", "a"]


def test_limit_keeps_the_earliest_alerts():
    con = database(
        [
            event(10, Host="a"),
            event(11, Host="a"),
            event(0, Host="b"),
            event(1, Host="b"),
        ]
    )
    try:
        rows, _ = execute_plan(con, plan_for([detection(), correlation()]), limit=0)
    finally:
        con.close()
    assert [r["group_keys"]["Host"] for r in rows] == ["b"]
