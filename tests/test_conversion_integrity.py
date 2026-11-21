"""Run retained conditions and their exported prerequisites through public entry points."""

import copy
import json
import pickle
import sqlite3

import pytest
from helpers import correlation, detection
from sigma.collection import SigmaCollection
from sigma.exceptions import (
    SigmaConversionError,
    SigmaCorrelationRuleError,
    SigmaTransformationError,
)
from sigma.processing.pipeline import ProcessingPipeline

from sigma.backends.sqlite import sqliteBackend
from sigma.backends.sqlite.correlation import ReferenceConversionError
from sigma.backends.sqlite.runtime import execute_plan


def pipeline(*steps):
    return ProcessingPipeline.from_dict({"transformations": list(steps)})


def for_title(title, **step):
    return {
        **step,
        "rule_conditions": [
            {"type": "rule_attribute", "attribute": "title", "value": title}
        ],
    }


def mixed_rule(conditions):
    rule = detection()
    rule["detection"] = {
        "dead": {"Removed": 1},
        "ordinary": {"EventID": 1},
        "keyword": ["needle"],
        "network": {"IP|cidr": "10.0.0.0/24"},
        "condition": conditions,
    }
    return rule


def backend_dropping_removed():
    return sqliteBackend(
        pipeline(
            {
                "type": "drop_detection_item",
                "field_name_conditions": [
                    {"type": "include_fields", "fields": ["Removed"]}
                ],
            }
        ),
        cidr_mode="exact",
        fulltext_field="message",
    )


@pytest.mark.parametrize("identity_callback", [False, True])
def test_pipeline_omissions_preserve_each_conditions_schema_and_sql(identity_callback):
    conditions = ["dead", "keyword", "dead", "network", "ordinary"]
    seen = []

    def identity(rule, fmt, index, condition, predicate):
        seen.append(index)
        return predicate

    entries = json.loads(
        backend_dropping_removed().convert(
            SigmaCollection.from_dicts([mixed_rule(conditions)]),
            "zircolite",
            callback=identity if identity_callback else None,
        )
    )
    assert [
        (e["schema_version"], e["required_fields"], e["eventid"]) for e in entries
    ] == [
        (3, ["message"], []),
        (4, ["IP"], []),
        (2, ["EventID"], [1]),
    ]
    assert entries[0]["fulltext"][0]["field"] == "message"
    assert entries[1]["required_sql_functions"] == ["sigma_cidr_contains"]
    if identity_callback:
        assert seen == list(range(len(conditions)))
    assert (
        json.loads(
            backend_dropping_removed().convert(
                SigmaCollection.from_dicts([mixed_rule(["dead", "dead"])]),
                "zircolite",
                callback=identity if identity_callback else None,
            )
        )
        == []
    )


def test_nested_generate_uses_only_retained_predicates_and_can_be_reconverted_directly():
    rules = SigmaCollection.from_dicts(
        [
            mixed_rule(["dead", "keyword", "network", "ordinary"]),
            correlation(name="child", condition={"gte": 1}, generate=True),
            correlation(
                refs=("child",), name="parent", condition={"gte": 1}, generate=True
            ),
        ]
    )
    backend = backend_dropping_removed()

    def select(rule, fmt, index, condition, predicate):
        return None if rule.name == "a" and index in (1, 2) else predicate

    entries = json.loads(backend.convert(rules, "zircolite", callback=select))
    assert [entry["title"] for entry in entries] == ["a", "child", "parent"]
    base, child, parent = rules.rules
    assert base.get_conversion_result() == ["EventID=1"]
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(EventID INTEGER, timestamp TEXT, Host TEXT)")
        db.execute("INSERT INTO logs VALUES(1,'2025-01-01','x')")
        for entry in entries[1:]:
            assert entry["schema_version"] == entry["correlation_plan"]["version"] == 2
            assert entry["required_fields"] == ["EventID", "Host", "timestamp"]
            assert len(db.execute(entry["rule"][0]).fetchall()) == 1
            rows, _ = execute_plan(db, entry["correlation_plan"])
            assert [row["event_ids"] for row in rows] == [["0:1"]]

    backend.convert_rule(base, "zircolite", callback=lambda *_: None)
    with pytest.raises(SigmaCorrelationRuleError, match="no compiled predicates"):
        backend.convert_correlation_rule(child, "zircolite")
    backend.convert_rule(base, "zircolite")
    backend.convert_correlation_rule(child, "zircolite")
    [entry] = backend.convert_correlation_rule(parent, "zircolite")
    assert entry["schema_version"] == 4
    assert entry["required_fields"] == ["EventID", "Host", "IP", "message", "timestamp"]
    assert entry["fulltext"][0]["field"] == "message"


@pytest.mark.parametrize(
    "target,replacement", [("a", "Other=1"), ("child", "SELECT 1 WHERE 0")]
)
def test_structured_replacement_reports_the_rule_and_plain_sql_honors_it(
    target, replacement
):
    docs = [detection(), correlation(name="child", generate=True)]
    rules = SigmaCollection.from_dicts(docs)

    def replace(rule, fmt, index, condition, predicate):
        return replacement if rule.name == target else predicate

    backend = sqliteBackend()
    with pytest.raises(SigmaConversionError) as caught:
        backend.convert(rules, "zircolite", callback=replace)
    assert caught.value.rule.name == target
    queries = backend.convert(rules, callback=replace)
    assert replacement in queries[0 if target == "a" else -1]
    assert backend.convert(rules, "zircolite")


@pytest.mark.parametrize(
    "minimum,expected", [(99, []), (2, [(2, ["1:id:\x00a", "1:id:\x00b"])])]
)
def test_plain_sql_parent_consumes_replaced_child_rows(minimum, expected):
    # The extra reference is the parent's first source. The child's table ID
    # changes from 0 to 1 inside the parent.
    docs = [
        detection("other", 99),
        detection(),
        correlation(name="child", condition={"gte": 1}),
        correlation(
            "value_sum", ("other", "child"), {"field": "sigma_metric", "gte": 1}
        ),
    ]
    backend = sqliteBackend(
        pipeline(for_title("other", type="set_state", key="table", val="other_logs")),
        event_id_field="id",
    )
    calls = []

    def select(rule, fmt, index, condition, sql):
        if rule.name == "child":
            calls.append(rule.name)
            return f"SELECT * FROM ({sql}) WHERE metric_value >= {minimum}"
        return sql

    (parent,) = backend.convert(SigmaCollection.from_dicts(docs), callback=select)
    assert calls == ["child"]
    with sqlite3.connect(":memory:") as db:
        db.execute(
            "CREATE TABLE other_logs(Host, EventID, timestamp, sigma_metric, id)"
        )
        db.execute("CREATE TABLE logs(Host, EventID, timestamp, id)")
        db.executemany(
            "INSERT INTO logs VALUES('h',1,?,?)",
            [("2025-01-01", "id:\x00a"), ("2025-01-01T00:00:01", "id:\x00b")],
        )
        rows = db.execute(parent).fetchall()
    assert [(row[6], json.loads(row[8])) for row in rows] == expected


def test_plain_sql_parent_reads_replacement_metric_and_complete_group_text():
    docs = [
        detection(),
        correlation(name="child", condition={"gte": 1}),
        correlation("value_sum", ("child",), {"field": "sigma_metric", "eq": 8}),
    ]
    # Include both a literal JSON escape spelling and the corresponding control
    # character to distinguish escaping from actual data.
    group = "one\x00two\\u0000three\x01"

    def replace(rule, fmt, i, cond, sql):
        if rule.name == "child":
            return (
                "SELECT alert_id, occurrence_time, event_ids, "
                "json_object('Host', ?) AS group_keys, metric_value + 7 AS metric_value "
                f"FROM ({sql})"
            )
        return sql

    (query,) = sqliteBackend().convert(
        SigmaCollection.from_dicts(docs), callback=replace
    )
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(Host, EventID, timestamp)")
        db.execute("INSERT INTO logs VALUES('h',1,'2025-01-01')")
        (row,) = db.execute(query, (group,)).fetchall()
    assert (json.loads(row[1]), row[6]) == ({"Host": group}, 8)


def test_reconvert_replaced_child_when_its_source_table_changes():
    rules = SigmaCollection.from_dicts(
        [
            detection(),
            correlation(name="child"),
            correlation(refs=("child",), name="parent"),
        ]
    )
    rules.resolve_rule_references()
    base, child, parent = rules.rules
    backend = sqliteBackend()
    backend.convert_rule(base)
    backend.convert_correlation_rule(
        child, callback=lambda *args: args[-1] + " LIMIT 1"
    )
    sqliteBackend(table="archive").convert_rule(base)
    with pytest.raises(SigmaCorrelationRuleError, match="child.*source tables"):
        backend.convert_correlation_rule(parent)
    backend.convert_correlation_rule(
        child, callback=lambda *args: args[-1] + " LIMIT 1"
    )
    assert backend.convert_correlation_rule(parent)


def test_failed_intermediate_blocks_all_parents_until_retry():
    steps = pipeline(for_title("child", type="rule_failure", message="child rejected"))
    docs = [
        detection(),
        correlation(name="child", condition={"gte": 1}),
        correlation(refs=("child",), name="first", condition={"gte": 1}),
        correlation(refs=("child",), name="second", condition={"gte": 1}),
        detection("independent"),
    ]
    rules = SigmaCollection.from_dicts(docs)
    with pytest.raises(SigmaTransformationError, match="child rejected"):
        sqliteBackend(steps).convert(rules, "zircolite")
    backend = sqliteBackend(steps, collect_errors=True)
    assert [
        entry["title"] for entry in json.loads(backend.convert(rules, "zircolite"))
    ] == ["independent"]
    errors = {rule.name: error for rule, error in backend.errors}
    assert isinstance(errors["child"], SigmaTransformationError)
    for name in ("first", "second"):
        assert name in str(errors[name]) and "child" in str(errors[name])
    backend.processing_pipeline = None
    entries = json.loads(backend.convert(rules, "zircolite"))
    assert {e["title"] for e in entries} == {"first", "second", "independent"}
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(EventID INTEGER, timestamp TEXT, Host TEXT)")
        db.execute("INSERT INTO logs VALUES(1,'2025-01-01','x')")
        assert all(len(db.execute(e["rule"][0]).fetchall()) == 1 for e in entries)


def event_entry(item):
    rule = detection()
    rule["detection"]["s"] = item
    return json.loads(
        sqliteBackend().convert(SigmaCollection.from_dicts([rule]), "zircolite")
    )[0]


def test_eventid_bounds_survive_historical_integer_coercion():
    rule = detection()
    rule["detection"].update(
        s={"EventID": [1, 2]}, decimal={"EventID": "1.0"}, condition="s and decimal"
    )
    [entry] = json.loads(
        sqliteBackend().convert(SigmaCollection.from_dicts([rule]), "zircolite")
    )
    assert all(type(value) is int for value in entry["eventid"])
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(EventID INTEGER)")
        db.executemany("INSERT INTO logs VALUES(?)", [(1,), (2,)])
        assert db.execute(entry["rule"][0]).fetchall() == [(1,)]
    assert 1 in set(map(int, entry["eventid"]))


@pytest.mark.parametrize("value", ["abc", "1.5", 1.5, "9e999", "9007199254740993.0"])
def test_ambiguous_eventid_widens_disjunction(value):
    assert event_entry({"EventID": [2, value]})["eventid"] == []


def test_literal_channel_bounds_match_sql_after_sigma_escaping():
    entry = event_entry({"Channel": r"A\*B\?C"})
    assert entry["channel"] == ["A*B?C"]
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(Channel TEXT)")
        db.execute("INSERT INTO logs VALUES ('A*B?C')")
        assert db.execute(entry["rule"][0]).fetchall() == [("A*B?C",)]


def test_table_override_errors_are_rule_scoped():
    with pytest.raises(ValueError, match="table"):
        sqliteBackend(table="a.b.c")
    backend = sqliteBackend(
        pipeline(for_title("bad", type="set_state", key="table", val="main.bad.name")),
        table="main.logs",
        collect_errors=True,
    )
    entries = json.loads(
        backend.convert(
            SigmaCollection.from_dicts([detection("bad"), detection("good")]),
            "zircolite",
        )
    )
    assert [e["title"] for e in entries] == ["good"]
    assert [r.title for r, _ in backend.errors] == ["bad"]
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(EventID INTEGER)")
        assert db.execute(entries[0]["rule"][0]).fetchall() == []


def test_numeric_comparison_rejects_nul_terminated_prefix():
    entry = event_entry({"v|gt": 10})
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(v TEXT)")
        db.executemany("INSERT INTO logs VALUES(?)", [("11",), ("11\x00junk",)])
        assert db.execute(entry["rule"][0]).fetchall() == [("11",)]


def test_presence_table_override_errors_are_collectable_before_finalization():
    backend = sqliteBackend(
        pipeline(for_title("bad", type="set_state", key="table", val="main.bad.name")),
        presence_field="keys",
        collect_errors=True,
    )
    bad = detection("bad")
    bad["detection"]["s"] = {"value|exists": True}
    entries = json.loads(
        backend.convert(
            SigmaCollection.from_dicts([bad, detection("good")]), "zircolite"
        )
    )
    assert [entry["title"] for entry in entries] == ["good"]
    assert [rule.title for rule, error in backend.errors] == ["bad"]


def test_direct_correlation_preserves_the_converted_predicates_source():
    rules = SigmaCollection.from_dicts(
        [
            mixed_rule(["keyword"]),
            correlation(condition={"gte": 1}),
        ]
    )
    rules.resolve_rule_references()
    base, parent = rules.rules
    original = sqliteBackend(fulltext_field="raw_message", table="custom")
    original.convert_rule(base)
    [entry] = sqliteBackend().convert_correlation_rule(parent, "zircolite")
    assert entry["schema_version"] == 3
    assert entry["required_fields"] == ["Host", "raw_message", "timestamp"]
    assert entry["fulltext"][0]["table"] == "custom"
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE custom(raw_message TEXT, timestamp TEXT, Host TEXT)")
        db.execute("INSERT INTO custom VALUES('a needle','2025-01-01','x')")
        assert len(db.execute(entry["rule"][0]).fetchall()) == 1
        rows, _ = execute_plan(db, entry["correlation_plan"])
        assert [row["metric_value"] for row in rows] == [1]


def test_reference_only_callback_drop_does_not_retain_a_pending_plan():
    rules = SigmaCollection.from_dicts(
        [
            detection(),
            correlation(name="child", condition={"gte": 1}),
            correlation(refs=("child",), name="parent", condition={"gte": 1}),
        ]
    )
    backend = sqliteBackend(collect_errors=True)
    result = backend.convert(
        rules,
        "zircolite",
        callback=lambda rule, fmt, i, q, sql: None if rule.name == "child" else sql,
    )
    assert json.loads(result) == []
    assert [rule.name for rule, error in backend.errors] == ["parent"]
    assert backend._correlation_plans == {}
    [entry] = json.loads(backend.convert(rules, "zircolite"))
    assert entry["title"] == "parent"


def test_channel_that_depends_on_sqlite_numeric_affinity_widens():
    entry = event_entry({"Channel": "001"})
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(Channel NUMERIC)")
        db.execute("INSERT INTO logs VALUES('1')")
        assert db.execute(entry["rule"][0]).fetchall() == [(1,)]
    assert entry["channel"] == []


@pytest.mark.parametrize(
    "field, rule_values, pipeline_values, expected",
    [
        pytest.param(
            "Channel",
            [
                "Microsoft-Windows-PowerShell/Operational",
                "Microsoft-Windows-Sysmon/Operational",
                "PowerShellCore/Operational",
                "Security",
                "System",
                "Windows PowerShell",
            ],
            "System",
            ["System"],
            id="win_system_susp_eventlog_cleared",
        ),
        pytest.param(
            "EventID", [12, 13], [12, 13, 14], [12, 13], id="registry_event_mal_azorult"
        ),
    ],
)
def test_restored_sysmon_prefilters(field, rule_values, pipeline_values, expected):
    # These are the competing constraints from the two pinned corpus rules.
    rule = detection()
    rule["detection"]["s"] = {field: rule_values}
    backend = sqliteBackend(
        pipeline({"type": "add_condition", "conditions": {field: pipeline_values}})
    )
    [entry] = json.loads(
        backend.convert(SigmaCollection.from_dicts([rule]), "zircolite")
    )
    assert entry[field.lower()] == expected


def test_direct_retry_uses_the_current_pipeline():
    rules = SigmaCollection.from_dicts([detection(), correlation(name="child")])
    rules.resolve_rule_references()
    base, child = rules.rules
    backend = sqliteBackend(
        pipeline(for_title("child", type="rule_failure", message="disabled"))
    )
    backend.convert_rule(base)
    with pytest.raises(SigmaTransformationError, match="disabled"):
        backend.convert_correlation_rule(child)
    backend.processing_pipeline = None
    assert len(backend.convert_correlation_rule(child)) == 1


def test_custom_storage_can_disable_prefilter_bounds():
    rule = detection()
    rule["detection"]["s"] = {"Channel": "System", "EventID": 1}

    def compile_entry(**options):
        return json.loads(
            sqliteBackend(**options).convert(
                SigmaCollection.from_dicts([rule]), "zircolite"
            )
        )[0]

    standard = compile_entry()
    entry = compile_entry(prefilter_bounds="false")
    assert (standard["channel"], standard["eventid"]) == (["System"], [1])
    assert (entry["channel"], entry["eventid"]) == ([], [])
    assert standard["rule"] == entry["rule"]
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(Channel TEXT COLLATE RTRIM, EventID INTEGER)")
        db.execute("INSERT INTO logs VALUES('System ',1)")
        assert db.execute(entry["rule"][0]).fetchall() == [("System ", 1)]
    with pytest.raises(ValueError, match="prefilter_bounds"):
        sqliteBackend(prefilter_bounds=[])


def test_reference_errors_survive_pickling_and_copying():
    rules = SigmaCollection.from_dicts([detection(), correlation(name="parent")])
    rules.resolve_rule_references()
    error = ReferenceConversionError(rules.rules[1], "child", "failed to convert")
    for clone in (pickle.loads(pickle.dumps(error)), copy.copy(error)):
        assert type(clone) is ReferenceConversionError
        assert (str(clone), clone.dependency, clone.reason, clone.source) == (
            str(error),
            "child",
            "failed to convert",
            error.source,
        )
