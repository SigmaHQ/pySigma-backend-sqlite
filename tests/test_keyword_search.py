"""Keyword SQL is exercised against SQLite, including correlation plans."""

import json
import sqlite3

import pytest
import yaml
from helpers import regexp
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import SetStateTransformation

from sigma.backends.sqlite import runtime, sqliteBackend


def convert(docs, *, field="_sigma_fulltext", **options):
    collection = SigmaCollection.from_yaml(yaml.safe_dump_all(docs))
    return sqliteBackend(fulltext_field=field, **options).convert(
        collection, "zircolite"
    )


def detection(selection, condition="selection", *, name="search"):
    return {
        "title": name,
        "name": name,
        "logsource": {"category": "test"},
        "detection": {"selection": selection, "condition": condition},
    }


def database(values):
    connection = sqlite3.connect(":memory:")
    connection.execute(
        'CREATE TABLE logs (timestamp TEXT, Host TEXT, EventID INTEGER, "_sigma_fulltext" TEXT)'
    )
    connection.executemany(
        "INSERT INTO logs VALUES (?, ?, ?, ?)",
        [(f"2024-01-01T00:00:{i:02d}", "h", 1, text) for i, text in enumerate(values)],
    )
    connection.create_function("REGEXP", 2, regexp)
    return connection


@pytest.mark.parametrize(
    "selection,values,expected",
    [
        (["foo", "bar"], ["prefix FOO suffix", "a bar", "baz"], [0, 1]),
        ([123], ["code 123 end", "code 1234 end", "code 12 end"], [0, 1]),
        ([r"foo\*bar"], ["foo*bar", "fooxbar"], [0]),
        ([r"foo\?bar"], ["foo?bar", "fooxbar"], [0]),
        (["it's 100%_"], ["it's 100%_", "its 100%_", "it's 100AB"], [0]),
        ([r"C:\Temp\file.exe"], [r"C:\Temp\file.exe", "C:Tempfile.exe"], [0]),
        (["foo?bar"], ["fooxbar", "foo?bar", "foobar"], [0, 1]),
        ([{"|cased": "Fo*"}], ["Foo", "foo", "Fop"], [0, 2]),
        ([{"|cased": ["Foo", "Bar"]}], ["Foo", "foo", "Bar", "bar"], [0, 2]),
        ([{"|cased|all": ["Foo", "Bar"]}], ["Foo Bar", "foo bar", "Foo bar"], [0]),
        ([{"|windash": "-flag"}], ["x /flag", "x -flag", "x flag"], [0, 1]),
        ([{"|base64offset": "evil"}], ["ZXZpbA==", "evil"], [0]),
        ([{"|re": "(?i)fo+"}], ["FOO", "bar"], [0]),
        ([{"|re|i": "fo+"}], ["FOO", "bar"], [0]),
        ([{"|re|m": "^foo"}], ["bar\nfoo", "bar foo"], [0]),
        ([{"|all": ["alpha", "beta"]}], ["beta alpha", "alpha", "beta"], [0]),
    ],
)
def test_keyword_predicates_execute(selection, values, expected):
    entry = json.loads(convert([detection(selection)]))[0]
    with database(values) as connection:
        actual = [
            int(row[0][-2:]) for row in connection.execute(entry["rule"][0]).fetchall()
        ]
    assert actual == expected
    assert entry["schema_version"] == 3
    assert entry["fulltext"] == [
        {
            "table": "logs",
            "field": "_sigma_fulltext",
            "representation": "source-values-v1",
        }
    ]
    assert "_sigma_fulltext" in entry["required_fields"]


def test_condition_list_declares_only_the_fields_and_prerequisites_each_entry_reads():
    doc = detection(["needle"])
    doc["detection"].update(other={"EventID": 2}, condition=["selection", "other"])
    keyword, ordinary = json.loads(convert([doc]))
    assert keyword["schema_version"] == 3
    assert keyword["required_fields"] == ["_sigma_fulltext"]
    assert keyword["fulltext"][0]["field"] == "_sigma_fulltext"
    assert ordinary["schema_version"] == 2
    assert ordinary["required_fields"] == ["EventID"]
    assert "fulltext" not in ordinary
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(EventID INTEGER)")
        db.execute("INSERT INTO logs VALUES (2)")
        assert db.execute(ordinary["rule"][0]).fetchall() == [(2,)]
        with pytest.raises(ValueError, match="_sigma_fulltext"):
            runtime.validate_fulltext(db, keyword["fulltext"])


def test_callback_skipping_a_condition_preserves_the_next_querys_requirements():
    doc = detection(["needle"])
    doc["detection"].update(
        net={"Ip|cidr": "10.0.0.0/8"}, condition=["selection", "net"]
    )
    backend = sqliteBackend(fulltext_field="_text", cidr_mode="exact")
    (entry,) = json.loads(
        backend.convert(
            SigmaCollection.from_dicts([doc]),
            "zircolite",
            callback=lambda rule, fmt, index, condition, predicate: (
                predicate if index else None
            ),
        )
    )
    assert entry["required_fields"] == ["Ip"]
    assert entry["schema_version"] == 4
    assert entry["required_sql_functions"] == ["sigma_cidr_contains"]
    assert "fulltext" not in entry


def test_correlation_inherits_keyword_requirements_and_hides_evidence_column():
    corr = {
        "title": "burst",
        "name": "burst",
        "correlation": {
            "type": "event_count",
            "rules": ["search"],
            "timespan": "5s",
            "group-by": ["Host"],
            "condition": {"gte": 2},
        },
    }
    event = json.loads(convert([detection(["needle"])]))[0]
    correlated = json.loads(convert([detection(["needle"]), corr]))[0]
    assert correlated["schema_version"] == 3
    assert correlated["fulltext"] == event["fulltext"]
    plan = correlated["correlation_plan"]
    assert plan["version"] == 3
    assert plan["fulltext"] == event["fulltext"]
    assert "_sigma_fulltext" in plan["required_fields"]["logs"]
    with database(["needle", "needle"]) as connection:
        rows, _ = runtime.execute_plan(connection, plan)
    assert len(rows) == 1
    assert all("_sigma_fulltext" not in item["event"] for item in rows[0]["evidence"])


def test_validate_fulltext_rejects_missing_nontext_and_null_before_widening():
    requirement = [
        {
            "table": "logs",
            "field": "_sigma_fulltext",
            "representation": "source-values-v1",
        }
    ]
    with database(["ok", None]) as connection:
        with pytest.raises(ValueError, match="re-ingest|fulltext|text"):
            runtime.validate_fulltext(connection, requirement)
        connection.execute(
            "UPDATE logs SET _sigma_fulltext=? WHERE _sigma_fulltext IS NULL", (b"123",)
        )
        with pytest.raises(ValueError, match="re-ingest|fulltext|text"):
            runtime.validate_fulltext(connection, requirement)
        connection.execute(
            "UPDATE logs SET _sigma_fulltext='123' WHERE typeof(_sigma_fulltext)='blob'"
        )
        runtime.validate_fulltext(connection, requirement)
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE logs (EventID INTEGER)")
        with pytest.raises(ValueError, match="re-ingest|fulltext|text"):
            runtime.validate_fulltext(connection, requirement)
        assert [c[1] for c in connection.execute("PRAGMA table_info(logs)")] == [
            "EventID"
        ]


def test_keyword_without_fulltext_field_has_actionable_error():
    collection = SigmaCollection.from_yaml(yaml.safe_dump(detection(["needle"])))
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="fulltext_field"):
        sqliteBackend().convert(collection)


def test_keyword_without_fulltext_field_is_skipped_when_collecting_errors():
    collection = SigmaCollection.from_yaml(
        yaml.safe_dump_all(
            [detection(["needle"]), detection({"Host": "h"}, name="named")]
        )
    )
    backend = sqliteBackend(collect_errors=True)
    assert backend.convert(collection) == ["SELECT * FROM logs WHERE Host='h'"]
    assert [rule.title for rule, _ in backend.errors] == ["search"]


def test_fulltext_preflight_does_not_widen_old_table():
    corr = {
        "title": "burst",
        "name": "burst",
        "correlation": {
            "type": "event_count",
            "rules": ["search"],
            "timespan": "5s",
            "group-by": ["Host"],
            "condition": {"gte": 1},
        },
    }
    plan = json.loads(convert([detection(["needle"]), corr]))[0]["correlation_plan"]
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE logs (timestamp TEXT, EventID INTEGER)")
        with pytest.raises(ValueError, match="re-ingest"):
            runtime.execute_plan(connection, plan)
        assert [
            column[1] for column in connection.execute("PRAGMA table_info(logs)")
        ] == ["timestamp", "EventID"]


def test_keyword_boolean_not_and_quoted_identifiers_execute():
    doc = detection(["needle"])
    doc["detection"].update(other={"EventID": 2}, condition="selection and not other")
    entry = json.loads(convert([doc], field="select", table="my table"))[0]
    assert entry["fulltext"] == [
        {"table": "`my table`", "field": "select", "representation": "source-values-v1"}
    ]
    with sqlite3.connect(":memory:") as connection:
        connection.execute('CREATE TABLE "my table" (EventID INTEGER, "select" TEXT)')
        connection.executemany(
            'INSERT INTO "my table" VALUES (?, ?)',
            [(1, "a needle b"), (2, "needle"), (1, "other")],
        )
        assert connection.execute(entry["rule"][0]).fetchall() == [(1, "a needle b")]


def test_long_keyword_alternatives_execute_without_expression_depth_error():
    alternatives = [f"absent_{i}" for i in range(1200)] + ["needle"]
    entry = json.loads(convert([detection(alternatives)]))[0]
    with database(["needle", "haystack"]) as connection:
        assert len(connection.execute(entry["rule"][0]).fetchall()) == 1


def test_runtime_rejects_bad_fulltext_requirement_shapes():
    with database(["needle"]) as connection:
        for requirements in (
            None,
            [],
            {},
            [{}],
            [
                {
                    "table": "logs",
                    "field": "_sigma_fulltext",
                    "representation": "unknown",
                }
            ],
            [
                {
                    "table": "logs; DROP TABLE logs",
                    "field": "_sigma_fulltext",
                    "representation": "source-values-v1",
                }
            ],
        ):
            with pytest.raises(ValueError):
                runtime.validate_fulltext(connection, requirements)
        assert connection.execute("SELECT COUNT(*) FROM logs").fetchone() == (1,)


def test_multi_source_chained_correlation_inherits_keyword_table():
    keyword = detection(["needle"], name="keyword")
    keyword["logsource"]["category"] = "first"
    other = detection({"EventID": 2}, name="other")
    other["logsource"]["category"] = "second"
    child = {
        "title": "child",
        "name": "child",
        "correlation": {
            "type": "event_count",
            "rules": ["keyword"],
            "timespan": "5s",
            "group-by": ["Host"],
            "condition": {"gte": 1},
        },
    }
    parent = {
        "title": "parent",
        "name": "parent",
        "correlation": {
            "type": "temporal",
            "rules": ["child", "other"],
            "timespan": "5s",
            "group-by": ["Host"],
        },
    }
    pipeline = ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=SetStateTransformation("table", "first logs"),
                rule_conditions=[LogsourceCondition(category="first")],
            ),
            ProcessingItem(
                transformation=SetStateTransformation("table", "second logs"),
                rule_conditions=[LogsourceCondition(category="second")],
            ),
        ]
    )
    entries = json.loads(
        sqliteBackend(
            fulltext_field="_sigma_fulltext", processing_pipeline=pipeline
        ).convert(
            SigmaCollection.from_yaml(
                yaml.safe_dump_all([keyword, other, child, parent])
            ),
            "zircolite",
        )
    )
    parent_plan = entries[-1]["correlation_plan"]
    child_plan = json.loads(
        sqliteBackend(
            fulltext_field="_sigma_fulltext", processing_pipeline=pipeline
        ).convert(
            SigmaCollection.from_yaml(yaml.safe_dump_all([keyword, child])), "zircolite"
        )
    )[-1]["correlation_plan"]
    required = [
        {
            "table": "`first logs`",
            "field": "_sigma_fulltext",
            "representation": "source-values-v1",
        }
    ]
    assert all(
        plan["version"] == 3 and plan["fulltext"] == required
        for plan in (child_plan, parent_plan)
    )
    assert all(
        entry["fulltext"] == required for entry in entries if entry.get("correlation")
    )
    with sqlite3.connect(":memory:") as connection:
        for table in ("first logs", "second logs"):
            connection.execute(
                f'CREATE TABLE "{table}" (timestamp TEXT, Host TEXT, EventID INTEGER, _sigma_fulltext TEXT)'
            )
        connection.execute(
            'INSERT INTO "first logs" VALUES ("2024-01-01T00:00:00", "h", 1, "needle")'
        )
        connection.execute(
            'INSERT INTO "second logs" VALUES ("2024-01-01T00:00:01", "h", 2, "other")'
        )
        rows, _ = runtime.execute_plan(connection, parent_plan)
    assert len(rows) == 1
    assert {item["source_table"] for item in rows[0]["evidence"]} == {
        "`first logs`",
        "`second logs`",
    }


def test_correlation_preflight_hook_keeps_default_validation():
    corr = {
        "title": "burst",
        "name": "burst",
        "correlation": {
            "type": "event_count",
            "rules": ["search"],
            "timespan": "5s",
            "group-by": ["Host"],
            "condition": {"gte": 2},
        },
    }
    plan = json.loads(convert([detection(["needle"]), corr]))[0]["correlation_plan"]
    with database(["needle", "needle"]) as connection:
        traced = []
        connection.set_trace_callback(traced.append)

        def coverage_count():
            return sum(
                statement.lower().startswith("select 1 from logs where")
                and "typeof(" in statement.lower()
                and "_sigma_fulltext" in statement.lower()
                for statement in traced
            )

        assert len(runtime.execute_plan(connection, plan)[0]) == 1
        assert coverage_count() == 1
        traced.clear()
        assert len(runtime.execute_plan(connection, plan)[0]) == 1
        assert coverage_count() == 1

        checked = False
        calls = []

        def cached_preflight(requirements):
            nonlocal checked
            calls.append(requirements)
            if not checked:
                runtime.validate_fulltext(connection, requirements)
                checked = True

        traced.clear()
        assert (
            len(
                runtime.execute_plan(
                    connection, plan, fulltext_preflight=cached_preflight
                )[0]
            )
            == 1
        )
        assert coverage_count() == 1
        traced.clear()
        assert (
            len(
                runtime.execute_plan(
                    connection, plan, fulltext_preflight=cached_preflight
                )[0]
            )
            == 1
        )
        assert coverage_count() == 0
        assert calls == [plan["fulltext"], plan["fulltext"]]

        connection.execute("UPDATE logs SET _sigma_fulltext=NULL")
        traced.clear()
        with pytest.raises(ValueError, match="re-ingest"):
            runtime.execute_plan(connection, plan)
        assert coverage_count() == 1
