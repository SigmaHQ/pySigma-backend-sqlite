import json
import re
import sqlite3

import pytest
import yaml
from helpers import correlation, detection
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

from sigma.backends.sqlite import runtime, sqliteBackend


def compile_docs(docs, **options):
    collection = SigmaCollection.from_yaml(yaml.safe_dump_all(docs))
    return json.loads(sqliteBackend(**options).convert(collection, "zircolite"))


def entry_for(selection, *, condition="s", **options):
    doc = detection()
    doc["detection"] = {"s": selection, "condition": condition}
    return compile_docs([doc], **options)[0]


@pytest.mark.parametrize(
    "selection,condition,matched",
    [
        ({"name": "CAFÉ"}, "s", [1]),
        ({"name": "STRASSE"}, "s", [2]),
        ({"name|contains": "RAß"}, "s", [2]),
        ({"name": "Stra?e"}, "s", [2]),
        ({"name": "Stra??e"}, "s", []),
        ({"name": "stras*"}, "s", []),
        ({"name": "A_B?"}, "s", [3]),
        ({"name": "A_B?"}, "not s", [1, 2, 4, 5, 6]),
        ({"name|fieldref": "pattern"}, "s", [1, 2]),
        ({"name|fieldref|contains": "pattern"}, "s", [1, 2, 3]),
        ({"name|cased": "CAFÉ"}, "s", []),
        (["CAFÉ"], "s", [1]),
    ],
)
def test_unicode_predicates(selection, condition, matched):
    entry = entry_for(
        selection, condition=condition, text_mode="unicode", fulltext_field="text"
    )
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(name, pattern, text)")
        rows = [
            ("café", "CAFÉ"),
            ("Straße", "STRASSE"),
            ("a_b!", "_B"),
            ("aXb?", "_"),
            (None, None),
            ("", None),
        ]
        db.executemany(
            "INSERT INTO logs VALUES(?, ?, ?)", [(n, p, n or "-") for n, p in rows]
        )
        if "required_sql_functions" in entry:
            assert entry["schema_version"] == 5
            with pytest.raises(ValueError, match="function"):
                runtime.validate_entry(db, entry)
        runtime.register_sqlite_functions(db)
        runtime.validate_entry(db, entry)
        sql = entry["rule"][0].replace("SELECT *", "SELECT rowid")
        assert [r[0] for r in db.execute(sql)] == matched


@pytest.mark.parametrize("flag,matched", [(True, [2, 3, 4]), (False, [1])])
def test_presence_distinguishes_absent_and_present_null(flag, matched):
    entry = entry_for({"a.b`key|exists": flag}, presence_field="field list")
    assert entry["schema_version"] == 5
    assert entry["required_fields"] == ["field list"]
    assert entry["presence"] == [
        {"table": "logs", "field": "field list", "representation": "field-names-v1"}
    ]
    with sqlite3.connect(":memory:") as db:
        db.execute('CREATE TABLE logs("a.b`key", "field list")')
        key = "a.b`key"
        db.executemany(
            "INSERT INTO logs VALUES(?, ?)",
            [
                (None, "[]"),
                (None, json.dumps([key, key])),
                ("", json.dumps([key])),
                ("v", json.dumps([key])),
            ],
        )
        runtime.validate_entry(db, entry)
        assert [
            r[0]
            for r in db.execute(entry["rule"][0].replace("SELECT *", "SELECT rowid"))
        ] == matched


@pytest.mark.parametrize(
    "invalid", [None, 123, "{}", '["ok", 5]', "unparsed", '["bad\\u0000key"]']
)
def test_presence_preflight_before_schema_widening(invalid):
    base = detection()
    base["detection"]["s"] = {"any|exists": True}
    plan = compile_docs([base, correlation()], presence_field="keys")[0][
        "correlation_plan"
    ]
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(keys)")
        db.execute("INSERT INTO logs VALUES(?)", (invalid,))
        with pytest.raises(ValueError, match="presence"):
            runtime.execute_plan(db, plan)
        assert [r[1] for r in db.execute("PRAGMA table_info(logs)")] == ["keys"]


def test_per_table_presence_and_field_mapping():
    base = detection()
    base["detection"]["s"] = {"original|exists": True}
    pipe = ProcessingPipeline.from_yaml("""
transformations:
  - type: field_name_mapping
    mapping:
      original: mapped.name
  - type: set_state
    key: table
    val: source
  - type: set_state
    key: presence_field
    val: keys
""")
    entry = compile_docs(
        [base, correlation(condition={"gte": 1})],
        processing_pipeline=pipe,
        presence_field="default_keys",
    )[0]
    assert (
        entry["presence"]
        == entry["correlation_plan"]["presence"]
        == [{"table": "source", "field": "keys", "representation": "field-names-v1"}]
    )
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE source(timestamp, Host, keys)")
        db.execute("""INSERT INTO source VALUES('2024-01-01','h','["mapped.name"]')""")
        db.execute("""INSERT INTO source VALUES('2024-01-01','h','["original"]')""")
        rows, _ = runtime.execute_plan(db, entry["correlation_plan"])
        assert rows[0]["event_ids"] == ["0:1"]
        assert "keys" not in rows[0]["evidence"][0]["event"]


def test_regexp_declared_per_strict_entry_and_in_nested_plans():
    base = detection()
    base["detection"].update(r={"value|re": "^ok$"}, condition=["s", "r"])
    ordinary, regex = compile_docs([base], text_mode="unicode")
    assert ordinary["schema_version"] == 2
    assert regex["schema_version"] == 5 and regex["required_sql_functions"] == [
        "regexp"
    ]
    assert compile_docs([base])[1]["schema_version"] == 2
    entries = compile_docs(
        [
            base,
            correlation(condition={"gte": 1}),
            correlation(refs=("corr",), name="parent", condition={"gte": 1}),
        ],
        sum_mode="exact",
    )
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(timestamp, Host, EventID, value)")
        db.execute("INSERT INTO logs VALUES('2024-01-01','h',2,'ok')")
        db.execute("INSERT INTO logs VALUES('2024-01-01','h',2,NULL)")
        for entry in entries:
            plan = entry["correlation_plan"]
            assert (
                entry["required_sql_functions"]
                == plan["required_sql_functions"]
                == ["regexp"]
            )
            with pytest.raises(ValueError, match="regexp"):
                runtime.execute_plan(db, plan)
            runtime.register_sqlite_functions(db)
            assert runtime.execute_plan(db, plan)[0][0]["event_ids"] == ["0:1"]


def test_exact_window_aggregate_retracts_and_handles_intermediate_overflow():
    with sqlite3.connect(":memory:") as db:
        runtime.register_sqlite_functions(db)
        db.execute("CREATE TABLE samples(n)")
        m = 2**63 - 1
        db.executemany(
            "INSERT INTO samples VALUES(?)", [(m,), (1,), (-1,), (0.5,), (1,)]
        )
        rows = db.execute(
            "SELECT sigma_exact_sum(n) OVER(ORDER BY rowid ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM samples"
        )
        assert [r[0] for r in rows] == [m, str(m + 1), 0, -0.5, 1.5]
        assert db.execute(
            "SELECT sigma_numeric_cmp(?, ?)", (str(m + 1), m)
        ).fetchone() == (1,)


@pytest.mark.parametrize(
    "table", ["presence_keys", "main.presence_keys", "json_each", "temp.json_each"]
)
def test_presence_correlates_outer_source_when_identifiers_collide(table):
    entry = entry_for({"x|exists": True}, presence_field="value", table=table)
    with sqlite3.connect(":memory:") as db:
        db.execute(f"CREATE TABLE {table} (value)")
        db.executemany(f"INSERT INTO {table} VALUES(?)", [('["x"]',), ("[]",)])
        runtime.validate_entry(db, entry)
        assert db.execute(entry["rule"][0]).fetchall() == [('["x"]',)]


def test_very_wide_integer_input_is_still_one_sqlite_text_value():
    with sqlite3.connect(":memory:") as db:
        runtime.register_sqlite_functions(db)
        huge = "1" + "0" * 4500
        assert db.execute("SELECT sigma_exact_sum(?)", (huge,)).fetchone() == (huge,)
        assert db.execute("SELECT sigma_numeric_cmp(?,1)", (huge,)).fetchone() == (1,)


@pytest.mark.parametrize(
    "version,extra",
    [
        (2, {"presence": []}),
        (3, {"presence": []}),
        (4, {"required_sql_functions": ["sigma_numeric_cmp"]}),
        (5, {}),
        (5, {"required_sql_functions": ["unknown"]}),
    ],
)
def test_preflight_rejects_inconsistent_contract_versions(version, extra):
    with sqlite3.connect(":memory:") as db:
        with pytest.raises(ValueError):
            runtime.validate_entry(db, {"schema_version": version, **extra})


def test_mixed_requirements_follow_retained_predicates_across_reconversion():
    base = detection()
    base["detection"].update(
        filtered={"maybe|exists": True, "name|re": "^x$", "ip|cidr": "10.0.0.0/8"},
        keyword=["CAFÉ"],
        condition=["s", "filtered and keyword"],
    )
    rules = SigmaCollection.from_dicts([base, correlation(condition={"gte": 1})])
    backend = sqliteBackend(
        presence_field="keys", fulltext_field="text", cidr_mode="exact"
    )

    def retain_index(index):
        return lambda rule, fmt, i, condition, predicate: (
            None if rule.name == "a" and i != index else predicate
        )

    ordinary = json.loads(
        backend.convert(rules, "zircolite", callback=retain_index(0))
    )[0]
    assert ordinary["schema_version"] == ordinary["correlation_plan"]["version"] == 2
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(timestamp, Host, EventID)")
        db.execute("INSERT INTO logs VALUES('2024-01-01','h',1)")
        assert runtime.execute_plan(db, ordinary["correlation_plan"])[0][0][
            "event_ids"
        ] == ["0:1"]

    strict = json.loads(backend.convert(rules, "zircolite", callback=retain_index(1)))[
        0
    ]
    assert strict["schema_version"] == strict["correlation_plan"]["version"] == 5
    for key in ("presence", "fulltext", "required_sql_functions"):
        assert strict[key] == strict["correlation_plan"][key]
    assert strict["required_sql_functions"] == ["regexp", "sigma_cidr_contains"]
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(timestamp, Host, keys, text, name, ip)")
        db.execute(
            """INSERT INTO logs VALUES('2024-01-01','h','["maybe"]','CAFÉ','x','10.0.0.1')"""
        )
        runtime.register_sqlite_functions(db)
        runtime.validate_entry(db, strict)
        raw = db.execute(strict["rule"][0]).fetchone()
        materialized, _ = runtime.execute_plan(db, strict["correlation_plan"])
        assert materialized[0]["event_ids"] == json.loads(raw[8]) == ["0:1"]


@pytest.mark.parametrize("table", ["json_each", "main.json_each", "temp.json_each"])
def test_presence_correlation_runs_on_tables_named_like_json_functions(table):
    first = detection()
    first["detection"]["s"] = {"x|exists": True}
    second = detection("b", 2)
    ordered = correlation(
        "temporal_ordered", refs=["a", "b"], condition={"gte": 2}, name="ordered"
    )
    docs = [first, second, ordered, correlation(refs=["ordered"], condition={"gte": 1})]
    (entry,) = compile_docs(
        docs, presence_field="keys", table=table, timestamp_format="unix"
    )
    with sqlite3.connect(":memory:") as db:
        db.execute(
            f"CREATE TABLE {table}(keys TEXT, EventID INTEGER, timestamp INTEGER, Host TEXT)"
        )
        db.executemany(
            f"INSERT INTO {table} VALUES (?,?,?,?)",
            [('["x"]', 1, 1, "one"), ("[]", 2, 2, "one")],
        )
        rows, _ = runtime.execute_plan(db, entry["correlation_plan"])
        assert [row["event_ids"] for row in rows] == [["0:1", "0:2"]]
        assert len(rows[0]["evidence"]) == 2
        cursor = db.execute(entry["rule"][0])
        (row,) = cursor.fetchall()
        assert json.loads(
            row[[c[0] for c in cursor.description].index("event_ids")]
        ) == ["0:1", "0:2"]


def test_presence_works_with_both_json_table_names_shadowed():
    entry = entry_for({"User|exists": True}, presence_field="keys")
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(keys TEXT)")
        db.execute("CREATE TABLE json_each(x)")
        db.execute("CREATE TEMP TABLE json_tree(x)")
        db.executemany(
            "INSERT INTO logs VALUES (?)", [('["user"]',), ('["a","User"]',)]
        )
        runtime.validate_entry(db, entry)
        assert db.execute(entry["rule"][0]).fetchall() == [('["a","User"]',)]


def test_presence_and_json_each_on_different_correlation_sources():
    first = detection()
    first["detection"]["s"] = {"x|exists": True}
    pipe = ProcessingPipeline.from_yaml("""
transformations:
  - type: set_state
    key: table
    val: json_each
    rule_conditions:
      - type: rule_attribute
        attribute: title
        value: b
""")
    (entry,) = compile_docs(
        [first, detection("b", 2), correlation("temporal", refs=["a", "b"])],
        processing_pipeline=pipe,
        presence_field="keys",
        timestamp_format="unix",
    )
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(timestamp, Host, keys)")
        db.execute("""INSERT INTO logs VALUES(1,'host','["x"]')""")
        db.execute("CREATE TABLE json_each(timestamp, Host, EventID)")
        db.execute("INSERT INTO json_each VALUES(2,'host',2)")
        cursor = db.execute(entry["rule"][0])
        assert json.loads(cursor.fetchone()[8]) == ["0:1", "1:1"]
        rows, _ = runtime.execute_plan(db, entry["correlation_plan"])
        assert [row["event_ids"] for row in rows] == [["0:1", "1:1"]]


def test_presence_on_bytes_connection_preserves_source_values_and_evidence_ids():
    base = detection()
    base["detection"]["s"] = {"x|exists": True}
    (entry,) = compile_docs(
        [base, correlation(condition={"gte": 1})],
        presence_field="keys",
        event_id_field="id",
        timestamp_format="unix",
    )
    with sqlite3.connect(":memory:") as db:
        db.text_factory = bytes
        db.execute("CREATE TABLE logs(id, timestamp, Host, keys TEXT)")
        db.execute("""INSERT INTO logs VALUES('é:1',1,'host','["x"]')""")
        runtime.validate_entry(db, entry)
        rows, _ = runtime.execute_plan(db, entry["correlation_plan"])
        assert rows[0]["metric_name"] == "event_count"
        assert rows[0]["evidence"] == [
            {
                "event_id": "0:é:1",
                "source_table": "logs",
                "event": {"id": "é:1".encode(), "timestamp": 1, "Host": b"host"},
            }
        ]
        db.execute("UPDATE logs SET keys = CAST(keys AS BLOB)")
        with pytest.raises(ValueError, match="expected TEXT"):
            runtime.validate_entry(db, entry)


def test_evidence_retains_sqlite_distinct_unicode_column():
    base = detection()
    base["detection"]["s"] = {"x|exists": True}
    (entry,) = compile_docs(
        [base, correlation(condition={"gte": 1})],
        presence_field="keys",
        timestamp_format="unix",
    )
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(timestamp, Host, KEYS TEXT, Keys TEXT)")
        db.execute("""INSERT INTO logs VALUES(1,'host','["x"]','source value')""")
        rows, _ = runtime.execute_plan(db, entry["correlation_plan"])
        assert rows[0]["evidence"][0]["event"] == {
            "timestamp": 1,
            "Host": "host",
            "Keys": "source value",
        }


@pytest.mark.parametrize("condition", ["s", "not s"])
@pytest.mark.parametrize(
    "selection",
    [
        {"port|fieldref": "dport"},
        {"port|fieldref|startswith": "dport"},
        {"code": "1"},
        {"port": "44*"},
        {"big": "1.0e+20"},
    ],
)
def test_unicode_mode_keeps_sqlite_comparison_for_non_text_values(selection, condition):
    # Function results carry no column affinity. Values that are not TEXT keep
    # SQLite's own comparison, so the opt-in mode loses no portable match.
    results = {}
    for mode in ("portable", "unicode"):
        entry = entry_for(selection, condition=condition, text_mode=mode)
        with sqlite3.connect(":memory:") as db:
            runtime.register_sqlite_functions(db)
            db.execute(
                "CREATE TABLE logs(port INTEGER, dport TEXT, code REAL, big REAL)"
            )
            db.executemany(
                "INSERT INTO logs VALUES(?, ?, ?, ?)",
                [(445, "445", 1.0, 1e20), (80, "8080", None, None)],
            )
            sql = entry["rule"][0].replace("SELECT *", "SELECT rowid")
            results[mode] = db.execute(sql).fetchall()
    assert results["unicode"] == results["portable"]
    if condition == "s":
        assert results["portable"] == [(1,)]


@pytest.mark.parametrize("value", [1e20, 100.0, 1 / 3, -2.5e-300])
def test_strict_helpers_spell_reals_as_sqlite_text(value):
    with sqlite3.connect(":memory:") as db:
        runtime.register_sqlite_functions(db)
        (text,) = db.execute("SELECT CAST(? AS TEXT)", (value,)).fetchone()
        pattern = "^" + re.escape(text) + "$"
        assert db.execute(
            "SELECT regexp(?, ?), sigma_unicode_like(?, ?)",
            (pattern, value, value, text),
        ).fetchone() == (1, 1)


def test_strict_regexp_reads_blobs_as_text_not_python_repr():
    with sqlite3.connect(":memory:") as db:
        runtime.register_sqlite_functions(db)
        blob = b"\x00abc\xff"
        patterns = ["^b'", r"\\x00", r"^\x00abc"]
        assert db.execute(
            "SELECT regexp(?, ?), regexp(?, ?), regexp(?, ?)",
            [arg for pattern in patterns for arg in (pattern, blob)],
        ).fetchone() == (0, 0, 1)


def test_function_check_accepts_regexp_returning_null_for_null_input():
    entry = entry_for({"v|re": "^a"}, text_mode="unicode")
    assert "regexp" in entry["required_sql_functions"]
    with sqlite3.connect(":memory:") as db:
        runtime.register_sqlite_functions(db)
        db.create_function(
            "regexp",
            2,
            lambda p, v: None if v is None else int(re.search(p, v) is not None),
        )
        db.execute("CREATE TABLE logs(v)")
        runtime.validate_entry(db, entry)


def test_missing_cidr_function_points_to_register_cidr():
    with sqlite3.connect(":memory:") as db:
        with pytest.raises(ValueError, match=r"call register_cidr\(connection\)"):
            runtime.validate_sql_functions(db, ["sigma_cidr_contains"])


def test_presence_reads_escape_free_arrays_without_the_json_walk():
    entry = entry_for({"User|exists": True}, presence_field="keys")
    walked = []

    def json_extract(document, path):
        walked.append(document)
        if document is None:
            return None
        items = json.loads(document)
        index = int(path[2:-1])
        return items[index] if index < len(items) else None

    escaped = '["\\u0055ser"]'
    with sqlite3.connect(":memory:") as db:
        # Count the walk by overriding the built-in for this connection only.
        db.create_function("json_extract", 2, json_extract)
        db.execute("CREATE TABLE logs(keys TEXT)")
        db.executemany(
            "INSERT INTO logs VALUES (?)",
            [('["user"]',), ('["a", "User"]',), (escaped,), (None,)],
        )
        sql = entry["rule"][0].replace("SELECT *", "SELECT rowid")
        assert db.execute(sql).fetchall() == [(2,), (3,)]
    # A NULL list takes the walk too; it ends after one extraction.
    assert set(walked) == {escaped, None}


PRESENCE_NAMES = ["User", "user", ",", " ", ", ", "[", "a,b", 'a"b', "a\\b", "é", "a b"]


@pytest.mark.parametrize("field", PRESENCE_NAMES)
@pytest.mark.parametrize("flag", [True, False])
def test_presence_matches_decoded_names_in_every_json_spelling(field, flag):
    entry = entry_for({f"{field}|exists": flag}, presence_field="keys")
    arrays = [[], [field], ["x", field], [n for n in PRESENCE_NAMES if n != field]]
    documents = [
        json.dumps(keys, ensure_ascii=ascii, separators=separators)
        for keys in arrays
        for ascii in (True, False)
        for separators in ((",", ":"), (", ", ": "), (" , ", ": "))
    ]
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(keys TEXT)")
        db.executemany("INSERT INTO logs VALUES (?)", [(d,) for d in documents])
        runtime.validate_entry(db, entry)
        sql = entry["rule"][0].replace("SELECT *", "SELECT rowid")
        found = [rowid for (rowid,) in db.execute(sql)]
    expected = [
        i + 1 for i, d in enumerate(documents) if (field in json.loads(d)) == flag
    ]
    assert found == expected
