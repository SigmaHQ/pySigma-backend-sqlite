"""Exact CIDR rules across SQLite event queries, materialized plans and pySigma."""

import json
import sqlite3

import pytest
from helpers import correlation, database, detection, event
from sigma.collection import SigmaCollection
from sigma.matching.compiler import MatchCompiler
from sigma.types import SigmaCIDRExpression

from sigma.backends.sqlite import cidr, runtime, sqliteBackend


def cidr_rule(network="10.0.0.0/8", *, condition="s", field="User"):
    rule = detection()
    rule["detection"] = {"s": {field + "|cidr": network}, "condition": condition}
    return rule


def convert(docs, **options):
    backend = sqliteBackend(cidr_mode="exact", **options)
    return json.loads(backend.convert(SigmaCollection.from_dicts(docs), "zircolite"))


def test_cidr_mode_options():
    collection = SigmaCollection.from_dicts([cidr_rule()])
    assert sqliteBackend(cidr_mode="expanded").convert(
        collection
    ) == sqliteBackend().convert(collection)
    with pytest.raises(ValueError, match="cidr_mode"):
        sqliteBackend(cidr_mode="other")


@pytest.mark.parametrize(
    "address,network,matches",
    [
        ("10.255.0.1", "10.0.0.0/8", 1),
        ("11.0.0.0", "10.0.0.0/8", 0),
        ("123.4.5.6", "0.0.0.0/0", 1),
        ("2001:0DB8:0000:0000:0000:0000:0000:000F", "2001:db8::/124", 1),
        ("::ffff:192.0.2.1", "::ffff:0:0/96", 1),
        ("::ffff:192.0.2.1", "192.0.2.0/24", 0),
        ("192.0.2.1", "::/0", 0),
        ("192.00.2.1", "0.0.0.0/0", 0),
        ("10.4.3.999", "10.0.0.0/8", 0),
        ("10.4.3.1/32", "10.0.0.0/8", 0),
        (None, "0.0.0.0/0", 0),
        (0, "0.0.0.0/0", 0),
        (3.5, "0.0.0.0/0", 0),
        (b"\x00" * 4, "0.0.0.0/0", 0),
        ("::1", "garbage", 0),
        ("::1", None, 0),
        ("::1", b"::/0", 0),
    ],
)
def test_registered_function(address, network, matches):
    with sqlite3.connect(":memory:") as con:
        runtime.register_cidr(con)
        assert con.execute(
            "SELECT sigma_cidr_contains(?, ?)", (address, network)
        ).fetchone() == (matches,)


def test_registered_function_is_deterministic_and_connection_local():
    with sqlite3.connect(":memory:") as con, sqlite3.connect(":memory:") as other:
        runtime.register_cidr(con)
        con.execute("CREATE TABLE logs(ip TEXT)")
        con.execute("CREATE INDEX network ON logs(sigma_cidr_contains(ip, '::/0'))")
        with pytest.raises(ValueError, match="sigma_cidr_contains"):
            runtime.validate_sql_functions(other, ["sigma_cidr_contains"])
        runtime.validate_sql_functions(con, ["sigma_cidr_contains"])


def test_function_preflight_rejects_an_always_true_implementation():
    with sqlite3.connect(":memory:") as con:
        con.create_function("sigma_cidr_contains", 2, lambda ip, network: 1)
        with pytest.raises(ValueError, match="sigma_cidr_contains"):
            runtime.validate_sql_functions(con, ["sigma_cidr_contains"])


def test_cache_reuses_short_keys_and_parses_long_keys_without_retaining_them(
    monkeypatch,
):
    from unittest.mock import Mock

    network = Mock(wraps=cidr.ip_network)
    address = Mock(wraps=cidr.ip_address)
    monkeypatch.setattr(cidr, "ip_network", network)
    monkeypatch.setattr(cidr, "ip_address", address)
    long_ip = "::1%" + "x" * 8192
    sql = "SELECT sigma_cidr_contains(?, ?)"
    with sqlite3.connect(":memory:") as con:
        runtime.register_cidr(con)
        for _ in range(2):
            assert con.execute(sql, ("::1", "::1/128")).fetchone() == (1,)
        assert (address.call_count, network.call_count) == (1, 1)
        for _ in range(2):
            assert con.execute(sql, (long_ip, long_ip + "/128")).fetchone() == (1,)
        assert (address.call_count, network.call_count) == (3, 3)


@pytest.mark.parametrize(
    "networks,condition",
    [
        (["192.0.2.96/27", "2001:db8::/62"], "s"),
        ("0.0.0.0/0", "s"),
        ("0.0.0.0/1", "not s"),
        ("192.0.2.127/32", "not s"),
        ("2001:db8::1/128", "not s"),
    ],
)
def test_exact_queries_agree_with_matcher(networks, condition):
    doc = cidr_rule(networks, condition=condition, field="IP address")
    collection = SigmaCollection.from_dicts([doc])
    matches = MatchCompiler().compile_rule(collection.rules[0])
    events = [
        {"IP address": ip}
        for ip in (
            "192.0.2.95",
            "192.0.2.96",
            "192.0.2.127",
            "192.0.2.128",
            "192.0.2.BAD",
            "192.0.2.001",
            "2001:0DB8:0000:0000:0000:0000:0000:0001",
            "2001:db8:0:3::1",
            "2001:db8:0:4::1",
            "::ffff:192.0.2.127",
            "0.0.0.0",
            None,
            4,
            b"abcd",
        )
    ] + [{}]
    query = sqliteBackend(cidr_mode="exact").convert(collection)[0]
    with sqlite3.connect(":memory:") as con:
        runtime.register_cidr(con)
        con.execute("CREATE TABLE logs(id INTEGER, `IP address`)")
        con.executemany(
            "INSERT INTO logs VALUES (?, ?)",
            [(i, e.get("IP address")) for i, e in enumerate(events)],
        )
        assert {row[0] for row in con.execute(query)} == {
            i for i, e in enumerate(events) if matches(e, None)
        }


def test_exact_conversion_never_expands_cidr(monkeypatch):
    def forbid_expansion(*_):
        pytest.fail("exact mode expanded a CIDR")

    monkeypatch.setattr(SigmaCIDRExpression, "expand", forbid_expansion)
    doc = cidr_rule("2001:db8::/33")
    doc["detection"]["s"]["Host"] = "h"
    assert "sigma_cidr_contains" in convert([doc])[0]["rule"][0]


@pytest.mark.parametrize(
    "network,expected_calls,matches",
    [
        ("10.8.0.0/13", ["10.8.0.1", "10.16.0.1", "10.bad"], ["10.8.0.1"]),
        ("10.8.0.1/32", [], ["10.8.0.1"]),
    ],
)
def test_ipv4_guard_uses_index_and_skips_irrelevant_projected_rows(
    network, expected_calls, matches
):
    rule = cidr_rule(network)
    query = convert([rule])[0]["rule"][0]
    plan = convert([rule, correlation()])[0]["correlation_plan"]
    ips = ["10.8.0.1", "10.16.0.1", "10.bad", "1.2.3.4", "::1", None]
    with database([event(i, User=ip) for i, ip in enumerate(ips)]) as con:
        con.execute("CREATE INDEX ip ON logs(User COLLATE NOCASE)")
        con.execute("CREATE INDEX ip_binary ON logs(User)")
        runtime.register_cidr(con)
        details = " ".join(row[3] for row in con.execute("EXPLAIN QUERY PLAN " + query))
        assert "SEARCH logs USING INDEX ip" in details
        assert [row[4] for row in con.execute(query)] == matches
        calls = []
        con.create_function(
            "sigma_cidr_contains", 2, lambda ip, net: calls.append(ip) or 0
        )
        con.execute(plan["prepare"][0]["select"]).fetchall()
        assert calls == expected_calls


@pytest.mark.parametrize("case_sensitive_like", [0, 1])
@pytest.mark.parametrize(
    "network,matches,skip,expect_index",
    [
        ("2001:db8::/32", ["2001:0DB8::1", "2001:db8::2%en0"], ["2002::1"], True),
        ("1::/16", ["1::1", "01::2", "001::3", "0001::4"], ["10::1"], True),
        ("face::/16", ["FaCe::1", "FACE::2"], ["fac0::1"], True),
        ("ab::/16", ["aB::1", "0Ab::2", "00AB::3"], ["ab0::1"], False),
        ("::ffff:0:0/96", ["::FFFF:192.0.2.1", "0:0:0:0:0:ffff:c000:201"], [], False),
        ("::/0", ["::", "0::1", "fe80::1%en0", "::ffff:192.0.2.1"], [], False),
        ("2000::/3", ["2001::1", "3fff::1"], [], False),
    ],
)
def test_ipv6_guard_filters_event_queries_and_projected_flags(
    network, matches, skip, expect_index, case_sensitive_like, monkeypatch
):
    rule = cidr_rule(network)
    query = convert([rule])[0]["rule"][0]
    negated = convert([cidr_rule(network, condition="not s")])[0]["rule"][0]
    plan = convert([rule, correlation()])[0]["correlation_plan"]
    skip = [*skip, "192.0.2.1", "no address"]
    misses = [*skip, matches[0] + "!", None, b"2001:db8::1", 42]
    ips = [*matches, *misses]

    parsed = set()
    parse = cidr.ip_address

    def record_parse(value):
        parsed.add(value)
        return parse(value)

    monkeypatch.setattr(cidr, "ip_address", record_parse)
    with database([event(i, User=ip) for i, ip in enumerate(ips)]) as con:
        con.execute(f"PRAGMA case_sensitive_like={case_sensitive_like}")
        con.execute("CREATE INDEX ip_nocase ON logs(User COLLATE NOCASE)")
        con.execute("CREATE INDEX ip_binary ON logs(User)")
        runtime.register_cidr(con)
        projected = con.execute(plan["prepare"][0]["select"]).fetchall()
        matching_ids = set(range(1, len(matches) + 1))
        assert {int(row[0]) for row in projected if row[-1]} == matching_ids
        assert parsed.isdisjoint(skip)
        assert {row[0] for row in con.execute(query)} == matching_ids
        assert {row[0] for row in con.execute(negated)} == set(
            range(len(matches) + 1, len(ips) + 1)
        )
        if expect_index:
            details = [r[3] for r in con.execute("EXPLAIN QUERY PLAN " + query)]
            assert any("SEARCH logs USING INDEX ip_" in op for op in details)


@pytest.mark.parametrize("collation", ["BINARY", "NOCASE", "RTRIM"])
def test_exact_ipv4_host_runs_without_a_function(collation):
    network = "192.0.2.1/32"
    entry = convert([cidr_rule(network)])[0]
    assert entry["schema_version"] == 2
    assert "required_sql_functions" not in entry
    query = entry["rule"][0]
    negated = convert([cidr_rule(network, condition="not s")])[0]["rule"][0]
    values = [
        "192.0.2.1",
        "192.0.2.1 ",
        "192.0.2.1\x00",
        "::ffff:192.0.2.1",
        "192.000.2.1",
        b"192.0.2.1",
        1,
        None,
    ]
    with sqlite3.connect(":memory:") as con:
        con.execute(f"CREATE TABLE logs(id INTEGER, User TEXT COLLATE {collation})")
        con.execute("CREATE INDEX ip ON logs(User)")
        con.executemany("INSERT INTO logs VALUES (?, ?)", enumerate(values))
        assert [row[0] for row in con.execute(query)] == [0]
        assert {row[0] for row in con.execute(negated)} == set(range(1, len(values)))
        assert any(
            "SEARCH logs USING INDEX ip" in row[3]
            for row in con.execute("EXPLAIN QUERY PLAN " + query)
        )


def test_exact_ipv4_host_prerequisites_in_correlations_and_mixed_conditions():
    host = cidr_rule("192.0.2.1/32")
    entry = convert([host, correlation(condition={"gte": 1})])[0]
    plan = entry["correlation_plan"]
    assert entry["schema_version"] == plan["version"] == 2
    assert (
        "required_sql_functions" not in entry and "required_sql_functions" not in plan
    )
    with database([event(0, User="192.0.2.1"), event(1, User="192.0.2.1 ")]) as con:
        rows, _ = runtime.execute_plan(con, plan)
        assert [row["event_ids"] for row in rows] == [["0:1"]]
    host["detection"].update(
        k=["needle"],
        other={"User|cidr": "10.0.0.0/8"},
        condition=["s and k", "s or other"],
    )
    keyword, network = convert([host], fulltext_field="text")
    assert keyword["schema_version"] == 3 and "required_sql_functions" not in keyword
    assert network["schema_version"] == 4
    assert network["required_sql_functions"] == ["sigma_cidr_contains"]


def test_exact_requirements_are_per_emitted_entry():
    doc = cidr_rule()
    doc["detection"].update(other={"EventID": 1}, condition=["s", "other"])
    cidr, ordinary = convert([doc])
    assert cidr["schema_version"] == 4
    assert cidr["required_sql_functions"] == ["sigma_cidr_contains"]
    assert ordinary["schema_version"] == 2
    assert "required_sql_functions" not in ordinary
    assert "fulltext" not in cidr

    keyword = detection()
    keyword["detection"]["s"] = ["needle"]
    for docs in ([keyword], [keyword, correlation()]):
        entry = convert(docs, fulltext_field="text")[0]
        assert entry["schema_version"] == 3
        assert "required_sql_functions" not in entry
    ordinary_plan = convert([detection(), correlation()])[0]["correlation_plan"]
    assert ordinary_plan["version"] == 2
    assert "required_sql_functions" not in ordinary_plan


def test_function_requirements_propagate_through_nested_correlations():
    docs = [
        cidr_rule(),
        correlation(condition={"gte": 1}),
        correlation(refs=("corr",), condition={"gte": 1}, name="parent", generate=True),
    ]
    entries = convert(docs)
    assert {entry["title"] for entry in entries} == {"parent", "corr"}
    with database([event(0, User="10.0.0.1"), event(1, User="10.bad")]) as con:
        runtime.register_cidr(con)
        for entry in entries:
            plan = entry["correlation_plan"]
            assert entry["schema_version"] == plan["version"] == 4
            assert (
                entry["required_sql_functions"]
                == plan["required_sql_functions"]
                == ["sigma_cidr_contains"]
            )
            rows, _ = runtime.execute_plan(con, plan)
            assert [r["event_ids"] for r in rows] == [["0:1"]]
            assert [(r[0], r[6]) for r in con.execute(entry["rule"][0])] == [
                (rows[0]["alert_id"], rows[0]["metric_value"])
            ]


def test_exact_plan_preflights_functions_and_fulltext_before_widening():
    rule = cidr_rule()
    rule["detection"].update(keywords=["needle"], condition="s and keywords")
    plan = convert([rule, correlation(condition={"gte": 1})], fulltext_field="text")[0][
        "correlation_plan"
    ]
    assert plan["version"] == 4
    assert plan["fulltext"] == [
        {"field": "text", "table": "logs", "representation": "source-values-v1"}
    ]
    with sqlite3.connect(":memory:") as con:
        con.execute("CREATE TABLE logs(timestamp TEXT, User TEXT)")
        for requirements in (None, [], "sigma_cidr_contains", [123], ["unknown"]):
            with pytest.raises(ValueError, match="function"):
                runtime.execute_plan(
                    con, {**plan, "required_sql_functions": requirements}
                )
        with pytest.raises(ValueError, match="sigma_cidr_contains"):
            runtime.execute_plan(con, plan)
        runtime.register_cidr(con)
        with pytest.raises(ValueError, match="re-ingest"):
            runtime.execute_plan(con, plan)
        assert [r[1] for r in con.execute("PRAGMA table_info(logs)")] == [
            "timestamp",
            "User",
        ]
        con.execute("ALTER TABLE logs ADD COLUMN text TEXT")
        con.execute("ALTER TABLE logs ADD COLUMN Host TEXT")
        con.execute("INSERT INTO logs VALUES ('2024-01-01', '10.0.0.1', 'needle', 'h')")
        calls = []

        def check_fulltext(requirements):
            calls.append(requirements)
            runtime.validate_fulltext(con, requirements)

        rows, _ = runtime.execute_plan(con, plan, fulltext_preflight=check_fulltext)
        assert calls == [plan["fulltext"]]
        assert [r["event_ids"] for r in rows] == [["0:1"]]
        assert "text" not in rows[0]["evidence"][0]["event"]


@pytest.mark.parametrize("version", [2, 3])
def test_older_plan_cannot_bypass_required_function_check(version):
    base = detection()
    if version == 3:
        base["detection"]["s"] = ["needle"]
    plan = convert([base, correlation()], fulltext_field="text")[0]["correlation_plan"]
    plan["required_sql_functions"] = ["unknown"]
    with sqlite3.connect(":memory:") as con:
        con.execute("CREATE TABLE logs(text TEXT)")
        with pytest.raises(ValueError, match="function"):
            runtime.execute_plan(con, plan)
        assert [r[1] for r in con.execute("PRAGMA table_info(logs)")] == ["text"]
