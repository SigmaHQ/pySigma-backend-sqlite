import json
import sqlite3

import pytest
from helpers import regexp
from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import SetStateTransformation

from sigma.backends.sqlite import sqliteBackend


@pytest.fixture
def sqlite_backend():
    return sqliteBackend()


def convert_selection(selection, backend=None):
    """Queries for a rule whose condition is the single selection given."""
    rule = {
        "title": "Test",
        "status": "test",
        "logsource": {"category": "test_category", "product": "test_product"},
        "detection": {"sel": selection, "condition": "sel"},
    }
    return (backend or sqliteBackend()).convert(SigmaCollection.from_dicts([rule]))


def test_plugin_discovery_exposes_sqlite_backend():
    assert InstalledSigmaPlugins.autodiscover().backends["sqlite"] is sqliteBackend


@pytest.mark.parametrize("text, value", [("true", True), ("FALSE", False)])
def test_collate_nocase_option_reads_cli_strings(text, value):
    assert sqliteBackend(collate_nocase=text).collate_nocase is value


def test_max_flat_operands_option_reads_cli_strings():
    assert sqliteBackend(max_flat_operands="50").max_flat_operands == 50


@pytest.mark.parametrize(
    "options, message",
    [
        ({"collate_nocase": "yes"}, "collate_nocase"),
        ({"max_flat_operands": "1"}, "max_flat_operands"),
        ({"timestamp_format": "epoch"}, "timestamp_format"),
        ({"fulltext_field": ""}, "fulltext_field"),
        ({"table": ""}, "table"),
        ({"table": "main."}, "table"),
        ({"timestamp_field": ""}, "timestamp_field"),
        ({"event_id_field": ""}, "event_id_field"),
    ],
)
def test_invalid_options_are_rejected(options, message):
    with pytest.raises(ValueError, match=message):
        sqliteBackend(**options)


def test_misspelled_option_warns_and_is_still_available_to_pipelines():
    with pytest.warns(UserWarning, match="cidr_mod.*cidr_mode"):
        backend = sqliteBackend(cidr_mod="exact", tenant="example")
    convert_selection({"field": "value"}, backend)
    assert backend.last_processing_pipeline.vars["backend_cidr_mod"] == "exact"
    assert backend.last_processing_pipeline.vars["backend_tenant"] == "example"


def test_fieldref_target_is_a_required_field():
    rule = {
        "title": "Test",
        "logsource": {"category": "test"},
        "detection": {"sel": {"fieldA|fieldref": "fieldB"}, "condition": "sel"},
    }
    output = sqliteBackend().convert(SigmaCollection.from_dicts([rule]), "zircolite")
    assert json.loads(output)[0]["required_fields"] == ["fieldA", "fieldB"]


def test_sqlite_and_expression(sqlite_backend: sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
        )
    ) == ["SELECT * FROM logs WHERE fieldA='valueA' AND fieldB='valueB'"]


def test_sqlite_or_expression(sqlite_backend: sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
        )
    ) == ["SELECT * FROM logs WHERE fieldA='valueA' OR fieldB='valueB'"]


def test_sqlite_and_or_expression(sqlite_backend: sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """
        )
    ) == [
        "SELECT * FROM logs WHERE (fieldA='valueA1' OR fieldA='valueA2') AND (fieldB='valueB1' OR fieldB='valueB2')"
    ]


def test_sqlite_or_and_expression(sqlite_backend: sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
        )
    ) == [
        "SELECT * FROM logs WHERE (fieldA='valueA1' AND fieldB='valueB1') OR (fieldA='valueA2' AND fieldB='valueB2')"
    ]


def test_sqlite_value_list_becomes_or_chain(sqlite_backend: sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """
        )
    ) == [
        "SELECT * FROM logs WHERE fieldA='valueA' OR fieldA='valueB' OR fieldA LIKE 'valueC%' ESCAPE '\\'"
    ]


def test_sqlite_regex_query(sqlite_backend: sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """
        )
    ) == ["SELECT * FROM logs WHERE fieldA REGEXP 'foo.*bar' AND fieldB='foo'"]


def test_sqlite_regex_query_single_quote(sqlite_backend: sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: it's.exe
                condition: sel
        """
        )
    ) == ["SELECT * FROM logs WHERE fieldA REGEXP 'it''s.exe'"]


def test_sqlite_cidr_query(sqlite_backend: sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """
        )
    ) == ["SELECT * FROM logs WHERE field LIKE '192.168.%' ESCAPE '\\'"]


def test_sqlite_cidr_ipv6_prefix_ending_in_zero_groups(sqlite_backend: sqliteBackend):
    # pySigma 2 matches the zero groups both spelled out and compressed to "::".
    query = sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 2001:db8::/64
                condition: sel
        """
        )
    )[0]
    assert query == (
        "SELECT * FROM logs WHERE field LIKE '2001:db8:0:0:%' ESCAPE '\\' "
        "OR field LIKE '2001:db8::%' ESCAPE '\\'"
    )
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE logs (field TEXT)")
    connection.executemany(
        "INSERT INTO logs VALUES (?)",
        [
            ("2001:db8::1",),
            ("2001:db8:0:0:1::1",),
            ("2001:db8:0:1::1",),
            ("2001:db9::1",),
        ],
    )
    assert {row[0] for row in connection.execute(query)} == {
        "2001:db8::1",
        "2001:db8:0:0:1::1",
    }


def test_sqlite_cidr_ipv6_matches_uncompressed_spelling(sqlite_backend: sqliteBackend):
    # Sysmon writes IPv6 uncompressed (0:0:0:0:0:0:0:1 for ::1); since pySigma 2.0.3
    # a filter excludes both spellings instead of letting the uncompressed one through.
    query = sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Initiated: 'true'
                filter:
                    DestinationIp|cidr: '::1/128'
                condition: sel and not filter
        """
        )
    )[0]
    assert query == (
        "SELECT * FROM logs WHERE Initiated='true' AND (NOT COALESCE(("
        "DestinationIp='::1' OR DestinationIp='0:0:0:0:0:0:0:1'), 0))"
    )
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE logs (Initiated TEXT, DestinationIp TEXT)")
    connection.executemany(
        "INSERT INTO logs VALUES ('true', ?)",
        [("::1",), ("0:0:0:0:0:0:0:1",), ("0:0:0:0:0:0:0:2",), (None,)],
    )
    assert {row[1] for row in connection.execute(query)} == {"0:0:0:0:0:0:0:2", None}


def test_sqlite_cidr_expanding_to_several_patterns_stays_grouped(
    sqlite_backend: sqliteBackend,
):
    query = sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Image|endswith: foo.exe
                    DestinationIp|cidr: 172.16.0.0/15
                condition: sel
        """
        )
    )[0]
    assert query == (
        "SELECT * FROM logs WHERE Image LIKE '%foo.exe' ESCAPE '\\' AND "
        "(DestinationIp LIKE '172.16.%' ESCAPE '\\' OR DestinationIp LIKE '172.17.%' ESCAPE '\\')"
    )
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE logs (Image TEXT, DestinationIp TEXT)")
    connection.executemany(
        "INSERT INTO logs VALUES (?, ?)",
        [("c:\\foo.exe", "172.17.0.1"), ("c:\\bar.exe", "172.17.0.1")],
    )
    assert connection.execute(query).fetchall() == [("c:\\foo.exe", "172.17.0.1")]


@pytest.mark.parametrize(
    "condition,expected",
    [
        ("sel1 and sel2", {("11.1.2.3", "x")}),
        ("sel2 and sel1", {("11.1.2.3", "x")}),
        ("all of sel*", {("11.1.2.3", "x")}),
        ("other or sel2 and sel1", {("11.1.2.3", "x")}),
        ("sel2 or sel1", {("10.1.2.3", "y"), ("11.1.2.3", "y"), ("11.1.2.3", "x")}),
        ("sel2 and not sel1", set()),
    ],
)
def test_sqlite_cidr_selection_combined_by_condition_stays_grouped(
    sqlite_backend: sqliteBackend, condition, expected
):
    query = sqlite_backend.convert(
        SigmaCollection.from_yaml(
            f"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    src|cidr: 10.0.0.0/7
                sel2:
                    user: x
                other:
                    user: none
                condition: {condition}
        """
        )
    )[0]
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE logs (src TEXT, user TEXT)")
    connection.executemany(
        "INSERT INTO logs VALUES (?, ?)",
        [("10.1.2.3", "y"), ("11.1.2.3", "y"), ("11.1.2.3", "x")],
    )
    assert set(connection.execute(query).fetchall()) == expected


def test_sqlite_field_name_with_whitespace(sqlite_backend: sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """
        )
    ) == ["SELECT * FROM logs WHERE `field name`='value'"]


def test_sqlite_value_with_wildcards(sqlite_backend: sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: wildcard%value
                    fieldB: wildcard_value
                condition: sel
        """
        )
    ) == [
        "SELECT * FROM logs WHERE fieldA LIKE 'wildcard\\%value' ESCAPE '\\' AND fieldB LIKE 'wildcard\\_value' ESCAPE '\\'"
    ]


@pytest.mark.parametrize(
    "modifier, pattern",
    [
        ("contains", "%wildcard\\%value%"),
        ("startswith", "wildcard\\%value%"),
        ("endswith", "%wildcard\\%value"),
    ],
)
def test_sqlite_value_like_forms_escape_literal_percent(modifier, pattern):
    assert convert_selection({f"fieldA|{modifier}": "wildcard%value"}) == [
        f"SELECT * FROM logs WHERE fieldA LIKE '{pattern}' ESCAPE '\\'"
    ]


def test_sqlite_fts_keywords_str(sqlite_backend: sqliteBackend):
    with pytest.raises(Exception) as e:
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - value1
                    - value2
                condition: keywords
        """
            )
        )
    assert "fulltext_field" in str(e.value)
    assert "re-ingest" in str(e.value)


def test_sqlite_fts_keywords_num(sqlite_backend: sqliteBackend):
    with pytest.raises(Exception) as e:
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - 1
                    - 2
                condition: keywords
        """
            )
        )
    assert "fulltext_field" in str(e.value)
    assert "re-ingest" in str(e.value)


def test_sqlite_value_case_sensitive_contains(sqlite_backend: sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains|cased: VaLuE
                condition: sel
        """
        )
    ) == ["SELECT * FROM logs WHERE fieldA GLOB '*VaLuE*'"]


def test_sqlite_value_case_sensitive_match(sqlite_backend: sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cased: 'C:\Windows\System32\cmd.exe'
                condition: sel
        """
        )
    ) == [r"SELECT * FROM logs WHERE fieldA GLOB 'C:\Windows\System32\cmd.exe'"]


@pytest.mark.parametrize(
    ("detection", "stored", "should_match"),
    [
        # |cased must not emit "ESCAPE" (SQLite GLOB is a 2-arg operator) and must
        # not escape backslashes, otherwise these queries raise
        # "wrong number of arguments to function GLOB()" or silently mismatch.
        (r"fieldA|cased: 'C:\Temp\app.exe'", r"C:\Temp\app.exe", True),
        (r"fieldA|cased: 'C:\Temp\app.exe'", r"c:\temp\app.exe", False),
        ("fieldA|contains|cased: VaLuE", "prefix VaLuE suffix", True),
        ("fieldA|contains|cased: VaLuE", "prefix value suffix", False),
        ("fieldA|startswith|cased: VaLuE", "VaLuE at start", True),
        ("fieldA|startswith|cased: VaLuE", "no VaLuE here", False),
        ("fieldA|endswith|cased: VaLuE", "ends with VaLuE", True),
        ("fieldA|endswith|cased: VaLuE", "VaLuE not at end", False),
    ],
)
def test_sqlite_case_sensitive_executes_on_sqlite3(
    sqlite_backend: sqliteBackend, detection: str, stored: str, should_match: bool
):
    """Generated |cased queries must actually run against a real sqlite3 connection."""
    rule = SigmaCollection.from_yaml(
        "title: Test\n"
        "status: test\n"
        "logsource:\n"
        "    category: test_category\n"
        "    product: test_product\n"
        "detection:\n"
        "    sel:\n"
        f"        {detection}\n"
        "    condition: sel\n"
    )
    query = sqlite_backend.convert(rule)[0].replace("logs", "t")

    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE TABLE t (fieldA)")
        conn.execute("INSERT INTO t VALUES (?)", (stored,))
        matched = bool(conn.execute(query).fetchall())
    finally:
        conn.close()

    assert matched is should_match


def test_sqlite_zircolite_output(sqlite_backend: sqliteBackend):
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value
                condition: sel
        """
    )
    entries = json.loads(sqlite_backend.convert(rule, "zircolite"))
    assert len(entries) == 1
    assert entries[0]["title"] == "Test"
    assert entries[0]["rule"] == ["SELECT * FROM logs WHERE fieldA='value'"]
    assert entries[0]["schema_version"] == 2
    assert entries[0]["required_fields"] == ["fieldA"]
    assert entries[0]["source_table"] == "logs"
    assert entries[0]["logsource"]["product"] == "test_product"


def test_sqlite_zircolite_output_with_channel_and_eventid(
    sqlite_backend: sqliteBackend,
):
    """Test Zircolite output includes channel and eventid arrays"""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test with Channel and EventID
            status: test
            logsource:
                category: test_category
                product: windows
            detection:
                sel:
                    Channel:
                        - Security
                        - Microsoft-Windows-Sysmon/Operational
                    EventID:
                        - 1
                        - 4688
                        - 7045
                condition: sel
        """
    )
    result = json.loads(sqlite_backend.convert(rule, "zircolite"))
    assert result[0]["channel"] == ["Microsoft-Windows-Sysmon/Operational", "Security"]
    assert result[0]["eventid"] == [1, 4688, 7045]


def test_sqlite_zircolite_output_with_single_eventid(sqlite_backend: sqliteBackend):
    """Test Zircolite output with a single EventID"""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test with Single EventID
            status: test
            logsource:
                category: test_category
                product: windows
            detection:
                sel:
                    EventID: 4624
                condition: sel
        """
    )
    result = json.loads(sqlite_backend.convert(rule, "zircolite"))
    assert result[0]["channel"] == []
    assert result[0]["eventid"] == [4624]


def test_sqlite_zircolite_output_eventid_from_multiple_selections(
    sqlite_backend: sqliteBackend,
):
    """Test Zircolite output extracts EventIDs from multiple detection selections"""
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test with Multiple Selections
            status: test
            logsource:
                category: test_category
                product: windows
            detection:
                sel1:
                    EventID: 4624
                    LogonType: 10
                sel2:
                    EventID: 4625
                    LogonType: 10
                condition: sel1 or sel2
        """
    )
    result = json.loads(sqlite_backend.convert(rule, "zircolite"))
    assert result[0]["channel"] == []
    assert set(result[0]["eventid"]) == {4624, 4625}


# ==================== Field Reference (fieldref) Modifier Tests ====================


def test_sqlite_fieldref_equals(sqlite_backend: sqliteBackend):
    """Test field reference modifier - field equals another field"""
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|fieldref: fieldB
                condition: sel
        """
        )
    ) == ["SELECT * FROM logs WHERE fieldA=fieldB"]


def test_sqlite_fieldref_multiple_values(sqlite_backend: sqliteBackend):
    """Test field reference modifier with multiple field values"""
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|fieldref:
                        - fieldD
                        - fieldE
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """
        )
    ) == [
        "SELECT * FROM logs WHERE (fieldA=fieldD OR fieldA=fieldE) AND fieldB='foo' AND fieldC='bar'"
    ]


# ==================== Timestamp Part Modifier Tests ====================


@pytest.mark.parametrize(
    "modifier, value, part",
    [
        ("minute", 30, "%M"),
        ("hour", 14, "%H"),
        ("day", 15, "%d"),
        ("month", 12, "%m"),
        ("year", 2024, "%Y"),
    ],
)
def test_sqlite_timestamp_part(modifier, value, part):
    assert convert_selection({f"timestamp|{modifier}": value}) == [
        f"SELECT * FROM logs WHERE CAST(strftime('{part}', timestamp) AS INTEGER)={value}"
    ]


# ==================== Comparison Modifier Tests ====================


@pytest.mark.parametrize(
    "modifier, expected",
    [("gt", [3]), ("gte", [2, 3]), ("lt", [1]), ("lte", [1, 2])],
)
@pytest.mark.parametrize("affinity", ["TEXT COLLATE NOCASE", "NUMERIC", ""])
def test_sqlite_compare(modifier, expected, affinity):
    sql = convert_selection({f"fieldA|{modifier}": 10})[0]
    with sqlite3.connect(":memory:") as db:
        db.execute(f"CREATE TABLE logs(id INTEGER PRIMARY KEY, fieldA {affinity})")
        db.executemany(
            "INSERT INTO logs(fieldA) VALUES(?)",
            [
                ("2",),
                ("1e1",),
                ("20",),
                ("unavailable",),
                ("10px",),
                (None,),
                (b"99",),
                ("1e999",),
                (float("-inf"),),
            ],
        )
        assert [row[0] for row in db.execute(sql)] == expected


def test_numeric_comparison_preserves_integer_precision():
    sql = convert_selection({"fieldA|gt": 2**53})[0]
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(fieldA TEXT)")
        db.executemany("INSERT INTO logs VALUES(?)", [(str(2**53),), (str(2**53 + 1),)])
        assert db.execute(sql).fetchall() == [(str(2**53 + 1),)]


@pytest.mark.parametrize(
    ("field", "affinity", "left", "right", "extra"),
    [
        (
            "Channel",
            "TEXT COLLATE NOCASE",
            ["Security", "Setup"],
            ["security", "Setup"],
            "System",
        ),
        ("EventID", "INTEGER", [1, 2], ["1", 2], 3),
    ],
)
def test_metadata_bounds_cover_all_rows_returned_by_sql(
    field, affinity, left, right, extra
):
    rule = {
        "title": "Bounds",
        "logsource": {"category": "test"},
        "detection": {
            "a": {field: left},
            "b": {field: right},
            "c": {field: extra},
            "condition": "(a and b) or c",
        },
    }
    entry = json.loads(
        sqliteBackend().convert(SigmaCollection.from_dicts([rule]), "zircolite")
    )[0]
    with sqlite3.connect(":memory:") as db:
        db.execute(f"CREATE TABLE logs({field} {affinity})")
        db.executemany("INSERT INTO logs VALUES(?)", [(v,) for v in [*left, extra]])
        results = {str(v).lower() for (v,) in db.execute(entry["rule"][0])}
    bounds = entry[field.lower()]
    assert results <= {str(v).lower() for v in bounds}


@pytest.mark.parametrize(
    ("field", "broader", "narrower"),
    [
        ("Channel", ["Security", "System"], ["System"]),
        ("EventID", [12, 13, 14], [12, 13]),
    ],
)
def test_and_keeps_shortest_proven_allowlist(field, broader, narrower):
    doc = {
        "title": "Constrained by pipeline and rule",
        "logsource": {"category": "test"},
        "detection": {
            "a": {field: broader},
            "b": {field: narrower},
            "condition": "a and b",
        },
    }
    (entry,) = json.loads(
        sqliteBackend().convert(SigmaCollection.from_dicts([doc]), "zircolite")
    )
    assert entry[field.lower()] == narrower


# ==================== All Modifier Tests ====================


def test_sqlite_all_modifier(sqlite_backend: sqliteBackend):
    """Test all modifier - all values must match"""
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|all:
                        - value1
                        - value2
                condition: sel
        """
        )
    ) == ["SELECT * FROM logs WHERE fieldA='value1' AND fieldA='value2'"]


def test_sqlite_all_contains_modifier(sqlite_backend: sqliteBackend):
    """Test all modifier with contains"""
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|all|contains:
                        - part1
                        - part2
                condition: sel
        """
        )
    ) == [
        "SELECT * FROM logs WHERE fieldA LIKE '%part1%' ESCAPE '\\' AND fieldA LIKE '%part2%' ESCAPE '\\'"
    ]


# ==================== Null Value Tests ====================


def test_sqlite_null_value(sqlite_backend: sqliteBackend):
    """Test null value detection"""
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: null
                condition: sel
        """
        )
    ) == ["SELECT * FROM logs WHERE fieldA IS NULL"]


# ==================== Boolean Value Tests ====================


@pytest.mark.parametrize(
    "value, text, number", [(True, "true", 1), (False, "false", 0)]
)
def test_sqlite_boolean(value, text, number):
    assert convert_selection({"fieldA": value}) == [
        f"SELECT * FROM logs WHERE (fieldA='{text}' OR fieldA={number})"
    ]


# ==================== Additional Modifier Tests ====================


def test_sqlite_exists_modifier(sqlite_backend: sqliteBackend):
    """Test exists modifier - field must exist (not null)"""
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|exists: true
                condition: sel
        """
        )
    ) == ["SELECT * FROM logs WHERE fieldA IS NOT NULL"]


def test_sqlite_not_condition(sqlite_backend: sqliteBackend):
    """Test NOT condition"""
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                filter:
                    fieldB: valueB
                condition: sel and not filter
        """
        )
    ) == [
        "SELECT * FROM logs WHERE fieldA='valueA' AND (NOT COALESCE((fieldB='valueB'), 0))"
    ]


def test_sqlite_neq_single_value(sqlite_backend: sqliteBackend):
    """Test neq modifier with a single value"""
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|neq: valueA
                condition: sel
        """
        )
    ) == ["SELECT * FROM logs WHERE NOT COALESCE((fieldA='valueA'), 0)"]


def test_sqlite_neq_multi_value(sqlite_backend: sqliteBackend):
    """Test neq modifier with multiple values"""
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|neq:
                        - val1
                        - val2
                condition: sel
        """
        )
    ) == ["SELECT * FROM logs WHERE NOT COALESCE((fieldA='val1' OR fieldA='val2'), 0)"]


def test_sqlite_wildcard_filter_pattern(sqlite_backend: sqliteBackend):
    """Regression: filter selections matched via pattern_* with wildcard values"""
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                filter_foo:
                    fieldB: valueB*
                filter_bar:
                    fieldC: valueC
                condition: sel and not 1 of filter_*
        """
        )
    ) == [
        "SELECT * FROM logs WHERE fieldA='valueA' AND (NOT COALESCE((fieldB LIKE 'valueB%' ESCAPE '\\' OR fieldC='valueC'), 0))"
    ]


def test_sqlite_custom_timestamp_field():
    """Test that timestamp_field can be customized for temporal correlations"""
    backend = sqliteBackend(timestamp_field="event_time")

    rules = SigmaCollection.from_yaml(
        """
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Temporal Correlation
        status: test
        correlation:
            type: temporal
            rules: base_rule
            timespan: 5m
            condition:
                gte: 2
    """
    )
    result = backend.convert(rules)
    # The window arithmetic must read the configured field, not the default one
    assert "julianday(event_time)" in result[0]
    assert "timestamp" not in result[0]


def test_sqlite_table_name_from_setstate_pipeline():
    """Table name is set via a setState transformation ('table' key) for plain and correlation rules."""

    pipeline = ProcessingPipeline(
        items=[
            ProcessingItem(transformation=SetStateTransformation("table", "my_events"))
        ]
    )
    backend = sqliteBackend(processing_pipeline=pipeline)

    # Plain rule uses the pipeline-provided table name.
    plain = SigmaCollection.from_yaml(
        """
        title: Plain Rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA: valueA
            condition: sel
    """
    )
    assert backend.convert(plain) == ["SELECT * FROM my_events WHERE fieldA='valueA'"]

    # Correlation subquery uses it too, not the hardcoded 'logs'.
    correlation = SigmaCollection.from_yaml(
        """
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA: valueA
            condition: sel
---
        title: Event Count Correlation
        status: test
        correlation:
            type: event_count
            rules: base_rule
            group-by: fieldA
            timespan: 5m
            condition:
                gte: 10
    """
    )
    result = backend.convert(correlation)
    assert "FROM my_events" in result[0]
    assert "FROM logs" not in result[0]


# ==================== Behavioural tests ====================
#
# Everything above compares query text. These run the generated SQL against a database shaped
# like the one Zircolite builds -- every column TEXT/INTEGER COLLATE NOCASE, a regexp() user
# function, and events that simply lack fields -- and assert which rows come back. Sigma reads
# a condition on an absent field as false; SQL reads it as NULL, and the difference is only
# visible when the query actually runs.

EVENTS = [
    # row_id, Channel, EventID, CommandLine, Image, Flag, FlagNum, User
    (1, "Security", 4688, None, "C:\\Windows\\System32\\cmd.exe", "true", 1, "alice"),
    (
        2,
        "Security",
        4688,
        "foo.exe -x",
        "C:\\Windows\\System32\\cmd.exe",
        "false",
        0,
        "bob",
    ),
    (
        3,
        "Microsoft-Windows-Sysmon/Operational",
        3,
        "bar.exe",
        "a*b",
        "true",
        1,
        "alice",
    ),
    (
        4,
        "Microsoft-Windows-Sysmon/Operational",
        3,
        "baz.exe",
        "axb",
        "true",
        1,
        "alice",
    ),
]


def make_db():
    """An in-memory table shaped like Zircolite's: NOCASE columns and a regexp() function."""
    connection = sqlite3.connect(":memory:")
    connection.create_function(
        # Mirrors zircolite/core.py: a regexp against a missing field is false, not an error.
        "regexp",
        2,
        regexp,
    )
    connection.execute(
        "CREATE TABLE logs ("
        "row_id INTEGER PRIMARY KEY, "
        "Channel TEXT COLLATE NOCASE, "
        "EventID INTEGER COLLATE NOCASE, "
        "CommandLine TEXT COLLATE NOCASE, "
        "Image TEXT COLLATE NOCASE, "
        "Flag TEXT COLLATE NOCASE, "
        "FlagNum INTEGER COLLATE NOCASE, "
        "User TEXT COLLATE NOCASE)"
    )
    connection.executemany("INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?, ?)", EVENTS)
    return connection


def matching_rows(detection: str, backend: sqliteBackend = None) -> set:
    """Row ids returned by the rule's query, run against the fixture database."""
    backend = backend or sqliteBackend()
    query = backend.convert(
        SigmaCollection.from_yaml(
            "title: Test\nstatus: test\n"
            "logsource:\n    product: windows\n"
            "detection:\n" + detection
        )
    )[0].replace("SELECT *", "SELECT row_id", 1)
    with make_db() as connection:
        return {row[0] for row in connection.execute(query)}


def test_behaviour_negated_filter_keeps_event_lacking_the_field():
    """The Zircolite 4.0 fix: row 1 has no CommandLine, so "not filter" must not hide it."""
    assert matching_rows(
        "    sel:\n        EventID: 4688\n"
        "    filter:\n        CommandLine|contains: 'foo'\n"
        "    condition: sel and not filter\n"
    ) == {1}


def test_behaviour_nested_negation_on_absent_field():
    """not (a and not b) with b absent: Sigma reads b as false, so the inner not is true."""
    assert matching_rows(
        "    sel:\n        EventID: 4688\n"
        "    a:\n        Image|contains: 'cmd.exe'\n"
        "    b:\n        CommandLine|contains: 'foo'\n"
        "    condition: sel and not (a and not b)\n"
    ) == {2}


def test_behaviour_negated_regexp_on_absent_field():
    assert matching_rows(
        "    sel:\n        EventID: 4688\n"
        "    filter:\n        CommandLine|re: 'foo'\n"
        "    condition: sel and not filter\n"
    ) == {1}


def test_behaviour_exists_true_and_false():
    assert matching_rows(
        "    sel:\n        CommandLine|exists: true\n    condition: sel\n"
    ) == {2, 3, 4}
    assert matching_rows(
        "    sel:\n        CommandLine|exists: false\n    condition: sel\n"
    ) == {1}


def test_behaviour_neq_matches_event_lacking_the_field():
    assert matching_rows(
        "    sel:\n        CommandLine|neq: 'foo.exe -x'\n    condition: sel\n"
    ) == {1, 3, 4}


def test_behaviour_boolean_matches_text_and_numeric_storage():
    """Zircolite stores 'true'; a hand-built table is as likely to hold 1."""
    assert matching_rows("    sel:\n        Flag: true\n    condition: sel\n") == {
        1,
        3,
        4,
    }
    assert matching_rows("    sel:\n        FlagNum: true\n    condition: sel\n") == {
        1,
        3,
        4,
    }
    assert matching_rows("    sel:\n        Flag: false\n    condition: sel\n") == {2}
    assert matching_rows("    sel:\n        FlagNum: false\n    condition: sel\n") == {
        2
    }


def test_behaviour_cased_literal_glob_metacharacter():
    """A literal "*" in a |cased value must not act as a glob wildcard."""
    assert matching_rows(
        "    sel:\n        Image|cased: 'a\\*b'\n    condition: sel\n"
    ) == {3}
    assert matching_rows(
        "    sel:\n        Image|cased: 'a*b'\n    condition: sel\n"
    ) == {3, 4}


def test_behaviour_equality_is_case_insensitive_on_nocase_columns():
    """Sigma matches case-insensitively; Zircolite provides that with COLLATE NOCASE columns."""
    assert matching_rows("    sel:\n        User: 'ALICE'\n    condition: sel\n") == {
        1,
        3,
        4,
    }


def test_behaviour_collate_nocase_option_on_a_binary_column():
    """Without NOCASE columns the option is what keeps "=" Sigma-conformant."""
    rule = SigmaCollection.from_yaml(
        "title: Test\nstatus: test\nlogsource:\n    product: windows\n"
        "detection:\n    sel:\n        User: 'ALICE'\n    condition: sel\n"
    )
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE logs (row_id INTEGER PRIMARY KEY, User TEXT)")
    connection.execute("INSERT INTO logs VALUES (1, 'alice')")

    plain = sqliteBackend()
    assert connection.execute(plain.convert(rule)[0]).fetchall() == []

    collating = sqliteBackend(collate_nocase=True)
    assert connection.execute(collating.convert(rule)[0]).fetchall() == [(1, "alice")]


def test_behaviour_deep_or_chain_is_accepted_by_sqlite():
    """A flat chain of this length exceeds SQLITE_MAX_EXPR_DEPTH and never matched anything."""
    values = "".join(f"            - v{index}\n" for index in range(5000))
    assert matching_rows(
        "    sel:\n        CommandLine|contains:\n"
        + values
        + "            - bar.exe\n    condition: sel\n"
    ) == {3}


def test_fieldref_like_metacharacters_from_the_event_are_literal():
    """fieldref compares two fields, so a "%" in the second must not become a wildcard."""
    query = (
        sqliteBackend()
        .convert(
            SigmaCollection.from_yaml(
                "title: Test\nstatus: test\nlogsource:\n    product: windows\n"
                "detection:\n    sel:\n        a|fieldref|contains: b\n    condition: sel\n"
            )
        )[0]
        .replace("logs", "t")
        .replace("SELECT *", "SELECT row_id", 1)
    )
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE t (row_id INTEGER PRIMARY KEY, a TEXT, b TEXT)")
    connection.executemany(
        "INSERT INTO t VALUES (?, ?, ?)",
        [
            (1, "x1%0y", "1%0"),
            (2, "x100y", "1%0"),
            (3, "abc", "a_c"),
            (4, "a_c", "a_c"),
        ],
    )
    assert {row[0] for row in connection.execute(query)} == {1, 4}


# ---- Zircolite rule metadata ----


def zircolite_rule(detection: str) -> dict:
    return json.loads(
        sqliteBackend().convert(
            SigmaCollection.from_yaml(
                "title: Test\nstatus: test\nlogsource:\n    product: windows\n"
                "detection:\n" + detection
            ),
            "zircolite",
        )
    )[0]


def test_zircolite_metadata_ignores_negated_channel():
    """Zircolite reads these as an allow-list; a channel the rule excludes would starve it."""
    rule = zircolite_rule(
        "    sel:\n        EventID: 4688\n"
        "    filter:\n        Channel: 'Noise'\n"
        "    condition: sel and not filter\n"
    )
    assert rule["channel"] == []
    assert rule["eventid"] == [4688]


def test_zircolite_metadata_ignores_wildcard_channel():
    rule = zircolite_rule(
        "    sel:\n        Channel|contains: 'Sysmon'\n        EventID: 1\n    condition: sel\n"
    )
    assert rule["channel"] == []
    assert rule["eventid"] == [1]


def test_zircolite_metadata_keeps_the_event_ids_the_rule_wants():
    rule = zircolite_rule(
        "    sel:\n        Channel: Security\n        EventID:\n            - 4624\n            - 4625\n"
        "    filter:\n        EventID: 4624\n"
        "    condition: sel and not filter\n"
    )
    assert rule["channel"] == ["Security"]
    assert rule["eventid"] == [4624, 4625]


def test_zircolite_metadata_unbounded_when_an_or_branch_is():
    rule = zircolite_rule(
        "    sel1:\n        Channel: Security\n        EventID: 4624\n"
        "    sel2:\n        EventID: 1\n"
        "    condition: sel1 or sel2\n"
    )
    assert rule["channel"] == []
    assert rule["eventid"] == [1, 4624]


def test_zircolite_correlation_rule_is_marked():
    rules = SigmaCollection.from_yaml(
        """
        title: Base Rule
        name: base_rule
        status: test
        logsource:
            category: test_category
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Correlation
        status: test
        correlation:
            type: event_count
            rules: base_rule
            timespan: 5m
            condition:
                gte: 10
    """
    )
    converted = json.loads(sqliteBackend().convert(rules, "zircolite"))
    assert converted[-1]["correlation"] is True
    assert converted[-1]["channel"] == []
    assert converted[-1]["eventid"] == []


# ---- correlation behaviour ----

CORRELATION_BASE = """
        title: A
        name: rule_a
        status: test
        logsource:
            category: test_category
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: B
        name: rule_b
        status: test
        logsource:
            category: test_category
        detection:
            sel:
                EventID: 5678
            condition: sel
---
"""

CORRELATION_EVENTS = (
    # a burst of ten events inside five minutes, and twelve spread over an hour
    [
        (f"2024-01-01T11:0{index // 2}:00", "burst", f"u{index}", 100, 1234)
        for index in range(10)
    ]
    + [("2024-01-01T10:00:00", "spread", f"u{index}", 10, 1234) for index in range(6)]
    + [("2024-01-01T10:59:00", "spread", f"u{index}", 10, 1234) for index in range(6)]
    # rule_a then rule_b for "ordered", the reverse for "reversed"
    + [
        ("2024-01-02T10:00:00", "ordered", "x", 1, 1234),
        ("2024-01-02T10:01:00", "ordered", "x", 1, 5678),
    ]
    + [
        ("2024-01-02T10:00:00", "reversed", "x", 1, 5678),
        ("2024-01-02T10:01:00", "reversed", "x", 1, 1234),
    ]
)


def correlation_groups(correlation: str) -> set:
    """Groups selected by the correlation query, run against CORRELATION_EVENTS."""
    query = sqliteBackend().convert(
        SigmaCollection.from_yaml(CORRELATION_BASE + correlation)
    )[-1]
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE logs (timestamp TEXT COLLATE NOCASE, Host TEXT COLLATE NOCASE, "
        "User TEXT COLLATE NOCASE, Bytes INTEGER, EventID INTEGER)"
    )
    connection.executemany(
        "INSERT INTO logs VALUES (?, ?, ?, ?, ?)", CORRELATION_EVENTS
    )
    return {json.loads(row[1])["Host"] for row in connection.execute(query)}


@pytest.mark.parametrize(
    "correlation_type,condition,expected",
    [
        # "spread" has twelve events, but never ten inside one five-minute window
        ("event_count", "gte: 10", {"burst"}),
        ("value_count", "gte: 10\n                field: User", {"burst"}),
        ("value_sum", "gte: 1000\n                field: Bytes", {"burst"}),
        ("value_avg", "gte: 50\n                field: Bytes", {"burst"}),
        ("value_median", "gte: 50\n                field: Bytes", {"burst"}),
        (
            "value_percentile",
            "gte: 100\n                field: Bytes\n                percentile: 95",
            {"burst"},
        ),
    ],
)
def test_correlation_honours_the_timespan(correlation_type, condition, expected):
    assert (
        correlation_groups(
            f"""
        title: Correlation
        status: test
        correlation:
            type: {correlation_type}
            rules: rule_a
            group-by: Host
            timespan: 5m
            condition:
                {condition}
    """
        )
        == expected
    )


def test_correlation_temporal_ignores_order():
    assert correlation_groups(
        """
        title: Correlation
        status: test
        correlation:
            type: temporal
            rules:
                - rule_a
                - rule_b
            group-by: Host
            timespan: 5m
    """
    ) == {"ordered", "reversed"}


def test_correlation_temporal_ordered_enforces_order():
    """Without the ordering test this type was indistinguishable from plain temporal."""
    assert correlation_groups(
        """
        title: Correlation
        status: test
        correlation:
            type: temporal_ordered
            rules:
                - rule_a
                - rule_b
            group-by: Host
            timespan: 5m
    """
    ) == {"ordered"}


def test_correlation_temporal_extended_condition():
    assert correlation_groups(
        """
        title: Correlation
        status: test
        correlation:
            type: temporal
            rules:
                - rule_a
                - rule_b
            group-by: Host
            timespan: 5m
            condition: rule_a and not rule_b
    """
    ) == {"burst", "spread"}


def test_correlation_temporal_ordered_extended_condition():
    assert correlation_groups(
        """
        title: Correlation
        status: test
        correlation:
            type: temporal_ordered
            rules:
                - rule_a
                - rule_b
            group-by: Host
            timespan: 5m
            condition: rule_a and rule_b
    """
    ) == {"ordered"}
