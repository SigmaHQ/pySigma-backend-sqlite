import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError


@pytest.fixture
def sqlite_backend():
    return sqliteBackend()


# ==================== Basic Tests (existing) ====================


# TODO: implement tests for some basic queries and their expected results.
def test_sqlite_and_expression(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
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
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' AND fieldB='valueB'"]
    )


def test_sqlite_or_expression(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
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
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' OR fieldB='valueB'"]
    )


def test_sqlite_and_or_expression(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
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
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE (fieldA='valueA1' OR fieldA='valueA2') AND (fieldB='valueB1' OR fieldB='valueB2')"
        ]
    )


def test_sqlite_or_and_expression(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
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
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE (fieldA='valueA1' AND fieldB='valueB1') OR (fieldA='valueA2' AND fieldB='valueB2')"
        ]
    )


def test_sqlite_in_expression(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
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
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' OR fieldA='valueB' OR fieldA LIKE 'valueC%' ESCAPE '\\'"
        ]
    )


def test_sqlite_regex_query(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
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
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA REGEXP 'foo.*bar' AND fieldB='foo'"
        ]
    )


def test_sqlite_cidr_query(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
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
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE field LIKE '192.168.%' ESCAPE '\\'"]
    )


def test_sqlite_field_name_with_whitespace(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
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
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE `field name`='value'"]
    )


def test_sqlite_value_with_wildcards(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
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
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE 'wildcard\\%value' ESCAPE '\\' AND fieldB LIKE 'wildcard\\_value' ESCAPE '\\'"
        ]
    )


def test_sqlite_value_contains(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: wildcard%value
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE '%wildcard\\%value%' ESCAPE '\\'"
        ]
    )


def test_sqlite_value_startswith(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: wildcard%value
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE 'wildcard\\%value%' ESCAPE '\\'"
        ]
    )


def test_sqlite_value_endswith(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith: wildcard%value
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE '%wildcard\\%value' ESCAPE '\\'"
        ]
    )


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
    assert (
        str(e.value)
        == "Value-only string expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
    )


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
    assert (
        str(e.value)
        == "Value-only number expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
    )

def test_sqlite_value_case_sensitive_contains(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
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
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA GLOB '*VaLuE*' ESCAPE '\\'"
        ]
    )

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
    assert (
        sqlite_backend.convert(rule, "zircolite")
        == '[{"title": "Test", "id": "", "status": "test", "description": "", "author": "", "tags": [], "falsepositives": [], "level": "", "rule": ["SELECT * FROM logs WHERE fieldA=\'value\'"], "filename": "", "channel": [], "eventid": []}]'
    )


def test_sqlite_zircolite_output_with_channel_and_eventid(sqlite_backend: sqliteBackend):
    """Test Zircolite output includes channel and eventid arrays"""
    import json
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
    import json
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


def test_sqlite_zircolite_output_eventid_from_multiple_selections(sqlite_backend: sqliteBackend):
    """Test Zircolite output extracts EventIDs from multiple detection selections"""
    import json
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
    assert (
        sqlite_backend.convert(
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
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA=fieldB"]
    )


def test_sqlite_fieldref_multiple_values(sqlite_backend: sqliteBackend):
    """Test field reference modifier with multiple field values"""
    assert (
        sqlite_backend.convert(
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
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE (fieldA=fieldD OR fieldA=fieldE) AND fieldB='foo' AND fieldC='bar'"]
    )


# ==================== Timestamp Part Modifier Tests ====================

def test_sqlite_timestamp_hour(sqlite_backend: sqliteBackend):
    """Test hour timestamp part modifier"""
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    timestamp|hour: 14
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE CAST(strftime('%H', timestamp) AS INTEGER)=14"]
    )


def test_sqlite_timestamp_minute(sqlite_backend: sqliteBackend):
    """Test minute timestamp part modifier"""
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    timestamp|minute: 30
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE CAST(strftime('%M', timestamp) AS INTEGER)=30"]
    )


def test_sqlite_timestamp_day(sqlite_backend: sqliteBackend):
    """Test day timestamp part modifier"""
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    timestamp|day: 15
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE CAST(strftime('%d', timestamp) AS INTEGER)=15"]
    )


def test_sqlite_timestamp_week(sqlite_backend: sqliteBackend):
    """Test week timestamp part modifier"""
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    timestamp|week: 42
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE CAST(strftime('%W', timestamp) AS INTEGER)=42"]
    )


def test_sqlite_timestamp_month(sqlite_backend: sqliteBackend):
    """Test month timestamp part modifier"""
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    timestamp|month: 12
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE CAST(strftime('%m', timestamp) AS INTEGER)=12"]
    )


def test_sqlite_timestamp_year(sqlite_backend: sqliteBackend):
    """Test year timestamp part modifier"""
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    timestamp|year: 2024
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE CAST(strftime('%Y', timestamp) AS INTEGER)=2024"]
    )


# ==================== Comparison Modifier Tests ====================

def test_sqlite_compare_gt(sqlite_backend: sqliteBackend):
    """Test greater than comparison modifier"""
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|gt: 100
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA > 100"]
    )


def test_sqlite_compare_gte(sqlite_backend: sqliteBackend):
    """Test greater than or equal comparison modifier"""
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|gte: 100
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA >= 100"]
    )


def test_sqlite_compare_lt(sqlite_backend: sqliteBackend):
    """Test less than comparison modifier"""
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|lt: 50
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA < 50"]
    )


def test_sqlite_compare_lte(sqlite_backend: sqliteBackend):
    """Test less than or equal comparison modifier"""
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|lte: 50
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA <= 50"]
    )


# ==================== All Modifier Tests ====================

def test_sqlite_all_modifier(sqlite_backend: sqliteBackend):
    """Test all modifier - all values must match"""
    assert (
        sqlite_backend.convert(
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
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='value1' AND fieldA='value2'"]
    )


def test_sqlite_all_contains_modifier(sqlite_backend: sqliteBackend):
    """Test all modifier with contains"""
    assert (
        sqlite_backend.convert(
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
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE '%part1%' ESCAPE '\\' AND fieldA LIKE '%part2%' ESCAPE '\\'"]
    )


# ==================== Null Value Tests ====================

def test_sqlite_null_value(sqlite_backend: sqliteBackend):
    """Test null value detection"""
    assert (
        sqlite_backend.convert(
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
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA IS NULL"]
    )


# ==================== Boolean Value Tests ====================

def test_sqlite_boolean_true(sqlite_backend: sqliteBackend):
    """Test boolean true value"""
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: true
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA=true"]
    )


def test_sqlite_boolean_false(sqlite_backend: sqliteBackend):
    """Test boolean false value"""
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: false
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA=false"]
    )


# ==================== Correlation Tests ====================

def test_sqlite_correlation_event_count_basic(sqlite_backend: sqliteBackend):
    """Test basic event count correlation"""
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
        title: Event Count Correlation
        status: test
        correlation:
            type: event_count
            rules: base_rule
            timespan: 5m
            condition:
                gte: 10
    """
    )
    assert sqlite_backend.convert(rules) == [
        "SELECT *, COUNT(*) AS event_count FROM (SELECT * FROM logs WHERE EventID=1234) AS subquery HAVING event_count >= 10"
    ]


def test_sqlite_correlation_event_count_with_groupby(sqlite_backend: sqliteBackend):
    """Test event count correlation with group by - only selects grouped fields to avoid undefined behavior"""
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
        title: Event Count Correlation with Group By
        status: test
        correlation:
            type: event_count
            rules: base_rule
            group-by:
                - SourceIP
            timespan: 5m
            condition:
                gte: 5
    """
    )
    assert sqlite_backend.convert(rules) == [
        "SELECT SourceIP, COUNT(*) AS event_count FROM (SELECT * FROM logs WHERE EventID=1234) AS subquery GROUP BY SourceIP HAVING event_count >= 5"
    ]


def test_sqlite_correlation_value_count(sqlite_backend: sqliteBackend):
    """Test value count correlation"""
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
        title: Value Count Correlation
        status: test
        correlation:
            type: value_count
            rules: base_rule
            timespan: 5m
            condition:
                field: TargetUserName
                gte: 3
    """
    )
    assert sqlite_backend.convert(rules) == [
        "SELECT *, COUNT(DISTINCT TargetUserName) AS value_count FROM (SELECT * FROM logs WHERE EventID=1234) AS subquery HAVING value_count >= 3"
    ]


def test_sqlite_correlation_temporal(sqlite_backend: sqliteBackend):
    """Test temporal correlation - only selects grouped fields to avoid undefined behavior"""
    rules = SigmaCollection.from_yaml(
        """
        title: Rule A
        name: rule_a
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                EventID: 1234
            condition: sel
---
        title: Rule B
        name: rule_b
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
            rules:
                - rule_a
                - rule_b
            timespan: 5m
            group-by:
                - TargetUserName
    """
    )
    assert sqlite_backend.convert(rules) == [
        "SELECT TargetUserName, COUNT(DISTINCT sigma_rule_id) AS rule_count, MIN(timestamp) AS first_event, MAX(timestamp) AS last_event FROM (SELECT *, 'rule_a' AS sigma_rule_id FROM logs WHERE EventID=1234 UNION ALL SELECT *, 'rule_b' AS sigma_rule_id FROM logs WHERE EventID=1234) AS subquery GROUP BY TargetUserName HAVING rule_count >= 2 AND (julianday(last_event) - julianday(first_event)) * 86400 <= 300"
    ]


def test_sqlite_correlation_value_sum(sqlite_backend: sqliteBackend):
    """Test value sum correlation"""
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
        title: Value Sum Correlation
        status: test
        correlation:
            type: value_sum
            rules: base_rule
            timespan: 1h
            condition:
                field: BytesSent
                gte: 1000000
    """
    )
    assert sqlite_backend.convert(rules) == [
        "SELECT *, SUM(BytesSent) AS value_sum FROM (SELECT * FROM logs WHERE EventID=1234) AS subquery HAVING value_sum >= 1000000"
    ]


def test_sqlite_correlation_value_avg(sqlite_backend: sqliteBackend):
    """Test value avg correlation"""
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
        title: Value Avg Correlation
        status: test
        correlation:
            type: value_avg
            rules: base_rule
            timespan: 1h
            condition:
                field: BytesSent
                gte: 50000
    """
    )
    assert sqlite_backend.convert(rules) == [
        "SELECT *, AVG(BytesSent) AS value_avg FROM (SELECT * FROM logs WHERE EventID=1234) AS subquery HAVING value_avg >= 50000"
    ]


# ==================== Additional Modifier Tests ====================

def test_sqlite_exists_modifier(sqlite_backend: sqliteBackend):
    """Test exists modifier - field must exist (not null)"""
    assert (
        sqlite_backend.convert(
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
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA = fieldA"]
    )


def test_sqlite_not_condition(sqlite_backend: sqliteBackend):
    """Test NOT condition"""
    assert (
        sqlite_backend.convert(
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
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' AND (NOT fieldB='valueB')"]
    )


def test_sqlite_custom_timestamp_field():
    """Test that timestamp_field can be customized for temporal correlations"""
    backend = sqliteBackend(correlation_methods=["default"])
    backend.timestamp_field = "event_time"

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
    # Verify the custom timestamp field is used instead of the default 'timestamp'
    assert "MIN(event_time)" in result[0]
    assert "MAX(event_time)" in result[0]
    assert "MIN(timestamp)" not in result[0]
    assert "MAX(timestamp)" not in result[0]
