![Tests](https://github.com/wagga40/pySigma-backend-sqlite/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/wagga40/2ec45ded898fa11f2c42bcb9d2b163cf/raw/test.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma SQLite Backend

This is the SQLite backend for pySigma. It provides the package `sigma.backends.sqlite` with the `sqliteBackend` class.

This backend also aims to be compatible with [Zircolite](https://github.com/wagga40/Zircolite) which uses **pure SQLite queries** to perform SIGMA-based detection on EVTX, Auditd, Sysmon for linux, XML or JSONL/NDJSON Logs.

It supports the following output formats:

* **default**: plain SQLite queries
* **zircolite** : SQLite queries in JSON format for Zircolite

This backend is currently maintained by:

* [wagga](https://github.com/wagga40/)

## Requirements

* Python 3.10 or later
* [pySigma](https://github.com/SigmaHQ/pySigma) `>= 1.0.2, < 2.0` (tested with 1.5.0)

## Supported Features

### Sigma Modifiers

| Modifier | Description | SQLite Implementation |
|----------|-------------|----------------------|
| `contains` | Substring matching | `LIKE '%value%'` |
| `startswith` | Prefix matching | `LIKE 'value%'` |
| `endswith` | Suffix matching | `LIKE '%value'` |
| `all` | All values must match | Multiple `AND` conditions |
| `re` | Regular expressions | `REGEXP` |
| `cidr` | CIDR network matching | Expanded to `LIKE` patterns |
| `cased` | Case-sensitive matching | `GLOB` |
| `fieldref` | Compare two fields | `field1=field2` or with `LIKE` for startswith/endswith/contains |
| `exists` | Field existence check | `field IS NOT NULL` / `field IS NULL` |
| `gt`, `gte`, `lt`, `lte` | Numeric comparisons | `>`, `>=`, `<`, `<=` |
| `neq` | Not equal | `NOT COALESCE((field='value'), 0)` |
| `hour`, `minute`, `day`, `week`, `month`, `year` | Timestamp part extraction | `strftime()` |
| `base64`, `base64offset`, `wide`, `utf16`, `utf16be`, `windash` | Value expansion | handled by pySigma, emitted as ordinary string matches |

> **Note on `cased`:** SQLite's `GLOB` is a native 2-argument operator with no `ESCAPE` clause, so queries are emitted as `field GLOB 'pattern'` and backslashes are kept literal (e.g. Windows paths match as-is). A *literal* `*`, `?` or `[` in a `cased` value is escaped as the single-member character class `[*]`, `[?]` or `[[]`, which is the escape `GLOB` does have.

### Query semantics

The generated SQL is meant to mean what the Sigma rule means, without the caller having to repair it first.

#### Negation and absent fields

Sigma reads a condition on a field the event does not carry as **false**, so `selection and not filter` still matches when the filter names such a field. SQLite evaluates that comparison to `NULL`, `NOT NULL` is `NULL`, and the row is dropped. Every generated `NOT` therefore wraps its operand:

```sql
SELECT * FROM logs WHERE EventID=1 AND (NOT COALESCE((CommandLine LIKE '%foo%' ESCAPE '\'), 0))
```

The wrapper is applied at every `NOT`, not only the outermost, which is what makes nested negations come out right. Roughly one in five SigmaHQ rules contains a negation.

#### Case sensitivity

Sigma compares strings case-insensitively. SQLite's `=` does not, unless the column is declared `COLLATE NOCASE`. Against a table that does not, set `collate_nocase = True` and literal string equality is emitted as `field='value' COLLATE NOCASE`. It is off by default because a collation on an already-`NOCASE` column is noise and can cost an index seek. Comparisons emitted as `LIKE` are case-insensitive either way; `|cased` uses `GLOB`, which is case-sensitive by definition and is never collated. Note that SQLite's `NOCASE` folds ASCII only.

#### Booleans

A flattener has to choose how to store a JSON boolean: Zircolite stores the strings `'true'`/`'false'` because that is what Sigma rules compare against, while a hand-built table is as likely to hold `1`/`0` — and SQLite reads the bare keyword `true` as the integer `1`, which never equals the text `'true'`. Both are accepted:

```sql
SELECT * FROM logs WHERE (Flag='true' OR Flag=1)
```

#### Long value lists

SQLite parses `a OR b OR c` into a left-deep tree whose height is the operand count, and rejects anything over `SQLITE_MAX_EXPR_DEPTH` (1000 by default) with *"Expression tree is too large"*. Chains longer than `max_flat_operands` (100) are re-associated into nested groups, which is the same boolean value at a bounded height. SigmaHQ's *Vulnerable Driver Load*, with 4431 boolean operators, is rejected at prepare time without this and parses with it.

### Correlation Rules

The backend supports Sigma correlation rules with the following types:

| Correlation Type | Description |
|-----------------|-------------|
| `event_count` | Count events matching conditions |
| `value_count` | Count distinct field values |
| `temporal` | Events from multiple rules occurring within a timespan |
| `temporal_ordered` | Events occurring in a specific order within a timespan |
| `value_sum` | Sum of field values |
| `value_avg` | Average of field values |
| `value_percentile` | Percentile of field values |
| `value_median` | Median of field values |
| `temporal_extended` | Boolean expression over rule references within a timespan |
| `temporal_ordered_extended` | The same, with the declared rule order enforced |

Correlation rules support `group-by` for grouping results and `timespan` for temporal constraints.

#### The timespan is a sliding window

Sigma counts events *within the given timespan*. Aggregating over the whole search counts them over all time instead, which fires on a burst that never happened — twelve events an hour apart would satisfy "ten in five minutes". Every correlation query anchors on each matching event and looks forward over exactly one timespan:

```sql
WITH sigma_matched AS (SELECT * FROM logs WHERE EventID=1234)
SELECT DISTINCT SourceIP FROM (
  SELECT SourceIP, COUNT(*) OVER (
    PARTITION BY SourceIP
    ORDER BY CAST(strftime('%s', timestamp) AS INTEGER)
    RANGE BETWEEN CURRENT ROW AND 300 FOLLOWING) AS event_count
  FROM sigma_matched) AS sigma_correlated
WHERE event_count >= 10
```

Anchoring on the last event and looking back selects the same groups whenever the condition only grows with more events — every count, sum and average — but the two differ under a negation, and looking forward is the reading that answers it.

`event_count`, `value_sum` and `value_avg` use a window function. The others cannot: SQLite rejects `DISTINCT` inside a window function and does not allow a correlated subquery in `LIMIT`/`OFFSET`, so `value_count`, `value_percentile`, `value_median` and the temporal types use a scalar subquery correlated to each anchor row. That is exact, but quadratic in the number of matched events — a narrow base rule matters more for those types.

#### SQLite requirements for correlation

| Requirement | Description |
|-------------|-------------|
| **Timestamp field** | Required by every correlation type, since the timespan is applied to it. Must be a format SQLite's `strftime()` parses: ISO-8601 with or without `T`, `Z`, a fractional part or an offset. A column holding a bare epoch integer does **not** parse — `strftime('%s', 1553039077)` is `NULL`, not a time — so set `timestamp_seconds_expression` for one. |
| **Window functions** | SQLite 3.28 or later (`RANGE` frames). |

**Configurable parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `table` | `<TABLE_NAME>` | Table queried by non-correlation rules; can also be set by a `setState` transformation on the `table` key |
| `timestamp_field` | `timestamp` | Field name containing the event timestamp |
| `timestamp_seconds_expression` | `CAST(strftime('%s', {field}) AS INTEGER)` | How that field becomes seconds. Use `CAST({field} AS INTEGER)` for an epoch column |
| `collate_nocase` | `False` | Emit `COLLATE NOCASE` on literal string equality |
| `max_flat_operands` | `100` | Longest flat `AND`/`OR` chain before operands are regrouped |

```python
backend = sqliteBackend(correlation_methods=["default"])
backend.timestamp_field = "event_time"
```

**Notes:**
- For multi-rule correlations, the backend adds a `sigma_rule_id` column identifying which rule matched each event
- Timespan values are converted to seconds internally
- `temporal_ordered` enforces the declared order: the first occurrence of each referenced rule inside the window must not be later than the first occurrence of the next one
- Correlation queries are emitted as a CTE (`WITH ...`). Zircolite reads Channel/EventID bounds only off statement shapes it can prove, so a correlation rule leaves those bounds open — which is what it already does for any correlation rule, and is its documented fail-open

### Other Features

* **NULL value handling**: `field: null` → `field IS NULL`
* **Boolean values**: matched against both text and numeric storage (see *Booleans* above)
* **Field name quoting**: Special characters in field names are quoted with backticks
* **Wildcard escaping**: Proper escaping of `%` and `_` characters in values, including values read from a second field by `|fieldref`
* **Table name**: `<TABLE_NAME>` by default and `logs` for the `zircolite` format; both honour a `setState` transformation on the `table` key

## Known issues/limitations

* Full text search support will need some work and is not a priority since it needs virtual tables on SQLite side. Sigma rules using value-only (`keywords`) detections — about 3% of SigmaHQ — raise `SigmaFeatureNotSupportedByBackendError`
* `|re` is emitted as `field REGEXP 'pattern'`. SQLite has no built-in `REGEXP`, so the caller must register one; it should return false for a `NULL` input, as Zircolite's does, so that a regex on an absent field is false rather than an error
* `|cidr` is expanded into `LIKE` prefixes, since SQLite has no network type. For IPv6 this only matches addresses written in the same canonical form as the expansion
* The backend cannot know the target schema, so a rule naming a column the database does not have fails to prepare, taking its other branches with it. Zircolite widens its table with the missing columns as `NULL`; another consumer has to do the same

# Quick Start 

## Example script (default output) with sysmon pipeline

### Add pipelines 

```shell
poetry add pysigma-pipeline-sysmon
poetry add pysigma-pipeline-windows
```

### Convert a rule

```python
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline

# Combine pipelines to map both Channel and EventID:
# 1. sysmon_pipeline: maps category (e.g., process_creation) -> EventID (e.g., 1)
#                     and changes logsource to service=sysmon
# 2. windows_logsource_pipeline: maps service=sysmon -> Channel
#
# For process_creation/windows, this produces:
#   Channel='Microsoft-Windows-Sysmon/Operational' AND EventID=1
combined_pipeline = sysmon_pipeline() + windows_logsource_pipeline()
sqlite_backend = sqliteBackend(combined_pipeline)
# Set the table name for the generated SQL queries
sqlite_backend.table = "logs"


rule = SigmaCollection.from_yaml(
r"""
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
""")

print(sqlite_backend.convert(rule)[0])

```

## Running

```shell
poetry run python3 example.py
```
