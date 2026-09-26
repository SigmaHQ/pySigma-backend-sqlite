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
* [pySigma](https://github.com/SigmaHQ/pySigma) `>= 1.5.1, < 2.0`

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

### Correlation rules (version 2)

Correlation output is an **alert summary**, with an occurrence time and evidence,
not an arbitrary event or a list of group keys. The following eight types run on
SQLite: `event_count`, `value_count`, `value_sum`, `value_avg`, `value_median`,
`value_percentile`, `temporal`, and `temporal_ordered`. The last two also accept
pySigma's extended Boolean conditions; `temporal_extended` and
`temporal_ordered_extended` are internal conversion methods, not YAML types.

- Counts and statistics use backward, inclusive `[t - timespan, t]` windows at
  distinct matching event times. Separate qualifying times remain separate alerts.
- Ordered stages must have **strictly increasing timestamps**. The compiler finds
  a valid sequence even if earlier, out-of-order occurrences are present. Ties
  cannot establish order. Extended OR branches are evaluated independently and
  their evidence is merged when they describe the same window.
- A condition containing absence, such as `a and not b`, opens a forward window
  from a positive event and fires at its deadline. `observation_end` is Unix
  seconds; by default the horizon is the latest valid timestamp in the input
  tables, including events that match no detection. Unexpired windows are
  reported as `incomplete_window`, not successful absence alerts. Pure-negative
  conditions use observed events as context; an empty input invents no groups.
- String grouping keys are normalized to lowercase using SQLite's ASCII folding;
  original values remain in evidence. Value counts use NOCASE comparisons.
- Aliases are applied to individual reference projections. Chained correlations
  consume child alert occurrences, preserve child metrics and evidence, and
  honour `generate`. Parent fields outside a child's grouping keys are projected
  from its contributing events; a child counts once per parent group.
- An event matching several rules or condition branches counts once in an
  `event_count`. Temporal membership is retained separately.
- Invalid timestamps and missing grouping keys are excluded consistently and
  counted by the execution plan's diagnostics. Ordinary rules can still match
  such events. Numeric statistics ignore NULL, invalid and nonfinite values.
  Numeric text must be a valid JSON number (for example `12`, `-2.5`, `1e3`).
- Percentiles use linear interpolation at rank `(n - 1) * p / 100`. Percentile 50
  equals the median, including even sample sizes. Sums use SQLite REAL arithmetic
  to avoid integer accumulator overflow; large integers can lose precision.

SQLite **3.38.0 or newer, including its JSON functions**, is required for
correlations. No custom SQL function is required by the correlation engine.
The default ISO timestamp expression retains millisecond precision, the precision
of SQLite's date parser. Provide a numeric seconds expression to retain finer
precision. Plain detection SQL still only needs the features it uses; REGEXP
continues to require a registered function.

```python
backend = sqliteBackend(
    table="logs",
    timestamp_field="SystemTime",
    event_id_field="row_id",             # default: SQLite rowid
    observation_end=1704067500,           # optional explicit observation horizon
)
# For epoch seconds (including fractional seconds):
backend = sqliteBackend(timestamp_field="event_time", timestamp_format="unix")
```

Documented settings are constructor keywords. Existing instance-attribute
configuration remains supported; `timestamp_format` selects its expression at construction. `table` defaults to `logs` for both output formats; pipeline `setState`
values take precedence. Other settings are `timestamp_field` (default `timestamp`),
`timestamp_seconds_expression`, `event_id_field` (default `rowid`),
`timestamp_format` (`iso`, `unix`, `unix_ms`, `unix_us`),
`observation_end`, `collate_nocase` (default `False`), and `max_flat_operands`
(default `100`). Event identifiers must be non-NULL and unique within a table.

#### Result and execution contracts

The standalone SQL returns these columns:

| Column | Meaning |
|---|---|
| `alert_id` | Deterministic occurrence identifier within the input snapshot |
| `group_keys` | JSON object of grouping keys; `{}` for ungrouped correlations |
| `occurrence_time`, `window_start`, `window_end` | Unix seconds, including fractional seconds |
| `metric_name`, `metric_value` | Correlation type and aggregate value |
| `event_count` | Number of contributing physical events, separate from the metric |
| `event_ids` | JSON array of table-scoped source event identifiers |
| `child_alert_ids` | JSON array of child occurrence identifiers |

IDs refer to the current input snapshot, not a global event store. A pure-negative
alert's evidence records the observed context that started its timer.

The `zircolite` format retains the `rule` list of standalone SELECT statements
and adds `schema_version: 2`, `result_type`, and compiler-derived `required_fields`.
Ordinary rules also carry `source_table` and `logsource`. Correlations carry a
`correlation_plan` with version, ordered SELECT preparation stages and indexes,
result SQL, diagnostic SQL, source-table identities, and cleanup names.

```python
import json
from sigma.backends.sqlite.runtime import execute_plan

entry = json.loads(backend.convert(collection, "zircolite"))[-1]
alerts, diagnostics = execute_plan(connection, entry["correlation_plan"])
# alerts contain parsed group_keys/event_ids and full source event evidence.
```

`execute_plan` widens missing event fields from compiler metadata, materializes
indexed temporary relations, retrieves results and evidence, then removes the
temporary relations. Widening is a schema change to the source table itself:
`execute_plan` (like `ensure_fields`) adds each absent field as a NULL
`TEXT COLLATE NOCASE` column. It never commits the caller's transaction. Callers own
connection-level cancellation and transaction recovery after SQLite interrupts.
Set `include_events=False` to omit expanded source records, and `limit=N` to
retrieve at most `N + 1` summaries, earliest occurrences first, for a
discard-noisy-rule policy.

The CTE and indexed paths compile from the same relations. The indexed path avoids
full scans for each bounded lookup. Dense windows can nevertheless have quadratic
**evidence volume**, and medians/percentiles sort each qualifying sample. Use
selective base rules, result limits and measured runtime budgets; see
`tools/benchmark_correlations.py`.

See [the migration guide](docs/migration-v2.md).

### Other Features

* **NULL value handling**: `field: null` → `field IS NULL`
* **Boolean values**: matched against both text and numeric storage (see *Booleans* above)
* **Field name quoting**: Special characters in field names are quoted with backticks
* **Wildcard escaping**: Proper escaping of `%` and `_` characters in values, including values read from a second field by `|fieldref`
* **Table name**: `logs` for both output formats; both honour a `setState` transformation on the `table` key

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
