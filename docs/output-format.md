# Output format and execution

This page is for code that runs the backend's output: Zircolite or your own
SQLite consumer.

## `zircolite` entries

The `zircolite` format is a JSON list with one entry per converted condition or correlation.

| Key | Content |
|---|---|
| `title`, `id`, `status`, `description`, `author`, `tags`, `falsepositives`, `level` | Copied from the rule; pySigma strips control characters, line breaks included |
| `rule` | List of standalone `SELECT` statements |
| `channel`, `eventid` | Values the condition requires; an empty list means "unrestricted", not "inapplicable" |
| `required_fields` | Columns the SQL reads |
| `result_type` | `event` for detection rules, `correlation` for correlations |
| `source_table`, `logsource` | Detection rules only |
| `correlation`, `correlation_plan` | Correlations only (`correlation` is `true`) |
| `fulltext` | Searchable-text prerequisites of keyword rules (see [keyword search](keyword-search.md)) |
| `presence` | Per-table JSON field-name arrays required by source-aware `exists` predicates |
| `required_sql_functions` | Functions to register on the executing connection. Schema 4 allows only `sigma_cidr_contains`. Schema 5 supports the functions listed below |
| `schema_version` | `2` for ordinary entries, `3` for keyword text, `4` for exact CIDR with optional keyword text, `5` for a declared strict helper or presence source |
| `filename` | Empty; kept for Zircolite's rule format |

A detection with a condition list emits separate entries. Each entry declares
the fields, keyword text and SQL functions its condition uses. A correlation
plan collects requirements across the referenced predicates it evaluates.
An exact IPv4 `/32` uses built-in SQL and adds no function prerequisite.
The structured conversion callback may return the original query or drop it by
returning `None`. Substituting a different detection or correlation SQL string
raises a conversion error because the recorded field requirements and stages
describe the original query. The plain SQL format accepts replacement strings.
When a parent references a replaced correlation, it consumes the rows returned
by the callback's SELECT. The parent reads `alert_id`, `occurrence_time`,
`metric_value`, `event_ids`, and, for grouped rules, `group_keys`.
Returning `f"SELECT * FROM ({sql}) WHERE metric_value >= 2"`
filters the child alerts available to the parent. Keep event IDs in the child's
source-table numbering. The compiler maps those IDs to the parent's tables.

Channel and EventID allow-lists assume the Zircolite event model, with
case-insensitive channel comparison and integer event identifiers. Set
`prefilter_bounds=False` when the comparison contract is unknown, for example
when a custom SQLite collation equates `System` with `System `. The resulting
empty lists preserve every candidate for SQL evaluation.

Load related rule files into one collection: correlations resolve the rules they
reference by name. For events from several files, use one database;
correlations cannot span separate databases.

## Running detection rules

For schema 5, register the helpers once per connection and validate each entry
before creating any missing event columns. For example, an application running
a detection entry can use the reference runtime as follows.

```python
from sigma.backends.sqlite import runtime

runtime.register_sqlite_functions(connection)
runtime.validate_entry(connection, entry)
runtime.ensure_fields(connection, {entry["source_table"]: entry["required_fields"]})
rows = connection.execute(entry["rule"][0]).fetchall()
```

A schema-4 client can continue to call `runtime.register_cidr(connection)`.
Schemas 2–4 use a connection-level `regexp(pattern, value)` for regex rules.
Selecting `text_mode=unicode`, `sum_mode=exact`, or a presence source makes
regex-bearing entries declare `regexp` in schema 5. Rules with multiple
conditions list it only on the entries that execute a regex. A schema-5
correlation includes the regex requirements of its retained references.

### Schema 5 functions

| Name | SQL and data contract |
|---|---|
| `regexp(pattern, value)` | Python `re.search` with inline flags. A NULL value returns false. |
| `sigma_cidr_contains(address, network)` | Exact network membership, as in schema 4. |
| `sigma_unicode_like(value, pattern)` | Unicode default case folding. Unescaped SQL `%` and `_` match zero or more source code points and one source code point respectively. Backslash escapes the next pattern character. |
| `sigma_casefold(value)` | Python `str.casefold()` for text. Other SQLite types retain their values. Used for field equality, grouping and distinct counts. |
| `sigma_exact_sum(value)` | Integer-preserving aggregate/window function. An integer result in the signed 64-bit range has SQLite type INTEGER. A wider integer has type TEXT with its canonical base-10 spelling. A mixed REAL window yields REAL. |
| `sigma_numeric_cmp(left, right)` | Numeric comparison across those result types. Returns −1, 0 or 1, or NULL for a missing operand. |

In Unicode mode `Straße` matches both `STRASSE` and the Sigma wildcard pattern
`Stra?e`. Each wildcard borders a whole source character, so `stras*` does
not consume the first half of the fold of `ß`. Case folding uses the Python
runtime's Unicode database and performs no Unicode normalization. A composed
accent and a combining accent can therefore remain distinct. A literal
underscore, percent sign or backslash in a field reference retains its literal
meaning. The `cased` modifier uses SQLite GLOB. Explicit regex flags retain
Python regex semantics. Ordinary column indexes serve portable equality.
Queries calling a Unicode function on a source column can require a scan.

### Capturing source presence

Configure `presence_field="_present"` on the backend, or set the
`presence_field` processing-pipeline state alongside the per-rule `table`
state. Store a JSON **TEXT array** of present, flattened field names for each
source row. Use field names after the pipeline's field-name mapping, with
the exact case, dots, quotes and other punctuation that the mapping produces.
Array members must be nonempty strings without NUL. Duplicates are accepted.
For example, a row ingested with `{"User": null, "a.b": ""}` can store
`["User","a.b"]` in `_present`. Both keys satisfy `exists: true`. A row
storing `[]` satisfies `User|exists: false`.

An emitted requirement has the following form.

```json
{"presence":[{"table":"logs","field":"_present","representation":"field-names-v1"}]}
```

Capture the list before widening absent fields to NULL. A database containing
only the widened columns requires the original source keys or re-ingestion.
`validate_entry` and `execute_plan` scan every declared presence column and
reject missing columns and malformed rows before widening the schema.
`exists` scans the array by index with `json_extract`, so event tables can
use the names `json_each` and `json_tree`.
`execute_plan` omits the internal presence and fulltext columns from the
corresponding source table's evidence using SQLite's ASCII-only identifier
folding. With `connection.text_factory = bytes`, source TEXT values in evidence
are bytes and alert identifiers are strings. The event query's `SELECT *`
returns the source table's columns.

### Measured cost on a disposable table

Five local trials ingested 20,000 rows into fresh databases using Python
3.14.10. Each row contained `name` and `host`. Half carried `opt` before
flattening, equally split between NULL and a string. The source-aware run
also encoded the per-row key list as compact JSON TEXT. File sizes before
adding indexes were 339,968 bytes for portable ingestion and 724,992 bytes
with presence. The table below reports median wall time in milliseconds.

| Operation | SQLite 3.38.0 | SQLite 3.54.1 |
|---|---:|---:|
| Ingest flattened rows | 28.4 | 28.1 |
| Ingest with presence capture | 60.3 | 62.1 |
| Portable literal equality, NOCASE index | 0.18 | 0.16 |
| Unicode literal equality, same index available | 7.50 | 7.65 |
| Validate presence on every row | 26.54 | 26.90 |
| Retrieve all rows with `opt` present, including NULL | 23.15 | 23.56 |

The emitted equality selects returned the same 200 event IDs. On both engines
`EXPLAIN QUERY PLAN` reported an index search for portable equality, a table
scan for Unicode equality, and a table scan plus a recursive lookup
for source-aware existence. Before indexing, portable equality took 0.80 and
0.73 ms respectively. The flattened NULL test returned 5,000 rows and the
source-aware test returned 10,000, matching the ingested keys.

Correlation execution uses SQLite JSON virtual tables. A source named
`json_each` uses the built-in `json_tree` fallback. A connection that shadows
both built-ins must make a JSON virtual table available to execute a plan.

## Correlation results

The standalone SQL in `rule` returns one row per alert occurrence:

| Column | Meaning |
|---|---|
| `alert_id` | Deterministic occurrence identifier within this input |
| `group_keys` | JSON object of grouping keys; `{}` when ungrouped |
| `occurrence_time`, `window_start`, `window_end` | Unix seconds, fractions included |
| `metric_name`, `metric_value` | Correlation type and its value |
| `event_count` | Contributing physical events, separate from the metric |
| `event_ids` | JSON array of table-scoped event identifiers |
| `child_alert_ids` | JSON array of child occurrence identifiers (chains) |

Identifiers refer to the current input, not a global event store. Rows are
ordered by occurrence time.

## Correlation plans

`execute_plan` runs `correlation_plan`, the same relations, as indexed temporary
tables, avoiding a full scan per window lookup, and returns full event evidence:

```python
import json
from sigma.backends.sqlite.runtime import execute_plan

entry = json.loads(backend.convert(collection, "zircolite"))[-1]
alerts, diagnostics = execute_plan(connection, entry["correlation_plan"])
```

`execute_plan(connection, plan, *, limit=None, include_events=True, fulltext_preflight=None)`:

- checks the plan version, a nonnegative `limit` and SQLite >= 3.38;
- checks declared SQL functions in versions 4 and 5 and validates presence and
  fulltext prerequisites before widening tables. Pass `fulltext_preflight` to
  supply a cached fulltext check;
- adds missing columns like `ensure_fields`, which changes the source table;
- creates, indexes, queries and finally drops `sigma_*` temporary tables;
- returns alerts with parsed `group_keys`/`event_ids` and, unless
  `include_events=False`, an `evidence` list of full source rows;
- returns at most `limit + 1` alerts, earliest first, when `limit` is set,
  so a caller can detect and drop noisy rules;
- returns `diagnostics`, counts keyed `invalid_timestamp`, `missing_group_key`
  and `incomplete_window`;
- never commits. Cancellation and transaction recovery stay with the caller.

The plan holds `version`, `sqlite_min_version`, `prepare` (ordered stages with
indexes), `query`, `diagnostics`, `cleanup`, `required_fields` per table,
`event_id_field`, `source_tables` and any `presence`, `fulltext` and `required_sql_functions` prerequisites inherited from referenced rules and needed by the correlation stages.
