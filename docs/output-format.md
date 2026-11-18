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
| `required_sql_functions` | Schema 4 declares `["sigma_cidr_contains"]` when exact membership is required |
| `schema_version` | `4` for exact CIDR, `3` for keyword-only prerequisites, otherwise `2` |
| `filename` | Empty; kept for Zircolite's rule format |

A detection with a condition list emits separate entries. Each entry carries the rule-wide
keyword text prerequisites and the SQL functions used by its own condition.

Load related rule files into one collection: correlations resolve the rules they
reference by name. For events from several files, use one database;
correlations cannot span separate databases.

## Running detection rules

1. Register exact CIDR once on each connection that runs schema-4 entries with
   `runtime.register_cidr(connection)`. Before executing an entry, call
   `runtime.validate_sql_functions(connection, entry["required_sql_functions"])` if it declares functions.
   Register `REGEXP` if any rule uses `|re` (see the README's [Limitations](../README.md#limitations)).
2. If the entry declares `fulltext`, validate its contents before adding any columns.
   See [keyword search](keyword-search.md#contract).
3. Add columns the table lacks, as `NULL`, so a query naming them still prepares:
   `runtime.ensure_fields(connection, {entry["source_table"]: entry["required_fields"]})`.
   It adds each missing column as `TEXT COLLATE NOCASE`.
4. Run each statement in `rule`.

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
- checks the registered SQL function on version-4 plans and validates any
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
`event_id_field`, `source_tables` and any `fulltext` and `required_sql_functions` prerequisites inherited from referenced rules.
