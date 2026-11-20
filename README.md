![Tests](https://github.com/wagga40/pySigma-backend-sqlite/actions/workflows/test.yml/badge.svg)
![Upstream coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/wagga40/2ec45ded898fa11f2c42bcb9d2b163cf/raw/test.json)

# pySigma SQLite Backend

Converts [Sigma](https://github.com/SigmaHQ/sigma) rules into SQLite queries. The
package `sigma.backends.sqlite` provides `sqliteBackend`, registered as the
sigma-cli target `sqlite`. It is the converter behind
[Zircolite](https://github.com/wagga40/Zircolite), and its output runs on any
SQLite table of flattened events.

Maintained by [wagga](https://github.com/wagga40/).

## Install

```shell
pip install pysigma-backend-sqlite
```

Requires Python 3.11+ and [pySigma](https://github.com/SigmaHQ/pySigma) 2.1.0 or
newer within the 2.x series. Correlation output needs SQLite 3.38 or newer. Use sigma-cli 4.0 or newer:
sigma-cli 3.x requires pySigma 1.x, so alongside it pip installs backend 2.0.0,
which has no keyword search.

## Quick start

```python
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend

rules = SigmaCollection.from_yaml(r"""
title: Whoami execution
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
""")

print(sqliteBackend().convert(rules)[0])
# SELECT * FROM logs WHERE Image LIKE '%\\whoami.exe' ESCAPE '\'
```

Processing pipelines map a logsource to concrete fields. With
`sqliteBackend(sysmon_pipeline() + windows_logsource_pipeline())` the same rule becomes:

```sql
SELECT * FROM logs WHERE Channel='Microsoft-Windows-Sysmon/Operational' AND (EventID=1 AND Image LIKE '%\\whoami.exe' ESCAPE '\')
```

Install the pipelines with `pip install pysigma-pipeline-sysmon pysigma-pipeline-windows`;
releases 3.0 and newer support pySigma 2. With sigma-cli:

```shell
sigma convert -t sqlite -f zircolite -p sysmon -p windows-logsources rules/
```

## Output formats

| Format | Output |
|---|---|
| `default` | One standalone SQL statement per detection condition or correlation |
| `zircolite` | A JSON list with one entry per converted condition or correlation, including metadata and execution requirements. See [output format](https://github.com/wagga40/pySigma-backend-sqlite/blob/main/docs/output-format.md) |

## Options

Set options when constructing the backend or with `-O name=value` in sigma-cli.
Changing attributes after construction is unsupported.
Table and column names must be nonempty. pySigma also forwards options to the
processing pipeline as `backend_<name>`. A name resembling a misspelled SQLite
option produces a warning so you can check which setting took effect.

| Option | Default | Purpose |
|---|---|---|
| `table` | `logs` | Table to query. A pipeline `setState` on `table` takes precedence |
| `collate_nocase` | `false` | Emit `field='value' COLLATE NOCASE` for tables without `NOCASE` columns |
| `max_flat_operands` | `100` | Longer AND/OR chains are nested to stay under SQLite's expression depth limit |
| `cidr_mode` | `expanded` | Use portable prefix matching or opt into exact network membership with `exact` |
| `fulltext_field` | none | Column of searchable event text; enables [keyword search](https://github.com/wagga40/pySigma-backend-sqlite/blob/main/docs/keyword-search.md) |
| `timestamp_field` | `timestamp` | Event time column used by correlations |
| `timestamp_format` | `iso` | `iso`, `unix`, `unix_ms` or `unix_us` |
| `timestamp_seconds_expression` | ISO parser | SQL turning `{field}` into Unix seconds; overrides `timestamp_format` |
| `event_id_field` | `rowid` | Non-NULL, per-table unique event identifier for correlation evidence |
| `observation_end` | latest event | Unix seconds up to which absence windows can expire |

## Generated SQL

| Modifier | SQL |
|---|---|
| `contains`, `startswith`, `endswith` | `LIKE '%value%' ESCAPE '\'` and its prefix/suffix forms |
| `all` | `AND` of the values |
| `re` | `REGEXP` (needs a registered function, see [Limitations](#limitations)) |
| `cidr` | `=` or `LIKE` in expanded mode, registered membership function in exact mode |
| `cased` | `GLOB`; literal `*`, `?`, `[` become `[*]`, `[?]`, `[[]` |
| `fieldref` | `field1=field2`, or `LIKE` with the second field's `%` and `_` escaped |
| `exists` | `IS NOT NULL` / `IS NULL` |
| `gt`, `gte`, `lt`, `lte` | Compare finite numbers and numeric text numerically |
| `neq` | Negated equality |
| `minute`, `hour`, `day`, `week`, `month`, `year` | `strftime()` part |
| `base64`, `base64offset`, `wide`, `utf16*`, `windash` | Expanded by pySigma into ordinary matches |

Generated SQL handles the following cases.

- **Negation.** Sigma reads a condition on a missing field as false; SQLite reads
  it as `NULL`, and `NOT NULL` drops the row. Every `NOT` therefore wraps its
  operand: `EventID=1 AND (NOT COALESCE((CommandLine LIKE '%foo%' ESCAPE '\'), 0))`.
- **Case.** `LIKE` ignores case; `=` does only on `NOCASE` columns (Zircolite's
  layout), otherwise set `collate_nocase`.
- **Booleans.** `Flag: true` matches text or integer storage: `(Flag='true' OR Flag=1)`.
- **Field names.** SQLite keywords and names with characters other than letters,
  digits and `_` are quoted with backticks. `field: null` becomes `field IS NULL`.
- **Numeric comparisons.** `gt`, `gte`, `lt` and `lte` validate and convert the
  stored value before comparison. A plain index on that column cannot supply a
  range lookup for this predicate, even on an `INTEGER` column. Detections read
  `+11`, `11.` and `011` as eleven. Numeric correlation statistics accept text
  in JSON number syntax and skip all three spellings.

## Correlations

All Sigma correlation types run in SQLite, including chains, aliases and extended
temporal conditions. See [correlations](https://github.com/wagga40/pySigma-backend-sqlite/blob/main/docs/correlations.md)
for their semantics and the [migration guide](https://github.com/wagga40/pySigma-backend-sqlite/blob/main/docs/migration-v2.md)
for upgrading from backend 1.x.

## CIDR matching

The default `cidr_mode="expanded"` uses portable SQL. It checks the spelling of
an address and can use SQLite prefix indexes. Exact mode parses the event value
and tests membership in the network. For example, SQL generated for these inputs
has the following behavior.

| CIDR | Event value | Expanded | Exact |
|---|---|---|---|
| `10.0.0.0/8` | `10.1.2.300` | match | no match |
| `10.0.0.0/8` | `10.1.2.3` followed by a space | match | no match |
| `2001:db8::/32` | `2001:0db8:0:0::1` | no match | match |
| `10.0.0.0/8` | `::ffff:10.0.0.5` (IPv4-mapped IPv6) | no match | no match |
| `0.0.0.0/0` | `::ffff:10.0.0.5` | match | no match |
| `::/0` | `10.0.0.5` | match | no match |
| Either `/0` | `unknown` | match | no match |

Both expanded `/0` networks compile to `LIKE '%'` and match every non-NULL
text value. Exact mode parses the address and respects its IP family.

```python
from sigma.backends.sqlite.runtime import register_cidr

register_cidr(connection)
query = sqliteBackend(cidr_mode="exact").convert(rules)[0]
rows = connection.execute(query).fetchall()
```

For sigma-cli, pass `-O cidr_mode=exact` and register the function on the connection
that executes the SQL. IPv4 ranges with at least one fixed octet retain an indexable
guard. Exact IPv6 may parse every candidate row, which matters on columns with many
distinct addresses. Exact-dependent Zircolite output requires a schema-4 consumer.
Released Zircolite 4.7.1 supports expanded output. [Original CIDR report](https://github.com/SigmaHQ/pySigma-backend-sqlite/issues/17)

## Keyword search

Keyword (fieldless) rules need `fulltext_field`, a column holding each event's
searchable text. See [keyword search](https://github.com/wagga40/pySigma-backend-sqlite/blob/main/docs/keyword-search.md).

## Limitations

- **REGEXP.** SQLite has no built-in `REGEXP`. Register one that is false for `NULL`:
  `connection.create_function("regexp", 2, lambda p, v: v is not None and re.search(p, str(v)) is not None)`.
  pySigma validates `|re` with RE2 by default, rejecting lookarounds and
  backreferences. For trusted rules, pass `policy=TrustedPolicy` (from
  `sigma.policy.profiles`) to `SigmaCollection.from_yaml()`; the patterns must then
  suit Python's `re`.
- **Case folding** (`NOCASE`, `LIKE`) is ASCII only.
- **Timestamp parts** use `strftime()` and need ISO-8601 text; a numeric epoch is
  read as a Julian day. `%W` can return week 0.
- **Field existence.** SQL `NULL` cannot tell a missing field from an explicit null.
- **Multi-field `value_count`** (a list in `condition.field`) is rejected.
- **Unknown columns.** A query naming a column the table lacks fails to prepare.
  Add missing columns as `NULL` first; see [output format](https://github.com/wagga40/pySigma-backend-sqlite/blob/main/docs/output-format.md).

## Development

```shell
poetry install
poetry run pytest
SQLITE_MIN_BINARY=/path/to/sqlite-3.38 poetry run pytest tests/test_sqlite_minimum.py
```

`tools/audit_corpus.py` converts and prepares a SigmaHQ checkout per profile (see
[coverage](https://github.com/wagga40/pySigma-backend-sqlite/blob/main/docs/keyword-search.md#coverage)).
`tools/benchmark_correlations.py` times sparse and dense correlation windows.
`tools/benchmark_cidr.py` compares expanded and exact event queries and
materialized correlations over indexed and unindexed IPv4 and IPv6 data.
It checks event and evidence identities and records SQLite query plans.

```shell
poetry run python tools/benchmark_cidr.py --size 100000 --iterations 5 --output cidr.json
```
