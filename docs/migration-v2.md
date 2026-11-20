# Migrating to backend 2.x

Regenerate saved SQL and rulesets after upgrading; the package does not rewrite
SQL produced by an older version. Update any consumer that runs correlation
output before giving it 2.x rulesets.

## From 1.x to 2.0

**Configuration**

- Requires pySigma >=1.5.1,<2 and Python 3.10+ (2.1 raises both, see below).
  Correlations need SQLite 3.38+ with JSON functions.
- The default table is `logs` in both output formats.
- Options are constructor keywords (see the README's [Options](../README.md#options)). Point
  `timestamp_field` and `event_id_field` at your schema.
- On tables without `NOCASE` columns, set `collate_nocase=True` so string
  equality ignores case.

**Correlation results**

- A grouped correlation used to return one row per group for the whole input,
  such as `{"Host": "h"}`, hiding separate bursts. Each qualifying occurrence is
  now a row with its window, metric and evidence ([output format](output-format.md)).
- `metric_value` is the count or statistic; `event_count` counts supporting events.
- Counts and statistics look backward from each event; absence looks forward.
  With values 0 at t=0 and 100 at t=3, the average at t=3 is now 50, not 100.
  See [correlations](correlations.md).
- String group keys are lowercased and nested in `group_keys`.
- `generate: true` used to expose raw predicates; it now emits valid standalone
  queries.

**Consumers**

- Add missing columns from `required_fields` (or `runtime.ensure_fields`) rather
  than by scanning SQL text, which misses fields inside functions and CTEs.
- Run `correlation_plan` with `runtime.execute_plan` for indexed execution and
  event evidence. `rule` still holds standalone `SELECT` statements.
- Don't skip a rule because its `channel` list is empty.

## From 2.0 to 2.1

- Requires Python 3.11+ and pySigma 2. Backend 2.1.1 needs pySigma 2.0.1 or newer.
  The unpublished 2.1.2 changes used pySigma 2.0.3.
- Keyword rules convert when `fulltext_field` is set; their entries use
  `schema_version: 3` ([keyword search](keyword-search.md)). Other output keeps
  version 2. Without it they still raise `SigmaFeatureNotSupportedByBackendError`,
  but the message changed: update allowlists that match the old
  "Value-only string expressions..." text.
- IPv6 CIDR values follow pySigma 2's narrower expansion (19 SigmaHQ rules
  change), and a CIDR expanding to several patterns inside an AND is now
  parenthesized; before, it could match events failing the rest of the AND.
- A `value_count` over a list of fields raises
  `SigmaFeatureNotSupportedByBackendError` instead of a `TypeError`.

## From 2.1.1 to 2.2.0

Regenerate queries and rulesets from their Sigma sources. Version 2.2.0 includes
the unpublished 2.1.2 changes and requires pySigma 2.1.0 through the latest 2.x.

- Global filters with identifiers such as `_skip` now apply correctly.
- Numeric comparison modifiers reject malformed and nonfinite input, and compare
  numeric text by value. For example, a TEXT field holding `'2'` fails `gt: 10`.
- Channel and EventID metadata use the shortest proven allow-list for an AND.
  This preserves values SQLite may equate through case folding or numeric affinity.
- Each detection entry declares only the fields and keyword text its condition
  reads. Correlations collect prerequisites across their referenced predicates.
- CIDR expansion remains the default. Exact IPv4 `/32` predicates use built-in
  SQL. Other exact CIDRs require schema and plan version 4 and declare their
  SQL function. Consumers must register it before execution and continue to
  validate any keyword text prerequisites.
  [CIDR examples and registration](../README.md#cidr-matching)

The bundled pySigma 2.0.3 changes also affect existing portable output.

- IPv6 CIDR values also match the uncompressed form Sysmon writes, such as
  `0:0:0:0:0:0:0:1` for `::1`; a filter like `not DestinationIp|cidr: ::1/128` no
  longer lets that spelling through. All 20 SigmaHQ rules with IPv6 CIDR values change.
- Rule metadata loses control characters, line breaks included, so a multi-line
  `description` becomes one line with nothing where each break was.
