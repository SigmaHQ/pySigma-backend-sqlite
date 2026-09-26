# Migrating to SQLite backend 2.0

Version 2 changes correlation semantics and the result contract. Regenerate
saved SQL/rulesets; upgrading the Python package does not repair previously
generated SQL. Update a consumer that executes correlation output before
distributing version-2 rulesets to it.

## Dependencies and configuration

- pySigma >=1.5,<2; Python >=3.10; SQLite >=3.38 with JSON for correlations.
- The default table is now `logs` in both formats. Supply `table=` for another
  table. Identifiers and pipeline-selected table names are quoted correctly.
- Constructor options now work. Existing callers that set attributes continue
  to work. `collate_nocase=True` is recommended for ordinary string equality on
  schemas that do not declare NOCASE columns. SQLite's case folding is ASCII.
- Point `timestamp_field` and `event_id_field` at the consumer's schema
  (defaults `timestamp` and `rowid`).
  For numeric input use `timestamp_format="unix"`, `"unix_ms"`, or `"unix_us"`;
  malformed numeric values are excluded.
  Custom SQL expressions remain available for other representations.
- Correlation timestamps use milliseconds with the default ISO expression.
  Equal timestamps do not establish ordered stages. Use normalized numeric
  timestamps when finer precision is available and matters to the rule.

## Changed results

Previously a grouped correlation returned one row such as `{"Host":"h"}` for
the entire search, hiding separate bursts. It now returns each qualifying
occurrence's group object, window, aggregate, and evidence references.

`metric_value` is the rule's count/statistic. `event_count` counts supporting
physical records. String grouping values are normalized to lowercase with
SQLite's ASCII folding, while evidence preserves original spelling. Group names live inside
`group_keys`, avoiding collisions with event fields or aggregate names.

Counts and statistics now look backward. For values 0 at t=0 and 100 at t=3,
the average at t=3 is 50, not the isolated future-facing value 100. Absence
conditions look forward and emit at the timeout. By default no absence alert
is emitted beyond the last valid input timestamp; supply an explicit analysis
horizon when the available observation period extends further.

Aliases and chains are compiled from resolved rule structures. A child alert
has an occurrence time and evidence that later stages can consume. Aggregate
references may read a child's type-named metric, for example `event_count`.
Other parent fields come from child evidence; projections are deduplicated by
child occurrence and parent group/value. Report values deliberately when a
child spans several users or other grouping identities.

The old `generate: true` behavior could expose raw predicates. Version 2 emits
valid standalone queries while retaining the predicates internally. Only final
requested correlations are emitted; reference-only children are compiled.

## Consumer integration

Use `required_fields` to provision absent columns as NULL. The old SQL scanner
cannot reliably discover fields inside functions or CTE/window queries.
Use `correlation_plan` with `sigma.backends.sqlite.runtime.execute_plan` for
indexed execution and full event evidence. The `rule` list remains available
for consumers that execute standalone SELECT statements.

Load related YAML files into one collection. For multi-file event input use a
unified database; per-file databases cannot produce cross-file correlations.
Do not exclude a rule merely because its Channel allow-list is empty.

## Coverage and operations

Keyword/fieldless detections remain explicitly unsupported. IPv6 CIDR spelling,
Python REGEXP compatibility and SQLite's ASCII case folding remain limitations.
Run `tools/audit_corpus.py` against a pinned Sigma checkout; conversion and SQL
preparation counts are not evidence of detection accuracy.

Run `tools/benchmark_correlations.py` on representative sparse and dense input.
Evidence for every qualifying window can itself be very large. Result limits
bound retrieval, not every preparation stage. Preserve diagnostic counts for
invalid timestamps, missing grouping keys and incomplete absence windows.
