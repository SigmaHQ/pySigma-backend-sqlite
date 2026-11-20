# Correlations

Correlation stages use SQLite's built-in JSON functions. Referenced rules can
also require registered functions for exact CIDR matching or regular expressions.
A result row describes one **alert occurrence**, including its time, its window,
the metric, and the events behind it. Separate bursts are separate rows. Result
columns and plan execution are in [output format](output-format.md).

## Types

`event_count`, `value_count`, `value_sum`, `value_avg`, `value_median`,
`value_percentile`, `temporal` and `temporal_ordered`. The temporal types also
accept extended Boolean conditions such as `a and not b` or `(a or b) and c`.

Thresholds may be fractional (pySigma 2) and are compared exactly:
`event_count gte: 1.5` needs two events.

## Windows

- **Counts and statistics look backward.** Each distinct matching event time `t`
  is evaluated over the inclusive window `[t - timespan, t]`. With values 0 at
  t=0 and 100 at t=3, the average at t=3 is 50.
- **Ordered stages** need strictly increasing timestamps; equal timestamps cannot
  establish order. A valid sequence is found even after earlier out-of-order
  events.
- **Extended OR branches** are evaluated independently; their evidence is merged
  when they describe the same window.
- **Absence looks forward.** In `a and not b`, an `a` event opens a window that
  fires at its deadline if no `b` arrived. Windows still open at the observation
  horizon are reported as `incomplete_window` diagnostics, not alerts. The horizon
  is `observation_end` (Unix seconds) or, by default, the latest valid timestamp
  in the input, including events that match no rule.
- **Pure-negative conditions** use observed events as context; empty input
  invents no groups.

## Grouping and counting

- String group keys are lowercased with SQLite's ASCII folding; evidence keeps
  the original spelling. `value_count` compares values with `NOCASE`.
- Group names live inside `group_keys`, so they cannot collide with event fields.
- An event matching several rules or condition branches counts once in
  `event_count`.
- Events with an invalid timestamp or a missing group key are excluded and counted
  in the plan diagnostics. Detection rules can still match them.

## Values

- Statistics ignore NULL, invalid and nonfinite values. Numeric text must be a
  valid JSON number (`12`, `-2.5`, `1e3`). Text values such as `+11`, `11.`
  and `011` are excluded from these statistics. A detection using `|gt` or
  another numeric comparison treats those same text values as eleven.
- Percentiles interpolate linearly at rank `(n - 1) * p / 100`; percentile 50
  equals the median, even for even sample sizes.
- Sums use SQLite REAL arithmetic to avoid integer overflow; very large integers
  can lose precision.

## Chains and aliases

- Aliases apply to each referenced rule's projection.
- A chained correlation consumes its children's alert occurrences, with their
  metrics and evidence. An aggregate can read a child's metric by its type name,
  for example `event_count`.
- Parent fields outside a child's group keys come from the child's contributing
  events; a child counts once per parent group.
- A correlation referenced by another is compiled into its parent. With
  `generate: true` on the parent, the referenced rules, detections and
  correlations alike, are also emitted on their own.
- On SQLite 3.54 and later, the standalone SQL of a large chain, such as four
  stacked correlations or a correlation over two chained ones, exceeds SQLite's
  subquery nesting limit ("VIEWs and/or subqueries nested too deep").
  `execute_plan` runs each stage on its own and is not affected.

## Timestamps

`timestamp_field` (default `timestamp`) is parsed as ISO-8601 text, which SQLite
resolves to milliseconds. For numeric epochs use `timestamp_format` `unix`,
`unix_ms` or `unix_us`; malformed values are excluded. Use numeric timestamps when
finer precision matters, for example to order events within one millisecond.

```python
backend = sqliteBackend(
    timestamp_field="SystemTime",
    event_id_field="row_id",      # default: SQLite rowid
    observation_end=1704067500,   # optional absence horizon
)
backend = sqliteBackend(timestamp_field="event_time", timestamp_format="unix")
```

## Performance

The plan path indexes every stage, but dense windows can still produce evidence
that grows quadratically, and medians and percentiles sort each sample. Prefer
selective base rules and `execute_plan(limit=...)`; the limit bounds retrieval,
not preparation. Measure with `tools/benchmark_correlations.py`.
