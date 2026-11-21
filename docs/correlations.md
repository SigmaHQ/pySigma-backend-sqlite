# Correlations

Correlation stages use SQLite's built-in JSON functions. Correlations can
require registered functions for exact CIDR, regular expressions,
Unicode text matching or exact sums.
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
- An ordered numeric threshold reports the number of distinct reference positions
  present. For `gte: k`, at least one ordered subsequence of length `k` must
  exist. Each such choice of references starts at its earliest matching time
  in the window and takes the earliest strictly later match at each next
  position. Evidence includes the events and child alerts at those times for
  every successful choice. For `eq`, `neq`, `lt` and `lte`, all observed
  reference positions must occur in order and the count must pass the comparison.
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
- With `text_mode="unicode"`, group keys and distinct-count text values use
  Python Unicode case folding. The connection must register `sigma_casefold`.
- A list of fields, such as `condition: {field: [User, Image], gte: 3}`,
  counts distinct tuples within each group and window. Each component uses its
  reference's field alias and comparison semantics. A NULL component excludes
  the tuple from the metric. Evidence includes all matching events in the
  window, as for a scalar distinct count.
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
- The default `sum_mode="portable"` returns a signed 64-bit integer for an
  integer-only window whose total fits. Integer tokens in numeric text stay
  integers when representable. The SQL accumulates high and low 32-bit parts,
  so a transient overflow followed by cancellation still gives the exact total.
  The compatibility path uses SQLite REAL when a window has fractional or REAL
  input, an integer input or total exceeds int64, or a group has more than
  2,147,483,648 input rows. An all-NULL window has a NULL metric.
- With `sum_mode="exact"`, integer windows use an arbitrary-width integer
  accumulator. A total outside int64 appears as signed decimal text, and a
  parent sum can consume that text without rounding. For example, inputs
  `9223372036854775807` and `2` satisfy `gt: 9223372036854775808` and
  return the text `9223372036854775809`. A window with REAL input yields a
  REAL result. Register the version-5 functions with
  `register_sqlite_functions(connection)` before executing either output form.

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
- SQLite's default compound SELECT limit is 500 terms. Conversion reports a
  rule-scoped error if a node's input exceeds that limit. For numeric ordered
  thresholds, detections with the same source and field projection share a term.
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


### Ordered threshold measurements

`tools/benchmark_correlations.py --ordered --sizes 48 --repeats 5` runs the same
48 events on sparse and dense windows and compares every alert and evidence ID
across execution paths. The table gives five-run medians in milliseconds from
a local run. Prepare measures compilation with EXPLAIN. Standalone and plan
measure complete execution, including preparation.

| SQLite | References / threshold | Window density | Prepare (ms) | Standalone (ms) | Plan (ms) | Alerts |
|---|---|---|---:|---:|---:|---:|
| 3.38.0 | 5 / 2 | Sparse | 0.81 | 2.76 | 2.62 | 38 |
| 3.38.0 | 5 / 2 | Dense | 0.81 | 5.69 | 5.34 | 47 |
| 3.38.0 | 12 / 6 | Sparse | 0.93 | 8.01 | 7.36 | 28 |
| 3.38.0 | 12 / 6 | Dense | 0.92 | 19.27 | 17.73 | 43 |
| 3.54.1 | 5 / 2 | Sparse | 0.86 | 2.59 | 2.54 | 38 |
| 3.54.1 | 5 / 2 | Dense | 0.83 | 5.29 | 5.27 | 47 |
| 3.54.1 | 12 / 6 | Sparse | 0.94 | 7.31 | 6.86 | 28 |
| 3.54.1 | 12 / 6 | Dense | 0.92 | 17.30 | 16.37 | 43 |

On baseline `e37c71c`, the five-reference SQL was 24,129 bytes and the plan
had 59 stages. The twelve-reference SQL was 4,170,906 bytes and the plan had
8,325 stages. The bounded search emits 4,485 and 4,875 bytes respectively and
uses 12 stages in both cases. It retains each reachable window, reference,
timestamp and prefix length once. More matching timestamps in a dense window
still increase preparation and evidence costs.
