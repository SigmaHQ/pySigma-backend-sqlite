# Keyword search

Keyword (fieldless) selections such as `selection: ['event::clear', 'event::drop']`
match anywhere in an event. SQLite has no such notion, so the consumer stores the
event's text in one column and the backend searches it:

```python
backend = sqliteBackend(fulltext_field="_sigma_fulltext")
```

Without `fulltext_field`, keyword rules raise an error instead of guessing what
to search.

## Matching

Keywords become substring predicates, `_sigma_fulltext LIKE '%event::clear%' ESCAPE '\'`.
Sigma's `*` and `?` keep their meaning; punctuation and SQL wildcard characters
stay literal. Keyword `|all`, negation, combination with named fields, numbers
(searched as text), `|cased` (`GLOB`), `|re` (`REGEXP`), `|windash` and
`|base64offset` all work.

## The `source-values-v1` text

The column must hold the event's original decoded scalar values, captured before
flattening, field exclusions or transforms, and without field names or generated
metadata:

- dictionaries sorted by key, arrays in order, one value per line;
- strings unchanged, booleans as `true`/`false`, numbers via `str`, nulls omitted;
- an event without values gets empty text, not NULL.

Wildcards can therefore span value boundaries, and the terms of a keyword `|all`
can match different values. The backend never rebuilds this text from flattened
columns, so databases ingested without it must be re-ingested.

## Contract

- Keyword-dependent `zircolite` entries carry `schema_version: 3` and
  `fulltext: [{"table": "logs", "field": "_sigma_fulltext", "representation": "source-values-v1"}]`,
  deduplicated and sorted. Their correlation plans use `version: 3` with the same
  list. Exact CIDR dependencies raise both versions to 4 and preserve the fulltext declaration. Entries with neither prerequisite keep version 2.
- `runtime.validate_fulltext(connection, entry["fulltext"])` checks the column
  exists and every row holds non-NULL TEXT, raising `ValueError` otherwise. Run it
  before adding other missing columns or executing the SQL; `execute_plan` runs it
  itself ([output format](output-format.md#correlation-plans)).
- Never create a `fulltext` column empty or NULL: a missing search text must fail,
  not silently match nothing.
- Hide the column from displayed or exported rows. `execute_plan` strips it from
  the evidence of plans declaring keyword prerequisites; version-2 plans carry no `fulltext`
  metadata, so strip it yourself.

## Cost

The column duplicates every event's values, including ones flattening would drop,
so database size and ingestion memory grow. In a 100,000-event synthetic benchmark
(Zircolite, in-memory database), capture roughly doubled ingestion time and
database size, and a keyword query took 47-71 ms. Leading-wildcard `LIKE` cannot
use a B-tree index, so keyword predicates scan the rows they are applied to.

## Coverage

At Sigma revision `088855f00b65a19e345b09c1619272b44f92fea4`, with
`--fulltext-field _sigma_fulltext`, every standard rule converts and prepares
without errors:

| Profile | Rules | Keyword rules |
| --- | ---: | ---: |
| `raw` (no pipeline) | 3,164 | 86 |
| `windows-sysmon` | 2,427 | 12 |
| `windows-audit` | 2,427 | 12 |
| `linux` | 211 | 28 |

```sh
poetry run python tools/audit_corpus.py /path/to/sigma \
  --fulltext-field _sigma_fulltext --profile raw --output corpus.json
```

`windows-sysmon` needs `pysigma-pipeline-sysmon` and `pysigma-pipeline-windows`;
`windows-audit` needs `pysigma-pipeline-windows`. The counts are for the 2.0.0
releases of both: `pysigma-pipeline-windows` 2.0.1 and newer reject 10 registry
rules under `windows-audit`. The auditor provisions an empty TEXT column to prepare
the SQL, so these numbers measure conversion coverage, not detection accuracy.
