# Sigma 2.1 support in the SQLite backend

The table describes the Python backend and the sqlite target in sigma-cli with
pySigma 2.1.0. Both receive parsed rules. Correlation SQL and the reference
executor require SQLite 3.38 or later with JSON functions. [Sigma specification](https://github.com/SigmaHQ/sigma-specification/releases/tag/v2.1.0)

| Rule or input | Setting and runtime | Behavior |
|---|---|---|
| `message: CAFÉ` | Portable, BINARY columns | Literal equality is case-sensitive. Built-in LIKE folds ASCII for wildcard queries. |
| `message: Cafe` | Portable, NOCASE columns or `collate_nocase=True` | ASCII case-insensitive equality. Compatible indexes can serve literal lookups. |
| `message: CAFÉ`, `message: Stra?e` | `text_mode=unicode`, schema 5 helpers | Full Unicode case folding. A single wildcard consumes one source code point. Case folding does not normalize combining sequences. Field references, keywords, group keys and tuple counts use the selected semantics. |
| `message\|cased` and `message\|re\|i` | SQLite GLOB and a search-style REGEXP respectively | Cased text stays case-sensitive. Regex flags remain explicit. `re\|startswith` and `re\|endswith` anchor the whole alternation to the field boundary, including with multiline mode. |
| `message\|windash: —a-b` | Portable SQL | Each dash position matches any of the five Windows dash spellings when a value has at most three dashes. A longer value expands only the dashes that start a word, as pySigma does; pySigma accepts at most three of those. Wildcards, cased text and keyword selections are supported. |
| `image\|wide\|base64: ab` | pySigma modifier chain | Matches `YQBiAA==`. `utf16be` and `utf16` also require a text-compatible final encoding for binary values containing NUL. |
| `stamp\|week: 1` | ISO by default, or `week_mode=legacy` | ISO uses weeks 1–53. Week 53 extends the published 1–52 range. Week 0 matches no ISO date. Legacy %W counts days before the first Monday as week 0. |
| `User\|exists: true` | `presence_field=_present`, schema 5 | Absent, explicitly null and empty values remain distinguishable. Populate the JSON array with mapped field names at ingestion. With the default flattened schema, SQL NULL represents absence. |
| `ip\|cidr: 2001:db8::/32` | `cidr_mode=exact` | Address-family-aware membership. Register CIDR for exact networks except IPv4 /32. Default expanded mode checks text spellings. |
| `condition: {field: [User, Host], gte: 3}` on `value_count` | Portable SQLite | Counts distinct complete value tuples. A missing component excludes the tuple. Reference-specific aliases apply to each field. |
| Partial `temporal_ordered` thresholds | Portable SQLite | Ordered slots require strictly increasing times in the same window and group. The metric counts distinct slots observed and evidence retains qualifying ordered sequences. |
| `condition: {field: Bytes, gt: 1000}` on `value_sum` | Portable or `sum_mode=exact` | Portable SQL preserves integer sums when it can establish a safe range. Exact mode uses a widened accumulator. Integral totals beyond SQLite INTEGER range are decimal text. Fractional windows yield REAL. |
| `value_percentile` | Numeric field and explicit percentile | For a 95th percentile, use `condition: {field: Duration, percentile: 95, gt: 100}`. The categorical example without a percentile has no supported statistical interpretation. |

Modifier adaptations run before user processing pipelines and use the original
value and modifier sequence retained by pySigma. A later transformation that
replaces a value supplies the new matching expression. An already-transformed
detection item whose original value was discarded cannot be reconstructed.

## Inputs affected by pySigma parsing

The following limits are present in pySigma 2.1.0. The parser fixtures exercise
the same inputs against the installed dependency. [Compatibility tests](../tests/test_pysigma_compatibility.py)

| Published input | Parser behavior | Working input or dependency change |
|---|---|---|
| `utf16le\|base64` | The modifier name is rejected before conversion. | Use `wide\|base64`. The parser's modifier registry needs the `utf16le` alias. |
| Global filter `not 1 of them` or `not all of them` with a private `_helper` | Name qualification makes the private helper visible to the selector. | Use explicit selection names. Preserve the leading underscore when qualifying filter identifiers upstream. |
| Detection threshold `gt: 9007199254740993` | Constructing SigmaNumber rounds this rule literal to 9007199254740992 in pySigma. | Use an equivalent comparison with a representable boundary where possible. Preserve Python integers during type construction upstream. |
| Top-level `generate: true` | The parser drops the flag. Conflicting top-level and nested values cannot be detected after parsing. | Use `correlation.generate: true`. Normalize and validate both flags in pySigma before resolving references. |
| `condition: {gt: 100, lte: 200}` | pySigma rejects multiple comparison operators. | Use a single supported comparison. Combined bounds require a parser model that retains both operators for the same metric. |

The guide and published schema describe different spellings for some
correlations. Use the examples above for this dependency version.
[Correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html) · [Authoring guide](https://sigmahq.io/docs/meta/correlations.html) · [Modifier specification](https://sigmahq.io/sigma-specification/specification/sigma-appendix-modifiers.html)
