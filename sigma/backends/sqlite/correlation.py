"""Relational correlation compiler shared by SQL and materialized execution.

Every stage is a SELECT. The portable form combines stages as CTEs;
runtime.execute_plan materializes the same stages, with explicit indexes. No
finalized query or output-format dictionary is ever used as a predicate.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
from dataclasses import asdict, dataclass

from sigma.correlations import (
    CorrelationConditionAND,
    CorrelationConditionNOT,
    SigmaCorrelationRule,
    SigmaExtendedCorrelationCondition,
    SigmaRuleReference,
)
from sigma.exceptions import (
    SigmaConversionError,
    SigmaCorrelationConditionError,
    SigmaCorrelationRuleError,
    SigmaFeatureNotSupportedByBackendError,
    SigmaTimespanError,
)


def literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def quote(value: str) -> str:
    # Backticks, not double quotes: SQLite reads an unknown "name" as a string literal.
    return "`" + value.replace("`", "``") + "`"


# A name SQLite reads as an identifier without quoting, unless it is a keyword.
BARE_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
FULLTEXT_REPRESENTATION = "source-values-v1"
# Strict comparisons to infinity work on SQLite 3.38 too, whose decimal
# parser rounds the largest finite double literal up to infinity.
SQL_INFINITY = "1e999"
NUMERIC_KINDS = ("value_sum", "value_avg", "value_median", "value_percentile")


def json_array_function(tables):
    """A source table named json_each shadows SQLite's eponymous virtual table."""
    for table in tables:
        name = table.rsplit(".", 1)[-1]
        if name.lower() in ("json_each", "`json_each`"):
            return "json_tree"
    return "json_each"


def protect_json_text(document):
    """Keep embedded NULs intact when SQLite 3.38 decodes JSON strings.

    U+0001 followed by 0 or 1 represents NUL or U+0001 respectively. Escape
    literal backslashes first, so a string containing the six characters
    backslash-u-0-0-0-0 stays distinct from the code point.
    """
    return (
        rf"replace(replace(replace({document}, '\\', '\u005c'), "
        r"'\u0001', '\u00011'), '\u0000', '\u00010')"
    )


def restore_text(value):
    return (
        f"CASE WHEN instr({value}, char(1)) THEN "
        f"replace(replace({value}, char(1)||'0', char(0)), char(1)||'1', char(1)) "
        f"ELSE {value} END"
    )


def evidence_id(value):
    # Keep the common identifier path native. The two control codes are
    # encoded in sort order before the ID enters any internal JSON array.
    protected = protect_json_text(f"json_quote({value})")
    return (
        f"CASE WHEN instr({value}, char(0)) OR instr({value}, char(1)) "
        f"THEN json_extract({protected}, '$') ELSE {value} END"
    )


def public_ids(document):
    # Restore the escaped code points in the serialized result. This preserves
    # full strings even on SQLite versions that truncate decoded JSON scalars.
    return (
        rf"CASE WHEN instr({document}, '\u0001') THEN "
        rf"replace(replace(replace({document}, '\\', '\u005c'), "
        rf"'\u00010', '\u0000'), '\u00011', '\u0001') ELSE {document} END"
    )


def digest(rule, length: int) -> str:
    """Stable hex identity of a rule's content."""
    identity = json.dumps(rule.to_dict(), sort_keys=True, default=str)
    return hashlib.sha256(identity.encode()).hexdigest()[:length]


def json_object(pairs: list[tuple[str, str]]) -> str:
    # SQLite 3.38 caps a function at 127 arguments, 63 pairs. Build objects of
    # 30 pairs and json_patch them together; json_patch omits NULL members,
    # which json_extract reads back as NULL all the same.
    chunk = 30
    objects = [
        "json_object("
        + ", ".join(f"{literal(k)}, {v}" for k, v in pairs[i : i + chunk])
        + ")"
        for i in range(0, len(pairs), chunk)
    ]
    if not objects:
        return "'{}'"
    result = objects[0]
    for obj in objects[1:]:
        result = f"json_patch({result}, {obj})"
    return result


def numeric(expression: str, *, wide_integers: bool = False) -> str:
    """Accept finite SQLite numbers and JSON-number strings, never CAST junk to 0."""
    number = f"json_extract(trim({expression}), '$')"
    # JSON integer tokens beyond int64 extract as REAL. Pass their original
    # spelling to the exact aggregate, including totals from child alerts.
    wide = (
        f"WHEN json_type(trim({expression}))='integer' AND typeof({number})='real' "
        f"THEN trim({expression}) "
        if wide_integers
        else ""
    )
    return (
        f"CASE WHEN typeof({expression}) = 'integer' THEN {expression} "
        f"WHEN typeof({expression}) = 'real' AND abs({expression}) < {SQL_INFINITY} THEN {expression} "
        f"WHEN typeof({expression}) = 'text' AND instr({expression},char(0))=0 "
        f"THEN CASE WHEN json_valid(trim({expression})) THEN CASE {wide}"
        f"WHEN json_type(trim({expression})) IN ('integer', 'real') "
        f"AND abs(CAST({expression} AS REAL)) < {SQL_INFINITY} THEN {number} END END END"
    )


def metric_fields(rule) -> list[str]:
    field = getattr(rule.condition, "fieldref", None)
    kind = rule.type.name.lower()
    if field is None and kind not in (*NUMERIC_KINDS, "value_count"):
        return []
    if isinstance(field, list) and kind != "value_count":
        raise SigmaCorrelationConditionError(
            f"Correlation {rule.title!r} requires a single metric field",
            source=rule.source,
        )
    fields = field if isinstance(field, list) else [field]
    if not fields or not all(
        isinstance(f, str) and f and "\x00" not in f for f in fields
    ):
        raise SigmaCorrelationConditionError(
            f"Correlation {rule.title!r} requires nonempty metric field names without NUL",
            source=rule.source,
        )
    return fields


def terms(node, negative=False):
    """Boolean expression in disjunctive normal form, including nested NOT."""
    if isinstance(node, SigmaRuleReference):
        return [
            (
                set() if negative else {node.reference},
                {node.reference} if negative else set(),
            )
        ]
    if isinstance(node, CorrelationConditionNOT):
        return terms(node.args[0], not negative)
    conjunction = isinstance(node, CorrelationConditionAND) != negative
    children = [terms(arg, negative) for arg in node.args]
    if not conjunction:
        return list(itertools.chain.from_iterable(children))
    result = [(set(), set())]
    for child in children:
        result = [
            (a | c, b | d)
            for a, b in result
            for c, d in child
            if not ((a | c) & (b | d))
        ]
    return result


class ReferenceConversionError(SigmaCorrelationRuleError):
    """Preserve the originating failed dependency across a chain of correlations."""

    def __init__(self, parent, dependency, reason):
        self.dependency = dependency
        self.reason = reason
        super().__init__(
            f"Correlation {parent.title!r} references {dependency!r}, which {reason}",
            source=parent.source,
        )


@dataclass(frozen=True, slots=True)
class Stage:
    name: str
    select: str
    indexes: list[list[str]]


@dataclass(frozen=True, slots=True)
class ReplacedCorrelation:
    sql: str
    source_tables: dict[str, str]


class CorrelationCompiler:
    """Compile an already processed, resolved correlation dependency graph."""

    def __init__(self, backend, root, structured=False):
        self.structured = structured
        self.backend = backend
        self.root = root
        self.stages: list[Stage] = []
        self.stage_functions: set[str] = set()
        self.nodes = {}
        self.replacements: dict[int, ReplacedCorrelation] = {}
        self.active = set()
        self.records = {}
        self.fields = set()
        self.required_by_table: dict[str, set[str]] = {}
        self.source_tables = {}
        self.diagnostic_queries = []
        self._discover(root)
        fulltext = {
            (item["table"], item["field"]): item
            for states in self.records.values()
            for state in states
            for item in state.sqlite_predicate.fulltext
        }
        self.fulltext_requirements = [fulltext[key] for key in sorted(fulltext)]
        self.field_ids = {f: f"f{i}" for i, f in enumerate(sorted(self.fields))}
        # Stable identifiers make saved plans reproducible. Tables live in temp.
        self.prefix = "sigma_" + digest(root, 12)
        self.raw = {}
        self._raw_sources()
        self.array_items = json_array_function(self.source_tables.values())

    def add(self, suffix, select, indexes=()):
        name = f"{self.prefix}_{suffix}"
        self.stages.append(Stage(name, select, [list(i) for i in indexes]))
        return name

    def _discover(self, rule):
        if rule is not self.root:
            failure = getattr(rule, "_sqlite_dependency_failure", None)
            if failure is not None:
                raise ReferenceConversionError(self.root, *failure)
            if isinstance(rule, SigmaCorrelationRule):
                try:
                    states = rule.get_conversion_states()
                except SigmaConversionError:
                    states = []
                for state in states:
                    replacement = getattr(state, "sqlite_replacement", None)
                    if replacement is not None:
                        if self.structured:
                            raise ReferenceConversionError(
                                self.root, rule.title, "has callback-replaced SQL"
                            )
                        if (
                            not isinstance(replacement.sql, str)
                            or not replacement.sql.strip()
                        ):
                            raise ReferenceConversionError(
                                self.root, rule.title, "has no compiled query"
                            )
                        self.replacements[id(rule)] = replacement
        if id(rule) in self.active:
            raise SigmaCorrelationRuleError(
                f"Correlation {rule.title!r} has cyclic references", source=rule.source
            )
        self.active.add(id(rule))
        if isinstance(rule, SigmaCorrelationRule):
            self.fields.update(rule.group_by or [])
            self.fields.update(metric_fields(rule))
            for alias in rule.aliases:
                self.fields.add(alias.alias)
                self.fields.update(alias.mapping.values())
            for ref in rule.referenced_rules:
                self._discover(ref.rule)
        elif id(rule) not in self.records:
            self.records[id(rule)] = self._compiled_records(rule)
        self.active.remove(id(rule))

    def _compiled_records(self, rule):
        try:
            states = rule.get_conversion_states()
        except SigmaConversionError:
            states = []
        records = [state for state in states if hasattr(state, "sqlite_predicate")]
        if not records or not all(
            isinstance(state.sqlite_predicate.sql, str)
            and state.sqlite_predicate.sql.strip()
            for state in records
        ):
            raise ReferenceConversionError(
                self.root, rule.title, "has no compiled predicates"
            )
        if self.structured and any(
            state.sqlite_predicate.replaced for state in records
        ):
            raise ReferenceConversionError(
                self.root, rule.title, "has callback-replaced SQL"
            )
        return records

    @staticmethod
    def _alias_mapping(rule, ref):
        """Map each alias of a correlation to the field it names in one reference."""
        names = (ref.reference, ref.rule.name, str(ref.rule.id))
        return {
            alias.alias: field
            for alias in rule.aliases
            for target, field in alias.mapping.items()
            if target.reference in names
        }

    def _physical_fields(self, rule, wanted):
        if not isinstance(rule, SigmaCorrelationRule):
            for state in self.records[id(rule)]:
                table = state.sqlite_predicate.table
                self.required_by_table.setdefault(table, set()).update(wanted)
            return
        own = set(rule.group_by or []) | {rule.type.name.lower(), "sigma_metric"}
        # Parent fields not in the child's summary are propagated from evidence.
        needed = (set(wanted) - own) | set(rule.group_by or [])
        needed.update(metric_fields(rule))
        for ref in rule.referenced_rules:
            mapping = self._alias_mapping(rule, ref)
            self._physical_fields(ref.rule, {mapping.get(f, f) for f in needed})

    def _raw_sources(self):
        self._physical_fields(self.root, set())
        by_table = {}
        for key, states in self.records.items():
            for state in states:
                predicate = state.sqlite_predicate
                by_table.setdefault(predicate.table, {}).setdefault(key, []).append(
                    f"({predicate.sql})"
                )
                self.required_by_table[predicate.table].update(predicate.fields)
        self.raw_tables = {}
        for i, (table, rules) in enumerate(by_table.items()):
            self.source_tables[str(i)] = table
            fields = self.required_by_table[table]
            fields.add(self.backend.timestamp_field)
            if self.backend.event_id_field.lower() != "rowid":
                fields.add(self.backend.event_id_field)
            # Keep source values in SQLite columns. JSON extraction on SQLite
            # 3.38 truncates text at embedded NULs, before numeric or text matching.
            columns = [
                f"CASE WHEN typeof({quote(field)})='real' "
                f"AND abs({quote(field)}) >= {SQL_INFINITY} THEN NULL ELSE {quote(field)} END AS {fid}"
                for field, fid in self.field_ids.items()
                if field in fields
            ]
            flags = [
                f"COALESCE(({self.backend._join_operands(predicates, ' OR ')}), 0) AS b{j}"
                for j, predicates in enumerate(rules.values())
            ]
            time = self.backend._correlation_timestamp()
            event_id = f"CAST({quote(self.backend.event_id_field)} AS TEXT)"
            raw = self.add(
                f"raw{i}",
                f"SELECT {event_id} AS rid, {literal(str(i) + ':')} || {evidence_id(event_id)} AS eid, "
                f"{time} AS ts, {', '.join(columns + flags)} FROM {table}",
                [("eid",), ("ts",)],
            )
            self.raw_tables[raw] = table
            for j, key in enumerate(rules):
                self.raw.setdefault(key, []).append((raw, f"b{j}"))
            self.diagnostic_queries.append(
                f"SELECT 'invalid_timestamp' AS reason, COUNT(*) AS count FROM {raw} "
                f"WHERE ts IS NULL AND ({' OR '.join(f'b{j}' for j in range(len(rules)))})"
            )
        horizon = self.backend.observation_end
        if horizon is not None:
            expr = str(float(horizon))
        else:
            expr = (
                "(SELECT MAX(ts) FROM ("
                + " UNION ALL ".join(
                    f"SELECT ts FROM {source}" for source in self.raw_tables
                )
                + "))"
            )
        self.horizon = self.add("horizon", f"SELECT {expr} AS ts")

    def raw_field(self, raw, field):
        table = self.raw_tables[raw]
        return (
            self.field_ids[field] if field in self.required_by_table[table] else "NULL"
        )

    def source(self, rule, fields):
        if not isinstance(rule, SigmaCorrelationRule):
            columns = "".join(f", {self.field_ids[f]}" for f in fields)
            return " UNION ALL ".join(
                f"SELECT 'e:' || eid AS eid, ts, json_array(eid) AS evidence, "
                f"'[]' AS children{columns} FROM {raw} WHERE {flag}"
                for raw, flag in self.raw[id(rule)]
            )
        result = self.compile_node(rule)
        # Child metrics and grouping keys belong to the alert. Other parent
        # fields are read from the raw events that contributed to that alert.
        summary = {f: f"c.g{i}" for i, f in enumerate(rule.group_by or [])}
        for name in (rule.type.name.lower(), "sigma_metric"):
            summary.setdefault(name, "c.metric")
        evidence_fields = [f for f in fields if f not in summary]
        join = ""
        if evidence_fields:
            sources = []
            for raw in self.raw_tables:
                columns = "".join(
                    f", {self.raw_field(raw, f)} AS {self.field_ids[f]}"
                    for f in evidence_fields
                )
                sources.append(f"SELECT eid{columns} FROM {raw}")
            join = (
                f" JOIN {self.array_items}(c.evidence) e ON e.type='text'"
                f" JOIN ({' UNION ALL '.join(sources)}) r ON r.eid=e.value"
            )
        columns = "".join(
            f", {summary.get(f, 'r.' + self.field_ids[f])} AS {self.field_ids[f]}"
            for f in fields
        )
        return (
            f"SELECT DISTINCT 'c:' || c.alert_id AS eid, c.end AS ts, "
            f"c.evidence, json_array({evidence_id('c.alert_id')}) AS children{columns} FROM {result} c{join}"
        )

    @staticmethod
    def group_equal(left, right, count):
        return "".join(f"{left}.g{i} = {right}.g{i} AND " for i in range(count))

    def window(self, alias, anchor, count):
        return (
            self.group_equal(alias, anchor, count)
            + f"{alias}.ts BETWEEN {anchor}.start AND {anchor}.end"
        )

    def group_key(self, expression):
        if self.backend.text_mode == "unicode":
            self.stage_functions.add("sigma_casefold")
            return f"sigma_casefold({expression})"
        return f"CASE WHEN typeof({expression})='text' THEN lower({expression}) ELSE {expression} END"

    def contexts(self, rule, fields):
        """Project observed context through the same aliases as rule membership."""
        if not isinstance(rule, SigmaCorrelationRule):
            sources = []
            for raw, _ in self.raw[id(rule)]:
                columns = "".join(
                    f", {self.group_key(self.raw_field(raw, f))} AS g{i}"
                    for i, f in enumerate(fields)
                )
                sources.append(f"SELECT eid, ts{columns} FROM {raw}")
            return sources
        sources = []
        for ref in rule.referenced_rules:
            mapping = self._alias_mapping(rule, ref)
            sources.extend(self.contexts(ref.rule, [mapping.get(f, f) for f in fields]))
        return sources

    def portable_sum(self, stem, events, gs, partition, frame):
        """Sum the signed high and unsigned low halves, then propagate the carry.

        Each accumulator fits int64 for a partition of up to 2**31 rows.
        Guard their inputs so SQLite never accumulates an overflowing integer,
        even when the final total overflows or sliding-window sums cancel.
        """
        groups = "".join(f", {g}" for g in gs)
        sized = self.add(
            stem + "_sizes",
            f"SELECT *, COUNT(*) OVER ({partition}) AS n FROM {events}",
        )
        integer = "typeof(v)='integer' AND n <= 2147483648"
        totals = self.add(
            stem + "_sums",
            f"SELECT DISTINCT ts AS end{groups}, "
            f"SUM(v >> 32) FILTER (WHERE {integer}) OVER w AS hi, "
            f"SUM(v & 4294967295) FILTER (WHERE {integer}) OVER w AS lo, "
            f"COUNT(v) FILTER (WHERE NOT ({integer})) OVER w AS other, "
            f"SUM(CAST(v AS REAL)) OVER w AS fallback FROM {sized} WINDOW w AS ({frame})",
        )
        high = "(hi + (lo >> 32))"
        return self.add(
            stem + "_metrics",
            f"SELECT end{groups}, CASE WHEN other=0 AND {high} BETWEEN -2147483648 AND 2147483647 "
            f"THEN ({high} << 32) | (lo & 4294967295) ELSE fallback END AS metric FROM {totals}",
            [gs + ["end"]],
        )

    def ordered_threshold(self, rule, stem, matches, gs, span):
        """Find the union of greedy ordered witnesses without enumerating subsets.

        An edge into a slot chooses its first timestamp after the predecessor.
        Prefixes ending at the same (window, slot, time, length) have identical
        continuations. Trace winning prefixes backward to retain exactly the
        events that the successful branches would have contributed.
        """
        nslots = len(rule.referenced_rules)
        op = self.backend.correlation_condition_mapping[rule.condition.op]
        count = rule.condition.count
        groups = "".join(f", {g}" for g in gs)
        ag = "".join(f", a.{g}" for g in gs)
        wg = "".join(f", w.{g}" for g in gs)
        ng = "".join(f", n.{g}" for g in gs)
        cols = ", ".join(["end", *gs])
        anchors = f"(SELECT DISTINCT ts AS end{groups} FROM {matches})"
        target = "metric"
        if op in (">", ">="):
            target = math.floor(count) + 1 if op == ">" else math.ceil(count)
        if target == nslots or (op == "=" and count == nslots):
            # With every slot required there is only one greedy path per anchor.
            # Each step seeks the next timestamp on the (group, slot, ts) index.
            path = self.add(
                stem + "_path",
                f"WITH RECURSIVE path({cols}, slot, ts) AS ("
                f"SELECT a.end{ag}, 0, (SELECT MIN(m.ts) FROM {matches} m WHERE "
                f"{self.group_equal('m', 'a', len(gs))}m.slot=0 AND m.ts BETWEEN a.end-{span} AND a.end) "
                f"FROM {anchors} a UNION ALL "
                f"SELECT a.end{ag}, a.slot+1, (SELECT MIN(m.ts) FROM {matches} m WHERE "
                f"{self.group_equal('m', 'a', len(gs))}m.slot=a.slot+1 AND m.ts>a.ts AND m.ts<=a.end) "
                f"FROM path a WHERE a.ts IS NOT NULL AND a.slot<{nslots - 1}) "
                f"SELECT * FROM path WHERE ts IS NOT NULL",
                [gs + ["end", "slot"]],
            )
            return (
                f"SELECT w.end-{span} AS start, w.end{wg}, {nslots} AS metric, m.evidence, m.children "
                f"FROM {path} w JOIN {path} last ON {self.group_equal('last', 'w', len(gs))}"
                f"last.end=w.end AND last.slot={nslots - 1} "
                f"JOIN {matches} m ON {self.group_equal('m', 'w', len(gs))}m.slot=w.slot AND m.ts=w.ts"
            )
        slots = ", ".join([*gs, "slot"])
        positions = self.add(
            stem + "_positions",
            f"SELECT *, LAG(ts) OVER (PARTITION BY {slots} ORDER BY ts) AS prev "
            f"FROM (SELECT DISTINCT ts, slot{groups} FROM {matches})",
            [gs + ["ts"]],
        )
        nodes = self.add(
            stem + "_window_nodes",
            f"SELECT a.end{ag}, p.slot, p.ts, p.prev, "
            f"SUM(p.prev IS NULL OR p.prev < a.end-{span}) OVER "
            f"(PARTITION BY a.end{ag}) AS metric FROM {anchors} a JOIN {positions} p "
            f"ON {self.group_equal('p', 'a', len(gs))}p.ts BETWEEN a.end-{span} AND a.end",
        )
        if target != "metric" and target <= 0:
            # The empty subset imposes no ordering and contributes all evidence.
            winning = nodes
        else:
            prefix_cols = cols + ", slot, ts, prev, metric, target"
            same_window = self.group_equal("r", "n", len(gs)) + "r.end=n.end"
            edge = "r.slot<n.slot AND r.ts<n.ts AND (n.prev IS NULL OR r.ts>=n.prev)"
            winning = self.add(
                stem + "_winning",
                f"WITH RECURSIVE eligible AS MATERIALIZED "
                f"(SELECT *, {target} AS target FROM {nodes} WHERE metric {op} {count}), "
                f"prefix AS (SELECT {prefix_cols}, 1 AS depth FROM eligible "
                f"WHERE (prev IS NULL OR prev < end-{span}) AND slot <= {nslots}-target "
                f"UNION SELECT n.end{ng}, n.slot, n.ts, n.prev, "
                f"n.metric, n.target, r.depth+1 FROM prefix r JOIN eligible n ON {same_window} "
                f"AND {edge} WHERE r.depth<r.target AND n.slot <= {nslots}-n.target+r.depth), "
                f"witness AS (SELECT * FROM prefix WHERE depth=target UNION "
                f"SELECT r.* FROM witness n JOIN prefix r ON {same_window} AND {edge} "
                f"AND r.depth=n.depth-1) SELECT DISTINCT {cols}, slot, ts, metric FROM witness",
                [gs + ["slot", "ts"]],
            )
        return (
            f"SELECT w.end-{span} AS start, w.end{wg}, w.metric, m.evidence, m.children "
            f"FROM {winning} w JOIN {matches} m ON {self.group_equal('m', 'w', len(gs))}"
            f"m.slot=w.slot AND m.ts=w.ts"
        )

    def replacement_alerts(self, rule, replacement):
        """Read the public alert columns supplied by a plain SQL callback."""
        evidence = protect_json_text("c.event_ids")
        parent_ids = {table: key for key, table in self.source_tables.items()}
        if any(table not in parent_ids for table in replacement.source_tables.values()):
            raise ReferenceConversionError(
                self.root,
                rule.title,
                "must be reconverted after its source tables changed",
            )
        if any(
            parent_ids[table] != key for key, table in replacement.source_tables.items()
        ):
            # A child numbers its source tables independently of its parent.
            cases = " ".join(
                f"WHEN {literal(key)} THEN {literal(parent_ids[table])}"
                for key, table in replacement.source_tables.items()
            )
            colon = "instr(e.value, ':')"
            evidence = (
                f"(SELECT json_group_array(CASE substr(e.value, 1, {colon}-1) {cases} END "
                f"|| substr(e.value, {colon})) FROM {self.array_items}({evidence}) e WHERE e.type='text')"
            )
        groups_json = protect_json_text("c.group_keys")
        keys = "".join(
            f", (SELECT {restore_text('k.value')} FROM {self.array_items}({groups_json}) k "
            f"WHERE k.key={literal(field.replace(chr(1), chr(1) + '1'))}) AS g{i}"
            for i, field in enumerate(rule.group_by or [])
        )
        sql = replacement.sql.rstrip().removesuffix(";")
        return (
            f"SELECT c.alert_id, c.occurrence_time AS end, c.metric_value AS metric, "
            f"{evidence} AS evidence{keys} FROM ({sql}\n) c"
        )

    def compile_node(self, rule):
        if id(rule) in self.nodes:
            return self.nodes[id(rule)]
        n = len(self.nodes)
        self.nodes[id(rule)] = None
        stem = f"n{n}"
        kind = rule.type.name.lower()
        group = list(rule.group_by or [])
        if replacement := self.replacements.get(id(rule)):
            result = self.add(
                stem + "_alerts", self.replacement_alerts(rule, replacement)
            )
            self.nodes[id(rule)] = result
            return result
        count = len(group)
        gs = [f"g{i}" for i in range(count)]
        comma_groups = "".join(f", {g}" for g in gs)
        fields = metric_fields(rule)
        value_columns = ["v"] + [f"v{i}" for i in range(1, len(fields))]
        exact_sum = kind == "value_sum" and self.backend.sum_mode == "exact"
        is_extended = isinstance(rule.condition, SigmaExtendedCorrelationCondition)
        ordered_threshold = kind == "temporal_ordered" and not is_extended
        branches = []
        ordered_sources = {}
        names = {}
        for slot, ref in enumerate(rule.referenced_rules):
            names[ref.reference] = slot
            names[str(ref.rule.name or ref.rule.id)] = slot
            mapping = self._alias_mapping(rule, ref)
            mapped_groups = [mapping.get(f, f) for f in group]
            mapped_values = [mapping.get(f, f) for f in fields]
            groups = [self.group_key(f"s.{self.field_ids[f]}") for f in mapped_groups]
            values = [f"s.{self.field_ids[f]}" for f in mapped_values]
            if kind in NUMERIC_KINDS:
                values = [numeric(values[0], wide_integers=exact_sum)]
            if kind == "value_count" and self.backend.text_mode == "unicode":
                values = [self.group_key(v) for v in values]
            columns = "".join(f", {expr} AS g{i}" for i, expr in enumerate(groups))
            columns += "".join(
                f", {v} AS {col}" for v, col in zip(values or ["NULL"], value_columns)
            )
            if ordered_threshold and not isinstance(ref.rule, SigmaCorrelationRule):
                for raw, flag in self.raw[id(ref.rule)]:
                    ordered_sources.setdefault((raw, columns), []).append((slot, flag))
            else:
                source_fields = dict.fromkeys(mapped_groups + mapped_values)
                branches.append(
                    f"SELECT s.eid, s.ts, s.evidence, s.children, {slot} AS slot{columns} "
                    f"FROM ({self.source(ref.rule, source_fields)}) s"
                )
        # Read each physical projection once. A UNION term per position expands
        # the same raw CTE repeatedly inside SQLite's standalone query planner.
        for (raw, columns), flags in ordered_sources.items():
            slots = json.dumps([slot for slot, _ in flags])
            cases = " ".join(f"WHEN {slot} THEN s.{flag}" for slot, flag in flags)
            branches.append(
                f"SELECT 'e:' || s.eid AS eid, s.ts, json_array(s.eid) AS evidence, "
                f"'[]' AS children, j.value AS slot{columns} FROM {raw} s "
                f"JOIN {self.array_items}({literal(slots)}) j ON j.type='integer' AND CASE j.value {cases} END"
            )
        if len(branches) > 500:
            raise SigmaFeatureNotSupportedByBackendError(
                f"Correlation {rule.title!r} exceeds SQLite's limit of 500 compound SELECT terms",
                source=rule.source,
            )
        unfiltered = self.add(stem + "_input", " UNION ALL ".join(branches))
        guard = " AND ".join(
            ["ts IS NOT NULL", "eid IS NOT NULL"] + [f"{g} IS NOT NULL" for g in gs]
        )
        matches = self.add(
            stem + "_matches",
            f"SELECT DISTINCT * FROM {unfiltered} WHERE {guard}",
            [gs + ["ts"], gs + ["slot", "ts"], ["eid"]],
        )
        if gs:
            self.diagnostic_queries.append(
                f"SELECT 'missing_group_key' AS reason, COUNT(DISTINCT eid) AS count "
                f"FROM {unfiltered} WHERE " + " OR ".join(f"{g} IS NULL" for g in gs)
            )
        events = self.add(
            stem + "_events",
            f"SELECT DISTINCT eid, ts{comma_groups}, {', '.join(value_columns)} FROM {matches}",
            [gs + ["ts"]],
        )
        span = rule.timespan.seconds
        if span <= 0:
            raise SigmaTimespanError(
                f"Correlation {rule.title!r} needs a positive timespan",
                source=rule.source,
            )
        window_metrics = None
        if kind in ("event_count", "value_sum", "value_avg"):
            partition = "PARTITION BY " + ", ".join(gs) + " " if gs else ""
            frame = (
                f"{partition}ORDER BY ts RANGE BETWEEN {span} PRECEDING AND CURRENT ROW"
            )
            input_relation = events
            if kind == "event_count":
                input_relation = self.add(
                    stem + "_unique_events",
                    f"SELECT DISTINCT eid, ts{comma_groups} FROM {events}",
                )
            if kind == "value_sum" and not exact_sum:
                window_metrics = self.portable_sum(stem, events, gs, partition, frame)
            else:
                if exact_sum:
                    self.stage_functions.update(
                        ("sigma_exact_sum", "sigma_numeric_cmp")
                    )
                aggregate = {
                    "event_count": "COUNT(*)",
                    "value_sum": "sigma_exact_sum(v)",
                    "value_avg": "AVG(v)",
                }[kind]
                window_metrics = self.add(
                    stem + "_metrics",
                    f"SELECT DISTINCT ts AS end{comma_groups}, {aggregate} OVER ({frame}) AS metric "
                    f"FROM {input_relation}",
                    [gs + ["end"]],
                )
        clauses = terms(rule.condition.parsed) if is_extended else [(set(), set())]
        results = []
        if ordered_threshold:
            results.append(self.ordered_threshold(rule, stem, matches, gs, span))
            clauses = []
        for ti, (positive, negative) in enumerate(clauses):
            pos = sorted({names[x] for x in positive})
            neg = sorted({names[x] for x in negative})
            forward = bool(neg)
            name = f"{stem}_t{ti}"
            source_filter = ""
            anchor_source = matches
            if forward and not pos:
                # A purely negative expression needs an observed scope even
                # when none of its detections fires. Use actual input events
                # as context, never invent an empty/global series.
                contexts = self.contexts(rule, group)
                context = self.add(name + "_context", " UNION ".join(contexts))
                anchor_source = self.add(
                    name + "_scope",
                    f"SELECT * FROM {context} WHERE {guard}",
                    [gs + ["ts"]],
                )
            if forward and pos:
                source_filter = " WHERE slot IN (" + ",".join(map(str, pos)) + ")"
            start = "ts" if forward else f"ts - {span}"
            end = f"ts + {span}" if forward else "ts"
            anchors = self.add(
                name + "_anchors",
                f"SELECT DISTINCT {start} AS start, {end} AS end{comma_groups} "
                f"FROM {anchor_source}{source_filter}",
                [gs + ["end"]],
            )
            if forward:
                self.diagnostic_queries.append(
                    f"SELECT 'incomplete_window' AS reason, COUNT(*) AS count FROM {anchors} "
                    f"WHERE end > (SELECT ts FROM {self.horizon})"
                )
            predicate = self.window("m", "a", count)

            def presence(slot):
                return f"EXISTS (SELECT 1 FROM {matches} m WHERE {predicate} AND m.slot={slot})"

            conditions = [presence(s) for s in pos] + [
                f"NOT {presence(s)}" for s in neg
            ]
            if forward:
                conditions.append(f"a.end <= (SELECT ts FROM {self.horizon})")
            ordered = kind == "temporal_ordered"
            sequence = anchors
            slots = pos
            if ordered:
                for si, slot in enumerate(slots):
                    after = f" AND m.ts > a.q{si - 1}" if si else ""
                    t = f"q{si}"
                    sequence = self.add(
                        name + f"_seq{si}",
                        f"SELECT a.*, (SELECT MIN(m.ts) FROM {matches} m WHERE {predicate} "
                        f"AND m.slot={slot}{after}) AS {t} FROM {sequence} a",
                    )
                    conditions.append(f"a.{t} IS NOT NULL")
            if kind.startswith("temporal"):
                metric = f"(SELECT COUNT(DISTINCT m.slot) FROM {matches} m WHERE {predicate})"
            elif window_metrics:
                metric = (
                    f"(SELECT m.metric FROM {window_metrics} m WHERE "
                    f"{self.group_equal('m', 'a', count)}m.end=a.end)"
                )
            elif kind == "value_count":
                collate = "BINARY" if self.backend.text_mode == "unicode" else "NOCASE"
                if len(value_columns) == 1:
                    metric = f"(SELECT COUNT(DISTINCT m.v COLLATE {collate}) FROM {events} m WHERE {predicate})"
                else:
                    components = ", ".join(
                        f"m.{v} COLLATE {collate}" for v in value_columns
                    )
                    complete = " AND ".join(f"m.{v} IS NOT NULL" for v in value_columns)
                    metric = (
                        f"(SELECT COUNT(*) FROM (SELECT DISTINCT {components} FROM {events} m "
                        f"WHERE {predicate} AND {complete}))"
                    )
            elif kind in ("value_median", "value_percentile"):
                p = 50 if kind == "value_median" else rule.condition.percentile
                if p is None or not 0 <= p <= 100:
                    raise SigmaCorrelationConditionError(
                        f"Correlation {rule.title!r} needs a percentile between 0 and 100",
                        source=rule.source,
                    )
                rank = (
                    f"SELECT m.v, ROW_NUMBER() OVER (ORDER BY m.v) - 1 AS r, "
                    f"COUNT(*) OVER () AS n FROM {events} m WHERE {predicate} AND m.v IS NOT NULL"
                )
                position = f"((n - 1) * {float(p) / 100})"
                metric = (
                    f"(SELECT SUM(v * CASE WHEN r=CAST({position} AS INTEGER) "
                    f"THEN 1 - ({position} - CAST({position} AS INTEGER)) "
                    f"ELSE {position} - CAST({position} AS INTEGER) END) FROM ({rank}) "
                    f"WHERE r IN (CAST({position} AS INTEGER), CAST({position} AS INTEGER) + 1))"
                )
            else:
                raise SigmaFeatureNotSupportedByBackendError(
                    f"Unknown correlation type {kind}"
                )
            measured = self.add(
                name + "_measured",
                f"SELECT a.*, {metric} AS metric FROM {sequence} a WHERE "
                + (" AND ".join(conditions) or "1"),
            )
            condition = "1"
            if not is_extended:
                op = self.backend.correlation_condition_mapping[rule.condition.op]
                threshold = rule.condition.count
                condition = f"metric {op} {threshold}"
                if exact_sum:
                    condition = (
                        f"sigma_numeric_cmp(metric, {literal(str(threshold))}) {op} 0"
                    )
                elif (
                    kind == "value_sum"
                    and isinstance(threshold, int)
                    and not -(2**63) <= threshold < 2**63
                ):
                    # SQL parses this literal as REAL, which can round onto
                    # int64's lower boundary. Its order versus *any* int64
                    # metric is known exactly at conversion time.
                    comparison = 1 if threshold < 0 else -1
                    condition = f"CASE WHEN typeof(metric)='integer' THEN {comparison} {op} 0 ELSE {condition} END"
            qualified = self.add(
                name + "_qualified", f"SELECT * FROM {measured} WHERE {condition}"
            )
            evidence_filter = self.window("m", "a", count)
            if is_extended and pos:
                evidence_filter += " AND m.slot IN (" + ",".join(map(str, pos)) + ")"
            if ordered and slots:
                evidence_filter += (
                    " AND ("
                    + " OR ".join(
                        f"(m.slot={s} AND m.ts=a.q{i})" for i, s in enumerate(slots)
                    )
                    + ")"
                )
            if kind in NUMERIC_KINDS:
                evidence_filter += " AND m.v IS NOT NULL"
            evidence = (
                f"(SELECT json_group_array(DISTINCT e.value) FROM {matches} m, "
                f"{self.array_items}(m.evidence) e WHERE e.type='text' AND {evidence_filter})"
            )
            children = (
                f"(SELECT json_group_array(DISTINCT c.value) FROM {matches} m, "
                f"{self.array_items}(m.children) c WHERE c.type='text' AND {evidence_filter})"
            )
            if forward and not pos:
                evidence = (
                    f"(SELECT json_group_array(DISTINCT m.eid) FROM {anchor_source} m "
                    f"WHERE {self.group_equal('m', 'a', count)}m.ts=a.start)"
                )
            results.append(
                f"SELECT a.start, a.end{comma_groups}, a.metric, {evidence} AS evidence, "
                f"{children} AS children FROM {qualified} a"
            )
        if not results:
            results = [
                f"SELECT 0 AS start, 0 AS end{''.join(', NULL AS ' + g for g in gs)}, "
                "0 AS metric, '[]' AS evidence, '[]' AS children WHERE 0"
            ]
        combined = self.add(stem + "_combined", " UNION ".join(results))
        # OR branches may describe the same occurrence with different evidence:
        # merge it into one alert per window. Reading the combined relation
        # once keeps chained CTEs under SQLite's subquery nesting limit, and
        # flattening per window avoids materializing a row per event ID.
        keys = ", ".join(["start", "end"] + gs)
        grouped = self.add(
            stem + "_grouped",
            f"SELECT {keys}, MAX(metric) AS metric, "
            "json_group_array(json(evidence)) AS evidence, "
            "json_group_array(json(children)) AS children "
            f"FROM {combined} GROUP BY {keys}",
        )
        merged = [
            "(SELECT json_group_array(value) FROM (SELECT DISTINCT e.value "
            f"FROM json_each(w.{column}) a, json_each(a.value) e ORDER BY e.value)) AS {column}"
            for column in ("evidence", "children")
        ]
        if self.array_items == "json_tree":
            # Evidence and child IDs are the text leaves of these nested arrays.
            merged = [
                "(SELECT json_group_array(value) FROM (SELECT DISTINCT value "
                f"FROM json_tree(w.{column}) WHERE type='text' ORDER BY value)) AS {column}"
                for column in ("evidence", "children")
            ]
        combined = self.add(
            stem + "_merged",
            f"SELECT {keys}, metric, {', '.join(merged)} FROM {grouped} w",
        )
        group_json = json_object([(f, quote(g)) for f, g in zip(group, gs)])
        order = ", ".join(gs + ["end", "start", "metric", "evidence"])
        node_identity = digest(rule, 16)
        result = self.add(
            stem + "_alerts",
            f"SELECT {literal('sigma_alert_' + node_identity + ':')} || ROW_NUMBER() OVER (ORDER BY {order}) AS alert_id, "
            f"start, end, {group_json} AS group_keys, metric, evidence, children{comma_groups} "
            f"FROM {combined}",
            [("end",), ("alert_id",)],
        )
        self.nodes[id(rule)] = result
        return result

    def compile(self):
        root = self.compile_node(self.root)
        kind = self.root.type.name.lower()
        query = (
            f"SELECT alert_id, group_keys, end AS occurrence_time, start AS window_start, "
            f"end AS window_end, {literal(kind)} AS metric_name, metric AS metric_value, "
            f"json_array_length(evidence) AS event_count, {public_ids('evidence')} AS event_ids, "
            f"{public_ids('children')} AS child_alert_ids FROM {root} "
            # Alert IDs are numbered by group first; report in time order so a
            # consumer's LIMIT keeps the earliest occurrences.
            f"ORDER BY occurrence_time, alert_id"
        )
        ctes = ", ".join(f"{s.name} AS ({s.select})" for s in self.stages)
        diagnostics = " UNION ALL ".join(self.diagnostic_queries)
        plan = {
            "sqlite_min_version": "3.38.0",
            "prepare": [asdict(s) for s in self.stages],
            "query": query,
            "diagnostics": diagnostics,
            "cleanup": [s.name for s in reversed(self.stages)],
            "required_fields": {
                t: sorted(fs) for t, fs in self.required_by_table.items()
            },
            "event_id_field": self.backend.event_id_field,
            "source_tables": self.source_tables,
        }
        if self.fulltext_requirements:
            plan["fulltext"] = self.fulltext_requirements
        plan.update(
            self.backend.execution_contract(
                (state for states in self.records.values() for state in states),
                fulltext=bool(self.fulltext_requirements),
                extra_functions=self.stage_functions,
            )
        )
        return "WITH " + ctes + " " + query, plan
