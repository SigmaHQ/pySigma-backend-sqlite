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
    SigmaCorrelationConditionError,
    SigmaCorrelationRuleError,
    SigmaFeatureNotSupportedByBackendError,
    SigmaTimespanError,
)

from .cidr import required_sql_functions


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


def numeric(expression: str) -> str:
    """Accept finite SQLite numbers and JSON-number strings, never CAST junk to 0."""
    return (
        f"CASE WHEN typeof({expression}) = 'integer' THEN {expression} "
        f"WHEN typeof({expression}) = 'real' AND abs({expression}) < {SQL_INFINITY} THEN {expression} "
        f"WHEN typeof({expression}) = 'text' THEN CASE WHEN json_valid(trim({expression})) "
        f"THEN CASE WHEN json_type(trim({expression})) IN ('integer', 'real') "
        f"AND abs(CAST({expression} AS REAL)) < {SQL_INFINITY} "
        f"THEN CAST({expression} AS REAL) END END END"
    )


def group_key(expression: str) -> str:
    """Sigma's default string matching is case insensitive (SQLite: ASCII)."""
    return f"CASE WHEN typeof({expression})='text' THEN lower({expression}) ELSE {expression} END"


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


@dataclass(frozen=True, slots=True)
class Stage:
    name: str
    select: str
    indexes: list[list[str]]


class CorrelationCompiler:
    """Compile an already processed, resolved correlation dependency graph."""

    def __init__(self, backend, root):
        self.backend = backend
        self.root = root
        self.stages: list[Stage] = []
        self.nodes = {}
        self.active = set()
        self.base_rules = {}
        self.fields = set()
        self.required_by_table: dict[str, set[str]] = {}
        self.source_tables = {}
        self.diagnostic_queries = []
        self._discover(root)
        fulltext = {
            (item["table"], item["field"]): item
            for rule in self.base_rules.values()
            for item in self.backend.fulltext_requirements(rule)
        }
        self.fulltext_requirements = [fulltext[key] for key in sorted(fulltext)]
        self.field_ids = {f: f"f{i}" for i, f in enumerate(sorted(self.fields))}
        # Stable identifiers make saved plans reproducible. Tables live in temp.
        self.prefix = "sigma_" + digest(root, 12)
        self.raw = {}
        self._raw_sources()

    def add(self, suffix, select, indexes=()):
        name = f"{self.prefix}_{suffix}"
        self.stages.append(Stage(name, select, [list(i) for i in indexes]))
        return name

    def _discover(self, rule):
        if id(rule) in self.active:
            raise SigmaCorrelationRuleError(
                f"Correlation {rule.title!r} has cyclic references", source=rule.source
            )
        self.active.add(id(rule))
        if isinstance(rule, SigmaCorrelationRule):
            self.fields.update(rule.group_by or [])
            field = getattr(rule.condition, "fieldref", None)
            if isinstance(field, list):
                raise SigmaFeatureNotSupportedByBackendError(
                    f"Correlation condition field list {field} is not supported"
                )
            if field:
                self.fields.add(field)
            for alias in rule.aliases:
                self.fields.add(alias.alias)
                self.fields.update(alias.mapping.values())
            for ref in rule.referenced_rules:
                self._discover(ref.rule)
        else:
            self.base_rules[id(rule)] = rule
        self.active.remove(id(rule))

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

    def _field(self, payload, field):
        return f"json_extract({payload}, '$.{self.field_ids[field]}')"

    def _table(self, rule):
        states = rule.get_conversion_states()
        state = states[0].processing_state if states else {}
        return self.backend.resolve_table(state)

    def _physical_fields(self, rule, wanted):
        if not isinstance(rule, SigmaCorrelationRule):
            table = self._table(rule)
            self.required_by_table.setdefault(table, set()).update(wanted)
            return
        own = set(rule.group_by or []) | {rule.type.name.lower(), "sigma_metric"}
        # Parent fields not in the child's summary are propagated from evidence.
        needed = (set(wanted) - own) | set(rule.group_by or [])
        field = getattr(rule.condition, "fieldref", None)
        if field:
            needed.add(field)
        for ref in rule.referenced_rules:
            mapping = self._alias_mapping(rule, ref)
            self._physical_fields(ref.rule, {mapping.get(f, f) for f in needed})

    def _raw_sources(self):
        self._physical_fields(self.root, set())
        by_table = {}
        for rule in self.base_rules.values():
            table = self._table(rule)
            by_table.setdefault(table, []).append(rule)
            self.required_by_table.setdefault(table, set()).update(
                self.backend.required_fields(rule)
            )
        for item in self.fulltext_requirements:
            self.required_by_table.setdefault(item["table"], set()).add(item["field"])
        for i, (table, rules) in enumerate(by_table.items()):
            self.source_tables[str(i)] = table
            fields = self.required_by_table[table]
            fields.add(self.backend.timestamp_field)
            if self.backend.event_id_field.lower() != "rowid":
                fields.add(self.backend.event_id_field)
            payload = json_object(
                [
                    (
                        fid,
                        f"CASE WHEN typeof({quote(field)})='real' "
                        f"AND abs({quote(field)}) >= {SQL_INFINITY} THEN NULL ELSE {quote(field)} END",
                    )
                    for field, fid in self.field_ids.items()
                    if field in fields
                ]
            )
            flags = []
            for j, rule in enumerate(rules):
                queries = rule.get_conversion_result()
                if not queries or any(not isinstance(q, str) for q in queries):
                    raise SigmaCorrelationRuleError(
                        f"Correlation {self.root.title!r} references {rule.title!r}, "
                        "which has no compiled predicates",
                        source=self.root.source,
                    )
                predicate = self.backend._join_operands(
                    [f"({q})" for q in queries], " OR "
                )
                flags.append(f"COALESCE(({predicate}), 0) AS b{j}")
            time = self.backend._correlation_timestamp()
            event_id = f"CAST({quote(self.backend.event_id_field)} AS TEXT)"
            raw = self.add(
                f"raw{i}",
                f"SELECT {event_id} AS rid, {literal(str(i) + ':')} || {event_id} AS eid, "
                f"{time} AS ts, {payload} AS payload, {', '.join(flags)} FROM {table}",
                [("eid",), ("ts",)],
            )
            for j, rule in enumerate(rules):
                self.raw[id(rule)] = (raw, f"b{j}", i)
            self.diagnostic_queries.append(
                f"SELECT 'invalid_timestamp' AS reason, COUNT(*) AS count FROM {raw} "
                f"WHERE ts IS NULL AND ({' OR '.join(f'b{j}' for j in range(len(rules)))})"
            )
        horizon = self.backend.observation_end
        if horizon is not None:
            expr = str(float(horizon))
        else:
            sources = sorted({v[0] for v in self.raw.values()})
            expr = (
                "(SELECT MAX(ts) FROM ("
                + " UNION ALL ".join(f"SELECT ts FROM {source}" for source in sources)
                + "))"
            )
        self.horizon = self.add("horizon", f"SELECT {expr} AS ts")

    def source(self, rule):
        if not isinstance(rule, SigmaCorrelationRule):
            raw, flag, _ = self.raw[id(rule)]
            return (
                f"SELECT 'e:' || eid AS eid, ts, payload, json_array(eid) AS evidence, "
                f"'[]' AS children FROM {raw} WHERE {flag}"
            )
        result = self.compile_node(rule)
        # Rehydrate fields the parent needs from the child's evidence; summary
        # fields override raw values. Parent event_count still counts child IDs.
        raws = sorted({v[0] for v in self.raw.values()})
        union = " UNION ALL ".join(f"SELECT eid, payload FROM {raw}" for raw in raws)
        return (
            f"SELECT DISTINCT 'c:' || c.alert_id AS eid, c.end AS ts, "
            f"json_patch(r.payload, c.payload) AS payload, c.evidence, "
            f"json_array(c.alert_id) AS children FROM {result} c "
            f"JOIN json_each(c.evidence) e JOIN ({union}) r ON r.eid=e.value"
        )

    @staticmethod
    def group_equal(left, right, count):
        return "".join(f"{left}.g{i} = {right}.g{i} AND " for i in range(count))

    def window(self, alias, anchor, count):
        return (
            self.group_equal(alias, anchor, count)
            + f"{alias}.ts BETWEEN {anchor}.start AND {anchor}.end"
        )

    def contexts(self, rule, fields):
        """Project observed context through the same aliases as rule membership."""
        if not isinstance(rule, SigmaCorrelationRule):
            raw = self.raw[id(rule)][0]
            columns = "".join(
                f", {group_key(self._field('payload', field))} AS g{i}"
                for i, field in enumerate(fields)
            )
            return [f"SELECT eid, ts{columns} FROM {raw}"]
        sources = []
        for ref in rule.referenced_rules:
            mapping = self._alias_mapping(rule, ref)
            sources.extend(self.contexts(ref.rule, [mapping.get(f, f) for f in fields]))
        return sources

    def compile_node(self, rule):
        if id(rule) in self.nodes:
            return self.nodes[id(rule)]
        n = len(self.nodes)
        self.nodes[id(rule)] = None
        stem = f"n{n}"
        kind = rule.type.name.lower()
        group = list(rule.group_by or [])
        count = len(group)
        gs = [f"g{i}" for i in range(count)]
        comma_groups = "".join(f", {g}" for g in gs)
        field = getattr(rule.condition, "fieldref", None)
        branches = []
        names = {}
        for slot, ref in enumerate(rule.referenced_rules):
            names[ref.reference] = slot
            names[str(ref.rule.name or ref.rule.id)] = slot
            mapping = self._alias_mapping(rule, ref)
            groups = [
                group_key(self._field("s.payload", mapping.get(f, f))) for f in group
            ]
            value = (
                self._field("s.payload", mapping.get(field, field)) if field else "NULL"
            )
            if kind in NUMERIC_KINDS:
                value = numeric(value)
            columns = "".join(f", {expr} AS g{i}" for i, expr in enumerate(groups))
            branches.append(
                f"SELECT s.*, {slot} AS slot{columns}, {value} AS v "
                f"FROM ({self.source(ref.rule)}) s"
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
            f"SELECT DISTINCT eid, ts{comma_groups}, v FROM {matches}",
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
            aggregate = {
                "event_count": "COUNT(*)",
                "value_sum": "SUM(CAST(v AS REAL))",
                "value_avg": "AVG(v)",
            }[kind]
            window_metrics = self.add(
                stem + "_metrics",
                f"SELECT DISTINCT ts AS end{comma_groups}, {aggregate} OVER ({frame}) AS metric "
                f"FROM {input_relation}",
                [gs + ["end"]],
            )
        is_extended = isinstance(rule.condition, SigmaExtendedCorrelationCondition)
        clauses = terms(rule.condition.parsed) if is_extended else [(set(), set())]
        partial_order = False
        if kind == "temporal_ordered" and not is_extended:
            operator = self.backend.correlation_condition_mapping[rule.condition.op]
            if operator in (">", ">="):
                required = max(
                    0,
                    (
                        math.floor(rule.condition.count) + 1
                        if operator == ">"
                        else math.ceil(rule.condition.count)
                    ),
                )
                partial_order = True
                # A threshold of two out of three asks for an ordered pair;
                # an unrelated out-of-order third type must not veto it.
                references = [r.reference for r in rule.referenced_rules]
                clauses = [
                    (set(subset), set())
                    for subset in itertools.combinations(references, required)
                ]
        results = []
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
            slots = (
                pos
                if is_extended or partial_order
                else list(range(len(rule.referenced_rules)))
            )
            times = []
            if ordered:
                for si, slot in enumerate(slots):
                    previous = (
                        f"COALESCE({', '.join(reversed(times))})"
                        if len(times) > 1
                        else (times[0] if times else "NULL")
                    )
                    # Optional stages in a count condition may be absent. The
                    # last non-NULL chosen time must still constrain later stages.
                    after = (
                        f" AND ({previous} IS NULL OR m.ts > {previous})"
                        if times
                        else ""
                    )
                    t = f"q{si}"
                    sequence = self.add(
                        name + f"_seq{si}",
                        f"SELECT a.*, (SELECT MIN(m.ts) FROM {matches} m WHERE {predicate} "
                        f"AND m.slot={slot}{after}) AS {t} FROM {sequence} a",
                    )
                    times.append(t)
                    conditions.append(
                        f"a.{t} IS NOT NULL"
                        if is_extended
                        else f"(NOT {presence(slot)} OR a.{t} IS NOT NULL)"
                    )
            if kind.startswith("temporal"):
                metric = f"(SELECT COUNT(DISTINCT m.slot) FROM {matches} m WHERE {predicate})"
            elif window_metrics:
                metric = (
                    f"(SELECT m.metric FROM {window_metrics} m WHERE "
                    f"{self.group_equal('m', 'a', count)}m.end=a.end)"
                )
            elif kind == "value_count":
                aggregate = "COUNT(DISTINCT m.v COLLATE NOCASE)"
                metric = f"(SELECT {aggregate} FROM {events} m WHERE {predicate})"
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
            condition = (
                "1"
                if is_extended
                else f"metric {self.backend.correlation_condition_mapping[rule.condition.op]} {rule.condition.count}"
            )
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
                f"json_each(m.evidence) e WHERE {evidence_filter})"
            )
            children = (
                f"(SELECT json_group_array(DISTINCT c.value) FROM {matches} m, "
                f"json_each(m.children) c WHERE {evidence_filter})"
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
        combined = self.add(
            stem + "_merged",
            f"SELECT {keys}, metric, {', '.join(merged)} FROM {grouped} w",
        )
        group_json = json_object([(f, quote(g)) for f, g in zip(group, gs)])
        payload = json_object(
            [(self.field_ids[f], quote(g)) for f, g in zip(group, gs)]
            + [
                (self.field_ids[f], "metric")
                for f in (kind, "sigma_metric")
                if f in self.field_ids
            ]
        )
        order = ", ".join(gs + ["end", "start", "metric", "evidence"])
        node_identity = digest(rule, 16)
        result = self.add(
            stem + "_alerts",
            f"SELECT {literal('sigma_alert_' + node_identity + ':')} || ROW_NUMBER() OVER (ORDER BY {order}) AS alert_id, "
            f"start, end, {group_json} AS group_keys, metric, evidence, children, {payload} AS payload "
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
            f"json_array_length(evidence) AS event_count, evidence AS event_ids, "
            f"children AS child_alert_ids FROM {root} "
            # Alert IDs are numbered by group first; report in time order so a
            # consumer's LIMIT keeps the earliest occurrences.
            f"ORDER BY occurrence_time, alert_id"
        )
        ctes = ", ".join(f"{s.name} AS ({s.select})" for s in self.stages)
        diagnostics = " UNION ALL ".join(self.diagnostic_queries)
        plan = {
            "version": 3 if self.fulltext_requirements else 2,
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
        functions = required_sql_functions(
            state
            for base in self.base_rules.values()
            for state in base.get_conversion_states()
        )
        if functions:
            plan["required_sql_functions"] = functions
            plan["version"] = 4
        return "WITH " + ctes + " " + query, plan
