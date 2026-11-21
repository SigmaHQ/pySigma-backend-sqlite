import json
import math
import re
import warnings
from dataclasses import dataclass
from difflib import get_close_matches
from typing import Any, ClassVar

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.correlations import (
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
)
from sigma.exceptions import (
    SigmaConfigurationError,
    SigmaConversionError,
    SigmaError,
    SigmaFeatureNotSupportedByBackendError,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    TimestampPart,
)

from .cidr import CIDR_FUNCTION
from .correlation import (
    BARE_NAME,
    FULLTEXT_REPRESENTATION,
    SQL_INFINITY,
    CorrelationCompiler,
    ReferenceConversionError,
    ReplacedCorrelation,
    literal,
    numeric,
    quote,
)
from .modifiers import BoundedRegex, SQLiteModifiers
from .strict import PRESENCE_REPRESENTATION

_SQLITE_KEYWORDS = set(
    "ABORT ACTION ADD AFTER ALL ALTER ALWAYS ANALYZE AND AS ASC ATTACH AUTOINCREMENT BEFORE BEGIN BETWEEN BY CASCADE CASE CAST CHECK COLLATE COLUMN COMMIT CONFLICT CONSTRAINT CREATE CROSS CURRENT CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP DATABASE DEFAULT DEFERRABLE DEFERRED DELETE DESC DETACH DISTINCT DO DROP EACH ELSE END ESCAPE EXCEPT EXCLUDE EXCLUSIVE EXISTS EXPLAIN FAIL FILTER FIRST FOLLOWING FOR FOREIGN FROM FULL GENERATED GLOB GROUP GROUPS HAVING IF IGNORE IMMEDIATE IN INDEX INDEXED INITIALLY INNER INSERT INSTEAD INTERSECT INTO IS ISNULL JOIN KEY LAST LEFT LIKE LIMIT MATCH MATERIALIZED NATURAL NO NOT NOTHING NOTNULL NULL NULLS OF OFFSET ON OR ORDER OTHERS OUTER OVER PARTITION PLAN PRAGMA PRECEDING PRIMARY QUERY RAISE RANGE RECURSIVE REFERENCES REGEXP REINDEX RELEASE RENAME REPLACE RESTRICT RETURNING RIGHT ROLLBACK ROW ROWS SAVEPOINT SELECT SET TABLE TEMP TEMPORARY THEN TIES TO TRANSACTION TRIGGER UNBOUNDED UNION UNIQUE UPDATE USING VACUUM VALUES VIEW VIRTUAL WHEN WHERE WINDOW WITH WITHOUT".split()
)


_KEYWORD_VALUES = (SigmaString, SigmaNumber, SigmaRegularExpression, SigmaExpansion)


def _walk(cond):
    """A parsed condition and every condition nested in it."""
    yield cond
    for arg in getattr(cond, "args", []):
        yield from _walk(arg)


def _is_keyword(cond):
    """A value-only (fieldless) expression, matched against fulltext_field."""
    return isinstance(cond, ConditionValueExpression) and isinstance(
        cond.value, _KEYWORD_VALUES
    )


@dataclass(frozen=True, slots=True)
class RetainedPredicate:
    """SQL and source requirements kept on its original pySigma conversion state."""

    index: int
    sql: str
    table: str
    fields: list[str]
    fulltext: list[dict]
    replaced: bool


class sqliteBackend(TextQueryBackend):
    """SQLite backend."""

    identifier: ClassVar[str] = "sqlite"
    name: ClassVar[str] = "SQLite backend"
    formats: ClassVar[dict[str, str]] = {
        "default": "Plain SQLite queries",
        "zircolite": "Zircolite JSON format",
    }
    correlation_methods: ClassVar[dict[str, str]] = {
        "default": "Default SQLite correlation using subqueries and window functions",
    }

    backend_processing_pipeline = ProcessingPipeline(
        items=[ProcessingItem(SQLiteModifiers())]
    )

    parenthesize: bool = True
    group_expression: ClassVar[str] = "({expr})"

    # SQLite parses "a OR b OR c" into a left-deep tree whose height is the operand count and
    # refuses anything over SQLITE_MAX_EXPR_DEPTH (1000 by default) with "Expression tree is too
    # large"; SigmaHQ ships rules with thousands of alternatives. Chains longer than this are
    # re-associated into nested groups, which is the same boolean value at a bounded height.
    max_flat_operands: ClassVar[int] = 100

    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="

    # Field names are quoted by escape_and_quote_field; convert_value_str doubles quotes
    # inside string values.
    str_quote: ClassVar[str] = "'"
    escape_char: ClassVar[str] = "\\"  # LIKE escape character, declared by each ESCAPE
    wildcard_multi: ClassVar[str] = "%"
    wildcard_single: ClassVar[str] = "_"
    add_escaped: ClassVar[str] = "\\"  # Escaped in addition to the wildcards

    # |cased matching uses GLOB and its wildcards.
    wildcard_glob: ClassVar[str] = "*"
    wildcard_glob_single: ClassVar[str] = "?"
    # Literal GLOB metacharacters, written as single-member character classes. Order matters:
    # "[" is escaped first so the brackets introduced by the other two are not escaped again.
    glob_escaped_chars: ClassVar[dict[str, str]] = {"[": "[[]", "*": "[*]", "?": "[?]"}
    # Sentinels standing in for Sigma wildcards while literals are escaped. NUL cannot occur in
    # a SQLite string literal, so these cannot collide with rule content.
    glob_wildcard_multi_placeholder: ClassVar[str] = "\x00\x01"
    glob_wildcard_single_placeholder: ClassVar[str] = "\x00\x02"

    # A flattener has to decide how to store a JSON boolean. Zircolite stores the strings
    # 'true'/'false' because that is what Sigma rules compare against, while a hand-built table
    # is as likely to hold 1/0 -- and SQLite reads the bare keyword `true` as the integer 1,
    # which never equals the text 'true'. Accepting both is the only form that is right against
    # either table; see convert_condition_field_eq_val_bool.
    bool_values: ClassVar[dict[bool, str]] = {True: "'true'", False: "'false'"}
    bool_numeric_values: ClassVar[dict[bool, str]] = {True: "1", False: "0"}
    bool_expression: ClassVar[str] = "({field}={value} OR {field}={numeric_value})"

    # Any value with a wildcard (or a backslash LIKE must escape) is a LIKE pattern, so
    # startswith, endswith and contains need no templates of their own. contains_expression
    # serves keyword search.
    wildcard_match_expression: ClassVar[str] = "{field} LIKE '{value}' ESCAPE '\\'"
    contains_expression: ClassVar[str] = "{field} LIKE '%{value}%' ESCAPE '\\'"

    # Regular expressions pass through unescaped, flags as an (?i) style prefix;
    # convert_value_re doubles their quotes.
    re_expression: ClassVar[str] = "{field} REGEXP '{regex}'"
    re_escape_char: ClassVar[str] = ""
    re_escape: ClassVar[tuple[str, ...]] = ()

    # SQLite's GLOB is a 2-argument operator with no ESCAPE clause (unlike LIKE);
    # emitting "ESCAPE '\'" triggers "wrong number of arguments to function GLOB()" at runtime.
    # Wildcards for |startswith/|endswith/|contains|cased are embedded in the value via
    # case_sensitive_match_expression; dedicated startswith/endswith/contains templates
    # would place GLOB metacharacters outside the quoted literal and produce invalid SQL.
    case_sensitive_match_expression: ClassVar[str] = "{field} GLOB {value}"

    # Numeric comparison operators
    # NUMERIC affinity converts complete numeric text for the equality check;
    # CAST alone would turn malformed text into zero. Unary + removes the
    # column affinity without changing the stored value. CAST AS NUMERIC keeps
    # representable integers exact, including those beyond double precision.
    compare_op_expression: ClassVar[str] = (
        "(CASE WHEN (typeof({field}) != 'text' OR instr({field}, char(0)) = 0) AND "
        "+{field} = CAST({field} AS NUMERIC) AND "
        f"CAST({{field}} AS NUMERIC) > -{SQL_INFINITY} AND "
        f"CAST({{field}} AS NUMERIC) < {SQL_INFINITY} "
        "THEN CAST({field} AS NUMERIC) END) {operator} {value}"
    )
    compare_operators: ClassVar[dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Expression for comparing two event fields (fieldref modifier)
    field_equals_field_expression: ClassVar[str | None] = "{field1}={field2}"
    # |fieldref compares two fields, so the pattern side is event data rather than rule text:
    # a "%" or "_" that happens to occur in it would otherwise act as a LIKE wildcard and match
    # far more than the rule asks for. The backslash is escaped first so the two escapes the
    # other REPLACEs introduce are not escaped again.
    field_ref_like_escape: ClassVar[str] = (
        "REPLACE(REPLACE(REPLACE({field2}, '\\', '\\\\'), '%', '\\%'), '_', '\\_')"
    )
    field_equals_field_startswith_expression: ClassVar[str | None] = (
        "{field1} LIKE " + field_ref_like_escape + " || '%' ESCAPE '\\'"
    )
    field_equals_field_endswith_expression: ClassVar[str | None] = (
        "{field1} LIKE '%' || " + field_ref_like_escape + " ESCAPE '\\'"
    )
    field_equals_field_contains_expression: ClassVar[str | None] = (
        "{field1} LIKE '%' || " + field_ref_like_escape + " || '%' ESCAPE '\\'"
    )

    # Timestamp part expressions for time modifiers (|minute, |hour, |day, etc.)
    field_timestamp_part_expression: ClassVar[str | None] = (
        "CAST(strftime('{timestamp_part}', {field}) AS INTEGER)"
    )
    timestamp_part_mapping: ClassVar[dict[TimestampPart, str] | None] = {
        TimestampPart.MINUTE: "%M",
        TimestampPart.HOUR: "%H",
        TimestampPart.DAY: "%d",
        TimestampPart.WEEK: "%W",
        TimestampPart.MONTH: "%m",
        TimestampPart.YEAR: "%Y",
    }

    # Sigma compares strings case-insensitively; SQLite's "=" does not, unless the column is
    # declared COLLATE NOCASE -- which is how Zircolite builds its table, so its output needs
    # nothing here. Set this for a table that does not, and literal string equality is emitted
    # with an explicit collation instead. It is off by default because a COLLATE on an already
    # NOCASE column is noise, and because forcing a collation can cost an index seek.
    # Comparisons emitted as LIKE are case-insensitive either way; |cased uses GLOB, which is
    # case-sensitive by definition and is never collated.
    prefilter_bounds: bool = True
    collate_nocase: bool = False
    collation_expression: ClassVar[str] = "{expr} COLLATE NOCASE"

    # Wrapper applied to the operand of every generated NOT so that a comparison against an
    # absent field reads as false rather than NULL. See convert_condition_not.
    null_safe_expression: ClassVar[str] = "COALESCE({expr}, 0)"

    field_null_expression: ClassVar[str] = "{field} IS NULL"

    # A flattened event that lacks a field carries NULL in its column, so existence is a NULL
    # test, which can also use an index. Both forms are defined: pySigma would otherwise negate
    # the first, and "|exists: false" must match an absent field.
    field_exists_expression: ClassVar[str] = "{field} IS NOT NULL"
    field_not_exists_expression: ClassVar[str] = "{field} IS NULL"

    # Constructor options, see the README. Keyword (fieldless) values match fulltext_field.
    table = "logs"
    timestamp_field = "timestamp"
    event_id_field = "rowid"
    week_mode = "iso"
    modifier_mode = "sigma"
    timestamp_format = "iso"
    observation_end = None
    cidr_mode = "expanded"
    text_mode = "portable"
    sum_mode = "portable"
    presence_field: str | None = None
    fulltext_field: str | None = None
    timestamp_seconds_expression = (
        "ROUND((julianday({field}) - 2440587.5) * 86400000) / 1000.0"
    )
    correlation_condition_mapping = {
        **TextQueryBackend.correlation_condition_mapping,
        SigmaCorrelationConditionOperator.EQ: "=",
    }

    def __init__(self, processing_pipeline=None, collect_errors=False, **options):
        configurable = {
            "table",
            "timestamp_field",
            "event_id_field",
            "observation_end",
            "timestamp_seconds_expression",
            "timestamp_format",
            "week_mode",
            "modifier_mode",
            "collate_nocase",
            "prefilter_bounds",
            "max_flat_operands",
            "fulltext_field",
            "cidr_mode",
            "text_mode",
            "sum_mode",
            "presence_field",
        }
        for key in options.keys() - configurable:
            close = get_close_matches(key, configurable, n=1, cutoff=0.8)
            if close:
                warnings.warn(
                    f"Unknown SQLite option {key!r}. Did you mean {close[0]!r}? "
                    "The supplied option is forwarded to the processing pipeline.",
                    stacklevel=2,
                )
        for key in configurable & options.keys():
            value = options[key]
            if key in ("collate_nocase", "prefilter_bounds") and isinstance(value, str):
                if value.lower() not in ("true", "false"):
                    raise ValueError(f"{key} must be true or false")
                value = value.lower() == "true"
            if key == "prefilter_bounds" and not isinstance(value, bool):
                raise ValueError("prefilter_bounds must be true or false")
            if key == "max_flat_operands":
                value = int(value)
                if value < 2:
                    raise ValueError("max_flat_operands must be at least 2")
            setattr(self, key, value)
        if self.cidr_mode not in ("expanded", "exact"):
            raise ValueError("cidr_mode must be expanded or exact")
        if self.week_mode not in ("iso", "legacy"):
            raise ValueError("week_mode must be iso or legacy")
        if self.modifier_mode not in ("sigma", "pysigma"):
            raise ValueError("modifier_mode must be sigma or pysigma")
        if self.modifier_mode == "pysigma":
            # Skip the replay of windash and re|startswith/endswith. pySigma's own
            # expansion then stands, as in 2.1 releases of this backend.
            self.backend_processing_pipeline = ProcessingPipeline()
        if self.text_mode not in ("portable", "unicode"):
            raise ValueError("text_mode must be portable or unicode")
        if self.sum_mode not in ("portable", "exact"):
            raise ValueError("sum_mode must be portable or exact")
        if self.timestamp_format not in ("iso", "unix", "unix_ms", "unix_us"):
            raise ValueError("timestamp_format must be iso, unix, unix_ms or unix_us")
        if (
            self.timestamp_format != "iso"
            and "timestamp_seconds_expression" not in options
        ):
            divisor = {"unix": 1, "unix_ms": 1000, "unix_us": 1000000}[
                self.timestamp_format
            ]
            self.timestamp_seconds_expression = f"({numeric('{field}')}) / {divisor}.0"
        if self.observation_end is not None:
            try:
                finite = math.isfinite(float(self.observation_end))
            except (TypeError, ValueError):
                finite = False
            if not finite:
                raise ValueError("observation_end must be finite Unix seconds")
        self._quoted_table(self.table)
        for name in (
            "timestamp_field",
            "event_id_field",
            "fulltext_field",
            "presence_field",
        ):
            value = getattr(self, name)
            if name in ("fulltext_field", "presence_field") and value is None:
                continue
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ValueError(f"{name} must be a nonempty column name without NUL")
        self._correlation_plans = {}
        super().__init__(processing_pipeline, collect_errors, **options)

    def resolve_presence_field(self, processing_state):
        field = (processing_state or {}).get("presence_field", self.presence_field)
        if field is not None and (
            not isinstance(field, str) or not field or "\x00" in field
        ):
            raise SigmaFeatureNotSupportedByBackendError(
                "presence_field must be a nonempty column name without NUL"
            )
        return field

    def execution_contract(self, states, *, fulltext=False, extra_functions=()):
        """Derive the smallest supported schema for these retained predicates and stages."""
        functions = set(extra_functions)
        presence = set()
        uses_regex = False
        strict = (
            self.text_mode == "unicode"
            or self.sum_mode == "exact"
            or self.presence_field is not None
        )
        for state in states:
            if getattr(state, "sqlite_uses_cidr", False):
                functions.add(CIDR_FUNCTION)
            functions.update(getattr(state, "sqlite_functions", ()))
            uses_regex |= getattr(state, "sqlite_uses_regex", False)
            strict |= state.processing_state.get("presence_field") is not None
            strict |= getattr(state, "sqlite_strict_regex", False)
            source = getattr(state, "sqlite_presence_source", None)
            if source is not None:
                presence.add(source)
        if uses_regex and (strict or presence or functions - {CIDR_FUNCTION}):
            functions.add("regexp")
        contract = {"version": 3 if fulltext else 2}
        if functions:
            contract["version"] = 4 if functions == {CIDR_FUNCTION} else 5
            contract["required_sql_functions"] = sorted(functions)
        if presence:
            contract["version"] = 5
            contract["presence"] = [
                {
                    "table": table,
                    "field": field,
                    "representation": PRESENCE_REPRESENTATION,
                }
                for table, field in sorted(presence)
            ]
        return contract

    @staticmethod
    def _strict_function(state, name, *args):
        if not hasattr(state, "sqlite_functions"):
            state.sqlite_functions = set()
        state.sqlite_functions.add(name)
        return f"{name}({', '.join(args)})"

    def convert_condition_field_eq_val_exists(self, cond, state):
        field = self.resolve_presence_field(state.processing_state)
        if field is None:
            return super().convert_condition_field_eq_val_exists(cond, state)
        table = self.resolve_table(state.processing_state)
        state.sqlite_presence_source = (table, field)
        # Read the validated array with scalar functions. Tables elsewhere on the
        # connection may shadow either of SQLite's JSON virtual tables.
        source = f"{table}.{quote(field)}"
        table_name = (
            (state.processing_state.get("table") or self.table)
            .rsplit(".", 1)[-1]
            .lower()
        )
        alias = "field_names" if table_name == "presence_keys" else "presence_keys"
        negation = "" if cond.value.exists else "NOT "
        walk = (
            f"EXISTS (WITH RECURSIVE {alias}(i, key) AS ("
            f"SELECT 0, json_extract({source}, '$[0]') UNION ALL "
            f"SELECT i+1, json_extract({source}, '$[' || (i+1) || ']') "
            f"FROM {alias} WHERE key IS NOT NULL) "
            f"SELECT 1 FROM {alias} WHERE key = {literal(cond.field)} COLLATE BINARY)"
        )
        if not set(cond.field) - {" ", ","}:
            # Such a name could span the separator between two elements.
            return negation + walk
        # Each extraction re-reads the array from its start. Without a backslash,
        # every quote in the validated array delimits an element, so the quoted
        # name occurs exactly when one element equals it.
        name = literal(json.dumps(cond.field, ensure_ascii=False))
        return (
            f"{negation}(CASE WHEN instr({source}, '\\') = 0 "
            f"THEN instr({source}, {name}) > 0 ELSE {walk} END)"
        )

    @staticmethod
    def _unicode_text(guard, unicode, native):
        # Function results carry no column affinity: 445 = '445' only holds in
        # SQLite's own comparison. Values that are not TEXT keep that comparison.
        return f"CASE WHEN {guard} THEN {unicode} ELSE {native} END"

    def convert_condition_field_eq_field(self, cond, state):
        expression = super().convert_condition_field_eq_field(cond, state)
        # Only equality is collated: the startswith/endswith forms use LIKE.
        if self.collate_nocase and not (cond.value.starts_with or cond.value.ends_with):
            expression = self.collation_expression.format(expr=expression)
        if self.text_mode != "unicode":
            return expression
        left, right = self.convert_condition_field_eq_field_escape_and_quote(
            cond.field, cond.value.field
        )
        starts, ends = cond.value.starts_with, cond.value.ends_with
        if not starts and not ends:
            lhs = self._strict_function(state, "sigma_casefold", left)
            rhs = self._strict_function(state, "sigma_casefold", right)
            guard = f"typeof({left})='text' AND typeof({right})='text'"
            return self._unicode_text(guard, f"{lhs}={rhs}", expression)
        # The pattern is TEXT whatever the type of the referenced field.
        pattern = self.field_ref_like_escape.format(field2=right)
        if ends:
            pattern = "'%' || " + pattern
        if starts:
            pattern += " || '%'"
        unicode = self._strict_function(state, "sigma_unicode_like", left, pattern)
        return self._unicode_text(f"typeof({left})='text'", unicode, expression)

    def resolve_table(self, state=None):
        table = (state or {}).get("table")
        if table is None:
            return self._quoted_table(self.table)
        try:
            return self._quoted_table(table)
        except ValueError as error:
            raise SigmaConfigurationError(
                f"Invalid pipeline table override: {error}"
            ) from error

    def _quoted_table(self, table):
        if (
            not isinstance(table, str)
            or "\x00" in table
            or table.count(".") > 1
            or not all(table.split("."))
        ):
            raise ValueError(
                "table must have one or two nonempty name components without NUL"
            )
        return ".".join(self.escape_and_quote_field(part) for part in table.split("."))

    def escape_and_quote_field(self, field):
        # SQLite keywords are identifiers only when quoted. This set includes
        # all keywords in SQLite 3.38+, including window-function vocabulary.
        if re.fullmatch(BARE_NAME, field) and field.upper() not in _SQLITE_KEYWORDS:
            return field
        return quote(field)

    def _correlation_timestamp(self):
        field = self.escape_and_quote_field(self.timestamp_field)
        return self.timestamp_seconds_expression.format(field=field)

    def required_fields(self, rule, index=None, state=None):
        fields = set()
        conditions = rule.detection.parsed_condition
        for condition in conditions if index is None else (conditions[index],):
            for cond in _walk(condition.parsed):
                if isinstance(cond, ConditionFieldEqualsValueExpression):
                    if isinstance(cond.value, SigmaExists) and state is not None:
                        presence = self.resolve_presence_field(state.processing_state)
                        if presence is not None:
                            fields.add(presence)
                            continue
                    if cond.field:
                        fields.add(cond.field)
                    if isinstance(cond.value, SigmaFieldReference):
                        fields.add(cond.value.field)
                elif _is_keyword(cond) and self.fulltext_field is not None:
                    fields.add(self.fulltext_field)
        return sorted(fields)

    def fulltext_requirements(self, rule, state=None, index=None):
        if self.fulltext_field is None:
            return []
        conditions = rule.detection.parsed_condition
        states = rule.get_conversion_states() if state is None else None
        tables = {
            self.resolve_table(states[i].processing_state if state is None else state)
            for i in (range(len(conditions)) if index is None else (index,))
            if any(map(_is_keyword, _walk(conditions[i].parsed)))
        }
        return [
            {
                "table": table,
                "field": self.fulltext_field,
                "representation": FULLTEXT_REPRESENTATION,
            }
            for table in sorted(tables)
        ]

    def init_processing_pipeline(self, output_format=None):
        super().init_processing_pipeline(output_format)
        self._configured_pipeline = self.processing_pipeline

    def _prepare_conversion(self, rule, output_format):
        # Reset the previous attempt before a pipeline, callback or finalizer can fail.
        rule.set_conversion_result([])
        rule.set_conversion_states([])
        pipeline = getattr(self, "last_processing_pipeline", None)
        if (
            pipeline is None
            or self._configured_pipeline is not self.processing_pipeline
            or pipeline.vars.get("output_format")
            != (output_format or self.default_format)
        ):
            self.init_processing_pipeline(output_format)

    def _callback_result(self, callback, rule, fmt, index, condition, predicate):
        if callback is None:
            return predicate
        result = callback(rule, fmt, index, condition, predicate)
        if (
            (fmt or self.default_format) == "zircolite"
            and result is not None
            and result != predicate
        ):
            raise SigmaConversionError(
                rule,
                rule.source,
                f"Structured output for {rule.title!r} requires callbacks to return "
                "the original SQL or None so its execution requirements remain valid",
            )
        return result

    def convert_correlation_rule(
        self, rule, output_format=None, method=None, callback=None
    ):
        self._prepare_conversion(rule, output_format)
        # The dependency marker belongs to this attempt. An intermediate rule
        # with generate disabled still has a successful conversion result.
        rule._sqlite_dependency_failure = (rule.title, "failed to convert")
        replacement = None

        def select(rule, fmt, index, query, predicate):
            nonlocal replacement
            result = self._callback_result(callback, rule, fmt, index, query, predicate)
            if result is not None and result != predicate:
                replacement = ReplacedCorrelation(
                    result, self._correlation_plans[id(rule)]["source_tables"]
                )
            return result

        try:
            output = super().convert_correlation_rule(
                rule, output_format, method, select
            )
            if rule.get_conversion_result():
                del rule._sqlite_dependency_failure
                rule.get_conversion_states()[0].sqlite_replacement = replacement
            else:
                rule._sqlite_dependency_failure = (rule.title, "has no compiled query")
            return output
        except SigmaError as error:
            if isinstance(error, ReferenceConversionError):
                rule._sqlite_dependency_failure = (error.dependency, error.reason)
            if not self.collect_errors:
                raise
            self.errors.append((rule, error))
            return []
        finally:
            # A skipped query or exception may bypass both finalizers.
            self._correlation_plans.pop(id(rule), None)

    def convert_rule(self, rule, output_format=None, callback=None):
        self._prepare_conversion(rule, output_format)
        selected = []

        def select(rule, fmt, index, condition, predicate):
            result = self._callback_result(
                callback, rule, fmt, index, condition, predicate
            )
            if result is not None:
                selected.append((index, result, result != predicate))
            # Let pySigma apply its pipeline and compile every condition once.
            # Finalize after it exposes the states, using original indices.
            return None

        error_count = len(self.errors)
        super().convert_rule(rule, output_format, select)
        if len(self.errors) != error_count:
            return []
        states = rule.get_conversion_states()
        raw = rule._backreferences and not self.finalize_correlation_subqueries
        try:
            self.resolve_table(self.last_processing_pipeline.state)
            retained = []
            for index, query, replaced in selected:
                state = states[index]
                state.sqlite_predicate = RetainedPredicate(
                    index,
                    query,
                    self.resolve_table(state.processing_state),
                    self.required_fields(rule, index, state),
                    self.fulltext_requirements(rule, state.processing_state, index),
                    replaced,
                )
                retained.append(state)
            entries = []
            if rule._output or not raw:
                for state in retained:
                    predicate = state.sqlite_predicate
                    entries.append(
                        self.finalize_query(
                            rule,
                            predicate.sql,
                            predicate.index,
                            state,
                            output_format or self.default_format,
                        )
                    )
        except Exception as error:
            rule.set_conversion_states([])
            if not (self.collect_errors and isinstance(error, SigmaError)):
                raise
            self.errors.append((rule, error))
            return []
        rule.set_conversion_result(
            [state.sqlite_predicate.sql for state in retained] if raw else entries
        )
        return entries if rule._output else []

    def convert_correlation_rule_from_template(self, rule, correlation_type, method):
        self.resolve_table(self.last_processing_pipeline.state)
        structured = (
            self.last_processing_pipeline.vars.get("output_format") == "zircolite"
        )
        query, plan = CorrelationCompiler(self, rule, structured).compile()
        self._correlation_plans[id(rule)] = plan
        return [query]

    def _join_operands(self, args: list[str], joiner: str) -> str:
        """Join boolean operands, regrouping long chains to stay under SQLite's depth limit.

        Below `max_flat_operands` nothing is regrouped, so ordinary queries are byte-identical
        to a plain join.
        """
        if len(args) <= self.max_flat_operands:
            return joiner.join(args)
        chunk = max(2, self.max_flat_operands // 2)
        while len(args) > chunk:
            args = [
                self.group_expression.format(
                    expr=joiner.join(args[index : index + chunk])
                )
                for index in range(0, len(args), chunk)
            ]
        return joiner.join(args)

    def _convert_condition_boolean(
        self,
        cond: ConditionAND | ConditionOR,
        state: ConversionState,
        token: str,
        empty_expression: str | None,
    ) -> str | None:
        """Shared body of convert_condition_and/or, differing from pySigma only in the join.

        The backend emits no deferred expressions, so every operand is a string or None.
        """
        # don't repeat the same thing triple times if separator equals the operator token
        joiner = (
            token
            if self.token_separator == token
            else self.token_separator + token + self.token_separator
        )
        args = [
            converted
            for converted in (
                (
                    self.convert_condition(arg, state)
                    if self.compare_precedence(cond, arg)
                    else self.convert_condition_group(arg, state)
                )
                for arg in cond.args
            )
            if converted is not None
        ]
        if len(args) == 0:
            return empty_expression
        return self._join_operands(args, joiner)

    def convert_condition_or(
        self, cond: ConditionOR, state: ConversionState
    ) -> str | None:
        return self._convert_condition_boolean(
            cond, state, self.or_token, self.empty_or_expression
        )

    def convert_condition_and(
        self, cond: ConditionAND, state: ConversionState
    ) -> str | None:
        return self._convert_condition_boolean(
            cond, state, self.and_token, self.empty_and_expression
        )

    def convert_condition_not(
        self, cond: ConditionNOT, state: ConversionState
    ) -> str | None:
        """Conversion of NOT conditions, folding SQLite's three-valued logic back to Sigma's two.

        Sigma reads a condition on a field the event does not carry as false, so
        "selection and not filter" still matches when the filter names such a field. SQLite
        evaluates that comparison to NULL, NOT NULL is NULL, and the row is dropped without a
        word -- Sysmon network events carry no CommandLine, so every rule filtering on one
        matched nothing at all.

        COALESCE(<expr>, 0) turns that NULL back into the false Sigma means. Wrapping at every
        NOT rather than only the outermost keeps each negated subtree two-valued, which is what
        makes nested negations come out right: in SQL three-valued logic over AND/OR, whenever
        the result is NULL, reading the NULL leaves as false yields false.

        The emitted shape is exactly what Zircolite >= 4.0 rewrites statements into
        (zircolite/sqlscan.py), so its own pass recognises ours, leaves it alone, and its
        literal prefilter still plans it.
        """
        arg = cond.args[0]
        if arg is None:
            return None
        negated_group = arg.__class__ in self.precedence
        expr = (
            self.convert_condition_group(arg, state)
            if negated_group
            else self.convert_condition(arg, state)
        )
        if expr is None:
            return None
        if (
            not negated_group
        ):  # convert_condition_group already parenthesized the operand
            expr = self.group_expression.format(expr=expr)
        return (
            self.not_token
            + self.token_separator
            + self.null_safe_expression.format(expr=expr)
        )

    def convert_condition_field_eq_val_timestamp_part(self, cond, state):
        if cond.value.timestamp_part == TimestampPart.WEEK and self.week_mode == "iso":
            field = self.escape_and_quote_field(cond.field)
            # Thursday belongs to the ISO week-year. Its ordinal identifies the week.
            return (
                f"(1 + (CAST(strftime('%j', {field}, '-3 days', 'weekday 4') "
                f"AS INTEGER) - 1) / 7)={cond.value}"
            )
        return super().convert_condition_field_eq_val_timestamp_part(cond, state)

    def convert_condition(self, cond, state):
        value = getattr(cond, "value", None)
        if isinstance(value, (SigmaString, SigmaRegularExpression)) and "\x00" in str(
            value.regexp if isinstance(value, SigmaRegularExpression) else value
        ):
            raise SigmaFeatureNotSupportedByBackendError(
                "SQLite text query literals cannot contain NUL. Follow a byte encoding "
                "such as wide with base64 or base64offset."
            )
        return super().convert_condition(cond, state)

    def convert_value_str(
        self,
        s: SigmaString,
        state: ConversionState,
        no_quote: bool = False,
        glob_wildcards: bool = False,
    ) -> str:
        """Convert a SigmaString into a plain string which can be used in query."""

        if glob_wildcards:
            # GLOB has no ESCAPE clause, but it does have character classes, and "[*]", "[?]"
            # and "[[]" are how a literal metacharacter is written. Sigma wildcards are emitted
            # as sentinels first so that they survive that escaping pass and only then become
            # the real "*" and "?" -- otherwise a wildcard and an escaped literal would be
            # indistinguishable by the time we look at the string. Backslashes stay literal;
            # escaping them (as LIKE requires) would break matches like Windows paths.
            converted = s.convert(
                escape_char=self.escape_char,
                wildcard_multi=self.glob_wildcard_multi_placeholder,
                wildcard_single=self.glob_wildcard_single_placeholder,
                add_escaped="",
                filter_chars=self.filter_chars,
            )
            for literal, escaped in self.glob_escaped_chars.items():
                converted = converted.replace(literal, escaped)
            converted = converted.replace(
                self.glob_wildcard_multi_placeholder, self.wildcard_glob
            ).replace(self.glob_wildcard_single_placeholder, self.wildcard_glob_single)
        else:
            converted = s.convert(
                escape_char=self.escape_char,
                wildcard_multi=self.wildcard_multi,
                wildcard_single=self.wildcard_single,
                add_escaped=self.add_escaped,
                filter_chars=self.filter_chars,
            )

        converted = converted.replace(
            "'", "''"
        )  # Doubling single quote in SQL is mandatory

        if self.decide_string_quoting(s) and not no_quote:
            return self.quote_string(converted)
        else:
            return converted

    def convert_condition_field_eq_val_bool(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        """Conversion of field = boolean value expressions, matching text and numeric storage."""
        return self.bool_expression.format(
            field=self.escape_and_quote_field(cond.field),
            value=self.bool_values[cond.value.boolean],
            numeric_value=self.bool_numeric_values[cond.value.boolean],
        )

    def _record_regex(self, state):
        state.sqlite_uses_regex = True
        state.sqlite_strict_regex = (
            self.text_mode == "unicode"
            or self.sum_mode == "exact"
            or self.resolve_presence_field(state.processing_state) is not None
        )

    def convert_condition_field_eq_val_re(self, cond, state):
        self._record_regex(state)
        return super().convert_condition_field_eq_val_re(cond, state)

    def convert_value_re(
        self, r: SigmaRegularExpression, state: ConversionState
    ) -> str:
        # Doubling single quotes is mandatory: the regex is embedded in a '...' SQL string literal.
        pattern = super().convert_value_re(r, state)
        if isinstance(r, BoundedRegex):
            pattern = r.bound(pattern)
        return pattern.replace("'", "''")

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        """Conversion of field = string value expressions.

        A wildcard, or a literal backslash that LIKE must escape, makes the value a LIKE
        pattern. Anything else is literal equality, the only form collate_nocase applies to:
        LIKE already ignores case.
        """
        field = self.escape_and_quote_field(cond.field)
        value = cond.value
        if value.contains_special() or any(
            char in value
            for char in (self.wildcard_multi, self.wildcard_single, self.escape_char)
        ):
            expr = self.wildcard_match_expression.format(
                field=field, value=self.convert_value_str(value, state, no_quote=True)
            )
        else:
            expr = self.eq_expression.format(
                field=field, value=self.convert_value_str(value, state), backend=self
            )
            if self.collate_nocase:
                expr = self.collation_expression.format(expr=expr)
        if self.text_mode != "unicode":
            return expr
        pattern = self.convert_value_str(value, state, no_quote=True)
        unicode = self._strict_function(
            state, "sigma_unicode_like", field, f"'{pattern}'"
        )
        return self._unicode_text(f"typeof({field})='text'", unicode, expr)

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        """|cased: GLOB, with the wildcards embedded in the quoted value."""
        return self.case_sensitive_match_expression.format(
            field=self.escape_and_quote_field(cond.field),
            value=self.convert_value_str(cond.value, state, glob_wildcards=True),
        )

    def compare_precedence(self, outer, inner) -> bool:
        # A CIDR expanding to several patterns converts into an OR; group it like pySigma
        # groups a SigmaExpansion, whatever selection or condition shape contains it.
        if (
            self.cidr_mode == "expanded"
            and isinstance(inner, ConditionFieldEqualsValueExpression)
            and isinstance(inner.value, SigmaCIDRExpression)
            and len(inner.value.expand()) > 1
        ):
            return isinstance(outer, ConditionOR)
        return super().compare_precedence(outer, inner)

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        """Conversion of field matches CIDR value expressions."""
        cidr: SigmaCIDRExpression = cond.value
        if self.cidr_mode == "exact":
            field = self.escape_and_quote_field(cond.field)
            network = cidr.network
            if network.version == 4 and network.prefixlen == 32:
                # IPv4 hosts have one valid spelling. The first comparison can
                # use the column's index. BINARY rejects collation equivalents
                # such as trailing spaces under RTRIM. IS returns false for NULL.
                host = literal(str(network.network_address))
                return f"({field} IS {host} AND {field} COLLATE BINARY IS {host})"
            state.sqlite_uses_cidr = True
            exact = f"{CIDR_FUNCTION}({field}, {literal(str(network))})"
            if network.version == 6:
                hextet = network.network_address.packed[:2].hex().lstrip("0")
                if network.prefixlen < 16 or not hextet:
                    # A leading zero hextet can disappear into "::".
                    return f"CASE WHEN instr({field}, ':') THEN {exact} ELSE 0 END"
                prefixes = [hextet.zfill(n) for n in range(len(hextet), 5)]
                if hextet.isdigit():
                    checks = [f"{field} LIKE '{p}:%'" for p in prefixes]
                else:
                    # ':' and ';' are adjacent in NOCASE order. The range covers
                    # every letter case even when LIKE is case-sensitive. The UDF
                    # rejects the inclusive upper endpoint along with malformed IPs.
                    checks = [
                        f"{field} COLLATE NOCASE BETWEEN '{p}:' AND '{p};'"
                        for p in prefixes
                    ]
                guard = "(" + " OR ".join(checks) + ")"
            elif network.prefixlen < 8:
                return exact
            else:
                address = str(network.network_address)
                prefix = ".".join(address.split(".")[: network.prefixlen // 8])
                guard = f"{field} LIKE {literal(prefix + '.%')}"
            # The outer guard is indexable in WHERE. CASE also short-circuits the
            # function when the same predicate is projected as a correlation flag.
            return f"({guard} AND CASE WHEN {guard} THEN {exact} ELSE 0 END)"
        expanded_cond = ConditionOR(
            [
                ConditionFieldEqualsValueExpression(cond.field, SigmaString(network))
                for network in cidr.expand()
            ],
            cond.source,
        )
        return self.convert_condition(expanded_cond, state)

    def finalize_query_default(
        self,
        rule: SigmaRule | SigmaCorrelationRule,
        query: str,
        index: int,
        state: ConversionState,
    ) -> Any:
        if isinstance(rule, SigmaCorrelationRule):
            # The query is complete. The plan is only read by the zircolite format.
            self._correlation_plans.pop(id(rule), None)
            return query

        # Table name can be overridden per-pipeline via a setState transformation
        # setting the "table" state key, else fall back to the backend default.
        table = self.resolve_table(state.processing_state)
        sqlite_query = f"SELECT * FROM {table} WHERE {query}"

        return sqlite_query

    def _field_value_bound(self, cond: Any, field_name_lower: str) -> set | None:
        """The values `field_name_lower` may take for `cond` to match, or None when unbounded.

        Zircolite uses the `channel` and `eventid` keys of a rule as an allow-list to skip
        events before they are even flattened, so a value listed there that the rule does not
        actually require costs detections. Reading them off the detection items would list a
        value the rule *excludes* in a negated `filter:` block, and Zircolite would then admit
        only that value. So the bound is read from the parsed condition instead, and every
        uncertainty returns None: a missing bound only costs a little speed, a wrong one costs
        detections.
        """
        if isinstance(cond, ConditionFieldEqualsValueExpression):
            if cond.field is None or cond.field.lower() != field_name_lower:
                return None
            value = cond.value
            if type(value) is SigmaNumber:
                if field_name_lower == "eventid" and isinstance(value.number, int):
                    # Larger integers may compare equal after REAL affinity rounds them.
                    if abs(value.number) < 2**53:
                        return {value.number}
                return None
            if isinstance(value, SigmaString) and not value.contains_special():
                # to_plain() restores Sigma wildcard escapes. SQL compares their
                # decoded characters, which are already present in the string segments.
                text = value.convert(escape_char=None)
                if field_name_lower == "eventid":
                    # Decimal/exponent spellings depend on both column affinity
                    # and consumer coercion. Another AND operand may still bound them.
                    digits = text.lstrip("+-")
                    if len(digits) <= 16 and re.fullmatch(r"[+-]?[0-9]+", text):
                        number = int(text)
                        if abs(number) < 2**53:
                            return {number}
                    return None
                if re.fullmatch(
                    r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?",
                    text.strip(),
                ):
                    # NUMERIC affinity can match another spelling of this channel.
                    return None
                if self.text_mode != "unicode" or isinstance(value, SigmaCasedString):
                    return {text}
            return None

        if isinstance(cond, ConditionAND):
            # Every argument must hold, so any one of them may narrow the set.
            bounds = [
                bound
                for bound in (
                    self._field_value_bound(arg, field_name_lower) for arg in cond.args
                )
                if bound is not None
            ]
            # A Python intersection can discard values equivalent under SQLite
            # affinity or collation. Every AND operand independently bounds the result.
            return min(bounds, key=len, default=None)

        if isinstance(cond, ConditionOR):
            # One unbounded branch leaves the whole disjunction unbounded.
            bounds = [
                self._field_value_bound(arg, field_name_lower) for arg in cond.args
            ]
            if any(bound is None for bound in bounds):
                return None
            return set().union(*bounds)

        # ConditionNOT tells us which values the rule refuses, not which it wants, and a
        # value-only expression is not bound to a field at all.
        return None

    def _extract_field_values_from_rule(
        self, rule: SigmaRule, field_name: str, index: int = 0
    ) -> list[Any]:
        """Values of `field_name` that the rule's condition provably requires, sorted.

        An empty list means "no provable bound" and leaves the field unfiltered downstream.
        """
        if not self.prefilter_bounds:
            return []
        condition = rule.detection.parsed_condition[index].parsed
        bound = self._field_value_bound(condition, field_name.lower())
        return sorted(bound, key=str) if bound else []

    def finalize_query_zircolite(
        self,
        rule: SigmaRule | SigmaCorrelationRule,
        query: str,
        index: int,
        state: ConversionState,
    ) -> Any:
        if isinstance(rule, SigmaCorrelationRule):
            plan = self._correlation_plans.pop(id(rule))
            fulltext = plan.get("fulltext", [])
            contract = {
                key: plan[key]
                for key in ("version", "required_sql_functions", "presence")
                if key in plan
            }
            channels, event_ids = [], []
            kind = {
                # Zircolite's own converter sets this; it is what keeps a correlation rule out
                # of the Channel/EventID pre-filter, whose subquery shape it does not read.
                "correlation": True,
                "correlation_plan": plan,
                "required_fields": sorted(
                    set().union(*map(set, plan["required_fields"].values()))
                ),
                "result_type": "correlation",
            }
        else:
            predicate = state.sqlite_predicate
            fulltext = predicate.fulltext
            contract = self.execution_contract([state], fulltext=bool(fulltext))
            # Channels and event IDs the rule's condition provably requires
            channels = self._extract_field_values_from_rule(rule, "Channel", index)
            event_ids = self._extract_field_values_from_rule(rule, "EventID", index)
            kind = {
                "required_fields": predicate.fields,
                "result_type": "event",
                "source_table": predicate.table,
                "logsource": {
                    key: getattr(rule.logsource, key)
                    for key in ("product", "category", "service")
                    if getattr(rule.logsource, key, None) is not None
                },
            }
        # Read rule properties directly: to_dict() raises SigmaValueError once pipeline
        # transformations leave detection items that do not serialize back to plain data.
        zircolite_rule = {
            "title": rule.title,
            "id": str(rule.id) if rule.id else "",
            "status": rule.status.name.lower() if rule.status else "",
            "description": rule.description if rule.description else "",
            "author": rule.author if rule.author else "",
            "tags": [str(tag) for tag in rule.tags] if rule.tags else [],
            "falsepositives": list(rule.falsepositives) if rule.falsepositives else [],
            "level": rule.level.name.lower() if rule.level else "",
            "rule": [self.finalize_query_default(rule, query, index, state)],
            "filename": "",
            "channel": channels,
            "eventid": event_ids,
            **kind,
        }
        if fulltext:
            zircolite_rule["fulltext"] = fulltext
        zircolite_rule["schema_version"] = contract.pop("version")
        zircolite_rule.update(contract)
        return zircolite_rule

    def finalize_output_zircolite(self, queries: list[dict]) -> str:
        return json.dumps(list(queries))

    def _fulltext_column(self):
        if self.fulltext_field is None:
            # A SigmaError, so collect_errors (sigma-cli --skip-unsupported) skips only this rule.
            raise SigmaFeatureNotSupportedByBackendError(
                "Keyword search requires fulltext_field and a populated TEXT column; "
                "configure fulltext_field and re-ingest old events."
            )
        return self.escape_and_quote_field(self.fulltext_field)

    def convert_condition_val(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> str | None:
        """Also OR the values of keyword expansions (|windash, |base64offset)."""
        if isinstance(cond.value, SigmaExpansion):
            return self.convert_condition_or(
                ConditionOR(
                    [ConditionValueExpression(value) for value in cond.value.values],
                    cond.source,
                ),
                state,
            )
        return super().convert_condition_val(cond, state)

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> str:
        """Match a Sigma string anywhere in the captured source values."""
        field = self._fulltext_column()
        cased = isinstance(cond.value, SigmaCasedString)
        value = self.convert_value_str(
            cond.value, state, no_quote=True, glob_wildcards=cased
        )
        if cased:
            return f"{field} GLOB '*{value}*'"
        if self.text_mode == "unicode":
            return self._strict_function(
                state, "sigma_unicode_like", field, f"'%{value}%'"
            )
        return self.contains_expression.format(field=field, value=value)

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> str:
        """Match a number's source spelling as text (digits, sign, point: no escaping)."""
        return self.contains_expression.format(
            field=self._fulltext_column(), value=str(cond.value)
        )

    def convert_condition_val_re(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> str:
        field = self._fulltext_column()
        self._record_regex(state)
        regex = self.convert_value_re(cond.value, state)
        flags = self.get_flag_template(cond.value)
        return self.re_expression.format(field=field, regex=regex, **flags)
