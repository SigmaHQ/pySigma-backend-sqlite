from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import (
    ConditionItem,
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionValueExpression,
    ConditionFieldEqualsValueExpression,
)
from sigma.types import (
    SigmaBool,
    SigmaCompareExpression,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
    SigmaCIDRExpression,
    SigmaFieldReference,
    TimestampPart,
)
from sigma.correlations import (
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
)

from .correlation import CorrelationCompiler, numeric, quote

import re
import json
from typing import ClassVar, Dict, List, Optional, Pattern, Tuple, Union, Any


_SQLITE_KEYWORDS = set(
    "ABORT ACTION ADD AFTER ALL ALTER ALWAYS ANALYZE AND AS ASC ATTACH AUTOINCREMENT BEFORE BEGIN BETWEEN BY CASCADE CASE CAST CHECK COLLATE COLUMN COMMIT CONFLICT CONSTRAINT CREATE CROSS CURRENT CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP DATABASE DEFAULT DEFERRABLE DEFERRED DELETE DESC DETACH DISTINCT DO DROP EACH ELSE END ESCAPE EXCEPT EXCLUDE EXCLUSIVE EXISTS EXPLAIN FAIL FILTER FIRST FOLLOWING FOR FOREIGN FROM FULL GENERATED GLOB GROUP GROUPS HAVING IF IGNORE IMMEDIATE IN INDEX INDEXED INITIALLY INNER INSERT INSTEAD INTERSECT INTO IS ISNULL JOIN KEY LAST LEFT LIKE LIMIT MATCH MATERIALIZED NATURAL NO NOT NOTHING NOTNULL NULL NULLS OF OFFSET ON OR ORDER OTHERS OUTER OVER PARTITION PLAN PRAGMA PRECEDING PRIMARY QUERY RAISE RANGE RECURSIVE REFERENCES REGEXP REINDEX RELEASE RENAME REPLACE RESTRICT RETURNING RIGHT ROLLBACK ROW ROWS SAVEPOINT SELECT SET TABLE TEMP TEMPORARY THEN TIES TO TRANSACTION TRIGGER UNBOUNDED UNION UNIQUE UPDATE USING VACUUM VALUES VIEW VIRTUAL WHEN WHERE WINDOW WITH WITHOUT".split()
)


class sqliteBackend(TextQueryBackend):
    """SQLite backend."""

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name: ClassVar[str] = "SQLite backend"
    formats: Dict[str, str] = {
        "default": "Plain SQLite queries",
        "zircolite": "Zircolite JSON format",
    }
    requires_pipeline: bool = (
        False  # TODO: does the backend requires that a processing pipeline is provided? This information can be used by user interface programs like Sigma CLI to warn users about inappropriate usage of the backend.
    )

    # Correlation support
    correlation_methods: ClassVar[Dict[str, str]] = {
        "default": "Default SQLite correlation using subqueries and window functions",
    }

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    parenthesize: bool = True
    group_expression: ClassVar[str] = (
        "({expr})"  # Expression for precedence override grouping as format string with {expr} placeholder
    )

    # SQLite parses "a OR b OR c" into a left-deep tree whose height is the operand count and
    # refuses anything over SQLITE_MAX_EXPR_DEPTH (1000 by default) with "Expression tree is too
    # large". Rules with thousands of alternatives -- SigmaHQ ships several -- were rejected at
    # prepare time and had therefore never matched anything. Chains longer than this are
    # re-associated into nested groups, which is the same boolean value at a bounded height.
    max_flat_operands: ClassVar[int] = 100

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = (
        "="  # Token inserted between field and value (without separator)
    )

    # String output
    ## Fields
    ### Quoting

    # SQLite correct way to handle field name is detailed here : https://sqlite.org/lang_keywords.html.
    # Double-quoting should be the way to go. But since in some case quotes are interpreted as literals we need to find an alternative.
    # Obviously, we cannot use "[" and "]", because it is 2 different characters, so we are left with "`" (MySQL).
    field_quote: ClassVar[str] = (
        "`"  # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    )
    field_quote_pattern: ClassVar[Pattern] = re.compile(
        "^[a-zA-Z0-9_]*$"
    )  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation: ClassVar[bool] = (
        True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    )

    ## Values
    str_quote: ClassVar[str] = (
        "'"  # string quoting character (added as escaping character)
    )

    escape_char: ClassVar[str] = (
        "\\"  # Escaping character for special characters inside string
    )
    wildcard_multi: ClassVar[str] = "%"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "_"  # Character used as single-character wildcard

    # Special case for case sensitive string matching
    wildcard_glob: ClassVar[str] = "*"  # Character used as glob wildcard
    wildcard_glob_single: ClassVar[str] = "?"  # Character used as glob wildcard
    # Literal GLOB metacharacters, written as single-member character classes. Order matters:
    # "[" is escaped first so the brackets introduced by the other two are not escaped again.
    glob_escaped_chars: ClassVar[Dict[str, str]] = {"[": "[[]", "*": "[*]", "?": "[?]"}
    # Sentinels standing in for Sigma wildcards while literals are escaped. NUL cannot occur in
    # a SQLite string literal, so these cannot collide with rule content.
    glob_wildcard_multi_placeholder: ClassVar[str] = "\x00\x01"
    glob_wildcard_single_placeholder: ClassVar[str] = "\x00\x02"

    add_escaped: ClassVar[str] = (
        "\\"  # Characters quoted in addition to wildcards and string quote
    )
    # filter_chars    : ClassVar[str] = ""      # Characters filtered
    # A flattener has to decide how to store a JSON boolean. Zircolite stores the strings
    # 'true'/'false' because that is what Sigma rules compare against, while a hand-built table
    # is as likely to hold 1/0 -- and SQLite reads the bare keyword `true` as the integer 1,
    # which never equals the text 'true'. Accepting both is the only form that is right against
    # either table; see convert_condition_field_eq_val_bool.
    bool_values: ClassVar[Dict[bool, str]] = (
        {  # Values to which boolean values are mapped.
            True: "'true'",
            False: "'false'",
        }
    )
    bool_numeric_values: ClassVar[Dict[bool, str]] = {True: "1", False: "0"}
    bool_expression: ClassVar[str] = "({field}={value} OR {field}={numeric_value})"

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "{field} LIKE '{value}%' ESCAPE '\\'"
    endswith_expression: ClassVar[str] = "{field} LIKE '%{value}' ESCAPE '\\'"
    contains_expression: ClassVar[str] = "{field} LIKE '%{value}%' ESCAPE '\\'"
    wildcard_match_expression: ClassVar[str] = (
        "{field} LIKE '{value}' ESCAPE '\\'"  # Special expression if wildcards can't be matched with the eq_token operator
    )

    # Special expression if wildcards can't be matched with the eq_token operator
    wildcard_match_str_expression: ClassVar[str] = "{field} LIKE '{value}' ESCAPE '\\'"
    # wildcard_match_num_expression: ClassVar[str] = "{field} LIKE '%{value}%'"

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression: ClassVar[str] = "{field} REGEXP '{regex}'"
    re_escape_char: ClassVar[str] = (
        ""  # Character used for escaping in regular expressions
    )
    re_escape: ClassVar[Tuple[str]] = ()  # List of strings that are escaped
    re_escape_escape_char: bool = True  # If True, the escape character is also escaped
    re_flag_prefix: bool = (
        True  # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    )

    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    # re_flags : Dict[SigmaRegularExpressionFlag, str] = {}

    # SQLite's GLOB is a 2-argument operator with no ESCAPE clause (unlike LIKE);
    # emitting "ESCAPE '\'" triggers "wrong number of arguments to function GLOB()" at runtime.
    # Wildcards for |startswith/|endswith/|contains|cased are embedded in the value via
    # case_sensitive_match_expression; dedicated startswith/endswith/contains templates
    # would place GLOB metacharacters outside the quoted literal and produce invalid SQL.
    case_sensitive_match_expression: ClassVar[str] = "{field} GLOB {value}"

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = (
        "{field} {operator} {value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    )
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Expression for comparing two event fields (fieldref modifier)
    field_equals_field_expression: ClassVar[Optional[str]] = "{field1}={field2}"
    # |fieldref compares two fields, so the pattern side is event data rather than rule text:
    # a "%" or "_" that happens to occur in it would otherwise act as a LIKE wildcard and match
    # far more than the rule asks for. The backslash is escaped first so the two escapes the
    # other REPLACEs introduce are not escaped again.
    field_ref_like_escape: ClassVar[str] = (
        "REPLACE(REPLACE(REPLACE({field2}, '\\', '\\\\'), '%', '\\%'), '_', '\\_')"
    )
    field_equals_field_startswith_expression: ClassVar[Optional[str]] = (
        "{field1} LIKE " + field_ref_like_escape + " || '%' ESCAPE '\\'"
    )
    field_equals_field_endswith_expression: ClassVar[Optional[str]] = (
        "{field1} LIKE '%' || " + field_ref_like_escape + " ESCAPE '\\'"
    )
    field_equals_field_contains_expression: ClassVar[Optional[str]] = (
        "{field1} LIKE '%' || " + field_ref_like_escape + " || '%' ESCAPE '\\'"
    )
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (
        True,
        True,
    )  # If regular field-escaping/quoting is applied to field1 and field2.

    # Timestamp part expressions for time modifiers (|minute, |hour, |day, etc.)
    field_timestamp_part_expression: ClassVar[Optional[str]] = (
        "CAST(strftime('{timestamp_part}', {field}) AS INTEGER)"
    )
    timestamp_part_mapping: ClassVar[Optional[Dict[TimestampPart, str]]] = {
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
    collate_nocase: bool = False
    collation_expression: ClassVar[str] = "{expr} COLLATE NOCASE"

    # Wrapper applied to the operand of every generated NOT so that a comparison against an
    # absent field reads as false rather than NULL. See convert_condition_not.
    null_safe_expression: ClassVar[str] = "COALESCE({expr}, 0)"

    # Null/None expressions
    field_null_expression: ClassVar[str] = (
        "{field} IS NULL"  # Expression for field has null value as format string with {field} placeholder for field name
    )

    # Field existence condition expressions.
    # A flattened event that lacks a field carries NULL in its column, so existence is a NULL
    # test. Expressing it as "{field} = {field}" instead would be NULL for an absent field, and
    # since pySigma negates field_exists_expression when field_not_exists_expression is unset,
    # "|exists: false" became "NOT field = field" -- NULL again, and never a match. Defining both
    # also lets SQLite use an index on the column.
    field_exists_expression: ClassVar[str] = "{field} IS NOT NULL"
    field_not_exists_expression: ClassVar[str] = "{field} IS NULL"

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = False  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = (
        False  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    )
    field_in_list_expression: ClassVar[str] = (
        "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    )
    or_in_operator: ClassVar[str] = (
        "IN"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    )
    # and_in_operator : ClassVar[str] = "contains-all"   # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator: ClassVar[str] = ", "  # List element separator

    # Value not bound to a field

    # TODO : SQlite only handles FTS ("MATCH") with virtual tables. Not Handled for now.
    # unbound_value_str_expression : ClassVar[str] = "MATCH {value}"   # Expression for string value not bound to a field as format string with placeholder {value}
    # unbound_value_num_expression : ClassVar[str] = 'MATCH {value}'     # Expression for number value not bound to a field as format string with placeholder {value}

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str] = (
        ""  # String used as separator between main query and deferred parts
    )
    deferred_separator: ClassVar[str] = (
        ""  # String used to join multiple deferred query parts
    )
    deferred_only_query: ClassVar[str] = (
        ""  # String used as query if final query only contains deferred expression
    )

    # Correlations are compiled as relations, never nested finalized SQL strings.
    table = "logs"
    timestamp_field = "timestamp"
    event_id_field = "rowid"
    timestamp_format = "iso"
    observation_end = None
    timestamp_seconds_expression = (
        "ROUND((julianday({field}) - 2440587.5) * 86400000) / 1000.0"
    )
    correlation_condition_mapping = {
        SigmaCorrelationConditionOperator.LT: "<",
        SigmaCorrelationConditionOperator.LTE: "<=",
        SigmaCorrelationConditionOperator.GT: ">",
        SigmaCorrelationConditionOperator.GTE: ">=",
        SigmaCorrelationConditionOperator.EQ: "=",
        SigmaCorrelationConditionOperator.NEQ: "!=",
    }

    def __init__(self, processing_pipeline=None, collect_errors=False, **options):
        configurable = {
            "table",
            "timestamp_field",
            "event_id_field",
            "observation_end",
            "timestamp_seconds_expression",
            "timestamp_format",
            "collate_nocase",
            "max_flat_operands",
        }
        for key in configurable & options.keys():
            value = options[key]
            if key == "collate_nocase" and isinstance(value, str):
                if value.lower() not in ("true", "false"):
                    raise ValueError("collate_nocase must be true or false")
                value = value.lower() == "true"
            if key == "max_flat_operands":
                value = int(value)
                if value < 2:
                    raise ValueError("max_flat_operands must be at least 2")
            setattr(self, key, value)
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
        self._correlation_plans = {}
        super().__init__(processing_pipeline, collect_errors, **options)

    def convert_condition_field_eq_field(self, cond, state):
        expression = super().convert_condition_field_eq_field(cond, state)
        if (
            self.collate_nocase
            and isinstance(expression, str)
            and " LIKE " not in expression
        ):
            return self.collation_expression.format(expr=expression)
        return expression

    def init_processing_pipeline(self, output_format=None):
        self._output_format = output_format or self.default_format
        super().init_processing_pipeline(output_format)

    def resolve_table(self, state=None):
        table = (state or {}).get("table") or self.table
        # Keep simple names readable, quote every component of a qualified name.
        return ".".join(self.escape_and_quote_field(part) for part in table.split("."))

    def escape_and_quote_field(self, field):
        # SQLite keywords are identifiers only when quoted. This set includes
        # all keywords in SQLite 3.38+, including window-function vocabulary.
        if (
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field)
            and field.upper() not in _SQLITE_KEYWORDS
        ):
            return field
        return quote(field)

    def _correlation_timestamp(self, alias=None):
        field = self.escape_and_quote_field(self.timestamp_field)
        if alias:
            field = f"{alias}.{field}"
        return self.timestamp_seconds_expression.format(field=field)

    def required_fields(self, rule):
        fields = set()

        def walk(cond):
            if isinstance(cond, ConditionFieldEqualsValueExpression):
                if cond.field:
                    fields.add(cond.field)
                if isinstance(cond.value, SigmaFieldReference):
                    fields.add(cond.value.field)
            for arg in getattr(cond, "args", []):
                walk(arg)

        for condition in rule.detection.parsed_condition:
            walk(condition.parsed)
        return sorted(fields)

    def convert_correlation_rule(
        self, rule, output_format=None, method=None, callback=None
    ):
        if not hasattr(self, "last_processing_pipeline"):
            self.init_processing_pipeline(output_format)
        queries = super().convert_correlation_rule(
            rule, output_format, method, callback
        )
        return queries if rule._output else []

    def convert_rule(self, rule, output_format=None, callback=None):
        queries = super().convert_rule(rule, output_format, callback)
        # pySigma stores predicates for referenced rules. generate:true must
        # still emit finalized standalone queries without overwriting them.
        if (
            rule._backreferences
            and rule._output
            and not self.finalize_correlation_subqueries
        ):
            return [
                self.finalize_query(
                    rule,
                    query,
                    i,
                    rule.get_conversion_states()[i],
                    output_format or self.default_format,
                )
                for i, query in enumerate(queries)
            ]
        return queries

    def convert_correlation_rule_from_template(self, rule, correlation_type, method):
        if method != "default":
            raise ValueError(f"Unknown correlation method: {method}")
        query, plan = CorrelationCompiler(self, rule).compile()
        self._correlation_plans[id(rule)] = plan
        return [query]

    def _join_operands(self, args: List[str], joiner: str) -> str:
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
        cond: Union[ConditionAND, ConditionOR],
        state: ConversionState,
        token: str,
        empty_expression: Optional[str],
    ) -> Union[str, DeferredQueryExpression, None]:
        """Shared body of convert_condition_and/or, differing from pySigma only in the join."""
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
            and not isinstance(converted, DeferredQueryExpression)
        ]
        if len(args) == 0:
            return empty_expression
        return self._join_operands(args, joiner)

    def convert_condition_or(
        self, cond: ConditionOR, state: ConversionState
    ) -> Union[str, DeferredQueryExpression, None]:
        """Conversion of OR conditions."""
        try:
            return self._convert_condition_boolean(
                cond, state, self.or_token, self.empty_or_expression
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'or' not supported by the backend")

    def convert_condition_and(
        self, cond: ConditionAND, state: ConversionState
    ) -> Union[str, DeferredQueryExpression, None]:
        """Conversion of AND conditions."""
        try:
            return self._convert_condition_boolean(
                cond, state, self.and_token, self.empty_and_expression
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'and' not supported by the backend")

    def convert_condition_not(
        self, cond: ConditionNOT, state: ConversionState
    ) -> Union[str, DeferredQueryExpression, None]:
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
        try:
            negated_group = arg.__class__ in self.precedence
            expr = (
                self.convert_condition_group(arg, state)
                if negated_group
                else self.convert_condition(arg, state)
            )
            if isinstance(expr, DeferredQueryExpression):
                # negate deferred expression and pass it to parent
                return expr.negate()
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
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")

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
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = boolean value expressions, matching text and numeric storage."""
        if not isinstance(cond.value, SigmaBool):  # pragma: no cover - defensive
            raise TypeError(
                f"Expected SigmaBool for cond.value, got {type(cond.value)}"
            )
        return self.bool_expression.format(
            field=self.escape_and_quote_field(cond.field),
            value=self.bool_values[cond.value.boolean],
            numeric_value=self.bool_numeric_values[cond.value.boolean],
        )

    def convert_value_re(
        self, r: SigmaRegularExpression, state: ConversionState
    ) -> str:
        # Doubling single quotes is mandatory: the regex is embedded in a '...' SQL string literal.
        return super().convert_value_re(r, state).replace("'", "''")

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions.

        Follows pySigma's own cascade; the backend reimplements it because its LIKE templates
        carry their own quotes and so need the value converted unquoted.
        """
        try:
            # Expressions that use "LIKE" (startswith, endswith, ...) quote the value themselves
            remove_quote = True
            # Only literal equality is collatable: LIKE already ignores case, GLOB must not.
            collatable = False

            if (  # Check conditions for usage of 'startswith' operator
                self.startswith_expression
                is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(
                    SpecialChars.WILDCARD_MULTI
                )  # String ends with wildcard
                and (
                    self.startswith_expression_allow_special
                    or not cond.value[:-1].contains_special()
                )  # Remainder of string doesn't contains special characters or it's allowed
            ):
                expr = (
                    self.startswith_expression
                )  # If all conditions are fulfilled, use 'startswith' operartor instead of equal token
                value = cond.value[:-1]
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and (
                    self.endswith_expression_allow_special
                    or not cond.value[1:].contains_special()
                )
            ):
                expr = self.endswith_expression
                value = cond.value[1:]
            elif (  # contains: string starts and ends with wildcard
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and (
                    self.contains_expression_allow_special
                    or not cond.value[1:-1].contains_special()
                )
            ):
                expr = self.contains_expression
                value = cond.value[1:-1]
            elif (
                self.wildcard_match_expression is not None
                and (  # wildcard match expression: string contains wildcard
                    cond.value.contains_special()
                    or self.wildcard_multi in cond.value
                    or self.wildcard_single in cond.value
                    # A literal backslash has to be escaped for LIKE, which "=" would then
                    # compare literally, so such values go through the pattern form too.
                    or self.escape_char in cond.value
                )
            ):
                expr = self.wildcard_match_expression
                value = cond.value
            else:
                expr = self.eq_expression
                value = cond.value
                remove_quote = False
                collatable = True

            converted = expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(value, state, remove_quote),
                regex=self.convert_value_re(value.to_regex(self.add_escaped_re), state),
                backend=self,
            )
            if collatable and self.collate_nocase:
                converted = self.collation_expression.format(expr=converted)
            return converted
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals string value expressions with strings are not supported by the backend."
            )

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Case-sensitive matching via GLOB with literal backslashes (no ESCAPE clause)."""
        try:
            if (  # Check conditions for usage of 'startswith' operator
                self.case_sensitive_startswith_expression
                is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(
                    SpecialChars.WILDCARD_MULTI
                )  # String ends with wildcard
                and (
                    self.case_sensitive_startswith_expression_allow_special
                    or not cond.value[:-1].contains_special()
                )  # Remainder of string doesn't contains special characters or it's allowed
            ):
                expr = (
                    self.case_sensitive_startswith_expression
                )  # If all conditions are fulfilled, use 'startswith' operator instead of equal token
                value = cond.value[:-1]
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                self.case_sensitive_endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and (
                    self.case_sensitive_endswith_expression_allow_special
                    or not cond.value[1:].contains_special()
                )
            ):
                expr = self.case_sensitive_endswith_expression
                value = cond.value[1:]
            elif (  # contains: string starts and ends with wildcard
                self.case_sensitive_contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and (
                    self.case_sensitive_contains_expression_allow_special
                    or not cond.value[1:-1].contains_special()
                )
            ):
                expr = self.case_sensitive_contains_expression
                value = cond.value[1:-1]
            elif self.case_sensitive_match_expression is not None:
                expr = self.case_sensitive_match_expression
                value = cond.value
            else:
                raise NotImplementedError(
                    "Case-sensitive string matching is not supported by backend."
                )

            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(
                    value, state, no_quote=False, glob_wildcards=True
                ),
                regex=self.convert_value_re(value.to_regex(self.add_escaped_re), state),
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Case-sensitive field equals string value expressions with strings are not supported by the backend."
            )

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches CIDR value expressions."""
        cidr: SigmaCIDRExpression = cond.value
        expanded = cidr.expand()
        expanded_cond = ConditionOR(
            [
                ConditionFieldEqualsValueExpression(cond.field, SigmaString(network))
                for network in expanded
            ],
            cond.source,
        )
        return self.convert_condition(expanded_cond, state)

    def finalize_query_default(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
        query: str,
        index: int,
        state: ConversionState,
    ) -> Any:
        # For correlation rules, the query is already complete
        if isinstance(rule, SigmaCorrelationRule):
            return query

        # TODO : fields support will be handled with a backend option (all fields by default)
        # fields = "*" if len(rule.fields) == 0 else f"*, {', '.join(rule.fields)}"

        # Table name can be overridden per-pipeline via a setState transformation
        # setting the "table" state key, else fall back to the backend default.
        table = self.resolve_table(state.processing_state)
        sqlite_query = f"SELECT * FROM {table} WHERE {query}"

        return sqlite_query

    def _field_value_bound(self, cond: Any, field_name_lower: str) -> Optional[set]:
        """The values `field_name_lower` may take for `cond` to match, or None when unbounded.

        Zircolite uses the `channel` and `eventid` keys of a rule as an allow-list to skip
        events before they are even flattened, so a value listed there that the rule does not
        actually require costs detections. Reading them off the detection items -- which is what
        this backend used to do -- puts a value the rule *excludes* in a negated `filter:` block
        into the list, and Zircolite then admits only that value and discards everything the
        rule is looking for. So the bound is read from the parsed condition instead, and every
        uncertainty returns None: a missing bound only costs a little speed, a wrong one costs
        detections.
        """
        if isinstance(cond, ConditionFieldEqualsValueExpression):
            if cond.field is None or cond.field.lower() != field_name_lower:
                return None
            value = cond.value
            if isinstance(value, SigmaNumber):
                return {value.number}
            # A wildcard, regex, CIDR, comparison, field reference or existence test names no
            # single value the rule requires.
            if isinstance(value, SigmaString) and not value.contains_special():
                return {str(value)}
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
            if not bounds:
                return None
            return set.intersection(*bounds)

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
    ) -> List[Any]:
        """Values of `field_name` that the rule's condition provably requires, sorted.

        An empty list means "no provable bound" and leaves the field unfiltered downstream.
        """
        try:
            condition = rule.detection.parsed_condition[index].parsed
        except (AttributeError, IndexError):  # pragma: no cover - defensive
            return []
        bound = self._field_value_bound(condition, field_name.lower())
        if not bound:
            return []
        return sorted(bound, key=lambda value: str(value))

    def finalize_query_zircolite(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
        query: str,
        index: int,
        state: ConversionState,
    ) -> Any:
        # For correlation rules, use the query as-is (already formatted)
        if isinstance(rule, SigmaCorrelationRule):
            sqlite_query = query
            # Correlation rules don't have detection items in the same way
            channels = []
            event_ids = []
        else:
            # Zircolite's table is always named "logs"; a setState transformation may still
            # override it, exactly as finalize_query_default allows.
            table = self.resolve_table(state.processing_state)
            sqlite_query = f"SELECT * FROM {table} WHERE {query}"
            # Channels and event IDs the rule's condition provably requires
            channels = self._extract_field_values_from_rule(rule, "Channel", index)
            event_ids = self._extract_field_values_from_rule(rule, "EventID", index)

        # Access rule properties directly instead of using to_dict() to avoid
        # SigmaValueError when pipeline transformations have modified detection items
        # in ways that make them non-serializable back to plain data types.
        zircolite_rule = {
            "title": rule.title,
            "id": str(rule.id) if rule.id else "",
            "status": rule.status.name.lower() if rule.status else "",
            "description": rule.description if rule.description else "",
            "author": rule.author if rule.author else "",
            "tags": [str(tag) for tag in rule.tags] if rule.tags else [],
            "falsepositives": list(rule.falsepositives) if rule.falsepositives else [],
            "level": rule.level.name.lower() if rule.level else "",
            "rule": [sqlite_query],
            "filename": "",
            "channel": channels,
            "eventid": event_ids,
        }
        if isinstance(rule, SigmaCorrelationRule):
            # Zircolite's own converter sets this; it is what keeps a correlation rule out of
            # the Channel/EventID pre-filter, whose subquery shape it deliberately does not read.
            zircolite_rule["correlation"] = True
            plan = self._correlation_plans[id(rule)]
            zircolite_rule["correlation_plan"] = plan
            zircolite_rule["required_fields"] = sorted(
                set().union(*map(set, plan["required_fields"].values()))
            )
            zircolite_rule["result_type"] = "correlation"
        else:
            zircolite_rule["required_fields"] = self.required_fields(rule)
            zircolite_rule["result_type"] = "event"
            zircolite_rule["source_table"] = self.resolve_table(state.processing_state)
            zircolite_rule["logsource"] = {
                key: getattr(rule.logsource, key)
                for key in ("product", "category", "service")
                if getattr(rule.logsource, key, None) is not None
            }
        zircolite_rule["schema_version"] = 2
        return zircolite_rule

    def finalize_output_zircolite(self, queries: List[Dict]) -> str:
        return json.dumps(list(queries))

    # TODO : SQlite only handles FTS ("MATCH") with virtual tables. Not Handled for now.
    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only strings."""
        raise SigmaFeatureNotSupportedByBackendError(
            "Value-only string expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
        )

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only numbers."""
        raise SigmaFeatureNotSupportedByBackendError(
            "Value-only number expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
        )
