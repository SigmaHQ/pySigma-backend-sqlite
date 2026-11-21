"""Connection-local helpers for opt-in Unicode and exact sum semantics."""

import math
import re
from decimal import Decimal
from fractions import Fraction
from functools import lru_cache
from itertools import accumulate

from .cidr import register_cidr

PRESENCE_REPRESENTATION = "field-names-v1"


def _like_tokens(pattern):
    """Literal runs and unescaped SQLite LIKE wildcards, as distinct tokens."""
    tokens = []
    chars = []
    escaped = False
    for char in pattern:
        if escaped:
            chars.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char in "%_":
            if chars:
                tokens.append(("literal", "".join(chars).casefold()))
                chars.clear()
            tokens.append((char, None))
        else:
            chars.append(char)
    if escaped:
        return None
    if chars:
        tokens.append(("literal", "".join(chars).casefold()))
    return tokens


def _unicode_like(value, pattern, compile_pattern):
    if value is None or pattern is None:
        return None
    if isinstance(value, bytes) or not isinstance(pattern, str):
        return 0
    tokens = compile_pattern(pattern)
    if tokens is None:
        return 0
    source = str(value)
    folded = source.casefold()
    if len(tokens) == 1 and tokens[0][0] == "literal":
        return folded == tokens[0][1]
    # A literal may match a different number of source code points ("ss" = "ß").
    # Only complete code points can border a wildcard, and _ consumes one of them.
    offsets = range(len(source) + 1)
    boundaries = None
    if len(folded) != len(source):
        offsets = list(accumulate((len(c.casefold()) for c in source), initial=0))
        boundaries = {offset: pos for pos, offset in enumerate(offsets)}
    token = pos = 0
    star = None
    consumed = 0
    while True:
        if token == len(tokens):
            if pos == len(source):
                return 1
        else:
            kind, literal = tokens[token]
            if kind == "%":
                if token + 1 == len(tokens):
                    return 1
                star, consumed = token, pos
                token += 1
                continue
            if kind == "_" and pos < len(source):
                pos += 1
                token += 1
                continue
            if kind == "literal" and folded.startswith(literal, offsets[pos]):
                end = offsets[pos] + len(literal)
                if boundaries is not None:
                    end = boundaries.get(end)
                if end is not None:
                    pos = end
                    token += 1
                    continue
        if star is None or consumed == len(source):
            return 0
        consumed += 1
        pos, token = consumed, star + 1


_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_JSON_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")


def _number(value):
    if isinstance(value, str):
        value = value.strip(" \t\r\n")
        if _INTEGER.fullmatch(value):
            try:
                return int(value)
            except ValueError:
                # Python caps direct decimal string/int conversions. Decimal's
                # exact conversion can still represent these valid JSON integers.
                return int(Decimal(value))
        if not _JSON_NUMBER.fullmatch(value):
            return None
        value = float(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value


class _ExactSum:
    """Python integers for integral windows, reversible binary sums for mixed windows."""

    def __init__(self):
        self.total = 0
        self.count = 0
        self.reals = 0

    def _add(self, raw, sign):
        value = _number(raw)
        if value is None:
            return
        self.count += sign
        if isinstance(value, float):
            self.reals += sign
            value = Fraction.from_float(value)
        self.total += sign * value

    def step(self, raw):
        self._add(raw, 1)

    def inverse(self, raw):
        self._add(raw, -1)

    def value(self):
        if not self.count:
            return None
        if self.reals:
            try:
                return float(self.total)
            except OverflowError:
                return math.inf if self.total > 0 else -math.inf
        total = int(self.total)
        if -(2**63) <= total < 2**63:
            return total
        try:
            return str(total)
        except ValueError:
            return format(Decimal(total), "f")

    finalize = value


def _numeric_cmp(left, right):
    # A mixed REAL aggregate can itself overflow to infinity.
    left = left if isinstance(left, float) else _number(left)
    right = right if isinstance(right, float) else _number(right)
    if left is None or right is None:
        return None
    return (left > right) - (left < right)


def register_sqlite_functions(connection):
    """Install version-5 functions (including CIDR and REGEXP) on one SQLite connection."""
    register_cidr(connection)
    cached_pattern = lru_cache(maxsize=256)(_like_tokens)

    def unicode_like(value, pattern):
        # Dynamic field references can carry arbitrarily long patterns.
        compile_pattern = (
            cached_pattern
            if isinstance(pattern, str) and len(pattern) <= 1024
            else _like_tokens
        )
        return _unicode_like(value, pattern, compile_pattern)

    connection.create_function(
        "sigma_unicode_like", 2, unicode_like, deterministic=True
    )
    connection.create_function(
        "sigma_casefold",
        1,
        lambda v: v.casefold() if isinstance(v, str) else v,
        deterministic=True,
    )
    connection.create_function(
        "regexp",
        2,
        lambda pattern, value: (
            value is not None
            and pattern is not None
            and re.search(pattern, str(value)) is not None
        ),
        deterministic=True,
    )
    connection.create_window_function("sigma_exact_sum", 1, _ExactSum)
    connection.create_function("sigma_numeric_cmp", 2, _numeric_cmp, deterministic=True)
