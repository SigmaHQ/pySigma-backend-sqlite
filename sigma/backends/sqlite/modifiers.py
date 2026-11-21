"""Adapt pySigma modifier values to SQLite's search-style REGEXP and text queries."""

import re
from copy import copy
from dataclasses import dataclass, replace

from sigma.modifiers import (
    SigmaEndswithModifier,
    SigmaRegularExpressionModifier,
    SigmaStartswithModifier,
    SigmaWindowsDashModifier,
)
from sigma.processing.transformations.base import DetectionItemTransformation
from sigma.types import (
    SigmaCasedString,
    SigmaExpansion,
    SigmaRegularExpression,
    SigmaString,
)

# Hyphen-minus, slash, en dash, em dash and horizontal bar.
DASHES = "-/–—―"


class _WindowsDash(SigmaWindowsDashModifier):
    def modify(self, val: SigmaString) -> SigmaExpansion:
        # Canonicalize every dash position, including dashes inside a token.
        # Keep wildcard tokens and pre-existing placeholders intact.
        dashes = sum(
            part.count(dash)
            for part in val.s
            if isinstance(part, str)
            for dash in DASHES
        )
        if dashes > self.max_expanded_dashes:
            # pySigma limits only the dashes that start a word, as in "-a" or
            # " /b". Expand those, as pySigma does, rather than rejecting a path,
            # URL or hyphenated name that pySigma itself accepts.
            expansion = super().modify(val)
            if isinstance(val, SigmaCasedString):
                # pySigma's placeholder expansion returns plain strings.
                expansion.values = [
                    SigmaCasedString.from_sigma_string(v) for v in expansion.values
                ]
            return expansion
        alternatives = [type(val)()]
        for part in val.s:
            if not isinstance(part, str):
                alternatives = [prefix + part for prefix in alternatives]
                continue
            for token in re.split(f"([{DASHES}])", part):
                if not token:
                    continue
                choices = list(DASHES) if token in DASHES else [token]
                alternatives = [prefix + s for prefix in alternatives for s in choices]
        return SigmaExpansion(alternatives)


@dataclass
class BoundedRegex(SigmaRegularExpression):
    anchor_start: bool = False
    anchor_end: bool = False

    def replace_placeholders(self, callback):
        return [
            replace(self, regexp_init=pattern)
            for pattern in self.regexp.replace_placeholders(callback)
        ]

    def bound(self, pattern: str) -> str:
        # Preserve leading flag groups in front of our wrapper. In verbose mode
        # whitespace and comments may separate flags or terminate the pattern.
        pos = 0
        verbose = False
        while pos < len(pattern):
            flag = re.match(r"\(\?([aiLmsux]+)\)", pattern[pos:])
            if flag:
                verbose |= "x" in flag[1]
                pos += flag.end()
                continue
            comment = re.match(r"\(\?\#(?:\\.|[^)\\])*\)", pattern[pos:])
            if comment:
                pos += comment.end()
                continue
            if verbose and (
                gap := re.match(r"(?:[ \t\n\r\f\v]+|\#[^\n]*(?:\n|$))", pattern[pos:])
            ):
                pos += gap.end()
                continue
            break
        start = r"\A" if self.anchor_start else ""
        end = r"\Z" if self.anchor_end else ""
        newline = "\n" if verbose else ""
        return f"{pattern[:pos]}{newline}{start}(?:{pattern[pos:]}{newline}){end}"


class SQLiteModifiers(DetectionItemTransformation):
    def apply_detection_item(self, item):
        modifiers = item.modifiers
        windash = SigmaWindowsDashModifier in modifiers
        anchored = SigmaRegularExpressionModifier in modifiers and (
            SigmaStartswithModifier in modifiers or SigmaEndswithModifier in modifiers
        )
        if not (windash or anchored) or item.original_value is None:
            return
        # A pySigma value transformation can replace original_value with its
        # typed results. Those values have already passed through the modifiers.
        if not all(isinstance(v, SigmaString) for v in item.original_value):
            return
        # Replay the original sequence before user transformations. Keep the
        # rule's public modifier names and the original value for serialization.
        normalized = [
            _WindowsDash if mod is SigmaWindowsDashModifier else mod
            for mod in modifiers
            if not (
                anchored and mod in (SigmaStartswithModifier, SigmaEndswithModifier)
            )
        ]
        rebuilt = replace(
            item, modifiers=normalized, value=[copy(v) for v in item.original_value]
        )
        if anchored:
            for i, value in enumerate(rebuilt.value):
                if isinstance(value, SigmaRegularExpression):
                    rebuilt.value[i] = BoundedRegex(
                        value.regexp,
                        value.flags,
                        value.policy,
                        SigmaStartswithModifier in modifiers,
                        SigmaEndswithModifier in modifiers,
                    )
        item.value = rebuilt.value
