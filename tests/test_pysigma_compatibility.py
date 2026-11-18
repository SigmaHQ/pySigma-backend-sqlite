"""Exercise the pySigma contracts used by the backend without import shims."""

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import regexp
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaModifiedError, SigmaRegularExpressionError
from sigma.filters import SigmaFilter
from sigma.policy.profiles import TrustedPolicy

from sigma.backends.sqlite import sqliteBackend


def rule(selection):
    return {
        "title": "Compatibility",
        "logsource": {"category": "test"},
        "detection": {"selection": selection, "condition": "selection"},
    }


def test_fresh_process_imports_and_discovers_checkout_backend():
    subprocess.run(
        [
            sys.executable,
            "-c",
            "from sigma.backends.sqlite import sqliteBackend; "
            "from sigma.plugins import InstalledSigmaPlugins; "
            "assert InstalledSigmaPlugins.autodiscover().backends['sqlite'] is sqliteBackend",
        ],
        cwd=Path(__file__).parents[1],
        check=True,
        capture_output=True,
        text=True,
    )


def test_filter_with_leading_underscore_excludes_only_selected_events():
    rules = SigmaCollection.from_dicts([rule({"EventID": 1})])
    rules.apply_filters(
        [
            SigmaFilter.from_dict(
                {
                    "title": "Guest exclusion",
                    "logsource": {"category": "test"},
                    "filter": {
                        "rules": "any",
                        "_skip": {"User": "guest"},
                        "condition": "not _skip",
                    },
                }
            )
        ]
    )
    sql = sqliteBackend().convert(rules)[0]
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(EventID INTEGER, User TEXT)")
        db.executemany(
            "INSERT INTO logs VALUES(?,?)", [(1, "guest"), (1, "member"), (2, "other")]
        )
        assert db.execute(sql).fetchall() == [(1, "member")]


@pytest.mark.parametrize("field", ["message", ""])
def test_explicit_regex_policy_preserves_python_patterns(field):
    collection = SigmaCollection.from_dicts(
        [rule({f"{field}|re|i": "foo(?=bar)"})], policy=TrustedPolicy
    )
    query = sqliteBackend(fulltext_field="message").convert(collection)[0]
    with sqlite3.connect(":memory:") as connection:
        connection.create_function("regexp", 2, regexp)
        connection.execute("CREATE TABLE logs(message TEXT)")
        connection.executemany(
            "INSERT INTO logs VALUES (?)", [("FOObar",), ("fooqux",), (None,)]
        )
        assert connection.execute(query).fetchall() == [("FOObar",)]


@pytest.mark.parametrize("field", ["message", ""])
def test_default_regex_policy_rejects_python_only_patterns(field):
    with pytest.raises(SigmaRegularExpressionError):
        SigmaCollection.from_dicts([rule({f"{field}|re": "foo(?=bar)"})])


@pytest.mark.parametrize("field", ["message", ""])
def test_windash_expansion_boundary_matches_events(field):
    collection = SigmaCollection.from_dicts(
        [rule({f"{field}|windash": "-one -two -three"})]
    )
    query = sqliteBackend(fulltext_field="message").convert(collection)[0]
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE logs(message TEXT)")
        connection.executemany(
            "INSERT INTO logs VALUES (?)",
            [
                ("-one -two -three",),
                ("/one \u2013two \u2014three",),
                ("one two three",),
            ],
        )
        assert connection.execute(query).fetchall() == [
            ("-one -two -three",),
            ("/one \u2013two \u2014three",),
        ]


@pytest.mark.parametrize("field", ["message", ""])
def test_excessive_windash_expansion_is_not_silently_converted(field):
    with pytest.raises(SigmaModifiedError, match="at most three dash occurrences"):
        SigmaCollection.from_dicts([rule({f"{field}|windash": "-a -b -c -d"})])
