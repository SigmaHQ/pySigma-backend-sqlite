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
from sigma.processing.pipeline import ProcessingPipeline

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


@pytest.mark.parametrize("field", ["message", ""])
@pytest.mark.parametrize("modifiers", ["windash", "windash|cased", "cased|windash"])
@pytest.mark.parametrize("dash", list("-/–—―"))
def test_windash_accepts_each_spelling_in_rule_and_event(field, modifiers, dash):
    key = f"{field}|{modifiers}"
    rules = SigmaCollection.from_dicts([rule({key: dash + "a-b"})])
    sql = sqliteBackend(fulltext_field="message").convert(rules)[0]
    samples = [prefix + "a" + inner + "b" for prefix in "-/–—―" for inner in "-/–—―"]
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(message TEXT COLLATE NOCASE)")
        db.executemany(
            "INSERT INTO logs VALUES (?)", [(s,) for s in [*samples, "-A-B", "xx"]]
        )
        assert [s for (s,) in db.execute(sql)] == (
            samples if "cased" in modifiers else samples + ["-A-B"]
        )


@pytest.mark.parametrize("field", ["message", ""])
@pytest.mark.parametrize(
    "modifier,samples",
    [
        ("startswith", ["ab then", "cd", "AB\nx"]),
        ("endswith", ["then ab", "cd", "x\nAB"]),
    ],
)
def test_regex_boundaries_keep_flags_and_alternation(field, modifier, samples):
    rules = SigmaCollection.from_dicts([rule({f"{field}|re|i|m|{modifier}": "ab|cd"})])
    sql = sqliteBackend(fulltext_field="message").convert(rules)[0]
    with sqlite3.connect(":memory:") as db:
        db.create_function("regexp", 2, regexp)
        db.execute("CREATE TABLE logs(message TEXT)")
        db.executemany(
            "INSERT INTO logs VALUES (?)",
            [(s,) for s in [*samples, "xabx", "x\ncd\nx", None]],
        )
        assert [s for (s,) in db.execute(sql)] == samples


@pytest.mark.parametrize("key", ["v|wide", "|utf16", "v|utf16be", "v|wide|cased", "v"])
def test_nul_literal_has_a_conversion_diagnostic(key):
    from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

    rules = SigmaCollection.from_dicts([rule({key: "a\0b" if key == "v" else "ab"})])
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="NUL"):
        sqliteBackend(fulltext_field="v").convert(rules)


def test_wide_followed_by_base64_executes():
    rules = SigmaCollection.from_dicts([rule({"v|wide|base64": "ab"})])
    with sqlite3.connect(":memory:") as db:
        db.execute("create table logs(v text)")
        db.execute("insert into logs values ('YQBiAA==')")
        assert db.execute(sqliteBackend().convert(rules)[0]).fetchone() == ("YQBiAA==",)


# Each expected failure is tied to an observable parser result. When pySigma
# preserves the input, the same fixture exercises conversion and execution.
def test_published_utf16le_alias():
    from sigma.exceptions import SigmaModifierError

    try:
        rules = SigmaCollection.from_dicts([rule({"v|utf16le|base64": "ab"})])
    except SigmaModifierError as exc:
        if "Unknown modifier 'utf16le'" in str(exc):
            pytest.xfail("pySigma lacks the published utf16le alias; use wide")
        raise
    (sql,) = sqliteBackend().convert(rules)
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(v TEXT)")
        db.execute("INSERT INTO logs VALUES ('YQBiAA==')")
        assert db.execute(sql).fetchall() == [("YQBiAA==",)]


def test_detection_integer_threshold_survives_parsing():
    threshold = 9007199254740993
    rules = SigmaCollection.from_dicts([rule({"v|gt": threshold})])
    value = (
        rules.rules[0]
        .detection.detections["selection"]
        .detection_items[0]
        .original_value[0]
    )
    if value.number == threshold - 1:
        pytest.xfail("pySigma rounded the source integer before backend conversion")
    (sql,) = sqliteBackend().convert(rules)
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(v INTEGER)")
        db.executemany(
            "INSERT INTO logs VALUES (?)",
            [(threshold - 1,), (threshold,), (threshold + 1,)],
        )
        assert db.execute(sql).fetchall() == [(threshold + 1,)]


@pytest.mark.parametrize(
    "condition,expected",
    [
        ("not 1 of them", ["Bob", "Cal"]),
        ("not all of them", ["Bob", "Cal"]),
        ("not _helper", ["Al", "Cal"]),
    ],
)
def test_filters_keep_private_selection_names(condition, expected):
    first = rule({"EventID": 1})
    second = {**first, "title": "Other source", "logsource": {"category": "other"}}
    collection = SigmaCollection.from_dicts([first, second])

    def make_filter(title, selectors, expr):
        return SigmaFilter.from_dict(
            {
                "title": title,
                "logsource": first["logsource"],
                "filter": {"rules": "any", **selectors, "condition": expr},
            }
        )

    collection.apply_filters(
        [
            make_filter(
                "Users",
                {"selection": {"User": "Al"}, "_helper": {"User": "Bob"}},
                condition,
            ),
            make_filter("Disabled", {"disabled": {"User": "Dan"}}, "not disabled"),
        ]
    )
    first_query, second_query = sqliteBackend().convert(collection)
    names = ["Al", "Bob", "Cal", "Dan"]
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(EventID INTEGER, User TEXT)")
        db.executemany("INSERT INTO logs VALUES(1,?)", [(name,) for name in names])
        assert [r[1] for r in db.execute(second_query)] == names
        selected = [r[1] for r in db.execute(first_query)]
    if (condition, selected) in [
        ("not 1 of them", ["Cal"]),
        ("not all of them", ["Al", "Bob", "Cal"]),
    ]:
        pytest.xfail("pySigma filter qualification includes the private helper in them")
    assert selected == expected


@pytest.mark.parametrize(
    "top,nested",
    [(True, None), (None, True), (True, True), (False, False), (True, False)],
)
def test_correlation_generate_spellings(top, nested):
    from helpers import correlation, detection
    from sigma.exceptions import SigmaError

    derived = correlation(condition={"gte": 1})
    if top is not None:
        derived["generate"] = top
    if nested is not None:
        derived["correlation"]["generate"] = nested
    conflict = top is not None and nested is not None and top != nested
    try:
        collection = SigmaCollection.from_dicts([detection(), derived])
    except SigmaError:
        if conflict:
            return
        raise
    observed = collection.rules[-1].generate
    if top and not observed:
        pytest.xfail("pySigma discarded top-level generate during parsing")
    assert not conflict
    assert observed == (nested if nested is not None else top)
    assert len(sqliteBackend().convert(collection)) == (2 if observed else 1)


def test_correlation_range_bounds_share_one_metric():
    from helpers import correlation, detection, event, execute
    from sigma.exceptions import SigmaCorrelationConditionError

    docs = [detection(), correlation(condition={"gt": 100, "lte": 200})]
    try:
        SigmaCollection.from_dicts(docs)
    except SigmaCorrelationConditionError as exc:
        if "exactly one condition item" in str(exc):
            pytest.xfail("pySigma rejects a correlation with two comparison bounds")
        raise
    events = [
        event(0, EventID=1, Host=str(n)) for n in (100, 101, 200, 201) for _ in range(n)
    ]
    for materialized in (False, True):
        alerts = execute(docs, events, materialized=materialized)
        assert {row["metric_value"] for row in alerts} == {101, 200}


def test_bounded_regex_preserves_authored_inline_flags_and_comments():
    pattern = "(?x) (?i) a[bcd]  # trailing comment"
    rules = SigmaCollection.from_dicts(
        [rule({"v|re|startswith": pattern})], policy=TrustedPolicy
    )
    (sql,) = sqliteBackend().convert(rules)
    with sqlite3.connect(":memory:") as db:
        db.create_function("regexp", 2, regexp)
        db.execute("CREATE TABLE logs(v TEXT)")
        db.executemany("INSERT INTO logs VALUES (?)", [("ABb",), ("ac",), ("xac",)])
        assert db.execute(sql).fetchall() == [("ABb",), ("ac",)]


@pytest.mark.parametrize("attempts", [1, 2])
@pytest.mark.parametrize(
    "boundary,expected",
    [("startswith", ["HELLOx", "bye"]), ("endswith", ["xHELLO", "bye"])],
)
def test_bounded_regex_survives_placeholder_expansion(boundary, expected, attempts):
    rules = SigmaCollection.from_dicts(
        [rule({f"v|re|i|expand|{boundary}": "%needle%"})]
    )
    pipeline = ProcessingPipeline.from_dict(
        {
            "vars": {"needle": ["hello", "bye"]},
            "transformations": [{"type": "value_placeholders"}],
        }
    )
    backend = sqliteBackend(pipeline)
    for _ in range(attempts):
        (sql,) = backend.convert(rules)
    with sqlite3.connect(":memory:") as db:
        db.create_function("regexp", 2, regexp)
        db.execute("CREATE TABLE logs(v TEXT)")
        db.executemany(
            "INSERT INTO logs VALUES (?)", [("xHELLO",), ("HELLOx",), ("bye",)]
        )
        assert [v for (v,) in db.execute(sql)] == expected


@pytest.mark.parametrize("modifiers", ["contains|windash", "cased|contains|windash"])
@pytest.mark.parametrize(
    "value,matches,misses",
    [
        (" -urlcache -f http://", "c /urlcache –f http://x", "c -urlcache -f http:––x"),
        (
            "--remote-debugging-port",
            "-/remote-debugging-port",
            "-/remote–debugging-port",
        ),
    ],
)
def test_windash_beyond_three_dashes_expands_word_start_dashes(
    modifiers, value, matches, misses
):
    # pySigma limits only dashes that start a word. Expand those as pySigma does
    # instead of rejecting a rule that pySigma itself accepts.
    rules = SigmaCollection.from_dicts([rule({f"message|{modifiers}": value})])
    (sql,) = sqliteBackend().convert(rules)
    upper = matches.upper()
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE logs(message TEXT)")
        db.executemany("INSERT INTO logs VALUES (?)", [(matches,), (misses,), (upper,)])
        found = [v for (v,) in db.execute(sql)]
    assert found == ([matches] if "cased" in modifiers else [matches, upper])
