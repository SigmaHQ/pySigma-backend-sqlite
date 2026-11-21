"""Execute correlation plans on a consumer-owned SQLite connection."""

import json
import re
import sqlite3
from collections import Counter
from string import ascii_lowercase, ascii_uppercase

from .cidr import CIDR_FUNCTION
from .cidr import register_cidr as register_cidr
from .correlation import (
    BARE_NAME,
    FULLTEXT_REPRESENTATION,
    json_array_function,
    protect_json_text,
    quote,
    restore_text,
)
from .strict import PRESENCE_REPRESENTATION
from .strict import register_sqlite_functions as register_sqlite_functions

_NAME = rf"(?:{BARE_NAME}|`(?:[^`]|``)+`)"
_TABLE_NAME = re.compile(rf"{_NAME}(?:\.{_NAME})?\Z")
_ASCII_LOWER = str.maketrans(ascii_uppercase, ascii_lowercase)


def _identifier(name):
    """SQLite folds only ASCII letters when resolving column names."""
    return name.translate(_ASCII_LOWER)


def _result_text(value):
    """Decode runtime-owned TEXT on connections using text_factory=bytes."""
    return value.decode("utf-8") if isinstance(value, bytes) else value


def _columns(connection, table):
    """Lowercased column names of a table."""
    cursor = connection.execute(f"SELECT * FROM {table} LIMIT 0")
    columns = {_identifier(column[0]) for column in cursor.description}
    cursor.close()
    return columns


# Probe semantics and arity on the actual execution connection. The window check
# also catches connections that registered an ordinary aggregate of the same name.
_FUNCTION_CHECKS = {
    CIDR_FUNCTION: f"{CIDR_FUNCTION}('::1','::1/128') = 1 AND {CIDR_FUNCTION}('::2','::1/128') = 0",
    "regexp": "regexp('^a','ab') = 1 AND regexp('^a','ba') = 0 AND regexp('a',NULL) = 0",
    "sigma_casefold": "sigma_casefold('Straße') = 'strasse' AND sigma_casefold(7) IS 7",
    "sigma_unicode_like": "sigma_unicode_like('ß','ss') = 1 AND sigma_unicode_like('ß','_') = 1 AND sigma_unicode_like('ß','__') = 0",
    "sigma_exact_sum": "(SELECT v FROM (SELECT sigma_exact_sum(n) OVER (ORDER BY n) AS v FROM (SELECT 9223372036854775807 AS n UNION ALL SELECT 1)) ORDER BY v DESC LIMIT 1) = '9223372036854775808'",
    "sigma_numeric_cmp": "sigma_numeric_cmp('9223372036854775808',9223372036854775807) = 1 AND sigma_numeric_cmp('-10','-2') = -1",
}


def validate_sql_functions(connection, requirements, *, version=5):
    """Check the functions declared by a structured entry or plan."""
    if (
        not isinstance(requirements, list)
        or not requirements
        or any(
            not isinstance(f, str) or f not in _FUNCTION_CHECKS for f in requirements
        )
        or len(set(requirements)) != len(requirements)
        or version not in (4, 5)
        or (version == 4 and requirements != [CIDR_FUNCTION])
    ):
        raise ValueError(f"Unsupported required SQL functions: {requirements!r}")
    for name in requirements:
        try:
            result = connection.execute("SELECT " + _FUNCTION_CHECKS[name]).fetchone()
        except sqlite3.Error as error:
            registration = (
                "register_cidr" if version == 4 else "register_sqlite_functions"
            )
            raise ValueError(
                f"Required SQL function {name} unavailable; call {registration}(connection)"
            ) from error
        if result[0] != 1:
            raise ValueError(f"Required SQL function {name} failed its semantics check")


def validate_fulltext(connection, requirements):
    """Require a populated source-values-v1 TEXT column for every source row."""
    if not isinstance(requirements, list) or not requirements:
        raise ValueError("Keyword search requires nonempty fulltext requirements")
    for item in requirements:
        if (
            not isinstance(item, dict)
            or set(item) != {"table", "field", "representation"}
            or not isinstance(item["table"], str)
            or not _TABLE_NAME.fullmatch(item["table"])
            or not isinstance(item["field"], str)
            or not item["field"]
            or item["representation"] != FULLTEXT_REPRESENTATION
        ):
            raise ValueError(
                "Invalid fulltext requirement; re-ingest events for keyword search"
            )
        table, field = item["table"], item["field"]
        try:
            if _identifier(field) not in _columns(connection, table):
                raise ValueError(
                    f"Keyword text column {field!r} is missing from {table}; re-ingest events"
                )
            missing = connection.execute(
                f"SELECT 1 FROM {table} WHERE {quote(field)} IS NULL "
                f"OR typeof({quote(field)}) != 'text' LIMIT 1"
            ).fetchone()
        except sqlite3.Error as error:
            raise ValueError(
                f"Keyword text is unavailable in {table}; re-ingest events"
            ) from error
        if missing:
            raise ValueError(
                f"Keyword text in {table}.{field} is incomplete; re-ingest events"
            )


def validate_presence(connection, requirements):
    """Check every source row carries a JSON array of mapped field names before widening."""
    if not isinstance(requirements, list) or not requirements:
        raise ValueError("Invalid presence requirements")
    for item in requirements:
        if (
            not isinstance(item, dict)
            or set(item) != {"table", "field", "representation"}
            or not isinstance(item["table"], str)
            or not _TABLE_NAME.fullmatch(item["table"])
            or not isinstance(item["field"], str)
            or not item["field"]
            or "\x00" in item["field"]
            or item["representation"] != PRESENCE_REPRESENTATION
        ):
            raise ValueError("Invalid presence requirement")
        table, field = item["table"], item["field"]
        try:
            if _identifier(field) not in _columns(connection, table):
                raise ValueError(
                    f"Missing presence column {table}.{field}; re-ingest events"
                )
            column = quote(field)
            cursor = connection.execute(
                f"SELECT CASE WHEN typeof({column})='text' THEN {column} END FROM {table}"
            )
            try:
                for (source,) in cursor:
                    if source is None:
                        raise ValueError("expected TEXT")
                    keys = json.loads(_result_text(source))
                    if not isinstance(keys, list) or any(
                        not isinstance(key, str) or not key or "\x00" in key
                        for key in keys
                    ):
                        raise ValueError("expected an array of nonempty field names")
            finally:
                cursor.close()
        except (sqlite3.Error, ValueError, RecursionError) as error:
            raise ValueError(
                f"Invalid presence column {table}.{field}; re-ingest events: {error}"
            ) from error


def _validate_contract(connection, contract, version, fulltext_preflight=None):
    if version not in (2, 3, 4, 5):
        raise ValueError(f"Unsupported SQLite schema or plan version {version!r}")
    if version == 4 or "required_sql_functions" in contract:
        validate_sql_functions(
            connection, contract.get("required_sql_functions"), version=version
        )
    if version == 5 and not (
        contract.get("presence") or contract.get("required_sql_functions")
    ):
        raise ValueError("Version 5 requires a presence or SQL function declaration")
    if "presence" in contract:
        if version != 5:
            raise ValueError("Field presence requires version 5")
        validate_presence(connection, contract["presence"])
    if version == 3 or "fulltext" in contract:
        if version == 2:
            raise ValueError("Fulltext requires version 3 or newer")
        requirements = contract.get("fulltext")
        if fulltext_preflight is None:
            validate_fulltext(connection, requirements)
        else:
            fulltext_preflight(requirements)


def validate_entry(connection, entry):
    """Validate structured entry prerequisites before widening fields or running its SQL."""
    _validate_contract(connection, entry, entry.get("schema_version"))


def ensure_fields(connection, requirements):
    """Materialize absent event fields as NULL, using compiler metadata."""
    for table, fields in requirements.items():
        existing = _columns(connection, table)
        for field in fields:
            name = _identifier(field)
            if name not in existing and name != "rowid":
                connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN {quote(field)} TEXT COLLATE NOCASE"
                ).close()
                existing.add(name)


def execute_plan(
    connection, plan, *, limit=None, include_events=True, fulltext_preflight=None
):
    """Return (alert summaries, diagnostic counts), cleaning temporary relations.

    A limit truncates retrieval at limit+1 so the consumer can retain its
    discard-noisy-rule policy. The executor never commits the caller's work.
    Event IDs are scoped by source table; evidence carries each full source row.
    A caller may supply a cache-aware fulltext_preflight(requirements) hook;
    without one, plans requiring fulltext validate on every execution.
    """
    if plan.get("version") not in (2, 3, 4, 5):
        raise ValueError("Unsupported correlation plan version")
    if limit is not None and limit < 0:
        raise ValueError("limit must be nonnegative")
    if sqlite3.sqlite_version_info < (3, 38, 0):
        raise RuntimeError(
            "Correlation plans require SQLite >= 3.38 with JSON functions"
        )
    _validate_contract(connection, plan, plan["version"], fulltext_preflight)
    created = []
    try:
        for table in plan["source_tables"].values():
            connection.execute(
                f"SELECT {quote(plan['event_id_field'])} FROM {table} LIMIT 0"
            ).close()
        ensure_fields(connection, plan["required_fields"])
        for stage in plan["prepare"]:
            name = stage["name"]
            if not re.fullmatch(r"sigma_[a-zA-Z0-9_]+", name):
                raise ValueError("Invalid correlation relation name")
            # Never drop or overwrite a consumer's pre-existing temporary table.
            connection.execute(
                f"CREATE TEMP TABLE {quote(name)} AS {stage['select']}"
            ).close()
            created.append(name)
            for i, columns in enumerate(stage["indexes"]):
                connection.execute(
                    f"CREATE INDEX temp.{quote(name + '_i' + str(i))} "
                    f"ON {quote(name)} ({', '.join(map(quote, columns))})"
                ).close()
        diagnostics = Counter()
        if plan["diagnostics"]:
            for reason, count in connection.execute(plan["diagnostics"]):
                diagnostics[_result_text(reason)] += count
        sql = plan["query"]
        if limit is not None:
            sql += f" LIMIT {int(limit) + 1}"
        cursor = connection.execute(sql)
        columns = [d[0] for d in cursor.description]
        rows = [dict(zip(columns, map(_result_text, row))) for row in cursor]
        cursor.close()
        for row in rows:
            for field in ("group_keys", "event_ids", "child_alert_ids"):
                row[field] = json.loads(row[field])
        if include_events:
            internal_fields = {}
            for item in plan.get("fulltext", []) + plan.get("presence", []):
                internal_fields.setdefault(item["table"], set()).add(
                    _identifier(item["field"])
                )
            evidence = {}
            ids_by_table = {}
            for row in rows:
                for identity in row["event_ids"]:
                    table_id, event_id = identity.split(":", 1)
                    ids_by_table.setdefault(table_id, set()).add(event_id)
            event_field = quote(plan["event_id_field"])
            array_items = json_array_function(plan["source_tables"].values())
            for table_id, ids in ids_by_table.items():
                table = plan["source_tables"][table_id]
                # The CAST keeps IDs comparable whatever the column's type, but
                # it also defeats any index, so fetch every ID in one scan.
                cursor = connection.execute(
                    f"SELECT CAST({event_field} AS TEXT), * FROM {table} "
                    f"WHERE CAST({event_field} AS TEXT) IN "
                    f"(SELECT {restore_text('value')} FROM {array_items}({protect_json_text('?')}) WHERE type='text')",
                    (json.dumps(sorted(ids)),),
                )
                columns = [d[0] for d in cursor.description][1:]
                for event in cursor:
                    identity = table_id + ":" + _result_text(event[0])
                    evidence[identity] = {
                        "event_id": identity,
                        "source_table": table,
                        "event": {
                            k: v
                            for k, v in zip(columns, event[1:])
                            if v is not None
                            and _identifier(k) not in internal_fields.get(table, ())
                        },
                    }
                cursor.close()
            for row in rows:
                row["evidence"] = [evidence[i] for i in row["event_ids"]]
        return rows, dict(diagnostics)
    finally:
        for name in reversed(created):
            # An interrupted CREATE TABLE AS can roll back the temp schema.
            # Cleanup must preserve the original error even then.
            connection.execute(f"DROP TABLE IF EXISTS temp.{quote(name)}").close()
