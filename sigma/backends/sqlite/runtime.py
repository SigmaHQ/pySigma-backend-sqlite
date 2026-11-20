"""Execute correlation plans on a consumer-owned SQLite connection."""

import json
import re
import sqlite3
from collections import Counter

from .cidr import CIDR_FUNCTION
from .cidr import register_cidr as register_cidr
from .correlation import BARE_NAME, FULLTEXT_REPRESENTATION, quote

_NAME = rf"(?:{BARE_NAME}|`(?:[^`]|``)+`)"
_TABLE_NAME = re.compile(rf"{_NAME}(?:\.{_NAME})*\Z")


def _columns(connection, table):
    """Lowercased column names of a table."""
    cursor = connection.execute(f"SELECT * FROM {table} LIMIT 0")
    columns = {column[0].lower() for column in cursor.description}
    cursor.close()
    return columns


def validate_sql_functions(connection, requirements):
    """Check the version-4 function contract on the connection that will run the SQL."""
    if requirements != [CIDR_FUNCTION]:
        raise ValueError(f"Unsupported required SQL functions: {requirements!r}")
    try:
        result = connection.execute(
            f"SELECT {CIDR_FUNCTION}('::1', '::1/128') = 1 "
            f"AND {CIDR_FUNCTION}('::2', '::1/128') = 0"
        ).fetchone()
    except sqlite3.Error as error:
        raise ValueError(
            f"Required SQL function {CIDR_FUNCTION} unavailable; call register_cidr(connection)"
        ) from error
    if result[0] != 1:
        raise ValueError(
            f"Required SQL function {CIDR_FUNCTION} failed its membership check"
        )


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
            if field.lower() not in _columns(connection, table):
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


def ensure_fields(connection, requirements):
    """Materialize absent event fields as NULL, using compiler metadata."""
    for table, fields in requirements.items():
        existing = _columns(connection, table)
        for field in fields:
            if field.lower() not in existing and field.lower() != "rowid":
                connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN {quote(field)} TEXT COLLATE NOCASE"
                ).close()
                existing.add(field.lower())


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
    if plan.get("version") not in (2, 3, 4):
        raise ValueError("Unsupported correlation plan version")
    if limit is not None and limit < 0:
        raise ValueError("limit must be nonnegative")
    if sqlite3.sqlite_version_info < (3, 38, 0):
        raise RuntimeError(
            "Correlation plans require SQLite >= 3.38 with JSON functions"
        )
    if plan["version"] == 4:
        validate_sql_functions(connection, plan.get("required_sql_functions"))
    elif "required_sql_functions" in plan:
        raise ValueError("Required SQL functions must be declared in a version-4 plan")
    if plan["version"] == 3 or (plan["version"] == 4 and "fulltext" in plan):
        requirements = plan.get("fulltext")
        if fulltext_preflight is None:
            validate_fulltext(connection, requirements)
        else:
            fulltext_preflight(requirements)
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
                diagnostics[reason] += count
        sql = plan["query"]
        if limit is not None:
            sql += f" LIMIT {int(limit) + 1}"
        cursor = connection.execute(sql)
        columns = [d[0] for d in cursor.description]
        rows = [dict(zip(columns, row)) for row in cursor]
        cursor.close()
        for row in rows:
            for field in ("group_keys", "event_ids", "child_alert_ids"):
                row[field] = json.loads(row[field])
        if include_events:
            internal_fields = {
                item["field"].lower() for item in plan.get("fulltext", [])
            }
            evidence = {}
            ids_by_table = {}
            for row in rows:
                for identity in row["event_ids"]:
                    table_id, event_id = identity.split(":", 1)
                    ids_by_table.setdefault(table_id, set()).add(event_id)
            event_field = quote(plan["event_id_field"])
            for table_id, ids in ids_by_table.items():
                table = plan["source_tables"][table_id]
                # The CAST keeps IDs comparable whatever the column's type, but
                # it also defeats any index, so fetch every ID in one scan.
                cursor = connection.execute(
                    f"SELECT CAST({event_field} AS TEXT), * FROM {table} "
                    f"WHERE CAST({event_field} AS TEXT) IN "
                    "(SELECT value FROM json_each(?))",
                    (json.dumps(sorted(ids)),),
                )
                columns = [d[0] for d in cursor.description][1:]
                for event in cursor:
                    identity = table_id + ":" + event[0]
                    evidence[identity] = {
                        "event_id": identity,
                        "source_table": table,
                        "event": {
                            k: v
                            for k, v in zip(columns, event[1:])
                            if v is not None and k.lower() not in internal_fields
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
