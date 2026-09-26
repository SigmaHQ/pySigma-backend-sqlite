"""Execute a version-2 correlation plan on a consumer-owned SQLite connection."""

from __future__ import annotations

import json
import re
import sqlite3

from .correlation import quote


def ensure_fields(connection, requirements):
    """Materialize absent event fields as NULL, using compiler metadata."""
    for table, fields in requirements.items():
        cursor = connection.execute(f"SELECT * FROM {table} LIMIT 0")
        existing = {d[0].lower() for d in cursor.description}
        cursor.close()
        for field in fields:
            if field.lower() not in existing and field.lower() != "rowid":
                connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN {quote(field)} TEXT COLLATE NOCASE"
                ).close()
                existing.add(field.lower())


def execute_plan(connection, plan, *, limit=None, include_events=True):
    """Return (alert summaries, diagnostic counts), cleaning temporary relations.

    A limit truncates retrieval at limit+1 so the consumer can retain its
    discard-noisy-rule policy. The executor never commits the caller's work.
    Event IDs are scoped by source table; source filenames accompany evidence.
    """
    if plan.get("version") != 2:
        raise ValueError("Unsupported correlation plan version")
    if sqlite3.sqlite_version_info < (3, 38, 0):
        raise RuntimeError(
            "Correlation plans require SQLite >= 3.38 with JSON functions"
        )
    created = []
    try:
        for table in plan["source_tables"].values():
            connection.execute(
                f'SELECT {quote(plan["event_id_field"])} FROM {table} LIMIT 0'
            ).close()
        ensure_fields(connection, plan["required_fields"])
        for stage in plan["prepare"]:
            name = stage["name"]
            if not re.fullmatch(r"sigma_[a-zA-Z0-9_]+", name):
                raise ValueError("Invalid correlation relation name")
            # Never drop or overwrite a consumer's pre-existing temporary table.
            connection.execute(
                f'CREATE TEMP TABLE {quote(name)} AS {stage["select"]}'
            ).close()
            created.append(name)
            for i, columns in enumerate(stage["indexes"]):
                connection.execute(
                    f'CREATE INDEX temp.{quote(name + "_i" + str(i))} '
                    f'ON {quote(name)} ({", ".join(map(quote, columns))})'
                ).close()
        diagnostics = {}
        if plan["diagnostics"]:
            for reason, count in connection.execute(plan["diagnostics"]):
                diagnostics[reason] = diagnostics.get(reason, 0) + count
        sql = plan["query"]
        if limit is not None and limit >= 0:
            sql += f" LIMIT {int(limit) + 1}"
        cursor = connection.execute(sql)
        columns = [d[0] for d in cursor.description]
        rows = [dict(zip(columns, row)) for row in cursor]
        cursor.close()
        for row in rows:
            for field in ("group_keys", "event_ids", "child_alert_ids"):
                row[field] = json.loads(row[field])
        if include_events:
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
                            k: v for k, v in zip(columns, event[1:]) if v is not None
                        },
                    }
                cursor.close()
            for row in rows:
                row["evidence"] = [evidence[i] for i in row["event_ids"]]
        return rows, diagnostics
    finally:
        for name in reversed(created):
            # An interrupted CREATE TABLE AS can roll back the temp schema.
            # Cleanup must preserve the original error even then.
            connection.execute(f"DROP TABLE IF EXISTS temp.{quote(name)}").close()
