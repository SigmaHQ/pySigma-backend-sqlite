"""Compare generated expanded and exact CIDR event queries and materialized plans."""

import argparse
import hashlib
import json
import platform
import sqlite3
import sys
from contextlib import closing
from importlib.metadata import version
from ipaddress import ip_address
from pathlib import Path
from statistics import median
from time import perf_counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sigma.collection import SigmaCollection

from sigma.backends.sqlite import runtime, sqliteBackend

NETWORKS = {"IPv4": "10.32.0.0/12", "IPv6": "2001:db8:abcd::/48"}
BASES = {
    "IPv4": tuple(map(ip_address, ("10.32.0.0", "10.192.0.0", "172.0.0.0"))),
    "IPv6": tuple(
        map(ip_address, ("2001:db8:abcd::", "2001:db8:dcba::", "2001:db9::"))
    ),
}


def fixture(size):
    """Alternating IP families. Each family contributes one matching pair per 16 rows."""
    for index in range(size):
        ordinal, parity = divmod(index, 2)
        group, slot = divmod(ordinal, 16)
        family = "IPv6" if parity else "IPv4"
        target, near, far = BASES[family]
        if slot < 2:
            address = target + (2 * group + slot)
        elif slot < 4:
            address = near + (2 * group + slot - 2)
        else:
            address = far + ordinal
        yield index + 1, str(address)


def compile_queries(network, mode):
    base = {
        "title": "Subnet",
        "name": "subnet",
        "logsource": {"category": "network_connection"},
        "detection": {"s": {"ip|cidr": network}, "condition": "s"},
    }
    correlation = {
        "title": "Subnet pair",
        "correlation": {
            "type": "event_count",
            "rules": ["subnet"],
            "timespan": "3s",
            "group-by": ["host"],
            "condition": {"gte": 2},
            "generate": True,
        },
    }
    backend = sqliteBackend(
        cidr_mode=mode,
        event_id_field="id",
        timestamp_field="id",
        timestamp_seconds_expression="{field}",
    )
    entries = json.loads(
        backend.convert(SigmaCollection.from_dicts([base, correlation]), "zircolite")
    )
    return entries[0]["rule"][0], entries[1]["correlation_plan"]


def explain(connection, query):
    return [row[3] for row in connection.execute("EXPLAIN QUERY PLAN " + query)]


def measure(connection, mode, iterations, run, identities):
    """Time query execution and result retrieval; check identities outside the timer."""
    seconds = []
    reference = None
    for _ in range(iterations):
        if mode == "exact":
            runtime.register_cidr(connection)
        start = perf_counter()
        rows = run()
        seconds.append(perf_counter() - start)
        current = identities(rows)
        if reference is not None and current != reference:
            raise ValueError("Repeated executions returned different identities")
        reference = current
    digest = hashlib.sha256(
        json.dumps(reference, separators=(",", ":")).encode()
    ).hexdigest()
    return reference, {
        "matches": len(reference),
        "identities_sha256": digest,
        "seconds": seconds,
        "median_seconds": median(seconds),
    }


def alert_identities(rows):
    alerts = []
    for row in rows:
        members = sorted(row["event_ids"])
        evidence = sorted(item["event_id"] for item in row["evidence"])
        if members != evidence:
            raise ValueError("Materialized evidence differs from the alert's event IDs")
        alerts.append(
            (row["alert_id"], row["occurrence_time"], row["metric_value"], evidence)
        )
    return sorted(alerts)


def benchmark(size, iterations):
    # Two out of every 32 rows occupy the IPv4 /12, which has 2**20 unique addresses.
    if not 1 <= size <= 2**24 or iterations < 1:
        raise ValueError(
            "size must be between 1 and 16777216 and iterations must be positive"
        )
    results = []
    reference_alerts = {}
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.execute(
            "CREATE TABLE logs(id INTEGER PRIMARY KEY, ip TEXT COLLATE NOCASE, host TEXT)"
        )
        connection.executemany("INSERT INTO logs VALUES (?, ?, 'h')", fixture(size))
        for indexed in (False, True):
            if indexed:
                connection.execute("CREATE INDEX logs_ip ON logs(ip)")
            for family, network in NETWORKS.items():
                first = 2 if family == "IPv6" else 1
                expected_ids = [
                    event_id
                    for start in range(first, size + 1, 32)
                    for event_id in (start, start + 2)
                    if event_id <= size
                ]
                expected_evidence = sorted(
                    sorted([f"0:{start}", f"0:{start + 2}"])
                    for start in range(first, size - 1, 32)
                )
                for mode in ("expanded", "exact"):
                    query, plan = compile_queries(network, mode)
                    ids, events = measure(
                        connection,
                        mode,
                        iterations,
                        lambda: connection.execute(query).fetchall(),
                        lambda rows: sorted(row[0] for row in rows),
                    )
                    if ids != expected_ids:
                        raise ValueError(
                            f"{family} {mode} event identities differ from the fixture"
                        )
                    events["query_plan"] = explain(connection, query)
                    alerts, counts = measure(
                        connection,
                        mode,
                        iterations,
                        lambda: runtime.execute_plan(connection, plan)[0],
                        alert_identities,
                    )
                    if sorted(alert[-1] for alert in alerts) != expected_evidence:
                        raise ValueError(
                            f"{family} {mode} evidence differs from the fixture"
                        )
                    if reference_alerts.setdefault(family, alerts) != alerts:
                        raise ValueError(
                            f"{family} alert identities differ between benchmark cases"
                        )
                    counts["evidence_events"] = sum(len(alert[-1]) for alert in alerts)
                    counts["query_plan"] = explain(
                        connection, plan["prepare"][0]["select"]
                    )
                    results.append(
                        {
                            "family": family,
                            "network": network,
                            "indexed": indexed,
                            "mode": mode,
                            "events": events,
                            "event_count": counts,
                        }
                    )
    return {
        "size": size,
        "iterations": iterations,
        "sqlite_version": sqlite3.sqlite_version,
        "python_version": platform.python_version(),
        "pysigma_version": version("pysigma"),
        "timing": "Seconds per execution, including result retrieval and evidence hydration. Fresh exact CIDR caches per execution. Correlation query plans describe the source stage.",
        "cases": results,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--size", type=int, default=10000, help="total unique, canonical IP events"
    )
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument(
        "--output", type=Path, help="write the aggregate JSON report to this path"
    )
    args = parser.parse_args()
    try:
        report = benchmark(args.size, args.iterations)
    except ValueError as error:
        parser.error(str(error))
    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
