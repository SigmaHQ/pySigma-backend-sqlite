import sqlite3
from datetime import date, timedelta

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.sqlite import sqliteBackend


@pytest.mark.parametrize("week", [0, 1, 2, 52, 53])
@pytest.mark.parametrize("mode", ["iso", "legacy"])
def test_calendar_week_transitions(mode, week):
    days = [
        date(y, 12, 24) + timedelta(days=i)
        for y in range(2018, 2026)
        for i in range(19)
    ]
    rule = {
        "title": "Week",
        "logsource": {"category": "test"},
        "detection": {"s": {"stamp|week": week}, "condition": "s"},
    }
    opts = {} if mode == "iso" else {"week_mode": mode}
    (query,) = sqliteBackend(**opts).convert(SigmaCollection.from_dicts([rule]))
    with sqlite3.connect(":memory:") as conn:
        conn.execute("CREATE TABLE logs(stamp TEXT)")
        conn.executemany(
            "INSERT INTO logs VALUES (?)",
            [(d.isoformat(),) for d in days] + [(None,), ("invalid",)],
        )
        assert [s for (s,) in conn.execute(query)] == [
            d.isoformat()
            for d in days
            if (d.isocalendar().week if mode == "iso" else int(d.strftime("%W")))
            == week
        ]


def test_unknown_week_convention():
    with pytest.raises(ValueError, match="week_mode"):
        sqliteBackend(week_mode="us")
