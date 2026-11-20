import json
import subprocess
import sys
from pathlib import Path


def test_benchmark_checks_mode_parity_and_reports_aggregate_measurements(tmp_path):
    tool = Path(__file__).parents[1] / "tools" / "benchmark_cidr.py"
    report = tmp_path / "results.json"
    subprocess.run(
        [
            sys.executable,
            str(tool),
            "--size",
            "64",
            "--iterations",
            "2",
            "--output",
            str(report),
        ],
        check=True,
    )
    results = json.loads(report.read_text())
    assert results["size"] == 64
    assert results["iterations"] == 2
    assert len(results["cases"]) == 8
    for family in ("IPv4", "IPv6"):
        cases = [case for case in results["cases"] if case["family"] == family]
        assert {(case["indexed"], case["mode"]) for case in cases} == {
            (indexed, mode)
            for indexed in (True, False)
            for mode in ("expanded", "exact")
        }
        for metric, matches in (("events", 4), ("event_count", 2)):
            assert {case[metric]["matches"] for case in cases} == {matches}
            assert len({case[metric]["identities_sha256"] for case in cases}) == 1
            for case in cases:
                assert len(case[metric]["seconds"]) == 2
                assert case[metric]["query_plan"]
        assert {case["event_count"]["evidence_events"] for case in cases} == {4}
        if family == "IPv4":
            assert all(
                any("USING INDEX" in step for step in case["events"]["query_plan"])
                for case in cases
                if case["indexed"]
            )
