"""The corpus auditor must provision the same prerequisites as a consumer."""

import importlib.util
from pathlib import Path

import yaml

spec = importlib.util.spec_from_file_location(
    "audit_corpus", Path(__file__).parents[1] / "tools" / "audit_corpus.py"
)
audit_corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_corpus)


def test_audit_provisions_keyword_text_and_correlation_dependencies(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    detection = {
        "title": "Keyword base",
        "name": "keyword_base",
        "logsource": {"category": "test"},
        "detection": {"selection": ["event::clear"], "condition": "selection"},
    }
    correlation = {
        "title": "Keyword correlation",
        "correlation": {
            "type": "event_count",
            "rules": ["keyword_base"],
            "timespan": "5m",
            "condition": {"gte": 1},
        },
    }
    (rules / "keywords.yml").write_text(yaml.safe_dump_all([detection, correlation]))
    result = audit_corpus.audit(tmp_path, "raw", fulltext_field="_sigma_fulltext")
    assert result["errors"] == []
    assert result["counts"]["converted_rules"] == 2
    assert result["counts"]["prepared_queries"] == 1
    assert result["counts"]["fulltext_queries"] == 1
    assert result["fulltext_field"] == "_sigma_fulltext"


def test_audit_keyword_configuration_is_explicit(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "keywords.yml").write_text(
        "title: Keyword\nlogsource: {category: test}\n"
        "detection:\n  selection: ['event::clear']\n  condition: selection\n"
    )
    result = audit_corpus.audit(tmp_path, "raw")
    assert len(result["errors"]) == 1
    assert result["errors"][0]["stage"] == "conversion"
    # Keyword rules without fulltext_field are a visible gap, not a failed audit.
    assert not audit_corpus.failed(result["errors"])
    assert audit_corpus.failed([dict(stage="conversion", error="Unexpected")])
    assert audit_corpus.failed([dict(stage="preparation", error="no such column")])


def test_audit_exact_cidr_registers_required_function(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "network.yml").write_text(
        "title: Address\nlogsource: {category: test}\ndetection:\n"
        "  network: {IP|cidr: '2001:db8::/32'}\n  condition: network\n"
    )
    result = audit_corpus.audit(tmp_path, "raw", cidr_mode="exact")
    assert result["errors"] == []
    assert result["counts"]["exact_cidr_queries"] == 1
    assert result["counts"]["prepared_queries"] == 1
