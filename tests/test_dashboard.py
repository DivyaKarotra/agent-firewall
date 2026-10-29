"""
Smoke tests for the Streamlit dashboard components and helper functions.
"""

from __future__ import annotations

import pytest

from agent_firewall.cascade import CascadeResult
from agent_firewall.policy import Decision, Policy, RiskLevel
from agent_firewall.rules import RULES
from dashboard.app import (
    FRIENDLY_RULE_LABELS,
    generate_verdict_sentence,
    get_cascade,
    get_classifier_model,
    get_friendly_rule_label,
    load_benchmark_results,
)


def test_dashboard_classifier_loader():
    """Verify that get_classifier_model returns a classifier or None gracefully."""
    clf = get_classifier_model()
    # If scikit-learn is installed, it should be trained and fitted
    if clf is not None:
        assert hasattr(clf, "predict_proba")


@pytest.mark.parametrize("combine_mode", ["gated", "max", "blend", "verify"])
def test_dashboard_get_cascade(combine_mode: str):
    """Verify get_cascade creates a valid cascade for all combine modes."""
    cascade = get_cascade(
        judge_name="mock",
        model="",
        combine=combine_mode,
        prompt_ver="v2",
        with_clf=False,
    )
    assert cascade is not None
    assert cascade.combine == combine_mode

    # Test evaluation smoke test
    result = cascade.evaluate("Hello, please summarize this document.")
    assert isinstance(result, CascadeResult)
    assert 0.0 <= result.suspicion <= 1.0
    assert len(result.layers) >= 1

    # Policy decisions smoke test
    policy = Policy()
    decisions = policy.decide_all(result.suspicion)
    assert set(decisions.keys()) == set(RiskLevel)
    for dec in decisions.values():
        assert isinstance(dec, Decision)


def test_friendly_rule_labels_covers_all_rules():
    """Verify that friendly rule label mapping covers every rule in rules.py."""
    bank_rule_names = {rule.name for rule in RULES}
    for rule_name in bank_rule_names:
        assert rule_name in FRIENDLY_RULE_LABELS, f"Rule '{rule_name}' missing from FRIENDLY_RULE_LABELS"
        label = get_friendly_rule_label(rule_name)
        assert label, f"Rule '{rule_name}' produced empty friendly label"
        assert label != rule_name, f"Rule '{rule_name}' was not mapped to a human label"


@pytest.mark.parametrize(
    ("decision", "suspicion", "risk", "tool_name", "expected_prefix"),
    [
        (Decision.ALLOW, 0.0, RiskLevel.LOW, "search web", "Allowed:"),
        (Decision.ALLOW, 0.05, RiskLevel.MEDIUM, "save note", "Allowed:"),
        (Decision.ASK, 0.65, RiskLevel.HIGH, "send email", "Ask the user:"),
        (Decision.BLOCK, 0.95, RiskLevel.HIGH, "send email", "Blocked:"),
    ],
)
def test_verdict_sentence_generated_for_all_decisions(
    decision: Decision,
    suspicion: float,
    risk: RiskLevel,
    tool_name: str,
    expected_prefix: str,
):
    """Verify that a clear verdict sentence is generated for ALLOW, ASK, and BLOCK."""
    sentence = generate_verdict_sentence(
        decision=decision,
        suspicion=suspicion,
        risk=risk,
        tool_name=tool_name,
        rule_hits=["override_previous"] if decision == Decision.BLOCK else None,
    )
    assert sentence.startswith(expected_prefix)
    assert f"{int(round(suspicion * 100))}%" in sentence
    assert tool_name in sentence
    assert risk.value in sentence


def test_load_benchmark_results():
    """Verify that load_benchmark_results reads real numbers and expected keys."""
    results = load_benchmark_results()
    assert "rules_classifier_catch" in results
    assert "full_cascade_catch" in results
    assert "sample_count" in results
    assert isinstance(results["sample_count"], int)
    assert results["sample_count"] > 0
