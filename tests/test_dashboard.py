"""
Smoke tests for the Streamlit dashboard components and helper functions.
"""

from __future__ import annotations

import pytest

from agent_firewall.cascade import CascadeResult
from agent_firewall.policy import Decision, Policy, RiskLevel
from dashboard.app import get_cascade, get_classifier_model


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
