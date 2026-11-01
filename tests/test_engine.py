"""
Unit tests for dashboard.engine module (no Streamlit dependencies).
"""

from __future__ import annotations

import pytest

from agent_firewall.policy import Decision, RiskLevel
from dashboard.engine import (
    build_cascade,
    build_precomputed_map,
    generate_verdict_sentence,
    get_friendly_rule_label,
    get_honest_note,
    scan,
)
from dashboard.examples import DEMO_EMAILS, EXAMPLES, NORMAL_EMAIL, POISONED_EMAIL


@pytest.fixture
def precomputed_map():
    return build_precomputed_map(EXAMPLES, DEMO_EMAILS)


@pytest.fixture
def cascade_obj(precomputed_map):
    return build_cascade(
        precomputed_map=precomputed_map,
        judge_mode="precomputed",
        classifier=None,
        combine="gated",
        profile="balanced",
    )


def test_friendly_rule_labels():
    assert get_friendly_rule_label("override_previous") == "Overrides previous instructions"
    assert get_friendly_rule_label("unknown_rule_xyz") == "Unknown Rule Xyz"


def test_generate_verdict_sentence():
    s_block = generate_verdict_sentence(
        Decision.BLOCK, 0.95, RiskLevel.HIGH, tool_name="send email", rule_hits=["override_previous"]
    )
    assert "Blocked:" in s_block
    assert "send email" in s_block

    s_ask = generate_verdict_sentence(Decision.ASK, 0.55, RiskLevel.MEDIUM)
    assert "Ask the user:" in s_ask

    s_allow = generate_verdict_sentence(Decision.ALLOW, 0.05, RiskLevel.LOW)
    assert "Allowed:" in s_allow


def test_honest_notes():
    note_a011 = get_honest_note("a011", 1.0, 0.0, 0.0)
    assert note_a011 is not None
    assert "Base64" in note_a011

    note_a021 = get_honest_note("a021", 1.0, 0.0, 0.01)
    assert note_a021 is not None
    assert "spoof" in note_a021

    note_a015 = get_honest_note("a015", 0.2, 0.99, 0.8)
    assert note_a015 is not None
    assert "Multilingual" in note_a015 or "multilingual" in note_a015


def test_scan_empty_text(cascade_obj, precomputed_map):
    trace = scan(
        text="",
        tool_risk=RiskLevel.HIGH,
        profile="balanced",
        judge_mode="precomputed",
        cascade=cascade_obj,
        precomputed_map=precomputed_map,
    )
    assert trace.decision == Decision.ALLOW
    assert trace.rules_score == 0.0
    assert trace.combined_suspicion == 0.0
    d = trace.to_dict()
    assert d["tool_risk"] == "high"
    assert d["decision"] == "ALLOW"


def test_scan_poisoned_email(cascade_obj, precomputed_map):
    trace = scan(
        text=POISONED_EMAIL,
        tool_risk=RiskLevel.HIGH,
        profile="balanced",
        judge_mode="precomputed",
        cascade=cascade_obj,
        precomputed_map=precomputed_map,
    )
    assert trace.decision in (Decision.BLOCK, Decision.ASK)
    assert trace.rules_score > 0.0
    assert len(trace.rules_hits) > 0
    assert trace.judge_status in ("precomputed", "skipped: earlier layer already sure")
    assert len(trace.reasons) > 0


def test_scan_normal_email(cascade_obj, precomputed_map):
    trace = scan(
        text=NORMAL_EMAIL,
        tool_risk=RiskLevel.HIGH,
        profile="balanced",
        judge_mode="precomputed",
        cascade=cascade_obj,
        precomputed_map=precomputed_map,
    )
    assert trace.decision == Decision.ALLOW
    assert trace.rules_score == 0.0
    assert trace.combined_suspicion == 0.0
