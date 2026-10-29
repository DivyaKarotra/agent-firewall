"""
Smoke tests for the Streamlit dashboard components and helper functions.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agent_firewall.cascade import CascadeResult
from agent_firewall.policy import Decision, Policy, RiskLevel
from agent_firewall.rules import RULES
from dashboard.app import (
    AUTHOR_NAME,
    CSS_STYLING,
    FRIENDLY_RULE_LABELS,
    PALETTE_PAIRS,
    REPO_URL,
    generate_verdict_sentence,
    get_cascade,
    get_classifier_model,
    get_friendly_rule_label,
    load_benchmark_results,
)


def _srgb_to_linear(val: float) -> float:
    c = val / 255.0
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _relative_luminance(hex_color: str) -> float:
    hex_clean = hex_color.lstrip("#")
    r = int(hex_clean[0:2], 16)
    g = int(hex_clean[2:4], 16)
    b = int(hex_clean[4:6], 16)
    return 0.2126 * _srgb_to_linear(r) + 0.7152 * _srgb_to_linear(g) + 0.0722 * _srgb_to_linear(b)


def _calculate_contrast_ratio(c1: str, c2: str) -> float:
    l1 = _relative_luminance(c1)
    l2 = _relative_luminance(c2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def test_dashboard_classifier_loader():
    """Verify that get_classifier_model returns a classifier or None gracefully."""
    clf = get_classifier_model()
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


def test_palette_pairs_wcag_contrast():
    """Verify that all PALETTE_PAIRS meet WCAG AA contrast ratio >= 4.5:1."""
    assert len(PALETTE_PAIRS) >= 10, "Expected at least 10 documented palette color pairs"
    for pair_name, (text_color, bg_color) in PALETTE_PAIRS.items():
        ratio = _calculate_contrast_ratio(text_color, bg_color)
        assert ratio >= 4.5, f"Palette pair '{pair_name}' ({text_color} on {bg_color}) has contrast {ratio:.2f}:1 (< 4.5:1)"


def test_footer_contains_repo_and_author():
    """Verify that footer metadata contains repo URL and author name."""
    assert "Divya Karotra" in AUTHOR_NAME
    assert "github.com/DivyaKarotra/agent-firewall" in REPO_URL


def test_css_text_opacity_and_contrast():
    """Verify that no CSS text color uses an alpha/opacity below 0.85."""
    # Check for any opacity rule below 0.85
    opacity_matches = re.findall(r"opacity:\s*(0\.\d+)", CSS_STYLING)
    for op in opacity_matches:
        assert float(op) >= 0.85, f"Found CSS opacity below 0.85: opacity: {op}"

    # Check for color declarations using rgba with alpha below 0.85
    rgba_text_matches = re.findall(r"color:\s*rgba\([^)]+,\s*([\d.]+)\)", CSS_STYLING)
    for alpha in rgba_text_matches:
        assert float(alpha) >= 0.85, f"Found CSS text color with alpha below 0.85: {alpha}"


def test_layout_and_responsive_css():
    """Verify that layout is wide via set_page_config, position: fixed for header,
    media query at 768px, clamp( usage, scroll-margin-top, and no default underline
    on nav/button links."""
    app_file = Path(__file__).parent.parent / "dashboard" / "app.py"
    app_content = app_file.read_text(encoding="utf-8")

    # 1. layout wide via set_page_config call
    assert 'layout="wide"' in app_content, "Expected layout='wide' in set_page_config call"

    # 2. position: fixed for the header
    assert re.search(r"position:\s*fixed", CSS_STYLING), "Expected position: fixed for header in CSS"

    # 3. a media query at 768px
    assert re.search(r"@media[^{]*768px", CSS_STYLING), "Expected media query at 768px in CSS"

    # 4. clamp( usage
    assert "clamp(" in CSS_STYLING, "Expected clamp() usage in CSS"

    # 5. scroll-margin-top
    assert "scroll-margin-top" in CSS_STYLING, "Expected scroll-margin-top in CSS"

    # 6. that no CSS rule sets underline on nav/button links by default
    nav_rule = re.search(r"\.nav-link-item\s*\{([^}]+)\}", CSS_STYLING)
    assert nav_rule, "Expected .nav-link-item CSS rule"
    assert "text-decoration: underline" not in nav_rule.group(1), ".nav-link-item must not have underline by default"

    cta_rule = re.search(r"\.hero-cta-btn\s*\{([^}]+)\}", CSS_STYLING)
    assert cta_rule, "Expected .hero-cta-btn CSS rule"
    assert "text-decoration: underline" not in cta_rule.group(1), ".hero-cta-btn must not have underline by default"

    cta_primary = re.search(r"\.hero-cta-primary\s*\{([^}]+)\}", CSS_STYLING)
    assert cta_primary, "Expected .hero-cta-primary CSS rule"
    assert "text-decoration: underline" not in cta_primary.group(1), ".hero-cta-primary must not have underline by default"

