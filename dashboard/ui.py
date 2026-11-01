"""
UI components, CSS design tokens, SVG icons, and HTML builders for AgentFirewall dashboard.

Keeps pure presentation logic cleanly isolated and unit-testable.
"""

from __future__ import annotations

import html
from typing import Any

from agent_firewall.policy import Decision

# ---------------------------------------------------------------------------
# Color Palette & Contrast Verification Pairs (WCAG AA >= 4.5:1)
# ---------------------------------------------------------------------------
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
# Inline SVGs
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
# Global CSS Styling
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

.strip-link {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: #22D3EE !important;
  font-size: 15px !important;
  font-weight: 600 !important;
  text-decoration: none !important;
  margin-top: 12px;
  transition: gap 0.15s ease;
}

.strip-link:hover, .strip-link:focus {
  text-decoration: underline !important;
  gap: 8px;
}

/* Live Demo Read-Only Styled Email Box */
.email-preview-box {
  background-color: #121A33;
  border: 1px solid #263261;
  border-radius: 12px;
  padding: 16px 20px;
  margin: 12px 0 24px 0;
}

.email-preview-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
  padding-bottom: 8px;
  border-bottom: 1px solid #263261;
}

.email-preview-badge {
  font-size: 14px !important;
  font-weight: 700 !important;
  text-transform: uppercase;
  padding: 3px 8px;
  border-radius: 6px;
  letter-spacing: 0.5px;
}

.email-preview-badge-attack {
  background: #300E12;
  color: #F87171;
  border: 1px solid #EF4444;
}

.email-preview-badge-normal {
  background: #0F2E1D;
  color: #22C55E;
  border: 1px solid #22C55E;
}

.email-preview-subject {
  font-size: 15px !important;
  color: #A9B3D1;
  font-family: 'JetBrains Mono', monospace !important;
}

.email-preview-body {
  color: #E8ECF8 !important;
  opacity: 1 !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 15px !important;
  line-height: 1.55 !important;
  white-space: pre-wrap !important;
  word-break: break-word !important;
  margin: 0 !important;
  background: transparent !important;
  padding: 0 !important;
}

/* Master-Detail Workspace Grid (Screens >= 1100px: 46% / 54%) */
@media (min-width: 1100px) {
  div.st-key-workspace_container > div[data-testid="stVerticalBlock"],
  div[class*="st-key-workspace_container"] > div[data-testid="stVerticalBlock"] {
    display: grid !important;
    grid-template-columns: minmax(0, 46%) minmax(0, 54%) !important;
    grid-template-areas:
      "samples result"
      "custom  result" !important;
    gap: 28px !important;
    align-items: start !important;
  }

  div[class*="st-key-workspace_samples"] {
    grid-area: samples !important;
    min-width: 0 !important;
  }

  div[class*="st-key-workspace_result"] {
    grid-area: result !important;
    min-width: 0 !important;
    position: sticky !important;
    top: 96px !important;
    align-self: start !important;
  }

  div[class*="st-key-workspace_custom"] {
    grid-area: custom !important;
    min-width: 0 !important;
  }
}

/* Master-Detail Workspace Stacked Layout (Screens < 1100px) */
@media (max-width: 1099px) {
  div.st-key-workspace_container > div[data-testid="stVerticalBlock"],
  div[class*="st-key-workspace_container"] > div[data-testid="stVerticalBlock"] {
    display: flex !important;
    flex-direction: column !important;
    gap: 24px !important;
  }

  div[class*="st-key-workspace_samples"] {
    order: 1 !important;
    width: 100% !important;
  }

  div[class*="st-key-workspace_result"] {
    order: 2 !important;
    width: 100% !important;
    position: static !important;
  }

  div[class*="st-key-workspace_custom"] {
    order: 3 !important;
    width: 100% !important;
  }
}

/* Benchmark Sample Cards: Container-wrapped, Equal Height by Construction */
div[class*="st-key-card_"] {
  height: 100% !important;
  display: flex !important;
  flex-direction: column !important;
  justify-content: space-between !important;
}

div[class*="st-key-card_"] > div[data-testid="stVerticalBlockBorderWrapper"],
div[class*="st-key-card_"] > div {
  height: 100% !important;
  display: flex !important;
  flex-direction: column !important;
  justify-content: space-between !important;
  padding: 16px !important;
  border-radius: 16px !important;
  border: 1px solid #263261 !important;
  background-color: #172042 !important;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25) !important;
  transition: border-color 0.15s ease, box-shadow 0.15s ease !important;
}

div[class*="st-key-card_"]:hover > div[data-testid="stVerticalBlockBorderWrapper"],
div[class*="st-key-card_"]:hover > div {
  border-color: #22D3EE !important;
}

/* Selected container state: cyan border + subtle cyan glow */
div[class*="st-key-card_"]:has(.sample-card-selected) > div[data-testid="stVerticalBlockBorderWrapper"],
div[class*="st-key-card_"]:has(.sample-card-selected) > div,
div[class*="st-key-card_"]:has(.sample-card-selected),
div[data-testid="stVerticalBlockBorderWrapper"]:has(.sample-card-selected) {
  border: 1px solid #22D3EE !important;
  box-shadow: 0 0 16px rgba(34, 211, 238, 0.35) !important;
}

.sample-card-inner {
  display: flex;
  flex-direction: column;
  flex: 1 1 auto;
}

.sample-tag-row {
  display: flex;
  align-items: center;
  gap: 8px;
  height: 28px;
  margin-bottom: 8px;
}

.ex-pill-attack {
  display: inline-block;
  background: #300E12;
  color: #F87171;
  border: 1px solid #EF4444;
  font-size: 14px !important;
  font-weight: 700 !important;
  padding: 3px 8px;
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
  padding: 3px 8px;
  border-radius: 6px;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}

.ex-pill-selected {
  display: inline-block;
  background: #163B48;
  color: #22D3EE;
  border: 1px solid #22D3EE;
  font-size: 14px !important;
  font-weight: 700 !important;
  padding: 3px 8px;
  border-radius: 6px;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}

.sample-card-title {
  font-size: 17px !important;
  font-weight: 700 !important;
  color: #E8ECF8 !important;
  line-height: 22px !important;
  height: 44px !important;
  display: -webkit-box !important;
  -webkit-line-clamp: 2 !important;
  -webkit-box-orient: vertical !important;
  overflow: hidden !important;
  margin-bottom: 8px !important;
}

.sample-card-desc {
  font-size: 14px !important;
  line-height: 20px !important;
  color: #A9B3D1 !important;
  height: 60px !important;
  display: -webkit-box !important;
  -webkit-line-clamp: 3 !important;
  -webkit-box-orient: vertical !important;
  overflow: hidden !important;
  margin-bottom: 12px !important;
}

div[class*="st-key-card_"] div[data-testid="stButton"] {
  margin-top: auto !important;
  width: 100% !important;
}

div[class*="st-key-card_"] div[data-testid="stButton"] button {
  width: 100% !important;
  font-size: 15px !important;
  height: 44px !important;
}

/* Empty State Card */
.empty-state-card {
  padding: 48px 32px;
  background: #172042;
  border: 1px dashed #263261;
  border-radius: 16px;
  text-align: center;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
  margin-top: 12px;
}

.empty-state-icon {
  font-size: 36px;
  margin-bottom: 12px;
  line-height: 1;
}

.empty-state-title {
  font-size: 20px !important;
  font-weight: 700;
  color: #E8ECF8;
  margin-bottom: 8px;
}

.empty-state-desc {
  font-size: 15px !important;
  color: #A9B3D1;
  max-width: 440px;
  margin: 0 auto;
  line-height: 1.55;
}

/* Ground Truth Badges */
.badge-correct {
  background: #0F2E1D;
  color: #22C55E;
  border: 1px solid #22C55E;
  padding: 3px 10px;
  border-radius: 6px;
  font-weight: 700;
  font-size: 14px;
  margin-left: 12px;
  letter-spacing: 0.5px;
}

.badge-missed {
  background: #300E12;
  color: #F87171;
  border: 1px solid #EF4444;
  padding: 3px 10px;
  border-radius: 6px;
  font-weight: 700;
  font-size: 14px;
  margin-left: 12px;
  letter-spacing: 0.5px;
}

.badge-false-alarm {
  background: #33260A;
  color: #F59E0B;
  border: 1px solid #F59E0B;
  padding: 3px 10px;
  border-radius: 6px;
  font-weight: 700;
  font-size: 14px;
  margin-left: 12px;
  letter-spacing: 0.5px;
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

# ---------------------------------------------------------------------------
# In-Page Navigation & Active Section Tracking Script
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

    var sectionIds = ['who-its-for', 'live-demo', 'scan-your-own-text', 'how-it-works', 'why-layers', 'benchmarks'];
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

# ---------------------------------------------------------------------------
# HTML Builders (Pure Functions, Testable)
# ---------------------------------------------------------------------------
def build_header_html(live: dict[str, bool], links: dict[str, str]) -> str:
    """Build the fixed 68px top navigation bar."""
    if live.get("docs", False):
        docs_nav = f'<a href="{links["docs"]}" target="_blank" rel="noopener noreferrer" class="nav-link-item">Docs</a>'
    else:
        docs_nav = '<span class="nav-link-item nav-link-disabled" title="Documentation site deploying soon">Docs <span class="nav-soon-pill">Soon</span></span>'

    if live.get("github", False):
        gh_btn = f'<a href="{links["github_repo"]}" target="_blank" rel="noopener noreferrer" class="nav-github-btn">GitHub</a>'
    else:
        gh_btn = '<span class="nav-github-btn nav-link-disabled">GitHub</span>'

    return f"""
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
    {docs_nav}
  </nav>
  <div class="header-right-action">
    {gh_btn}
  </div>
</header>
"""


def build_hero_html(brand_tagline: str, hero_body: str, stats_data: dict[str, Any]) -> str:
    """Build the 2-column hero container with a single CTA button."""
    catch_stat = stats_data.get("rules_classifier_catch", "83.9%")
    fp_stat = stats_data.get("rules_classifier_fp", "5.1%")
    samples_stat = stats_data.get("sample_count", 115)

    return f"""
<div class="hero-container">
  <div class="hero-grid">
    <div class="hero-left-col">
      <h1 class="hero-headline"><span class="brand-gradient-text">AgentFirewall</span></h1>
      <div class="hero-tagline">{brand_tagline}</div>
      <p class="hero-body-text">{hero_body}</p>
      <div class="hero-btn-row">
        <a href="#live-demo" target="_self" class="hero-cta-btn hero-cta-primary">Try the live demo &darr;</a>
      </div>
      <div class="hero-chips-row">
        <div class="hero-stat-chip"><strong>{catch_stat}</strong> attacks caught</div>
        <div class="hero-stat-chip"><strong>{fp_stat}</strong> false alarms</div>
        <div class="hero-stat-chip"><strong>{samples_stat}</strong> benchmark samples</div>
      </div>
    </div>
    <div class="hero-right-col">
      {HERO_ILLUSTRATION_SVG}
    </div>
  </div>
</div>
"""


def build_who_its_for_html(items: list[dict[str, str]]) -> str:
    """Build the Who It's For section cards."""
    cards_html = []
    for item in items:
        cards_html.append(
            f"""
  <div class="strip-card">
    <div class="strip-card-top">
      <span class="strip-title">{item['title']}</span>
    </div>
    <p class="strip-desc">{item['desc']}</p>
    <a href="{item['link_target']}" target="_self" class="strip-link">{item['link_label']}</a>
  </div>"""
        )
    cards_joined = "".join(cards_html)
    return f"""<div class="strip-container">{cards_joined}</div>"""


def build_email_preview_html(active_email: str, is_attack: bool, subject_text: str) -> str:
    """Build the read-only email preview box for Live Demo."""
    badge_class = "email-preview-badge-attack" if is_attack else "email-preview-badge-normal"
    badge_text = "Hidden Injection" if is_attack else "Benign Message"
    escaped_email = html.escape(active_email)
    return f"""
<div class="email-preview-box">
  <div class="email-preview-header">
    <span class="email-preview-badge {badge_class}">{badge_text}</span>
    <span class="email-preview-subject">{subject_text}</span>
  </div>
  <pre class="email-preview-body">{escaped_email}</pre>
</div>
"""


def build_verdict_banner_html(decision: Decision, sentence: str, gt_badge: str = "") -> str:
    """Build the solid dark verdict banner box with colored left border."""
    if decision == Decision.BLOCK:
        b_class, t_class, v_icon, v_head = (
            "verdict-banner-block",
            "verdict-title-block",
            "🛑",
            "BLOCKED",
        )
    elif decision == Decision.ASK:
        b_class, t_class, v_icon, v_head = (
            "verdict-banner-ask",
            "verdict-title-ask",
            "⚠️",
            "ASK THE USER",
        )
    else:
        b_class, t_class, v_icon, v_head = (
            "verdict-banner-allow",
            "verdict-title-allow",
            "✅",
            "ALLOWED",
        )

    return f"""
<div class="verdict-banner-box {b_class}">
  <div class="{t_class}">{v_icon} {v_head}{gt_badge}</div>
  <p class="verdict-body-text">{sentence}</p>
</div>
"""


def build_layer_cards_html(
    rules_pct: int,
    rules_time: str,
    chips_html: str,
    c_pill: str,
    c_note: str,
    clf_pct: int,
    j_pill: str,
    j_note: str,
    judge_pct: int,
) -> str:
    """Build the 3 layer cards grid."""
    return f"""
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
"""


def build_how_it_works_strip_html(steps: list[dict[str, str]]) -> str:
    """Build the 3-step strip in How It Works."""
    icons = {
        "doc": ICON_DOC_SVG,
        "shield": ICON_SHIELD_SVG,
        "traffic": ICON_TRAFFIC_SVG,
    }
    cards = []
    for s in steps:
        icon_svg = icons.get(s.get("icon", ""), ICON_SHIELD_SVG)
        cards.append(f"""
  <div class="strip-card">
    <div class="strip-card-top">
      <span class="strip-num-badge">{s['step']}</span>
      {icon_svg}
      <span class="strip-title">{s['title']}</span>
    </div>
    <p class="strip-desc">{s['desc']}</p>
  </div>""")
    return f"""<div class="strip-container">{''.join(cards)}</div>"""


def build_policy_matrix_html() -> str:
    """Build the 3x3 policy matrix table."""
    return """
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
"""


def build_footer_html(
    author_name: str, brand_name: str, live: dict[str, bool], links: dict[str, str]
) -> str:
    """Build the 3-column site footer with LIVE flags and LINKS references."""
    if live.get("github", False):
        footer_license = f'<a href="{links["license"]}" target="_blank" rel="noopener noreferrer" style="color:#22D3EE; font-weight:600; text-decoration:none;">MIT License</a> &middot; Open Source'
        res_github = f'<li><a href="{links["github_repo"]}" target="_blank" rel="noopener noreferrer">GitHub Repository</a></li>'
        res_issues = f'<li><a href="{links["issues"]}" target="_blank" rel="noopener noreferrer">Report a Bug / Issue</a></li>'
        footer_author = f'Built by <a href="{links["author_profile"]}" target="_blank" rel="noopener noreferrer" style="color:#22D3EE; font-weight:600; text-decoration:none;">{author_name}</a>'
    else:
        footer_license = 'MIT License &middot; Open Source'
        res_github = '<li><span class="footer-link-disabled">GitHub Repository (Coming Soon)</span></li>'
        res_issues = '<li><span class="footer-link-disabled">Report a Bug / Issue (Coming Soon)</span></li>'
        footer_author = f'Built by <span style="color:#22D3EE; font-weight:600;">{author_name}</span>'

    if live.get("docs", False):
        res_docs = f'<li><a href="{links["docs"]}" target="_blank" rel="noopener noreferrer">Documentation Site</a></li>'
    else:
        res_docs = '<li><span class="footer-link-disabled">Documentation Site (Coming Soon)</span></li>'

    if live.get("pypi", False):
        res_pypi = f'<li><a href="{links["pypi"]}" target="_blank" rel="noopener noreferrer">PyPI Package (agent-firewall-cascade)</a></li>'
    else:
        res_pypi = '<li><span class="footer-link-disabled">PyPI Package (Coming Soon)</span></li>'

    if live.get("dataset", False):
        res_dataset = f'<li><a href="{links["dataset"]}" target="_blank" rel="noopener noreferrer">HuggingFace Dataset Card</a></li>'
    else:
        res_dataset = '<li><span class="footer-link-disabled">HuggingFace Dataset (Coming Soon)</span></li>'

    return f"""
<footer class="site-footer">
  <div class="footer-grid">
    <div class="footer-col">
      <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
        {LOGO_SVG}
        <span class="footer-brand-name">{brand_name}</span>
      </div>
      <p class="footer-text">A risk-aware firewall for AI agents stopping prompt injection attacks.</p>
      <p class="footer-text">{footer_license}</p>
    </div>
    <div class="footer-col">
      <div class="footer-col-title">Resources &amp; Links</div>
      <ul class="footer-links-list">
        {res_github}
        {res_docs}
        {res_pypi}
        {res_dataset}
        {res_issues}
      </ul>
    </div>
    <div class="footer-col">
      <div class="footer-col-title">Author &amp; Research</div>
      <p class="footer-text">{footer_author}</p>
      <p class="footer-text">Research in AI Safety, Agent Tool Call Interception, and Prompt Injection Defense.</p>
    </div>
  </div>
  <div class="footer-bottom-bar">
    &copy; 2026 {author_name} &middot; Research prototype, not a guarantee of security &middot; Live demo runs rules + classifier; judge verdicts are precomputed.
  </div>
</footer>
"""
