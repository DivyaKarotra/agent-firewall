"""
Copy, text content, and metadata for the AgentFirewall dashboard.

Keeps all user-facing copy, explanations, limitations, and links separate
from layout and UI components.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Brand & Author Metadata
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

# ---------------------------------------------------------------------------
# Hero Copy
# ---------------------------------------------------------------------------
HERO_BODY_TEXT = (
    "AI assistants read emails, documents, and web pages. Attackers hide commands "
    "inside them to hijack actions like forwarding passwords or data. "
    "AgentFirewall checks every action before execution to keep agents safe."
)

# ---------------------------------------------------------------------------
# Who It's For Copy
# ---------------------------------------------------------------------------
WHO_ITS_FOR_ITEMS = [
    {
        "title": "Agent Developers",
        "desc": (
            "Drop-in defense for LangChain, LlamaIndex, or custom agents.<br>"
            "Protect tool calls with a single line of Python code."
        ),
        "link_target": "#how-it-works",
        "link_label": "See integration &rarr;",
    },
    {
        "title": "Security & Red-Team Engineers",
        "desc": (
            "Calibrated risk thresholds with zero false alarms on safe text.<br>"
            "Full detection trace with latency and score breakdown per layer."
        ),
        "link_target": "#why-layers",
        "link_label": "Explore defense layers &rarr;",
    },
    {
        "title": "Researchers & Reviewers",
        "desc": (
            "Reproducible 115-sample benchmark across 10 attack classes.<br>"
            "Complete ablation data for rules, ML classifier, and LLM judge."
        ),
        "link_target": "#benchmarks",
        "link_label": "View benchmark results &rarr;",
    },
]

# ---------------------------------------------------------------------------
# How It Works Copy
# ---------------------------------------------------------------------------
HOW_IT_WORKS_STEPS = [
    {
        "step": "1",
        "title": "AI reads content",
        "desc": "Unchecked text from emails, web search results, or user documents enters the agent.",
        "icon": "doc",
    },
    {
        "step": "2",
        "title": "Firewall scores risk",
        "desc": "3 layers: Fast Rules (<1 ms) &rarr; Calibrated ML (~25 ms) &rarr; Gated AI Judge (~3 s).",
        "icon": "shield",
    },
    {
        "step": "3",
        "title": "Action-aware verdict",
        "desc": "Dangerous tools require strict checks: <strong>ALLOW</strong> / <strong>ASK</strong> / <strong>BLOCK</strong>.",
        "icon": "traffic",
    },
]

CODE_SNIPPET_INTEGRATION = """from agent_firewall import Cascade, Policy, Warden

warden = Warden(cascade=Cascade(), policy=Policy())
clean_result = warden.protect(tool_fn, *args, risk="high")"""

# ---------------------------------------------------------------------------
# Why Layers Copy
# ---------------------------------------------------------------------------
WHY_LAYERS_CARDS = [
    {
        "title": "Regex Rules",
        "icon": "rules",
        "speed": "<1 ms",
        "cost": "Free",
        "strengths": "Deterministic, instantaneous. Catches known delimiters, raw Base64, and hidden HTML comments without GPU compute.",
        "blind_spots": "Misses creative synonyms, multilingual attacks, or rephrased instructions that avoid literal keywords.",
    },
    {
        "title": "ML Classifier",
        "icon": "classifier",
        "speed": "~25 ms",
        "cost": "Minimal",
        "strengths": "Statistical n-gram & TF-IDF model. Catches paraphrased commands and multilingual patterns (e.g. Hinglish).",
        "blind_spots": "Lacks semantic understanding of complex multi-step workflows or contextual user instructions.",
    },
    {
        "title": "AI Judge",
        "icon": "judge",
        "speed": "~3.5 s",
        "cost": "High",
        "strengths": "Deep reasoning LLM. Understands nuanced conversational context, intent, and indirect injections.",
        "blind_spots": "100x slower, expensive, and can be tricked by adversarial jailbreak prompts or spoofed JSON.",
    },
]

GATED_CASCADE_ADVANTAGE = (
    "Instead of calling a slow 3-second LLM for every input, AgentFirewall executes "
    "Fast Rules and the ML Classifier first. If their verdict is clear (<35% or >75%), "
    "the system makes an instant decision in ~25 ms. The expensive AI Judge is only "
    "invoked for the borderline 15% of inputs, achieving <strong>85%+ protection</strong> "
    "while keeping <strong>over 80% of agent traffic sub-25ms</strong>."
)

# ---------------------------------------------------------------------------
# Limitations & Scope Copy (from docs/limitations.md)
# ---------------------------------------------------------------------------
LIMITATIONS_ITEMS = [
    (
        "Rules catch 0% of non-English attacks",
        "Regex rules rely on English vocabulary; on multilingual test sets, rules alone caught 0/12 (0.0%). The calibrated ML classifier caught 9/12 (75.0%), showing non-English inputs require statistical or LLM reasoning.",
    ),
    (
        "Small 3B judge flags educational & non-English benign texts",
        "The local llama3.2:3b judge can produce false alarms on benign non-English texts and security educational articles quoting exploit payloads.",
    ),
    (
        "Indirect attacks achieve ~70% catch rate without judge",
        "Complex indirection (e.g., hiding instructions in email footers or resume attachments) requires semantic LLM reasoning to exceed 70% detection.",
    ),
    (
        "Rule false positives on resume and contact forwarding",
        "Aggressive exfiltration heuristics may flag routine workplace requests like 'forward your resume to hr@example.com'.",
    ),
    (
        "~3.3 seconds per judge call on CPU",
        "Local evaluation of llama3.2:3b on CPU averages 3.36s per call. Gated cascading saves ~80% of calls, but active judge evaluations introduce noticeable latency.",
    ),
    (
        "Single-author dataset curation",
        "Benchmark datasets (115 fresh evaluation samples, 200 dev, 65 test) were hand-curated. Production enterprise workloads may feature different attack distributions.",
    ),
    (
        "Session-wide monotonic taint",
        "Warden taint tracking elevates suspicion monotonically for the entire session until explicitly reset via warden.reset().",
    ),
    (
        "Tool arguments not schema-scanned",
        "Warden inspects untrusted content and safeguards execution based on session taint and tool risk tier; it does not parse arbitrary outgoing tool argument schemas.",
    ),
]

NO_NOVELTY_CLAIM = (
    "AgentFirewall does not claim algorithmic novelty. It is an open-source, "
    "action-aware defense system combining established engineering practices "
    "(regex rules, calibrated ML classification, LLM-as-judge) with reproducible "
    "public benchmarks."
)

# ---------------------------------------------------------------------------
# FAQ & Explanations Copy
# ---------------------------------------------------------------------------
SUSPICION_SCORE_EXPLANATION = """
**Suspicion Score (0% to 100%):**
- **0%–34%:** Harmless, everyday workplace requests or clean text.
- **35%–74%:** Borderline or ambiguous phrasing requiring deeper evaluation.
- **75%–100%:** Blatant prompt injections or system override commands.
"""

TOOL_RISK_EXPLANATION = """
**Action Danger Levels:**
- **Low Risk:** Read-only operations (read email, web search). Allowed unless suspicion is high.
- **Medium Risk:** Internal modifications (save note, edit draft). Asks for confirmation on borderline inputs.
- **High Risk:** External or privileged actions (send email, delete records, pay). Blocks immediately on moderate-to-high suspicion.
"""
