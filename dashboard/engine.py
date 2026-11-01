"""
Dashboard scan engine – no Streamlit imports.

Provides ``scan()`` which runs the AgentFirewall cascade and returns a
plain-data ``Trace`` dataclass ready for the UI to render.
"""

from __future__ import annotations

import hashlib
import time
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from agent_firewall.cascade import Cascade, CascadeResult
from agent_firewall.judge import BaseJudge, JudgeResult, make_judge
from agent_firewall.policy import (
    PROFILES,
    Decision,
    Policy,
    RiskLevel,
    Thresholds,
)
from agent_firewall.rules import RULES

# ---------------------------------------------------------------------------
# Friendly rule labels (covers every rule in agent_firewall.rules.RULES)
# ---------------------------------------------------------------------------
FRIENDLY_RULE_LABELS: dict[str, str] = {
    "override_previous": "Overrides previous instructions",
    "new_instructions": "Claims new or updated instructions",
    "do_not_follow": "Tells AI not to follow original rules",
    "from_now_on": "Alters AI persona or behavior 'from now on'",
    "role_switch": "Attempts role-play or persona switch",
    "act_as": "Commands AI to act as another persona",
    "jailbreak_dan": "DAN / unrestricted persona jailbreak",
    "jailbreak_keywords": "Jailbreak / developer mode keywords",
    "fake_system_header": "Fake system or admin message header",
    "prompt_delimiters": "Prompt injection delimiters or tokens",
    "addressing_ai": "Direct command addressed to the AI model",
    "hidden_instruction": "Hidden HTML comment or zero-opacity text",
    "exfil_passwords": "Attempts to leak passwords or credentials",
    "exfil_targeted": "Targeted exfiltration to external URL or email",
    "external_address": "External URL or email address detected",
    "exfil_inbox": "Attempts to forward inbox or private messages",
    "exfil_files": "Attempts to extract private files or keys",
    "bulk_delete": "Bulk deletion or destructive command",
    "money_transfer": "Unauthorized money or crypto transfer command",
    "reveal_system_prompt": "Attempts to reveal system or secret prompt",
    "secrecy": "Instructs AI to hide action from user",
    "stealth_adverbs": "Stealth instructions (e.g. silently, covertly)",
    "authority_claim": "False administrator or developer authority claim",
    "higher_priority": "Claims instruction has higher priority or authority",
    "spoof_judge_verdict": "Fakes safe verdict JSON to trick judge",
    "spoof_judge_reasoning": "Fakes benign reasoning to spoof evaluation",
    "close_fence": "Attempts to escape untrusted text delimiters",
    "instruction_to_ai": "Imperative command forcing AI compliance",
    "transmit_command": "Direct command to transmit data externally",
}


def get_friendly_rule_label(rule_name: str) -> str:
    """Return a human-readable label for a rule name, falling back to title-case."""
    return FRIENDLY_RULE_LABELS.get(rule_name, rule_name.replace("_", " ").title())


# ---------------------------------------------------------------------------
# Trace dataclass – the engine's output
# ---------------------------------------------------------------------------
PROFILE_HELP: dict[str, str] = {
    "strict": "For payments, admin tools, and high-security operations",
    "balanced": "Default – good protection with low false alarms",
    "lenient": "For high-throughput or low-risk browsing workloads",
}


@dataclass
class Trace:
    """Complete scan result – everything the UI needs to render."""

    # Layer scores
    rules_score: float
    rules_hits: list[str]            # friendly labels
    classifier_score: Optional[float]
    judge_score: Optional[float]
    judge_status: str                 # "precomputed" / "skipped: earlier layer already sure" / "off" / "not run in this demo" / "live"

    # Combined
    combined_suspicion: float
    uncertain_band: tuple[float, float]
    tool_risk: RiskLevel
    thresholds: Thresholds
    decision: Decision

    # Decisions across risk levels (computed via policy.py)
    decision_by_risk: dict[RiskLevel, Decision]

    # Latencies
    rules_latency_ms: float
    classifier_latency_ms: float
    judge_latency_ms: float

    # Human-readable
    reasons: list[str]

    # Judge reasoning (from cache or live)
    judge_reasoning: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON download, converting enums to strings."""
        d = asdict(self)
        d["tool_risk"] = self.tool_risk.value
        d["decision"] = self.decision.value
        d["thresholds"] = {"ask": self.thresholds.ask, "block": self.thresholds.block}
        d["decision_by_risk"] = {k.value: v.value for k, v in self.decision_by_risk.items()}
        return d


# ---------------------------------------------------------------------------
# Ollama reachability (no Streamlit import)
# ---------------------------------------------------------------------------
def check_ollama_reachable(base_url: str = "http://localhost:11434") -> bool:
    """Check whether local Ollama is reachable with 1 s timeout."""
    try:
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/api/tags",
            headers={"User-Agent": "agent-firewall-dashboard"},
        )
        handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(handler)
        with opener.open(req, timeout=1.0) as resp:
            return resp.status == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CloudDemoJudge – uses cached verdicts for benchmark examples
# ---------------------------------------------------------------------------
class CloudDemoJudge(BaseJudge):
    """Returns verified precomputed verdicts for benchmark examples; handles custom text."""

    def __init__(self, precomputed: dict[str, dict[str, Any]], live_judge: Optional[BaseJudge] = None) -> None:
        self.precomputed = precomputed
        self.live_judge = live_judge

    def check_available(self) -> tuple[bool, str]:
        if self.live_judge:
            return self.live_judge.check_available()
        return True, ""

    def evaluate(self, text: str) -> JudgeResult:
        key = hashlib.sha256(text.strip().encode("utf-8")).hexdigest()[:16]
        if key in self.precomputed:
            entry = self.precomputed[key]
            return JudgeResult(
                suspicion=entry["suspicion"],
                raw_is_injection=entry.get("raw_is_injection"),
                raw_confidence=entry.get("raw_confidence"),
                reason=entry.get("reason", "Precomputed Ollama (llama3.2:3b) v2 verdict"),
                error=None,
                latency_ms=entry.get("latency_ms", 3500.0),
            )

        if self.live_judge:
            avail, _ = self.live_judge.check_available()
            if avail:
                return self.live_judge.evaluate(text)

        # Custom text without live judge – return with error so cascade skips/zeros
        return JudgeResult(
            suspicion=0.0,
            raw_is_injection=False,
            raw_confidence=0.0,
            reason="Live LLM judge unavailable in cloud demo mode. Rules and classifier evaluated live.",
            error="Live LLM judge disabled (Ollama server not reachable)",
            latency_ms=0.0,
        )


# ---------------------------------------------------------------------------
# Verdict sentence generator
# ---------------------------------------------------------------------------
def generate_verdict_sentence(
    decision: Decision,
    suspicion: float,
    risk: RiskLevel = RiskLevel.HIGH,
    tool_name: Optional[str] = None,
    rule_hits: Optional[list[str]] = None,
    judge_reason: Optional[str] = None,
) -> str:
    """Generate a one-sentence plain-English explanation of the verdict."""
    pct = f"{int(round(suspicion * 100))}%"
    tool_desc = tool_name or (
        "sending email"
        if risk == RiskLevel.HIGH
        else ("saving a note" if risk == RiskLevel.MEDIUM else "reading data")
    )
    risk_desc = f"{risk.value}-risk action"

    if decision == Decision.BLOCK:
        if rule_hits:
            friendly_hits = [get_friendly_rule_label(h).lower() for h in rule_hits[:2]]
            trigger_desc = f"hidden command patterns ({', '.join(friendly_hits)})"
        elif judge_reason:
            trigger_desc = "untrusted command injection patterns"
        else:
            trigger_desc = "malicious instruction patterns"
        return f"Blocked: the content contained {trigger_desc} (suspicion {pct}), and {tool_desc} is a {risk_desc}."

    if decision == Decision.ASK:
        return f"Ask the user: the content showed moderate suspicion (suspicion {pct}), so {tool_desc} requires human confirmation as a {risk_desc}."

    return f"Allowed: the text contained no suspicious commands (suspicion {pct}), and {tool_desc} is safe to proceed as a {risk_desc}."


# ---------------------------------------------------------------------------
# Honest note
# ---------------------------------------------------------------------------
def get_honest_note(
    example_id: Optional[str],
    rules_score: float,
    classifier_score: Optional[float],
    judge_score: Optional[float],
) -> Optional[str]:
    """Return a short honest note when layers diverge or an AI judge was fooled."""
    if example_id == "a011":
        return (
            "The AI judge was tricked by raw Base64 encoding (gave 0% suspicion), "
            "but the rules layer decoded and caught it (100%). This is why we use defense-in-depth layers."
        )
    if example_id == "a021":
        return (
            "The attacker injected fake JSON reasoning to spoof the evaluation (judge gave 1%), "
            "but the rules layer caught the prompt injection delimiter (100%)."
        )
    if example_id == "a015":
        return (
            "English regex rules missed this multilingual phrasing (20%), "
            "but the calibrated ML classifier caught it immediately (99%)."
        )
    if rules_score >= 0.8 and judge_score is not None and judge_score < 0.3:
        return (
            "The AI judge was tricked here, but the rules layer still caught it. "
            "This is why multiple defense layers are essential."
        )
    if rules_score < 0.3 and classifier_score is not None and classifier_score >= 0.8:
        return (
            "Rule patterns did not match this exact phrasing, but the statistical classifier "
            "caught the underlying injection pattern."
        )
    return None


# ---------------------------------------------------------------------------
# Build helpers
# ---------------------------------------------------------------------------
def build_precomputed_map(examples: list[dict[str, Any]], demo_emails: list[tuple[str, dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    """Build hash -> cached-verdict map from examples and demo emails."""
    m: dict[str, dict[str, Any]] = {}
    for ex in examples:
        key = hashlib.sha256(ex["text"].strip().encode("utf-8")).hexdigest()[:16]
        m[key] = ex["cached_verdict"]
    for text, verdict in demo_emails:
        key = hashlib.sha256(text.strip().encode("utf-8")).hexdigest()[:16]
        m[key] = verdict
    return m


def build_cascade(
    precomputed_map: dict[str, dict[str, Any]],
    judge_mode: str,
    classifier: object | None,
    combine: str = "gated",
    profile: str = "balanced",
    ollama_reachable: bool = False,
) -> Cascade:
    """Build a Cascade object for the given judge mode."""
    if judge_mode == "off" or judge_mode == "none":
        judge_obj = None
    elif judge_mode == "mock":
        judge_obj = make_judge("mock", prompt_version="v2")
    elif judge_mode == "live" and ollama_reachable:
        live_ollama = make_judge("ollama", model="llama3.2:3b", prompt_version="v2")
        judge_obj = CloudDemoJudge(precomputed=precomputed_map, live_judge=live_ollama)
    else:
        # "precomputed" or live not reachable
        judge_obj = CloudDemoJudge(precomputed=precomputed_map, live_judge=None)

    return Cascade(judge=judge_obj, classifier=classifier, combine=combine, profile=profile)


# ---------------------------------------------------------------------------
# scan() – the main engine function
# ---------------------------------------------------------------------------
def scan(
    text: str,
    tool_risk: RiskLevel,
    profile: str,
    judge_mode: str,
    cascade: Cascade,
    precomputed_map: dict[str, dict[str, Any]],
) -> Trace:
    """
    Run the full cascade and return a Trace dataclass.

    Parameters
    ----------
    text : str
        The untrusted text to scan.
    tool_risk : RiskLevel
        The risk level of the tool the agent wants to invoke.
    profile : str
        Policy profile name ("strict", "balanced", "lenient").
    judge_mode : str
        "precomputed", "off", "live", "none", "mock".
    cascade : Cascade
        A pre-built Cascade object.
    precomputed_map : dict
        Hash -> cached verdict map for benchmark texts.
    """
    if not text or not text.strip():
        policy = Policy(profile=profile)
        thresholds = policy.thresholds[tool_risk]
        return Trace(
            rules_score=0.0,
            rules_hits=[],
            classifier_score=None,
            judge_score=None,
            judge_status="off",
            combined_suspicion=0.0,
            uncertain_band=policy.uncertain_band,
            tool_risk=tool_risk,
            thresholds=thresholds,
            decision=Decision.ALLOW,
            decision_by_risk={r: Decision.ALLOW for r in RiskLevel},
            rules_latency_ms=0.0,
            classifier_latency_ms=0.0,
            judge_latency_ms=0.0,
            reasons=["Empty text – nothing to scan."],
        )

    result: CascadeResult = cascade.evaluate(text)
    policy = Policy(profile=profile)
    decision = policy.decide(result.suspicion, tool_risk)
    decision_by_risk = policy.decide_all(result.suspicion)
    thresholds = policy.thresholds[tool_risk]

    # Extract layer info
    rules_layer = result.layers[0] if result.layers else None
    rules_score = rules_layer.score if rules_layer else 0.0
    rules_hits_raw = rules_layer.hits if rules_layer else []
    rules_hits = [get_friendly_rule_label(h) for h in rules_hits_raw]
    rules_latency = rules_layer.latency_ms if rules_layer else 0.0

    clf_layer = result.layers[1] if len(result.layers) > 1 else None
    classifier_score: Optional[float] = None
    clf_latency = 0.0
    if clf_layer and not clf_layer.skipped:
        classifier_score = clf_layer.score
        clf_latency = clf_layer.latency_ms

    # Judge
    judge_layer = result.layers[2] if len(result.layers) > 2 else None
    judge_score: Optional[float] = None
    judge_latency = 0.0
    judge_reasoning: Optional[str] = None

    # Determine judge status string
    text_key = hashlib.sha256(text.strip().encode("utf-8")).hexdigest()[:16]
    is_bench_match = text_key in precomputed_map
    cached_entry = precomputed_map.get(text_key)

    if judge_mode in ("off", "none") or (not is_bench_match and judge_mode != "live"):
        judge_status = "not run in this demo"
    elif is_bench_match and cached_entry:
        if judge_layer and judge_layer.skipped:
            judge_status = "skipped: earlier layer already sure"
            # Still provide the cached reasoning for display
            judge_reasoning = cached_entry.get("reason")
        else:
            judge_status = "precomputed"
            judge_score = cached_entry["suspicion"]
            judge_reasoning = cached_entry.get("reason")
            judge_latency = cached_entry.get("latency_ms", 0.0)
    elif judge_mode == "live" and judge_layer and not judge_layer.skipped and not judge_layer.error:
        judge_status = "live"
        judge_score = judge_layer.score
        judge_latency = judge_layer.latency_ms
        judge_reasoning = judge_layer.reason
    elif judge_layer and judge_layer.skipped:
        judge_status = "skipped: earlier layer already sure"
    else:
        judge_status = "not run in this demo"

    # Build reasons list
    reasons: list[str] = []
    if rules_hits:
        reasons.append(f"Rules matched: {', '.join(rules_hits[:3])}")
    if classifier_score is not None and classifier_score >= 0.5:
        reasons.append(f"ML classifier flagged with {int(round(classifier_score * 100))}% confidence")
    if judge_reasoning and judge_status in ("precomputed", "live"):
        reasons.append(f"Judge reasoning: {judge_reasoning}")
    reason_sentence = generate_verdict_sentence(
        decision=decision,
        suspicion=result.suspicion,
        risk=tool_risk,
        rule_hits=rules_hits_raw,
        judge_reason=judge_reasoning,
    )
    reasons.insert(0, reason_sentence)

    return Trace(
        rules_score=rules_score,
        rules_hits=rules_hits,
        classifier_score=classifier_score,
        judge_score=judge_score,
        judge_status=judge_status,
        combined_suspicion=result.suspicion,
        uncertain_band=policy.uncertain_band,
        tool_risk=tool_risk,
        thresholds=thresholds,
        decision=decision,
        decision_by_risk=decision_by_risk,
        rules_latency_ms=rules_latency,
        classifier_latency_ms=clf_latency,
        judge_latency_ms=judge_latency,
        reasons=reasons,
        judge_reasoning=judge_reasoning,
    )
