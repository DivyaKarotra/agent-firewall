"""agent-firewall: a risk-aware firewall for LLM agent tool calls."""

__version__ = "0.1.0"

from agent_firewall.cascade import Cascade, CascadeResult, LayerScore
from agent_firewall.classifier import Classifier, is_available, load_data
from agent_firewall.judge import (
    BaseJudge,
    JudgeResult,
    MockJudge,
    OllamaJudge,
    OpenAICompatJudge,
    make_judge,
)
from agent_firewall.policy import (
    DEFAULT_THRESHOLDS,
    DEFAULT_UNCERTAIN_BAND,
    PROFILE_UNCERTAIN_BANDS,
    PROFILES,
    Decision,
    Policy,
    RiskLevel,
    Thresholds,
)
from agent_firewall.rules import RULES, Rule, RuleHit, RulesResult, normalise, scan
from agent_firewall.warden import ToolBlocked, Warden, cli_confirm, deny_all

__all__ = [
    "BaseJudge",
    "Cascade",
    "CascadeResult",
    "Classifier",
    "DEFAULT_THRESHOLDS",
    "DEFAULT_UNCERTAIN_BAND",
    "Decision",
    "JudgeResult",
    "LayerScore",
    "MockJudge",
    "OllamaJudge",
    "OpenAICompatJudge",
    "PROFILES",
    "PROFILE_UNCERTAIN_BANDS",
    "Policy",
    "RiskLevel",
    "Rule",
    "RuleHit",
    "RULES",
    "RulesResult",
    "Thresholds",
    "ToolBlocked",
    "Warden",
    "cli_confirm",
    "deny_all",
    "is_available",
    "load_data",
    "make_judge",
    "normalise",
    "scan",
]
