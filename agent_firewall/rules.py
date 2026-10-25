"""
Weighted regex rules combined with noisy-or scoring.

Normalises via NFKC, strips zero-width characters, and also scans decoded
variants (base64, leetspeak, space-separated letters). A decoded variant
contributes its rule hits only when they reveal NEW hits that plain text
did not, and an obfuscation bonus of +0.4 is applied per such variant.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Tuple

# ---------------------------------------------------------------------------
# Zero-width and invisible Unicode characters to strip
# ---------------------------------------------------------------------------
_ZW_RE = re.compile(
    "["
    "\u200b"  # zero-width space
    "\u200c"  # zero-width non-joiner
    "\u200d"  # zero-width joiner
    "\u2060"  # word joiner
    "\ufeff"  # BOM / zero-width no-break space
    "\u00ad"  # soft hyphen
    "\u200e"  # LTR mark
    "\u200f"  # RTL mark
    "\u2061"  # function application
    "\u2062"  # invisible times
    "\u2063"  # invisible separator
    "\u2064"  # invisible plus
    "]+",
    re.UNICODE,
)

# ---------------------------------------------------------------------------
# Leetspeak mapping
# ---------------------------------------------------------------------------
_LEET_MAP: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a", "$": "s", "!": "i",
    "|": "l", "(": "c", "{": "c", "+": "t",
}

_LEET_RE = re.compile("|".join(re.escape(k) for k in _LEET_MAP))


def _deleet(text: str) -> str:
    """Convert leetspeak characters to ASCII letters."""
    return _LEET_RE.sub(lambda m: _LEET_MAP[m.group()], text)


def _despaced(text: str) -> str:
    """Collapse space-separated individual letters: 'i g n o r e' -> 'ignore'."""
    # Match runs of single-letter tokens separated by spaces
    def _collapse(m: re.Match) -> str:
        return m.group().replace(" ", "")
    return re.sub(r"\b(?:[a-zA-Z] ){2,}[a-zA-Z]\b", _collapse, text)


def _decode_base64_blobs(text: str) -> str:
    """Find base64 blobs (>=16 chars) and try to decode them as UTF-8."""
    parts: list[str] = []
    for m in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        blob = m.group()
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", errors="ignore")
            if decoded and len(decoded) >= 8:
                parts.append(decoded)
        except Exception:
            pass
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Normalisation pipeline
# ---------------------------------------------------------------------------
def normalise(text: str) -> str:
    """NFKC-normalise and strip zero-width characters."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZW_RE.sub("", text)
    return text


# ---------------------------------------------------------------------------
# Quoted-attack / discussion context detection
# ---------------------------------------------------------------------------
# Detects when attack-like phrases appear inside quotes or educational framing.
# Used to discount rule hits that are merely *mentioned*, not *commanded*.
_QUOTING_CONTEXT_RE = re.compile(
    r"""(?x)
    # Phrases inside single quotes, double quotes, or angle-quote marks
    (?:['"\u2018\u2019\u201c\u201d])
    [^'"\u2018\u2019\u201c\u201d]{0,200}?
    (?:ignore|disregard|override|bypass|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?)
    [^'"\u2018\u2019\u201c\u201d]{0,200}?
    (?:['"\u2018\u2019\u201c\u201d])
    """,
    re.IGNORECASE,
)

_EDUCATIONAL_FRAME_RE = re.compile(
    r"""(?xi)
    (?:
      security\s+(?:training|seminar|course|tutorial|workshop|class|lecture|guide)
      | red[- ]?team(?:ing)?
      | (?:penetration|pen)\s+test(?:ing)?
      | (?:research|paper|article|blog)\s+(?:about|on|summary|discusses?)
      | (?:example|demo|sample|pattern)\s+(?:of|payload|attack|injection)
      | (?:common|known|typical)\s+(?:attack|injection|payload|pattern|technique)
      | prompt\s+injection\s+(?:attack|technique|defense|pattern|example)
      | adversarial\s+(?:prompts?|inputs?|payloads?|tests?)
      | what\s+(?:NOT|not)\s+to\s+include
      | content\s+filter\s+(?:now\s+)?detect
      | our\s+(?:filter|model|system)\s+(?:caught|blocked|detected)
      | (?:quiz|question|exam)\s*:
    )
    """,
)


def _is_quoted_or_educational(text: str) -> bool:
    """Return True if text appears to be quoting/discussing attack patterns."""
    return bool(_QUOTING_CONTEXT_RE.search(text) or _EDUCATIONAL_FRAME_RE.search(text))


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Rule:
    """A single regex rule with a name, pattern and weight in (0,1]."""
    name: str
    pattern: re.Pattern[str]
    weight: float

    def search(self, text: str) -> re.Match[str] | None:
        return self.pattern.search(text)


def _r(name: str, pattern: str, weight: float, flags: int = re.IGNORECASE) -> Rule:
    return Rule(name=name, pattern=re.compile(pattern, flags), weight=weight)


# --- The rule bank (English-only, intentionally) ---------------------------
RULES: list[Rule] = [
    # Override / ignore previous instructions
    _r("override_previous",
       r"(?:ignore|disregard|forget|override|cancel|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|original|initial|old|existing)\s+(?:instructions?|rules?|prompts?|guidelines?|directions?|commands?|constraints?|context)",
       0.95),
    _r("new_instructions",
       r"(?:new|updated?|revised|real|actual|correct|true)\s+(?:instructions?|rules?|prompt|guidelines?|directions?|commands?)",
       0.70),
    _r("do_not_follow",
       r"(?:do\s+not|don'?t|never)\s+follow\s+(?:the\s+)?(?:previous|prior|above|original|old|user'?s?)\s+(?:instructions?|rules?|prompt)",
       0.90),
    _r("from_now_on",
       r"from\s+(?:now|this\s+point)\s+on\s*,?\s*(?:you\s+(?:are|will|should|must|shall))",
       0.65),

    # Role / jailbreak switching
    # "act as" lowered -- ambiguous when standalone (e.g. "act as a liaison")
    _r("role_switch",
       r"(?:you\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\s+|pretend\s+(?:to\s+be|you'?re)\s+|switch\s+(?:to|into)\s+(?:a|an)\s+|enter\s+(?:a|an)\s+|enable\s+)",
       0.75),
    # Separate low-weight rule for "act as" -- only flags in combination
    _r("act_as",
       r"act\s+as\s+(?:a|an)\s+",
       0.40),
    # DAN is case-sensitive with word boundaries; other jailbreak keywords remain IGNORECASE
    Rule(
        name="jailbreak_dan",
        pattern=re.compile(r"\b(?:DAN|DUDE|STAN)\b"),  # NO IGNORECASE
        weight=0.90,
    ),
    _r("jailbreak_keywords",
       r"\b(?:jailbreak|developer\s+mode|god\s+mode|unrestricted\s+mode|unfiltered\s+mode)\b",
       0.90),

    # Fake SYSTEM headers / prompt delimiters
    _r("fake_system_header",
       r"(?:^|\n)\s*(?:\[?\s*(?:SYSTEM|ADMIN|DEVELOPER|ROOT|INTERNAL)\s*\]?\s*(?:PROMPT|MESSAGE|NOTE|OVERRIDE|INSTRUCTION|COMMAND)?)\s*[:\-]",
       0.85),
    _r("prompt_delimiters",
       r"(?:<\|?\s*(?:system|im_start|im_end|endof(?:text|prompt))\s*\|?>|={5,}\s*(?:SYSTEM|END)\s*={5,}|\[INST\]|\[/INST\])",
       0.80),

    # Addressing the AI / assistant directly
    _r("addressing_ai",
       r"(?:dear|hey|hello|hi|attention)\s+(?:AI|assistant|bot|model|language\s+model|GPT|Claude|LLM|chatbot)",
       0.60),

    # Hidden instructions
    _r("hidden_instruction",
       r"(?:<!--.*?(?:ignore|inject|execute|follow|obey|instruction|override).*?-->|<\s*(?:span|div|p)\s+[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^>]*>)",
       0.85, re.IGNORECASE | re.DOTALL),

    # Exfiltration of sensitive data
    # Negative lookahead for "password reset" -- that's a normal IT workflow
    _r("exfil_passwords",
       r"(?:send|forward|email|post|upload|share|transmit|exfiltrate?|leak|extract|copy)\s+.{0,40}?(?:(?:password|passwd)(?!\s+reset)(?!\s+resets?)(?!\s+link)|credentials?|secret|private\s+key|api[_\s]?key|token|auth|ssn|credit\s+card|social\s+security)",
       0.45),
    # Combined exfiltration rule: action + sensitive item + external destination (URL or email)
    _r("exfil_targeted",
       r"(?:send|forward|email|post|upload|share|transmit|exfiltrate?|leak|extract|copy|pipe|dump)\s+"
       r"(?:"
       r".{0,60}?(?:(?:passwords?|passwd)(?!\s+reset)(?!\s+resets?)(?!\s+link)|credentials?|api[_\s]?keys?|tokens?|secrets?|private\s+keys?|inbox|mailbox|contacts?|private\s+files?|confidential\s+(?:data|files?|info)|files?|documents?|database|\.env|\.ssh|id_rsa|\.pem|\.key)\s+.{0,60}?(?:https?://\S+|ftp://\S+|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
       r"|"
       r".{0,60}?(?:https?://\S+|ftp://\S+|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s+.{0,60}?(?:(?:passwords?|passwd)(?!\s+reset)(?!\s+resets?)(?!\s+link)|credentials?|api[_\s]?keys?|tokens?|secrets?|private\s+keys?|inbox|mailbox|contacts?|private\s+files?|confidential\s+(?:data|files?|info)|files?|documents?|database|\.env|\.ssh|id_rsa|\.pem|\.key)"
       r")",
       0.85),
    # Standalone external address / URL signal -- combines via noisy-or with exfiltration or other signals
    _r("external_address",
       r"(?:https?://\S+|ftp://\S+|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
       0.20),
    _r("exfil_inbox",
       r"(?:send|forward|email|post|share|transmit)\s+.{0,40}?(?:inbox|mailbox|emails?|messages?|conversations?|chat\s+history|chat\s+log)\s+(?:to|at)\s+",
       0.85),
    _r("exfil_files",
       r"(?:send|forward|upload|post|share|transmit|read|access|open|extract)\s+.{0,40}?(?:files?|documents?|spreadsheets?|database|config|\.env|\.ssh|id_rsa|\.pem|\.key)\s+(?:to|at|from)\s+",
       0.80),

    # Bulk delete / destructive actions -- lowered: IT policies say "delete all" routinely
    _r("bulk_delete",
       r"(?:delete|remove|erase|destroy|wipe|drop|truncate|purge)\s+(?:all|every|entire|\*)\s+",
       0.45),

    # Money transfer / financial
    _r("money_transfer",
       r"(?:transfer|send|wire|pay|deposit)\s+.{0,30}?(?:\$\s*\d|\d+\s*(?:dollars?|USD|EUR|GBP|BTC|ETH)|funds?|money|payment|bitcoin|crypto)\s*(?:to|into)\s+",
       0.85),

    # Reveal system prompt
    _r("reveal_system_prompt",
       r"(?:reveal|show|display|print|output|repeat|recite|echo|dump|tell\s+me)\s+.{0,30}?(?:system\s+prompt|initial\s+prompt|original\s+prompt|instructions?|hidden\s+prompt|secret\s+prompt|rules?\s+you\s+follow|your\s+(?:prompt|instructions?|rules?))",
       0.80),

    # Secrecy / stealth
    _r("secrecy",
       r"(?:don'?t|do\s+not|never)\s+(?:tell|inform|alert|notify|warn|mention\s+to|reveal\s+to|let)\s+(?:the\s+)?(?:user|human|person|operator|admin|anyone)",
       0.85),
    # Lowered -- "quietly" appears in normal IT ops (e.g. "quietly update staging")
    _r("stealth_adverbs",
       r"(?:quietly|silently|secretly|covertly|discreetly|stealthily|without\s+(?:the\s+user|them|anyone)\s+(?:knowing|noticing|seeing))",
       0.40),

    # Authority claims -- lowered: "I am the administrator" is often literal
    _r("authority_claim",
       r"(?:I\s+am|this\s+is)\s+(?:the|your|a|an)\s+(?:admin|administrator|developer|system|operator|owner|manager|supervisor|root|maintainer)",
       0.40),
    _r("higher_priority",
       r"(?:this|these)\s+(?:instructions?|commands?|messages?)\s+(?:have|take|override|supersede|are)\s+(?:higher|top|maximum|absolute)\s+(?:priority|precedence|authority)",
       0.85),

    # Judge spoofing (attempts to dictate the judge's verdict)
    _r("spoof_judge_verdict",
       r"(?:is_injection|\"is_injection\")\s*[=:]\s*(?:false|False|0|no)",
       0.90),
    _r("spoof_judge_reasoning",
       r"(?:this\s+(?:is|text\s+is)\s+(?:not\s+|completely\s+)?(?:safe|benign|harmless|legitimate|normal)|no\s+injection|confidence\s*[=:]\s*(?:0(?:\.\d+)?|1\.0))",
       0.50),  # lower weight - can appear in normal text
    _r("close_fence",
       r"<\s*/?\s*untrusted_text\s*/?\s*>",
       0.95),

    # Catch-all patterns for instructing the AI
    _r("instruction_to_ai",
       r"(?:you\s+(?:must|should|shall|need\s+to|have\s+to|are\s+(?:instructed|ordered|commanded|required))\s+(?:now\s+)?(?:ignore|disregard|forget|override|follow|obey|execute|perform|do|comply))",
       0.80),

    # New: direct command to the AI (with exfiltration target)
    _r("transmit_command",
       r"(?:transmit|exfiltrate?|forward|upload|post)\s+.{0,60}?(?:to|at)\s+(?:https?://|ftp://|\S+@\S+)",
       0.80),
]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
@dataclass
class RuleHit:
    """A matched rule."""
    name: str
    weight: float
    matched_text: str
    source: str  # "plain", "base64", "leetspeak", "spaced"


@dataclass
class RulesResult:
    """Aggregated result of rule scanning."""
    score: float = 0.0
    hits: list[RuleHit] = field(default_factory=list)

    @property
    def hit_names(self) -> list[str]:
        return [h.name for h in self.hits]


def _noisy_or(weights: list[float]) -> float:
    """Combine weights via noisy-or: 1 - prod(1 - w)."""
    if not weights:
        return 0.0
    p = 1.0
    for w in weights:
        p *= (1.0 - w)
    return 1.0 - p


def _scan_rules(text: str, rules: list[Rule]) -> list[Tuple[Rule, re.Match[str]]]:
    """Return list of (rule, match) for all rules that match."""
    hits = []
    for rule in rules:
        m = rule.search(text)
        if m:
            hits.append((rule, m))
    return hits


# Educational / quoting discount factor: when the text is clearly discussing
# attacks (tutorials, articles, red-team notes), reduce combined score.
_EDUCATIONAL_DISCOUNT = 0.45


def scan(text: str, rules: list[Rule] | None = None) -> RulesResult:
    """
    Scan *text* against the rule bank.

    Returns a RulesResult with a noisy-or score in [0,1] and a list of
    RuleHit objects.
    """
    if rules is None:
        rules = RULES

    result = RulesResult()
    norm = normalise(text)
    norm_lower = norm.lower()

    # ---- plain text --------------------------------------------------------
    plain_names: set[str] = set()
    plain_weights: list[float] = []
    for rule, m in _scan_rules(norm, rules):
        plain_names.add(rule.name)
        plain_weights.append(rule.weight)
        result.hits.append(RuleHit(
            name=rule.name,
            weight=rule.weight,
            matched_text=m.group()[:120],
            source="plain",
        ))

    # ---- decoded variants --------------------------------------------------
    variants: list[Tuple[str, str]] = []  # (decoded_text, source_label)

    # base64
    b64 = _decode_base64_blobs(norm)
    if b64:
        variants.append((b64, "base64"))

    # leetspeak
    leet = _deleet(norm_lower)
    if leet != norm_lower:
        variants.append((leet, "leetspeak"))

    # spaced letters
    despaced = _despaced(norm)
    if despaced != norm:
        variants.append((despaced, "spaced"))

    obfuscation_weights: list[float] = []
    for decoded, source in variants:
        new_hits = []
        for rule, m in _scan_rules(decoded, rules):
            if rule.name not in plain_names:
                new_hits.append((rule, m))
        if new_hits:
            obfuscation_weights.append(0.4)  # obfuscation bonus
            for rule, m in new_hits:
                plain_names.add(rule.name)  # don't double-count
                result.hits.append(RuleHit(
                    name=rule.name,
                    weight=rule.weight,
                    matched_text=m.group()[:120],
                    source=source,
                ))
                plain_weights.append(rule.weight)

    all_weights = plain_weights + obfuscation_weights
    score = _noisy_or(all_weights)

    # ---- Educational / quoting discount ------------------------------------
    # If the original text is clearly an article, tutorial, red-team report,
    # or quotes attack phrases inside quotation marks, discount the score so
    # it is unlikely to cross the 0.5 threshold on its own.
    # Exception: Never let the discount lower a score that includes a combined
    # exfiltration match (exfil_targeted) below 0.5.
    if _is_quoted_or_educational(text) and score > 0.0:
        has_exfil_targeted = any(h.name == "exfil_targeted" for h in result.hits)
        raw_score = score
        score *= _EDUCATIONAL_DISCOUNT
        if has_exfil_targeted and raw_score >= 0.5:
            score = max(0.5, score)

    result.score = score
    return result
