"""
Risk-aware policy engine.

Maps (suspicion, risk_level) -> ALLOW | ASK | BLOCK.

Default thresholds per risk level:
  low:    ASK=None (never ask), BLOCK=0.90
  medium: ASK=0.80,             BLOCK=0.90
  high:   ASK=0.75,             BLOCK=0.85
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Decision(Enum):
    ALLOW = "ALLOW"
    ASK = "ASK"
    BLOCK = "BLOCK"


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Thresholds:
    """Thresholds for a single risk level."""
    ask: Optional[float]   # None means never ASK -> go straight to BLOCK
    block: float


PROFILES: dict[str, dict[RiskLevel, Thresholds]] = {
    "strict": {
        RiskLevel.LOW:    Thresholds(ask=None,  block=0.85),
        RiskLevel.MEDIUM: Thresholds(ask=0.70,  block=0.85),
        RiskLevel.HIGH:   Thresholds(ask=0.50,  block=0.80),
    },
    "balanced": {
        RiskLevel.LOW:    Thresholds(ask=None,  block=0.90),
        RiskLevel.MEDIUM: Thresholds(ask=0.80,  block=0.90),
        RiskLevel.HIGH:   Thresholds(ask=0.75,  block=0.85),
    },
    "lenient": {
        RiskLevel.LOW:    Thresholds(ask=None,  block=0.95),
        RiskLevel.MEDIUM: Thresholds(ask=0.85,  block=0.95),
        RiskLevel.HIGH:   Thresholds(ask=0.80,  block=0.90),
    },
}

DEFAULT_THRESHOLDS: dict[RiskLevel, Thresholds] = PROFILES["balanced"]

PROFILE_UNCERTAIN_BANDS: dict[str, tuple[float, float]] = {
    "strict": (0.35, 0.75),
    "balanced": (0.35, 0.75),
    "lenient": (0.35, 0.80),
}

DEFAULT_UNCERTAIN_BAND: tuple[float, float] = PROFILE_UNCERTAIN_BANDS["balanced"]


class Policy:
    """
    Decide ALLOW / ASK / BLOCK based on suspicion and risk level.
    Supports named profiles: 'strict', 'balanced', 'lenient'.
    """

    def __init__(
        self,
        thresholds: Optional[dict[RiskLevel, Thresholds]] = None,
        profile: Optional[str] = None,
        uncertain_band: Optional[tuple[float, float]] = None,
    ) -> None:
        if profile is not None:
            if profile not in PROFILES:
                raise ValueError(
                    f"Unknown profile '{profile}'. Choose from: {list(PROFILES.keys())}"
                )
            self.profile = profile
            self.thresholds = dict(PROFILES[profile])
            self.uncertain_band = uncertain_band or PROFILE_UNCERTAIN_BANDS[profile]
        else:
            self.profile = "balanced"
            self.thresholds = thresholds or dict(DEFAULT_THRESHOLDS)
            self.uncertain_band = uncertain_band or DEFAULT_UNCERTAIN_BAND

    def decide(self, suspicion: float, risk: RiskLevel) -> Decision:
        """
        Given a suspicion score (0..1) and a risk level, return a Decision.
        """
        t = self.thresholds[risk]

        if suspicion >= t.block:
            return Decision.BLOCK

        if t.ask is not None and suspicion >= t.ask:
            return Decision.ASK

        return Decision.ALLOW

    def decide_all(self, suspicion: float) -> dict[RiskLevel, Decision]:
        """Return decisions for all risk levels."""
        return {r: self.decide(suspicion, r) for r in RiskLevel}
