"""
Detection cascade: rules -> classifier (optional) -> LLM judge.

Skips later layers when an earlier one is decisive (score >= 0.90).
Combine modes:
  - "max":    judge can only raise suspicion (default)
  - "blend":  judge can also lower it (weighted average)
  - "verify": judge verifies rule hits (>=0.5); only lowers if is_injection=false and confidence>=0.8
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from agent_firewall.judge import BaseJudge, JudgeResult
from agent_firewall.policy import DEFAULT_UNCERTAIN_BAND, PROFILE_UNCERTAIN_BANDS
from agent_firewall.rules import RulesResult
from agent_firewall.rules import scan as scan_rules


@dataclass
class LayerScore:
    """Score from a single cascade layer."""
    name: str
    score: float
    latency_ms: float
    skipped: bool = False
    hits: list[str] = field(default_factory=list)
    reason: str = ""
    error: Optional[str] = None


@dataclass
class CascadeResult:
    """Full cascade result with per-layer details."""
    suspicion: float  # final combined score
    layers: list[LayerScore] = field(default_factory=list)
    total_latency_ms: float = 0.0

    @property
    def rules_score(self) -> float:
        for layer in self.layers:
            if layer.name == "rules":
                return layer.score
        return 0.0

    @property
    def classifier_score(self) -> Optional[float]:
        for layer in self.layers:
            if layer.name == "classifier" and not layer.skipped:
                return layer.score
        return None

    @property
    def judge_score(self) -> Optional[float]:
        for layer in self.layers:
            if layer.name == "judge" and not layer.skipped:
                return layer.score
        return None


# Threshold above which we skip later layers
DECISIVE_THRESHOLD = 0.90


class Cascade:
    """
    Detection cascade: rules -> classifier (optional) -> judge.

    Parameters
    ----------
    judge : BaseJudge or None
        The LLM judge to use (can be None to skip).
    classifier : object or None
        A classifier with a predict_proba(text) -> float method.
    combine : str
        "max" (default), "blend", or "verify".
    """

    def __init__(
        self,
        judge: Optional[BaseJudge] = None,
        classifier: object | None = None,
        combine: str = "max",
        uncertain_band: Optional[tuple[float, float]] = None,
        profile: Optional[str] = None,
    ) -> None:
        self.judge = judge
        self.classifier = classifier
        if combine not in ("max", "blend", "verify", "gated"):
            raise ValueError(f"combine must be 'max', 'blend', 'verify', or 'gated', got {combine!r}")
        self.combine = combine
        self.profile = profile
        if uncertain_band is not None:
            self.uncertain_band = uncertain_band
        elif profile is not None and profile in PROFILE_UNCERTAIN_BANDS:
            self.uncertain_band = PROFILE_UNCERTAIN_BANDS[profile]
        else:
            self.uncertain_band = DEFAULT_UNCERTAIN_BAND

    def evaluate(self, text: str) -> CascadeResult:
        """Run the full cascade on *text*."""
        layers: list[LayerScore] = []

        # --- Layer 1: Rules -------------------------------------------------
        t0 = time.perf_counter()
        rules_result: RulesResult = scan_rules(text)
        rules_ms = (time.perf_counter() - t0) * 1000
        layers.append(LayerScore(
            name="rules",
            score=rules_result.score,
            latency_ms=rules_ms,
            hits=[h.name for h in rules_result.hits],
        ))

        rules_score = rules_result.score
        rules_fired = rules_score >= 0.5
        current_score = rules_score

        # --- Layer 2: Classifier (optional) ---------------------------------
        if self.classifier is not None and hasattr(self.classifier, "predict_proba"):
            if current_score >= DECISIVE_THRESHOLD:
                layers.append(LayerScore(
                    name="classifier",
                    score=0.0,
                    latency_ms=0.0,
                    skipped=True,
                    reason="Skipped: rules decisive",
                ))
            else:
                t0 = time.perf_counter()
                try:
                    clf_score = self.classifier.predict_proba(text)
                    clf_ms = (time.perf_counter() - t0) * 1000
                    layers.append(LayerScore(
                        name="classifier",
                        score=clf_score,
                        latency_ms=clf_ms,
                    ))
                    # Use max of rules and classifier
                    current_score = max(current_score, clf_score)
                except Exception as e:
                    clf_ms = (time.perf_counter() - t0) * 1000
                    layers.append(LayerScore(
                        name="classifier",
                        score=0.0,
                        latency_ms=clf_ms,
                        error=str(e),
                    ))
        else:
            layers.append(LayerScore(
                name="classifier",
                score=0.0,
                latency_ms=0.0,
                skipped=True,
                reason="Not available",
            ))

        # --- Layer 3: Judge -------------------------------------------------
        if self.judge is not None:
            if self.combine == "gated":
                lo, hi = self.uncertain_band
                in_band = (lo <= current_score <= hi)
                skip_judge = not in_band
                skip_reason = f"Skipped: score {current_score:.2f} outside uncertain band [{lo:.2f}, {hi:.2f}]"
            elif self.combine == "verify":
                # In 'verify' mode, always call the judge when rules fire (score >= 0.5), even if rules >= 0.90
                skip_judge = (current_score >= DECISIVE_THRESHOLD) and not rules_fired
                skip_reason = "Skipped: earlier layers decisive"
            else:
                skip_judge = (current_score >= DECISIVE_THRESHOLD)
                skip_reason = "Skipped: earlier layers decisive"

            if skip_judge:
                layers.append(LayerScore(
                    name="judge",
                    score=0.0,
                    latency_ms=0.0,
                    skipped=True,
                    reason=skip_reason,
                ))
            else:
                judge_result: JudgeResult = self.judge.evaluate(text)
                judge_layer = LayerScore(
                    name="judge",
                    score=judge_result.suspicion,
                    latency_ms=judge_result.latency_ms,
                    reason=judge_result.reason,
                    error=judge_result.error,
                )
                layers.append(judge_layer)

                if self.combine in ("max", "gated"):
                    # in gated mode, the judge may only raise suspicion
                    current_score = max(current_score, judge_result.suspicion)
                elif self.combine == "blend":
                    # Weighted average: rules have more weight
                    current_score = 0.5 * current_score + 0.5 * judge_result.suspicion
                elif self.combine == "verify":
                    if rules_fired:
                        # Judge may lower suspicion only if it returns is_injection=false with confidence >= 0.8;
                        # otherwise keep the rules score.
                        is_inj = judge_result.raw_is_injection
                        conf = judge_result.raw_confidence
                        if conf is None and not judge_result.error:
                            conf = 1.0 - judge_result.suspicion if is_inj is False else judge_result.suspicion
                        if not judge_result.error and is_inj is False and conf is not None and conf >= 0.8:
                            current_score = judge_result.suspicion
                        else:
                            current_score = max(rules_score, judge_result.suspicion) if (not judge_result.error and is_inj is True) else rules_score
                    else:
                        # When rules do not fire, behave as "max"
                        current_score = max(current_score, judge_result.suspicion)
        else:
            layers.append(LayerScore(
                name="judge",
                score=0.0,
                latency_ms=0.0,
                skipped=True,
                reason="No judge configured",
            ))

        total_ms = sum(layer.latency_ms for layer in layers if not layer.skipped)

        return CascadeResult(
            suspicion=min(1.0, max(0.0, current_score)),
            layers=layers,
            total_latency_ms=total_ms,
        )
