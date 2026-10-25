"""
Warden: the main entry point that sits between an AI agent and its tools.

- protect(func, risk, name, untrusted_output): wraps a tool call
- Scans untrusted tool output and taints the session
- Checks policy, calls confirm callback for ASK, raises ToolBlocked for BLOCK
- Structured JSONL event log
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from agent_firewall.cascade import Cascade, CascadeResult
from agent_firewall.policy import Decision, Policy, RiskLevel


class ToolBlocked(Exception):
    """Raised when a tool call is blocked by the firewall."""

    def __init__(self, decision: Decision, reason: str, suspicion: float, tool_name: str) -> None:
        self.decision = decision
        self.reason = reason
        self.suspicion = suspicion
        self.tool_name = tool_name
        super().__init__(
            f"Tool '{tool_name}' {decision.value}: suspicion={suspicion:.2f} -- {reason}"
        )


def deny_all(tool_name: str, suspicion: float, cascade_result: CascadeResult) -> bool:
    """Default confirm callback: deny everything (safest default)."""
    return False


def cli_confirm(tool_name: str, suspicion: float, cascade_result: CascadeResult) -> bool:
    """Interactive CLI confirm callback."""
    print(f"\n[!]  FIREWALL ASK: tool '{tool_name}' (suspicion={suspicion:.2f})")
    for layer in cascade_result.layers:
        if not layer.skipped:
            print(f"   {layer.name}: {layer.score:.2f}", end="")
            if layer.hits:
                print(f" hits={layer.hits}", end="")
            if layer.reason:
                print(f" reason={layer.reason}", end="")
            print()
    answer = input("   Allow this call? [y/N] ").strip().lower()
    return answer in ("y", "yes")


@dataclass
class _Event:
    """A single event in the Warden log."""
    timestamp: float
    event_type: str
    tool_name: str
    risk: str
    suspicion: float
    decision: str
    rules_score: float = 0.0
    classifier_score: Optional[float] = None
    judge_score: Optional[float] = None
    rule_hits: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    error: Optional[str] = None
    confirmed: Optional[bool] = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "timestamp": self.timestamp,
            "event": self.event_type,
            "tool": self.tool_name,
            "risk": self.risk,
            "suspicion": round(self.suspicion, 4),
            "decision": self.decision,
            "rules_score": round(self.rules_score, 4),
            "latency_ms": round(self.latency_ms, 1),
        }
        if self.classifier_score is not None:
            d["classifier_score"] = round(self.classifier_score, 4)
        if self.judge_score is not None:
            d["judge_score"] = round(self.judge_score, 4)
        if self.rule_hits:
            d["rule_hits"] = self.rule_hits
        if self.error:
            d["error"] = self.error
        if self.confirmed is not None:
            d["confirmed"] = self.confirmed
        return d


# Map string risk names to RiskLevel
_RISK_MAP: dict[str, RiskLevel] = {
    "low": RiskLevel.LOW,
    "medium": RiskLevel.MEDIUM,
    "high": RiskLevel.HIGH,
}


class Warden:
    """
    Sits between an AI agent and its tools.

    Parameters
    ----------
    cascade : Cascade
        The detection cascade to use.
    policy : Policy
        The policy engine.
    confirm : callable
        Callback for ASK decisions: (tool_name, suspicion, cascade_result) -> bool.
    log_path : Path or None
        Path for the JSONL event log.
    """

    def __init__(
        self,
        cascade: Cascade,
        policy: Optional[Policy] = None,
        confirm: Callable[..., bool] = deny_all,
        log_path: Optional[Path] = None,
    ) -> None:
        self.cascade = cascade
        self.policy = policy or Policy()
        self.confirm = confirm
        self.log_path = log_path
        self._events: list[_Event] = []
        self._session_suspicion: float = 0.0  # worst suspicion seen

    @property
    def session_suspicion(self) -> float:
        return self._session_suspicion

    @property
    def suspicion(self) -> float:
        """Alias for session_suspicion."""
        return self._session_suspicion

    def reset(self) -> None:
        """Reset the session (clear taint and events)."""
        self._session_suspicion = 0.0
        self._events = []

    def _log_event(self, event: _Event) -> None:
        self._events.append(event)
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")

    def scan(self, text: str) -> CascadeResult:
        """Scan text through the cascade (no policy check)."""
        return self.cascade.evaluate(text)

    def protect(
        self,
        func: Callable[..., Any],
        *args: Any,
        risk: str = "medium",
        name: str = "",
        untrusted_output: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Protect a tool call.

        Parameters
        ----------
        func : callable
            The tool function to call.
        risk : str
            Risk level: "low", "medium", "high".
        name : str
            Human-readable tool name.
        untrusted_output : bool
            If True, the tool's return value is scanned and taints the session.
        """
        tool_name = name or getattr(func, "__name__", str(func))
        risk_level = _RISK_MAP.get(risk.lower(), RiskLevel.MEDIUM)

        # Use session suspicion for the decision
        suspicion = self._session_suspicion
        decision = self.policy.decide(suspicion, risk_level)

        # Build a cascade result for logging (from session taint, not a new scan)
        cascade_result = CascadeResult(suspicion=suspicion, layers=[], total_latency_ms=0)

        event = _Event(
            timestamp=time.time(),
            event_type="tool_call",
            tool_name=tool_name,
            risk=risk,
            suspicion=suspicion,
            decision=decision.value,
        )

        if decision == Decision.BLOCK:
            event.event_type = "tool_blocked"
            self._log_event(event)
            raise ToolBlocked(
                decision=decision,
                reason=f"Session suspicion {suspicion:.2f} exceeds block threshold for {risk} risk",
                suspicion=suspicion,
                tool_name=tool_name,
            )

        if decision == Decision.ASK:
            confirmed = self.confirm(tool_name, suspicion, cascade_result)
            event.confirmed = confirmed
            if not confirmed:
                event.event_type = "tool_denied"
                event.decision = "BLOCK"
                self._log_event(event)
                raise ToolBlocked(
                    decision=Decision.ASK,
                    reason=f"ASK denied by user for '{tool_name}' (suspicion={suspicion:.2f})",
                    suspicion=suspicion,
                    tool_name=tool_name,
                )
            event.event_type = "tool_approved"

        # Call the tool
        self._log_event(event)
        result = func(*args, **kwargs)

        # Scan untrusted output
        if untrusted_output and result is not None:
            text_to_scan = str(result)
            cr = self.cascade.evaluate(text_to_scan)
            self._session_suspicion = max(self._session_suspicion, cr.suspicion)

            scan_event = _Event(
                timestamp=time.time(),
                event_type="output_scan",
                tool_name=tool_name,
                risk=risk,
                suspicion=cr.suspicion,
                decision="TAINT" if cr.suspicion > 0 else "CLEAN",
                rules_score=cr.rules_score,
                classifier_score=cr.classifier_score,
                judge_score=cr.judge_score,
                rule_hits=[h for layer in cr.layers for h in layer.hits],
                latency_ms=cr.total_latency_ms,
            )
            self._log_event(scan_event)

        return result
