"""
CLI entry point: python -m agent_firewall scan "text" [--judge none|mock|ollama|openai]
"""

from __future__ import annotations

import argparse
import sys

from agent_firewall.cascade import Cascade
from agent_firewall.judge import make_judge
from agent_firewall.policy import Policy, RiskLevel


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agent-firewall",
        description="Risk-aware firewall for LLM agent tool calls",
    )
    sub = parser.add_subparsers(dest="command")

    # scan command
    scan_p = sub.add_parser("scan", help="Scan text for prompt injection")
    scan_p.add_argument("text", help="Text to scan")
    scan_p.add_argument(
        "--judge", default="none",
        choices=["none", "mock", "ollama", "openai"],
        help="Judge to use (default: none)",
    )
    scan_p.add_argument("--model", default=None, help="Model for the judge")
    scan_p.add_argument(
        "--combine", default="max",
        choices=["max", "blend"],
        help="Combine mode (default: max)",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        _do_scan(args)


def _do_scan(args: argparse.Namespace) -> None:
    judge_kwargs = {}
    if args.model and args.judge in ("ollama", "openai"):
        judge_kwargs["model"] = args.model

    judge = make_judge(args.judge, **judge_kwargs)

    if judge is not None:
        avail, msg = judge.check_available()
        if not avail:
            print(f"[!]  Judge not available: {msg}", file=sys.stderr)
            print("   Continuing without judge.\n", file=sys.stderr)
            judge = None

    classifier = None
    try:
        from agent_firewall.classifier import MODEL_PATH, Classifier, is_available, load_data
        if is_available():
            clf = Classifier()
            if MODEL_PATH.exists():
                clf.load(MODEL_PATH)
            else:
                train_texts, train_labels, _, _ = load_data()
                clf.train(train_texts, train_labels, calibrate=True)
            classifier = clf
    except Exception:
        classifier = None

    cascade = Cascade(judge=judge, classifier=classifier, combine=args.combine)
    result = cascade.evaluate(args.text)

    # Print results
    print(f"\n{'='*60}")
    print("  agent-firewall scan result")
    print(f"{'='*60}")
    print(f"  Final suspicion:  {result.suspicion:.4f}")
    print(f"  Total latency:    {result.total_latency_ms:.1f} ms")
    print()

    for layer in result.layers:
        status = "SKIPPED" if layer.skipped else f"{layer.score:.4f}"
        print(f"  [{layer.name:12s}]  score={status:>10s}  latency={layer.latency_ms:.1f}ms")
        if layer.hits:
            print(f"                   hits: {', '.join(layer.hits)}")
        if layer.reason:
            reason_short = layer.reason[:100]
            print(f"                   reason: {reason_short}")
        if layer.error:
            print(f"                   error: {layer.error}")

    # Policy decisions
    policy = Policy()
    decisions = policy.decide_all(result.suspicion)
    print(f"\n  {'Risk Level':<12s}  Decision")
    print(f"  {'-'*12}  {'-'*8}")
    for risk in RiskLevel:
        dec = decisions[risk]
        marker = "[OK]" if dec.value == "ALLOW" else ("[?]" if dec.value == "ASK" else "[X]")
        print(f"  {risk.value:<12s}  {marker} {dec.value}")

    print()


if __name__ == "__main__":
    main()
