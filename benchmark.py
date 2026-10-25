"""
Benchmark: evaluate detection configurations on the dataset.

Usage:
  python benchmark.py --judge none --threshold 0.5
  python benchmark.py --judge mock
  python benchmark.py --judge ollama --model llama3.2:3b

Caches judge verdicts per text so every configuration reuses them.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from agent_firewall.cascade import Cascade
from agent_firewall.classifier import Classifier
from agent_firewall.classifier import is_available as sklearn_available
from agent_firewall.judge import BaseJudge, JudgeResult, make_judge
from agent_firewall.policy import Policy, RiskLevel
from agent_firewall.rules import scan as scan_rules

RESULTS_DIR = Path(__file__).parent / "results"
CACHE_DIR = RESULTS_DIR / ".cache"


# ---------------------------------------------------------------------------
# Wilson 95 % confidence interval
# ---------------------------------------------------------------------------
def _wilson_ci(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Return (lower, upper) Wilson score interval as percentages."""
    if total == 0:
        return (0.0, 0.0)
    p_hat = successes / total
    denom = 1 + z * z / total
    centre = (p_hat + z * z / (2 * total)) / denom
    spread = z * math.sqrt((p_hat * (1 - p_hat) + z * z / (4 * total)) / total) / denom
    lo = max(0.0, centre - spread) * 100
    hi = min(1.0, centre + spread) * 100
    return (lo, hi)


def _fmt_pct_ci(successes: int, total: int) -> str:
    """Format 'XX.X% [lo, hi]'."""
    if total == 0:
        return "N/A"
    pct = successes / total * 100
    lo, hi = _wilson_ci(successes, total)
    return f"{pct:.1f}% [{lo:.1f}, {hi:.1f}]"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
@dataclass
class Sample:
    id: str
    label: str  # "attack" or "normal"
    kind: str
    tool: str
    split: str  # "dev" or "test"
    text: str

    @property
    def is_attack(self) -> bool:
        return self.label == "attack"

    @property
    def risk(self) -> str:
        tool_risk = {"read_email": "low", "send_email": "high", "save_note": "medium"}
        return tool_risk.get(self.tool, "medium")


def load_samples(data_dir: Optional[Path] = None) -> list[Sample]:
    if data_dir is None:
        data_dir = Path(__file__).parent / "data"
    samples = []
    for jsonl_file in sorted(data_dir.glob("*.jsonl")):
        # Skip fresh_test.jsonl -- evaluated separately
        if jsonl_file.name == "fresh_test.jsonl":
            continue
        with open(jsonl_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                samples.append(Sample(**d))
    return samples


def load_fresh_test(data_dir: Optional[Path] = None, filename: str = "fresh_test.jsonl") -> list[Sample]:
    """Load a fresh test JSONL file, used for truly held-out evaluation."""
    if data_dir is None:
        data_dir = Path(__file__).parent / "data"
    path = data_dir / filename
    if not path.exists():
        return []
    samples = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            samples.append(Sample(**d))
    return samples


# ---------------------------------------------------------------------------
# Judge verdict cache
# ---------------------------------------------------------------------------
def _cache_key(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _load_cache(judge_name: str) -> dict[str, dict]:
    cache_file = CACHE_DIR / f"{judge_name}.json"
    if cache_file.exists():
        with open(cache_file, encoding="utf-8") as f:
            return json.load(f)
    return {}


def _save_cache(judge_name: str, cache: dict[str, dict]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"{judge_name}.json"
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


class CachedJudge(BaseJudge):
    """Wraps an LLM judge to cache verdicts per text in results/.cache/<name>.json."""

    def __init__(self, inner: BaseJudge, cache_name: str) -> None:
        self.inner = inner
        self.cache_name = cache_name
        self.cache = _load_cache(cache_name)

    def evaluate(self, text: str) -> JudgeResult:
        key = _cache_key(text)
        if key in self.cache:
            entry = self.cache[key]
            return JudgeResult(
                suspicion=entry["suspicion"],
                raw_is_injection=entry.get("raw_is_injection", entry.get("is_injection")),
                raw_confidence=entry.get("raw_confidence", entry.get("confidence")),
                reason=entry.get("reason", ""),
                error=entry.get("error"),
                latency_ms=entry.get("latency_ms", 0.0),
            )
        res = self.inner.evaluate(text)
        self.cache[key] = {
            "suspicion": res.suspicion,
            "raw_is_injection": res.raw_is_injection,
            "raw_confidence": res.raw_confidence,
            "latency_ms": res.latency_ms,
            "error": res.error,
            "reason": res.reason,
        }
        _save_cache(self.cache_name, self.cache)
        return res

    def check_available(self) -> tuple[bool, str]:
        return self.inner.check_available()


# ---------------------------------------------------------------------------
# Single-layer evaluators
# ---------------------------------------------------------------------------
def eval_rules_only(samples: list[Sample]) -> tuple[dict[str, float], dict[str, float]]:
    """Evaluate rules-only on samples, return (scores, latencies)."""
    scores = {}
    latencies = {}
    for s in samples:
        t0 = time.perf_counter()
        result = scan_rules(s.text)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        scores[s.id] = result.score
        latencies[s.id] = elapsed_ms
    return scores, latencies


def eval_classifier_only(
    train_samples: list[Sample],
    eval_samples: list[Sample],
) -> tuple[dict[str, float], dict[str, float]]:
    """Train classifier on train_samples (calibrated), evaluate on eval_samples."""
    if not sklearn_available():
        return {}, {}
    clf = Classifier()
    texts = [s.text for s in train_samples]
    labels = [1 if s.is_attack else 0 for s in train_samples]
    clf.train(texts, labels, calibrate=True)
    scores = {}
    latencies = {}
    for s in eval_samples:
        t0 = time.perf_counter()
        scores[s.id] = clf.predict_proba(s.text)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        latencies[s.id] = elapsed_ms
    return scores, latencies


def eval_judge_only(
    samples: list[Sample],
    judge: BaseJudge,
    judge_name: str,
) -> tuple[dict[str, float], dict[str, float], set[str], set[str], dict[str, float]]:
    """Evaluate judge on samples. Returns (scores, latencies, called_ids, error_ids, judge_latencies)."""
    scores = {}
    latencies = {}
    called_ids: set[str] = set()
    error_ids: set[str] = set()
    judge_latencies: dict[str, float] = {}

    for s in samples:
        called_ids.add(s.id)
        result = judge.evaluate(s.text)
        scores[s.id] = result.suspicion
        latencies[s.id] = result.latency_ms
        judge_latencies[s.id] = result.latency_ms
        if result.error:
            error_ids.add(s.id)
    return scores, latencies, called_ids, error_ids, judge_latencies


# ---------------------------------------------------------------------------
# Cascade evaluation
# ---------------------------------------------------------------------------
def eval_cascade(
    samples: list[Sample],
    judge: Optional[BaseJudge],
    judge_name: str,
    classifier: object | None,
    combine: str,
) -> tuple[dict[str, float], dict[str, float], set[str], set[str], dict[str, float]]:
    """Evaluate full cascade. Returns (scores, latencies, judge_called_ids, judge_error_ids, judge_latencies)."""
    cascade = Cascade(judge=judge, classifier=classifier, combine=combine)
    scores = {}
    latencies = {}
    judge_called_ids: set[str] = set()
    judge_error_ids: set[str] = set()
    judge_latencies: dict[str, float] = {}

    for s in samples:
        result = cascade.evaluate(s.text)
        scores[s.id] = result.suspicion
        latencies[s.id] = result.total_latency_ms
        for layer in result.layers:
            if layer.name == "judge" and not layer.skipped:
                judge_called_ids.add(s.id)
                judge_latencies[s.id] = layer.latency_ms
                if layer.error:
                    judge_error_ids.add(s.id)

    return scores, latencies, judge_called_ids, judge_error_ids, judge_latencies


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def compute_metrics(
    samples: list[Sample],
    scores: dict[str, float],
    threshold: float,
) -> dict:
    attacks = [s for s in samples if s.is_attack and s.id in scores]
    normals = [s for s in samples if not s.is_attack and s.id in scores]

    caught = sum(1 for s in attacks if scores[s.id] >= threshold)
    false_pos = sum(1 for s in normals if scores[s.id] >= threshold)

    return {
        "n_attacks": len(attacks),
        "n_normal": len(normals),
        "caught": caught,
        "caught_pct": caught / len(attacks) * 100 if attacks else 0,
        "false_pos": false_pos,
        "false_pos_pct": false_pos / len(normals) * 100 if normals else 0,
        "caught_ci": _fmt_pct_ci(caught, len(attacks)),
        "false_pos_ci": _fmt_pct_ci(false_pos, len(normals)),
    }


def compute_metrics_by_kind(
    samples: list[Sample],
    scores: dict[str, float],
    threshold: float,
) -> dict[str, dict]:
    by_kind: dict[str, list[Sample]] = defaultdict(list)
    for s in samples:
        if s.id in scores:
            by_kind[s.kind].append(s)

    results = {}
    for kind, kind_samples in sorted(by_kind.items()):
        attacks = [s for s in kind_samples if s.is_attack]
        normals = [s for s in kind_samples if not s.is_attack]
        caught = sum(1 for s in attacks if scores[s.id] >= threshold)
        fp = sum(1 for s in normals if scores[s.id] >= threshold)
        results[kind] = {
            "attacks": len(attacks),
            "caught": caught,
            "caught_pct": caught / len(attacks) * 100 if attacks else 0,
            "caught_ci": _fmt_pct_ci(caught, len(attacks)),
            "normals": len(normals),
            "false_pos": fp,
            "false_pos_pct": fp / len(normals) * 100 if normals else 0,
            "false_pos_ci": _fmt_pct_ci(fp, len(normals)),
        }
    return results


def compute_action_outcomes_by_risk(
    samples: list[Sample],
    scores: dict[str, float],
    policy: Policy,
) -> dict[RiskLevel, dict[str, dict[str, int]]]:
    """Compute ALLOW/ASK/BLOCK outcomes applying each sample under ALL three risk levels."""
    results = {}
    for risk in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]:
        outcomes = {"attacks": defaultdict(int), "normal": defaultdict(int)}
        for s in samples:
            if s.id not in scores:
                continue
            decision = policy.decide(scores[s.id], risk)
            bucket = "attacks" if s.is_attack else "normal"
            outcomes[bucket][decision.value] += 1
        results[risk] = outcomes
    return results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
def _write_ablation(
    configs: dict[str, dict],
    all_samples: list[Sample],
    threshold: float,
    suffix: str = "",
) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = RESULTS_DIR / f"ablation{suffix}.md"
    with open(out_file, "w", encoding="utf-8") as f:
        title = f"Ablation Study ({suffix.lstrip('_').upper()} Test Set)" if suffix else "Ablation Study"
        f.write(f"# {title}\n\n")
        f.write(f"Threshold: {threshold}\n\n")
        f.write("> [!NOTE]\n")
        f.write("> Percentages include Wilson 95% confidence intervals [lo, hi].\n")
        f.write("> Differences smaller than the intervals overlap are **not statistically significant**\n")
        f.write("> at the 95% level. With small N, intervals are wide -- treat narrow wins as noise.\n\n")

        # Main table
        f.write("| Configuration | Split | Attacks Caught | False Positive | Avg Latency (ms) | Judge Calls | Judge Time Saved (s) | Judge Errors |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")

        max_judge_time_ms = 0.0
        if "full_cascade_max" in configs:
            max_jl = configs["full_cascade_max"].get("judge_latencies", {})
            max_judge_time_ms = sum(max_jl.values())

        for name, cfg in configs.items():
            for split_name, split_samples in cfg.get("splits", {}).items():
                m = compute_metrics(split_samples, cfg["scores"], threshold)
                lats = [cfg["latencies"].get(s.id, 0) for s in split_samples if s.id in cfg["scores"]]
                avg_lat = sum(lats) / len(lats) if lats else 0
                j_calls = sum(1 for s in split_samples if s.id in cfg.get("judge_called_ids", set()))
                j_errs = sum(1 for s in split_samples if s.id in cfg.get("judge_error_ids", set()))

                this_jl = cfg.get("judge_latencies", {})
                this_j_time = sum(this_jl.get(s.id, 0) for s in split_samples if s.id in cfg.get("judge_called_ids", set()))
                if max_judge_time_ms > 0:
                    time_saved_s = (max_judge_time_ms - this_j_time) / 1000.0
                    saved_str = f"{time_saved_s:.1f}s"
                else:
                    saved_str = "0.0s"

                f.write(
                    f"| {name} | {split_name} "
                    f"| {m['caught_ci']} "
                    f"| {m['false_pos_ci']} "
                    f"| {avg_lat:.2f} | {j_calls} | {saved_str} | {j_errs} |\n"
                )

        # By kind
        f.write("\n## Attacks Caught by Kind\n\n")
        f.write("| Configuration | Kind | Caught/Total | % |\n")
        f.write("|---|---|---|---|\n")
        kinds_order = ["direct", "indirect", "multilingual", "reworded", "framed", "judge_targeted", "encoded"]
        for name, cfg in configs.items():
            by_kind = compute_metrics_by_kind(
                [s for s in all_samples if s.id in cfg["scores"]],
                cfg["scores"], threshold,
            )
            for kind in kinds_order:
                if kind in by_kind and by_kind[kind]["attacks"] > 0:
                    km = by_kind[kind]
                    f.write(f"| {name} | {kind} | {km['caught']}/{km['attacks']} | {km['caught_ci']} |\n")
            for kind, km in sorted(by_kind.items()):
                if kind not in kinds_order and km["attacks"] > 0:
                    f.write(f"| {name} | {kind} | {km['caught']}/{km['attacks']} | {km['caught_ci']} |\n")

        # Action outcomes
        f.write("\n## Action-Aware Outcomes\n\n")
        policy = Policy()

        max_judge_calls: Optional[int] = None
        if "full_cascade_max" in configs:
            max_cfg = configs["full_cascade_max"]
            max_judge_calls = sum(1 for s in all_samples if s.id in max_cfg.get("judge_called_ids", set()))

        for name, cfg in configs.items():
            f.write(f"\n### {name}\n\n")
            this_j = sum(1 for s in all_samples if s.id in cfg.get("judge_called_ids", set()))
            this_jl = cfg.get("judge_latencies", {})
            this_j_time = sum(this_jl.get(s.id, 0) for s in all_samples if s.id in cfg.get("judge_called_ids", set()))
            if max_judge_calls is not None:
                saved = max_judge_calls - this_j
                saved_time_s = (max_judge_time_ms - this_j_time) / 1000.0
                f.write(f"- **Judge calls**: {this_j} ({saved} calls saved vs full_cascade_max, {saved_time_s:.1f}s judge time saved)\n\n")
            else:
                f.write(f"- **Judge calls**: {this_j}\n\n")

            outcomes_by_risk = compute_action_outcomes_by_risk(
                [s for s in all_samples if s.id in cfg["scores"]],
                cfg["scores"], policy,
            )
            for risk in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]:
                t = policy.thresholds[risk]
                ask_str = f"{t.ask:.2f}" if t.ask is not None else "None"
                f.write(f"#### {risk.value.capitalize()} Risk Tools (ASK={ask_str}, BLOCK={t.block:.2f})\n\n")
                f.write("| | ALLOW | ASK | BLOCK |\n")
                f.write("|---|---|---|---|\n")
                outcomes = outcomes_by_risk[risk]
                for bucket in ["attacks", "normal"]:
                    f.write(f"| {bucket} | {outcomes[bucket].get('ALLOW', 0)} | {outcomes[bucket].get('ASK', 0)} | {outcomes[bucket].get('BLOCK', 0)} |\n")
                f.write("\n")


def _write_failures(
    configs: dict[str, dict],
    all_samples: list[Sample],
    threshold: float,
    suffix: str = "",
) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = RESULTS_DIR / f"failures{suffix}.md"
    with open(out_file, "w", encoding="utf-8") as f:
        title = "Failures Analysis (Fresh Test Set)" if suffix else "Failures Analysis"
        f.write(f"# {title}\n\n")
        f.write(f"Threshold: {threshold}\n\n")

        for name, cfg in configs.items():
            f.write(f"\n## {name}\n\n")

            # Missed attacks
            missed = [
                s for s in all_samples
                if s.is_attack and s.id in cfg["scores"] and cfg["scores"][s.id] < threshold
            ]
            f.write(f"### Missed Attacks ({len(missed)})\n\n")
            for s in missed:
                f.write(f"- **{s.id}** (split={s.split}, kind={s.kind}, score={cfg['scores'][s.id]:.4f}): {s.text[:100]}...\n")

            # False positives
            fps = [
                s for s in all_samples
                if not s.is_attack and s.id in cfg["scores"] and cfg["scores"][s.id] >= threshold
            ]
            f.write(f"\n### False Positives ({len(fps)})\n\n")
            for s in fps:
                f.write(f"- **{s.id}** (split={s.split}, kind={s.kind}, score={cfg['scores'][s.id]:.4f}): {s.text[:100]}...\n")


def _write_details_csv(
    configs: dict[str, dict],
    all_samples: list[Sample],
    suffix: str = "",
) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = RESULTS_DIR / f"details{suffix}.csv"
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        header = ["id", "label", "kind", "tool", "split"]
        for name in configs:
            header.append(f"{name}_score")
            header.append(f"{name}_latency_ms")
        writer.writerow(header)

        for s in all_samples:
            row = [s.id, s.label, s.kind, s.tool, s.split]
            for name, cfg in configs.items():
                row.append(f"{cfg['scores'].get(s.id, '')}")
                row.append(f"{cfg['latencies'].get(s.id, '')}")
            writer.writerow(row)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="agent-firewall benchmark")
    parser.add_argument(
        "--judge",
        default="none",
        choices=["none", "mock", "ollama", "openai", "ollama_v1", "ollama_v2", "openai_v1", "openai_v2"],
    )
    parser.add_argument(
        "--prompt-version",
        default="v2",
        choices=["v1", "v2"],
        help="Prompt version for LLM judge (default: v2)",
    )
    parser.add_argument("--model", default=None)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--data-dir", type=Path, default=None)
    parser.add_argument(
        "--split",
        choices=["test", "dev", "all", "fresh", "fresh2"],
        default="test",
        help="Evaluation split to report in summary table (default: test)",
    )
    parser.add_argument(
        "--fresh-test",
        type=Path,
        default=None,
        help="Path to fresh_test.jsonl (defaults to data/fresh_test.jsonl)",
    )
    args = parser.parse_args()

    # Mock judge warning
    if args.judge == "mock":
        print("=" * 65)
        print("  [!]  WARNING: Using MockJudge. All judge-based numbers are")
        print("     MEANINGLESS. Use --judge ollama or openai for real results.")
        print("=" * 65)
        print()

    # Load data
    all_samples = load_samples(args.data_dir)
    dev_samples = [s for s in all_samples if s.split == "dev"]
    test_samples = [s for s in all_samples if s.split == "test"]
    print(f"Loaded {len(all_samples)} samples ({len(dev_samples)} dev, {len(test_samples)} test)")
    print(f"  Attacks: {sum(1 for s in all_samples if s.is_attack)}")
    print(f"  Normal:  {sum(1 for s in all_samples if not s.is_attack)}")
    print()

    # Load fresh test if available
    fresh_filename = "fresh2_test.jsonl" if args.split == "fresh2" else "fresh_test.jsonl"
    fresh_dir = Path(args.fresh_test).parent if args.fresh_test else (args.data_dir or Path(__file__).parent / "data")
    if args.fresh_test:
        fresh_samples = load_fresh_test(fresh_dir, filename=Path(args.fresh_test).name)
    else:
        fresh_samples = load_fresh_test(args.data_dir, filename=fresh_filename)

    if fresh_samples:
        print(f"Fresh test set ({fresh_filename}): {len(fresh_samples)} samples (held-out)")
    else:
        if args.split in ("fresh", "fresh2"):
            print(f"\n[!] Cannot evaluate --split {args.split}: data/{fresh_filename} is missing or empty.")
            print(f"    (Add held-out samples in JSONL format to data/{fresh_filename} first.)\n")
            return
        else:
            print("data/fresh_test.jsonl is empty. (Add held-out samples for truly unbiased evaluation.)")

    # Setup judge
    judge_kwargs = {}
    if args.model:
        judge_kwargs["model"] = args.model
    if args.judge in ("ollama", "openai"):
        judge_kwargs["prompt_version"] = args.prompt_version

    judge_name = args.judge
    cache_judge_name = judge_name
    if judge_name in ("ollama", "openai"):
        cache_judge_name = f"{judge_name}_{args.prompt_version}"

    judge = make_judge(judge_name, **judge_kwargs)
    if judge is not None:
        avail, msg = judge.check_available()
        if not avail:
            print(f"[!]  Judge not available: {msg}")
            print("   Proceeding without judge for judge-dependent configs.\n")
            judge = None
        else:
            judge = CachedJudge(judge, cache_judge_name)

    # Train classifier if available
    classifier = None
    if sklearn_available():
        try:
            clf = Classifier()
            train_texts = [s.text for s in dev_samples]
            train_labels = [1 if s.is_attack else 0 for s in dev_samples]
            clf.train(train_texts, train_labels, calibrate=True)
            classifier = clf
            print("Classifier trained on dev split (Platt calibrated).")
            rel = clf.reliability_summary(train_texts, train_labels)
            print(f"  Reliability Summary (Dev): Brier Score={rel['brier_score']:.4f}, Log Loss={rel['log_loss']:.4f}")
            for b in rel["bins"]:
                print(f"    Predicted Prob: {b['predicted']:.4f} -> Empirical Positive Rate: {b['empirical']:.4f}")
        except Exception as e:
            print(f"Classifier training failed: {e}")
    else:
        print("scikit-learn not available; skipping classifier configs.")
    print()

    # ---------------------------------------------------------------------------
    # Evaluate configurations
    # ---------------------------------------------------------------------------
    configs: dict[str, dict] = {}
    if args.split in ("fresh", "fresh2"):
        target_samples = fresh_samples
        target_splits = {args.split: fresh_samples}
    elif args.split == "dev":
        target_samples = dev_samples
        target_splits = {"dev": dev_samples}
    elif args.split == "test":
        target_samples = test_samples
        target_splits = {"test": test_samples}
    else:
        target_samples = all_samples
        target_splits = {"dev": dev_samples, "test": test_samples, "all": all_samples}

    # 1. Rules only
    print("Evaluating: rules only...")
    rules_scores, rules_latencies = eval_rules_only(target_samples)
    configs["rules_only"] = {
        "scores": rules_scores,
        "latencies": rules_latencies,
        "judge_called_ids": set(),
        "judge_error_ids": set(),
        "judge_latencies": {},
        "splits": target_splits,
    }

    # 2. Classifier only (if available)
    if classifier is not None:
        print("Evaluating: classifier only...")
        if args.split in ("fresh", "fresh2"):
            # Trained on split=dev only, evaluated on fresh_samples
            clf_scores, clf_lats = eval_classifier_only(dev_samples, fresh_samples)
            configs["classifier_only"] = {
                "scores": clf_scores,
                "latencies": clf_lats,
                "judge_called_ids": set(),
                "judge_error_ids": set(),
                "judge_latencies": {},
                "splits": target_splits,
            }
        else:
            # For test: train on dev, eval on test
            clf_scores_test, clf_lats_test = eval_classifier_only(dev_samples, test_samples)
            # For dev: use same training set (train = dev, optimistic)
            clf_scores_dev, clf_lats_dev = eval_classifier_only(dev_samples, dev_samples)
            clf_all_scores = {**clf_scores_dev, **clf_scores_test}
            clf_all_lats = {**clf_lats_dev, **clf_lats_test}
            configs["classifier_only"] = {
                "scores": clf_all_scores,
                "latencies": clf_all_lats,
                "judge_called_ids": set(),
                "judge_error_ids": set(),
                "judge_latencies": {},
                "splits": target_splits,
            }

    # 3. Judge only (if available)
    if judge is not None:
        print(f"Evaluating: judge only ({cache_judge_name})...")
        j_scores, j_lats, j_called_ids, j_err_ids, j_judge_lats = eval_judge_only(target_samples, judge, cache_judge_name)
        configs["judge_only"] = {
            "scores": j_scores,
            "latencies": j_lats,
            "judge_called_ids": j_called_ids,
            "judge_error_ids": j_err_ids,
            "judge_latencies": j_judge_lats,
            "splits": target_splits,
        }

    # 4. Rules + Classifier (if available)
    if classifier is not None:
        print("Evaluating: rules + classifier...")
        rc_scores, rc_lats, rc_called_ids, rc_err_ids, rc_judge_lats = eval_cascade(
            target_samples, judge=None, judge_name="none", classifier=classifier, combine="max",
        )
        configs["rules_classifier"] = {
            "scores": rc_scores,
            "latencies": rc_lats,
            "judge_called_ids": rc_called_ids,
            "judge_error_ids": rc_err_ids,
            "judge_latencies": rc_judge_lats,
            "splits": target_splits,
        }

    # 5. Full cascade (max)
    if judge is not None:
        print("Evaluating: full cascade (max)...")
        fc_scores, fc_lats, fc_called_ids, fc_err_ids, fc_judge_lats = eval_cascade(
            target_samples, judge=judge, judge_name=cache_judge_name, classifier=classifier, combine="max",
        )
        configs["full_cascade_max"] = {
            "scores": fc_scores,
            "latencies": fc_lats,
            "judge_called_ids": fc_called_ids,
            "judge_error_ids": fc_err_ids,
            "judge_latencies": fc_judge_lats,
            "splits": target_splits,
        }

    # 6. Full cascade (blend)
    if judge is not None:
        print("Evaluating: full cascade (blend)...")
        fb_scores, fb_lats, fb_called_ids, fb_err_ids, fb_judge_lats = eval_cascade(
            target_samples, judge=judge, judge_name=cache_judge_name, classifier=classifier, combine="blend",
        )
        configs["full_cascade_blend"] = {
            "scores": fb_scores,
            "latencies": fb_lats,
            "judge_called_ids": fb_called_ids,
            "judge_error_ids": fb_err_ids,
            "judge_latencies": fb_judge_lats,
            "splits": target_splits,
        }

    # 7. Full cascade (verify)
    if judge is not None:
        print("Evaluating: full cascade (verify)...")
        fv_scores, fv_lats, fv_called_ids, fv_err_ids, fv_judge_lats = eval_cascade(
            target_samples, judge=judge, judge_name=cache_judge_name, classifier=classifier, combine="verify",
        )
        configs["full_cascade_verify"] = {
            "scores": fv_scores,
            "latencies": fv_lats,
            "judge_called_ids": fv_called_ids,
            "judge_error_ids": fv_err_ids,
            "judge_latencies": fv_judge_lats,
            "splits": target_splits,
        }

    # 8. Gated cascade
    if judge is not None:
        print("Evaluating: gated cascade...")
        gc_scores, gc_lats, gc_called_ids, gc_err_ids, gc_judge_lats = eval_cascade(
            target_samples, judge=judge, judge_name=cache_judge_name, classifier=classifier, combine="gated",
        )
        configs["gated_cascade"] = {
            "scores": gc_scores,
            "latencies": gc_lats,
            "judge_called_ids": gc_called_ids,
            "judge_error_ids": gc_err_ids,
            "judge_latencies": gc_judge_lats,
            "splits": target_splits,
        }

    print()

    # ---------------------------------------------------------------------------
    # Fresh test preview (when evaluating standard dev/test splits)
    # ---------------------------------------------------------------------------
    if fresh_samples and args.split != "fresh":
        print("Evaluating fresh test set (rules only)...")
        fresh_scores, fresh_lats = eval_rules_only(fresh_samples)
        fresh_m = compute_metrics(fresh_samples, fresh_scores, args.threshold)
        print(f"  Fresh test -- Caught: {fresh_m['caught_ci']}, FP: {fresh_m['false_pos_ci']}")
        print()

    # ---------------------------------------------------------------------------
    # Print summary
    # ---------------------------------------------------------------------------
    if args.split == "test":
        report_samples = test_samples
    elif args.split == "dev":
        report_samples = dev_samples
    elif args.split == "fresh":
        report_samples = fresh_samples
    else:
        report_samples = all_samples

    print(f"{'='*75}")
    print(f"  BENCHMARK RESULTS (split={args.split}, N={len(report_samples)}, threshold={args.threshold})")
    if args.judge == "mock":
        print("  [!] MOCK JUDGE -- numbers for judge-based configs are MEANINGLESS")
    print(f"{'='*75}")
    print()

    if args.split == "fresh":
        fmt = "  {:<24s} {:>22s} {:>22s} {:>10s} {:>8s} {:>8s}"
        print(fmt.format("Config", "Caught% (95% CI)", "FP% (95% CI)", "Avg ms", "J.Calls", "J.Errs"))
        print(f"  {'-'*24} {'-'*22} {'-'*22} {'-'*10} {'-'*8} {'-'*8}")
        for name, cfg in configs.items():
            m = compute_metrics(report_samples, cfg["scores"], args.threshold)
            lats = [cfg["latencies"].get(s.id, 0) for s in report_samples if s.id in cfg["scores"]]
            avg_lat = sum(lats) / len(lats) if lats else 0
            j_calls = sum(1 for s in report_samples if s.id in cfg.get("judge_called_ids", set()))
            j_errs = sum(1 for s in report_samples if s.id in cfg.get("judge_error_ids", set()))
            print(fmt.format(
                name,
                m["caught_ci"],
                m["false_pos_ci"],
                f"{avg_lat:.2f}",
                str(j_calls),
                str(j_errs),
            ))

        # Print per-kind table for each configuration on fresh split
        print()
        print(f"{'='*80}")
        print("  ATTACKS CAUGHT BY KIND (split=fresh)")
        print(f"{'='*80}")
        print()
        kind_fmt = "  {:<24s} {:<16s} {:>12s} {:>22s}"
        print(kind_fmt.format("Config", "Kind", "Caught/Total", "% (95% CI)"))
        print(f"  {'-'*24} {'-'*16} {'-'*12} {'-'*22}")
        kinds_order = ["direct", "indirect", "multilingual", "reworded", "framed", "judge_targeted", "encoded"]
        for name, cfg in configs.items():
            by_kind = compute_metrics_by_kind(report_samples, cfg["scores"], args.threshold)
            for kind in kinds_order:
                if kind in by_kind and by_kind[kind]["attacks"] > 0:
                    km = by_kind[kind]
                    print(kind_fmt.format(
                        name,
                        kind,
                        f"{km['caught']}/{km['attacks']}",
                        km["caught_ci"],
                    ))
            for kind, km in sorted(by_kind.items()):
                if kind not in kinds_order and km["attacks"] > 0:
                    print(kind_fmt.format(
                        name,
                        kind,
                        f"{km['caught']}/{km['attacks']}",
                        km["caught_ci"],
                    ))

        # Print action-aware outcomes for each configuration on fresh split
        print()
        print(f"{'='*80}")
        print("  ACTION-AWARE OUTCOMES BY RISK LEVEL (split=fresh)")
        print(f"{'='*80}")
        print()
        policy = Policy()
        max_judge_calls: Optional[int] = None
        if "full_cascade_max" in configs:
            max_cfg = configs["full_cascade_max"]
            max_judge_calls = sum(1 for s in report_samples if s.id in max_cfg.get("judge_called_ids", set()))

        for name, cfg in configs.items():
            this_j = sum(1 for s in report_samples if s.id in cfg.get("judge_called_ids", set()))
            saved_str = f"{max_judge_calls - this_j} saved vs full_cascade_max" if max_judge_calls is not None else "N/A"
            print(f"--- {name} (Judge calls: {this_j}, {saved_str}) ---")
            all_risk_outcomes = compute_action_outcomes_by_risk(
                [s for s in report_samples if s.id in cfg["scores"]],
                cfg["scores"], policy,
            )
            for risk in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]:
                out = all_risk_outcomes[risk]
                atk = out["attacks"]
                norm = out["normal"]
                t = policy.thresholds[risk]
                ask_str = f"{t.ask:.2f}" if t.ask is not None else "None"
                print(f"  {risk.value.upper():<6} Risk (ASK={ask_str}, BLOCK={t.block:.2f}) | Attacks: ALLOW={atk.get('ALLOW', 0):<2} ASK={atk.get('ASK', 0):<2} BLOCK={atk.get('BLOCK', 0):<2} | Normal: ALLOW={norm.get('ALLOW', 0):<2} ASK={norm.get('ASK', 0):<2} BLOCK={norm.get('BLOCK', 0):<2}")
            print()
    else:
        fmt = "  {:<24s} {:>8s} {:>8s} {:>10s} {:>8s} {:>8s}"
        print(fmt.format("Config", "Caught%", "FP%", "Avg ms", "J.Calls", "J.Errs"))
        print(f"  {'-'*24} {'-'*8} {'-'*8} {'-'*10} {'-'*8} {'-'*8}")
        for name, cfg in configs.items():
            m = compute_metrics(report_samples, cfg["scores"], args.threshold)
            lats = [cfg["latencies"].get(s.id, 0) for s in report_samples if s.id in cfg["scores"]]
            avg_lat = sum(lats) / len(lats) if lats else 0
            j_calls = sum(1 for s in report_samples if s.id in cfg.get("judge_called_ids", set()))
            j_errs = sum(1 for s in report_samples if s.id in cfg.get("judge_error_ids", set()))
            print(fmt.format(
                name,
                f"{m['caught_pct']:.1f}%",
                f"{m['false_pos_pct']:.1f}%",
                f"{avg_lat:.2f}",
                str(j_calls),
                str(j_errs),
            ))

    print()

    # Write reports with structured naming: ablation_<split>_<judge>_<prompt>.md
    prompt_str = args.prompt_version if args.judge != "none" else "none"
    structured_suffix = f"_{args.split}_{args.judge}_{prompt_str}"
    report_source_samples = fresh_samples if args.split == "fresh" else all_samples

    _write_ablation(configs, report_source_samples, args.threshold, suffix=structured_suffix)
    _write_failures(configs, report_source_samples, args.threshold, suffix=structured_suffix)
    _write_details_csv(configs, report_source_samples, suffix=structured_suffix)

    # Also write canonical split file for convenience
    legacy_suffix = "_fresh" if args.split == "fresh" else ("" if args.split in ("test", "all") else f"_{args.split}")
    _write_ablation(configs, report_source_samples, args.threshold, suffix=legacy_suffix)
    _write_failures(configs, report_source_samples, args.threshold, suffix=legacy_suffix)
    _write_details_csv(configs, report_source_samples, suffix=legacy_suffix)

    print(f"Reports written to {RESULTS_DIR}/")
    print(f"  - ablation{structured_suffix}.md")
    print(f"  - failures{structured_suffix}.md")
    print(f"  - details{structured_suffix}.csv")
    if legacy_suffix:
        print(f"  - ablation{legacy_suffix}.md (canonical)")


if __name__ == "__main__":
    main()
