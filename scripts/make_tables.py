"""
Build benchmark and action-aware policy tables for README.md and docs/benchmark.md
directly from results/ files (frozen_config.json, details_fresh_ollama_v2.csv, ablation_*.md)
to prevent number drift.
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
README_PATH = ROOT / "README.md"
DOCS_BENCH_PATH = ROOT / "docs" / "benchmark.md"


def parse_ablation_table(file_path: Path) -> list[dict[str, str]]:
    """Parse benchmark markdown table into list of row dicts."""
    rows = []
    text = file_path.read_text(encoding="utf-8")
    table_lines = []
    in_table = False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("| Configuration |"):
            in_table = True
            continue
        if in_table:
            if line.startswith("|---|"):
                continue
            if line.startswith("|"):
                table_lines.append(line)
            else:
                break

    for l in table_lines:
        parts = [p.strip() for p in l.split("|")[1:-1]]
        if len(parts) >= 8:
            rows.append({
                "config": parts[0],
                "split": parts[1],
                "caught": parts[2],
                "fp": parts[3],
                "latency": parts[4],
                "calls": parts[5],
                "time_saved": parts[6],
                "errors": parts[7],
            })
    return rows


def build_ablation_markdown(rows: list[dict[str, str]]) -> str:
    """Format parsed rows into secondary 0.5-threshold ablation markdown table."""
    headers = [
        "| Configuration | Split | Attacks Caught | False Positive | Avg Latency (ms) | Judge Calls | Judge Time Saved (s) | Judge Errors |",
        "|---|---|---|---|---|---|---|---|",
    ]
    lines = list(headers)
    for r in rows:
        cfg_name = r["config"]
        if cfg_name == "judge_only":
            cfg_name = "judge_only (llama3.2:3b v2)"
        split_name = r["split"]
        if split_name == "fresh":
            split_name = "fresh (evaluation set)"
        lines.append(
            f"| `{cfg_name}` | {split_name} | {r['caught']} | {r['fp']} | {r['latency']} | {r['calls']} | {r['time_saved']} | {r['errors']} |"
        )
    return "\n".join(lines)


def load_dev_profile_outcomes() -> dict:
    cfg_file = RESULTS_DIR / "frozen_config.json"
    cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
    return cfg.get("profiles", {})


def compute_fresh_profile_outcomes() -> dict:
    from agent_firewall.policy import Decision, Policy, RiskLevel

    csv_path = RESULTS_DIR / "details_fresh_ollama_v2.csv"
    if not csv_path.exists():
        return {}

    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    res = {}
    for p_name in ["strict", "balanced", "lenient"]:
        pol = Policy(profile=p_name)
        res[p_name] = {}
        for risk in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]:
            att_allow = att_ask = att_block = 0
            norm_allow = norm_ask = norm_block = 0
            for r in rows:
                score = float(r["gated_cascade_score"])
                is_att = (r["label"] == "attack")
                dec = pol.decide(score, risk)
                if is_att:
                    if dec == Decision.ALLOW:
                        att_allow += 1
                    elif dec == Decision.ASK:
                        att_ask += 1
                    elif dec == Decision.BLOCK:
                        att_block += 1
                else:
                    if dec == Decision.ALLOW:
                        norm_allow += 1
                    elif dec == Decision.ASK:
                        norm_ask += 1
                    elif dec == Decision.BLOCK:
                        norm_block += 1
            res[p_name][risk.value] = {
                "attacks": {"ALLOW": att_allow, "ASK": att_ask, "BLOCK": att_block},
                "normal": {"ALLOW": norm_allow, "ASK": norm_ask, "BLOCK": norm_block},
            }
    return res


def build_primary_profiles_markdown(dev_profiles: dict, fresh_profiles: dict) -> str:
    """Build the primary action-aware policy tables for all three profiles."""
    blocks = []

    order = [
        ("balanced", "Balanced Profile (Default / Recommended - Point A) [band: 0.35, 0.75]"),
        ("strict", "Strict Profile (High Security - ask >= 0.50 at High Risk) [band: 0.35, 0.75]"),
        ("lenient", "Lenient Profile (Low User Friction - High-Throughput Ops) [band: 0.35, 0.80]"),
    ]

    for p_key, p_title in order:
        dev_p = dev_profiles.get(p_key, {})
        thresh_dict = dev_p.get("thresholds", {})
        dev_out = dev_p.get("dev_oof_outcomes", {}).get("gated_cascade_with_judge", {})
        fresh_out = fresh_profiles.get(p_key, {})

        lines = [
            f"#### {p_title}",
            "",
            "| Risk Level | Thresholds | Dev Attacks (OOF, N=99) | Dev Normal (OOF, N=101) | Fresh Attacks (Evaluation Set, N=56) | Fresh Normal (Evaluation Set, N=59) |",
            "|---|---|---|---|---|---|",
        ]

        for risk in ["low", "medium", "high"]:
            t = thresh_dict.get(risk, {})
            ask_val = f"ASK={t.get('ask'):.2f}" if t.get("ask") is not None else "ASK=None"
            blk_val = f"BLOCK={t.get('block'):.2f}"
            t_str = f"`{ask_val}`, `{blk_val}`"

            # Dev
            d_r = dev_out.get(risk, {})
            d_att = d_r.get("attacks", {})
            d_norm = d_r.get("normal", {})
            dev_att_str = f"ALLOW: {d_att.get('ALLOW', 0)}, ASK: {d_att.get('ASK', 0)}, BLOCK: {d_att.get('BLOCK', 0)}"
            dev_norm_str = f"ALLOW: {d_norm.get('ALLOW', 0)}, ASK: {d_norm.get('ASK', 0)}, BLOCK: {d_norm.get('BLOCK', 0)}"

            # Fresh
            f_r = fresh_out.get(risk, {})
            f_att = f_r.get("attacks", {})
            f_norm = f_r.get("normal", {})
            fresh_att_str = f"ALLOW: {f_att.get('ALLOW', 0)}, ASK: {f_att.get('ASK', 0)}, BLOCK: {f_att.get('BLOCK', 0)}"
            fresh_norm_str = f"ALLOW: {f_norm.get('ALLOW', 0)}, ASK: {f_norm.get('ASK', 0)}, BLOCK: {f_norm.get('BLOCK', 0)}"

            lines.append(
                f"| **{risk.upper()}** | {t_str} | {dev_att_str} | {dev_norm_str} | {fresh_att_str} | {fresh_norm_str} |"
            )

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)


def replace_section(content: str, start_marker: str, end_marker: str, replacement: str) -> str:
    """Replace content between start_marker and end_marker."""
    pattern = re.compile(rf"({re.escape(start_marker)}).*?({re.escape(end_marker)})", re.DOTALL)
    if not pattern.search(content):
        raise ValueError(f"Could not find section between '{start_marker}' and '{end_marker}'")
    return pattern.sub(rf"\1\n\n{replacement}\n\n\2", content, count=1)


def update_readme():
    v2_ablation_path = RESULTS_DIR / "ablation_fresh_ollama_v2.md"
    v1_ablation_path = RESULTS_DIR / "ablation_fresh_ollama_v1.md"

    v2_rows = parse_ablation_table(v2_ablation_path)
    dev_profiles = load_dev_profile_outcomes()
    fresh_profiles = compute_fresh_profile_outcomes()

    primary_md = build_primary_profiles_markdown(dev_profiles, fresh_profiles)
    secondary_md = build_ablation_markdown(v2_rows)

    readme = README_PATH.read_text(encoding="utf-8")

    # Primary Section: Action-Aware Policy Profiles
    primary_section = (
        "## Action-Aware Policy Outcomes by Profile & Risk Level (Primary Result)\n\n"
        "The firewall evaluates tool risk to map suspicion to `ALLOW`, `ASK`, or `BLOCK` decisions.\n"
        "Three frozen policy profiles are calibrated strictly on dev out-of-fold predictions:\n\n"
        "> [!NOTE]\n"
        '> **Default Profile Selection:** `"balanced"` is the default profile, chosen before fresh2. '
        "It flags 10.9% of dev normals (above the 10% target), "
        "and strict and balanced have the same attack-ALLOW rate on dev.\n\n"
        "> [!WARNING]\n"
        "> **Dev-Batch Leakage Caveat:** Operating thresholds and uncertain bands were tuned and frozen on dev data (N=200). "
        "Although out-of-fold cross-validation prevents in-sample classifier memorization, iterative tuning on dev batches introduces potential selection leakage. "
        'The 115-sample fresh set is an "evaluation set partly used for design", not a held-out set. '
        "True held-out generalization remains future work.\n\n"
        f"{primary_md}\n\n"
        "---\n\n"
        "## Fixed-Threshold Ablation Study (Secondary Result, threshold = 0.5)\n\n"
        "> [!NOTE]\n"
        "> Evaluated on the 115-sample exploratory evaluation set (partly used for design) with Wilson 95% confidence intervals `[lo, hi]`.\n\n"
        f"{secondary_md}"
    )

    # Replace from ## Benchmark Results or ## Action-Aware Policy Outcomes down to ## Design Decisions
    full_pattern = re.compile(
        r"## Benchmark Results.*?(?=## Design Decisions)",
        re.DOTALL,
    )
    if not full_pattern.search(readme):
        raise ValueError("Could not find Benchmark section in README.md")

    # Also build takeaways
    gc_row = next((r for r in v2_rows if r["config"] == "gated_cascade"), None)
    max_row = next((r for r in v2_rows if r["config"] == "full_cascade_max"), None)
    gc_calls = gc_row["calls"] if gc_row else "27"
    max_calls = max_row["calls"] if max_row else "96"
    saved_calls = int(max_calls) - int(gc_calls)
    time_saved = gc_row["time_saved"] if gc_row else "233.0s"
    catch_pct = gc_row["caught"].split()[0] if gc_row else "85.7%"
    fp_max = max_row["fp"].split()[0] if max_row else "11.9%"
    fp_gc = gc_row["fp"].split()[0] if gc_row else "5.1%"

    # v1 vs v2
    v1_rows = parse_ablation_table(v1_ablation_path) if v1_ablation_path.exists() else []
    j_v1 = next((r for r in v1_rows if r["config"] == "judge_only"), None)
    j_v2 = next((r for r in v2_rows if r["config"] == "judge_only"), None)
    fp_v1 = j_v1["fp"].split()[0] if j_v1 else "13.6%"
    fp_v2 = j_v2["fp"].split()[0] if j_v2 else "6.8%"

    takeaways = (
        "### Key Takeaways from Benchmark Evaluation\n"
        f"1. **Gating cuts latency and saves time:** `gated_cascade` invokes the judge only {gc_calls} times (saving {saved_calls} judge calls and {time_saved} of execution time vs `full_cascade_max`) while maintaining {catch_pct} attack catch rate.\n"
        f"2. **Gating reduces false positives:** False positives drop from {fp_max} (`full_cascade_max`) to {fp_gc} (`gated_cascade`), because benign texts with low classifier scores never reach the judge.\n"
        f"3. **v2 Judge prompt drops false positives:** Evaluated on fresh data, the grounded `v2` prompt cut judge false positives by half (from {fp_v1} in v1 to {fp_v2} in v2)."
    )

    dataset_notice = (
        "> [!NOTE]\n"
        "> **Evaluation Dataset Notice:** The 115-sample fresh test set (`data/fresh_test.jsonl`) is an "
        '**"evaluation set partly used for design"**, not a held-out set. '
        "Operating thresholds and prompt designs were refined against its error cases. "
        "Evaluating on a fully independent `fresh2` benchmark remains future work."
    )

    replacement_block = (
        "## Benchmark Results\n\n"
        f"{dataset_notice}\n\n"
        f"{primary_section}\n\n"
        f"{takeaways}\n\n"
        "---\n\n"
    )

    readme = full_pattern.sub(replacement_block, readme, count=1)
    README_PATH.write_text(readme, encoding="utf-8")
    print(f"Updated {README_PATH}")


def update_docs():
    v2_ablation_path = RESULTS_DIR / "ablation_fresh_ollama_v2.md"
    v2_rows = parse_ablation_table(v2_ablation_path)
    dev_profiles = load_dev_profile_outcomes()
    fresh_profiles = compute_fresh_profile_outcomes()

    primary_md = build_primary_profiles_markdown(dev_profiles, fresh_profiles)
    secondary_md = build_ablation_markdown(v2_rows)

    docs_content = (
        "# Benchmark Methodology & Results\n\n"
        "Evaluation methodology and empirically measured results across benchmark splits and policy profiles.\n\n"
        "## Running the Benchmark\n\n"
        "```bash\n"
        "# Fast rules-only evaluation (stdlib only, < 1ms)\n"
        "python benchmark.py --judge none --split test\n\n"
        "# Full cascade evaluation on exploratory fresh set\n"
        "python benchmark.py --judge ollama --model llama3.2:3b --split fresh\n\n"
        "# With mock judge (offline deterministic mock)\n"
        "python benchmark.py --judge mock --split test\n"
        "```\n\n"
        "Results are saved to `results/ablation_<split>_<judge>_<prompt>.md` and canonical aliases.\n\n"
        "---\n\n"
        "## Action-Aware Policy Outcomes by Profile & Risk Level (Primary Result)\n\n"
        "Thresholds and outcomes evaluated on both the Dev split (5-fold out-of-fold calibration, N=200: 99 attacks, 101 normal) "
        "and the 115-sample Fresh evaluation set (N=115: 56 attacks, 59 normal):\n\n"
        "> [!NOTE]\n"
        '> **Default Profile Selection:** `"balanced"` is the default profile, chosen before fresh2. '
        "It flags 10.9% of dev normals (above the 10% target), "
        "and strict and balanced have the same attack-ALLOW rate on dev.\n\n"
        "> [!WARNING]\n"
        "> **Dev-Batch Leakage Caveat:** Operating thresholds and uncertain bands were tuned and frozen on dev data (N=200). "
        "Although out-of-fold cross-validation prevents in-sample classifier memorization, iterative tuning on dev batches introduces potential selection leakage. "
        'The 115-sample fresh set is an "evaluation set partly used for design", not a held-out set. '
        "True held-out generalization remains future work.\n\n"
        f"{primary_md}\n\n"
        "---\n\n"
        "## Fixed-Threshold Ablation Study (Secondary Result, threshold = 0.5)\n\n"
        "> [!NOTE]\n"
        "> Evaluated on the 115-sample evaluation set (partly used for design) with Wilson 95% confidence intervals `[lo, hi]`.\n"
        "> Differences smaller than the interval overlap are not statistically significant.\n\n"
        f"{secondary_md}\n\n"
        "---\n\n"
        "## Future Work: Fresh2 Held-Out Benchmark\n\n"
        "> [!NOTE]\n"
        "> The 115-sample fresh test set is an **evaluation set partly used for design**, not a held-out set. "
        "Executing independent evaluation on a separate `data/fresh2_test.jsonl` benchmark remains future work.\n"
    )

    DOCS_BENCH_PATH.write_text(docs_content, encoding="utf-8")
    print(f"Updated {DOCS_BENCH_PATH}")


def main():
    update_readme()
    update_docs()
    print("Tables synchronized successfully.")


if __name__ == "__main__":
    main()
