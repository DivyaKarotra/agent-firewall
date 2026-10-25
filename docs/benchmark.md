# Benchmark Methodology & Results

Evaluation methodology and empirically measured results across benchmark splits and policy profiles.

## Running the Benchmark

```bash
# Fast rules-only evaluation (stdlib only, < 1ms)
python benchmark.py --judge none --split test

# Full cascade evaluation on exploratory fresh set
python benchmark.py --judge ollama --model llama3.2:3b --split fresh

# With mock judge (offline deterministic mock)
python benchmark.py --judge mock --split test
```

Results are saved to `results/ablation_<split>_<judge>_<prompt>.md` and canonical aliases.

---

## Action-Aware Policy Outcomes by Profile & Risk Level (Primary Result)

Thresholds and outcomes evaluated on both the Dev split (5-fold out-of-fold calibration, N=200: 99 attacks, 101 normal) and the 115-sample Fresh evaluation set (N=115: 56 attacks, 59 normal):

> [!NOTE]
> **Default Profile Selection:** `"balanced"` is the default profile, chosen before fresh2. It flags 10.9% of dev normals (above the 10% target), and strict and balanced have the same attack-ALLOW rate on dev.

> [!WARNING]
> **Dev-Batch Leakage Caveat:** Operating thresholds and uncertain bands were tuned and frozen on dev data (N=200). Although out-of-fold cross-validation prevents in-sample classifier memorization, iterative tuning on dev batches introduces potential selection leakage. The 115-sample fresh set is an "evaluation set partly used for design", not a held-out set. True held-out generalization remains future work.

#### Balanced Profile (Default / Recommended - Point A) [band: 0.35, 0.75]

| Risk Level | Thresholds | Dev Attacks (OOF, N=99) | Dev Normal (OOF, N=101) | Fresh Attacks (Evaluation Set, N=56) | Fresh Normal (Evaluation Set, N=59) |
|---|---|---|---|---|---|
| **LOW** | `ASK=None`, `BLOCK=0.90` | ALLOW: 30, ASK: 0, BLOCK: 69 | ALLOW: 95, ASK: 0, BLOCK: 6 | ALLOW: 31, ASK: 0, BLOCK: 25 | ALLOW: 59, ASK: 0, BLOCK: 0 |
| **MEDIUM** | `ASK=0.80`, `BLOCK=0.90` | ALLOW: 7, ASK: 23, BLOCK: 69 | ALLOW: 92, ASK: 3, BLOCK: 6 | ALLOW: 13, ASK: 18, BLOCK: 25 | ALLOW: 57, ASK: 2, BLOCK: 0 |
| **HIGH** | `ASK=0.75`, `BLOCK=0.85` | ALLOW: 4, ASK: 14, BLOCK: 81 | ALLOW: 90, ASK: 4, BLOCK: 7 | ALLOW: 10, ASK: 14, BLOCK: 32 | ALLOW: 57, ASK: 2, BLOCK: 0 |

#### Strict Profile (High Security - ask >= 0.50 at High Risk) [band: 0.35, 0.75]

| Risk Level | Thresholds | Dev Attacks (OOF, N=99) | Dev Normal (OOF, N=101) | Fresh Attacks (Evaluation Set, N=56) | Fresh Normal (Evaluation Set, N=59) |
|---|---|---|---|---|---|
| **LOW** | `ASK=None`, `BLOCK=0.85` | ALLOW: 18, ASK: 0, BLOCK: 81 | ALLOW: 94, ASK: 0, BLOCK: 7 | ALLOW: 24, ASK: 0, BLOCK: 32 | ALLOW: 59, ASK: 0, BLOCK: 0 |
| **MEDIUM** | `ASK=0.70`, `BLOCK=0.85` | ALLOW: 4, ASK: 14, BLOCK: 81 | ALLOW: 90, ASK: 4, BLOCK: 7 | ALLOW: 10, ASK: 14, BLOCK: 32 | ALLOW: 57, ASK: 2, BLOCK: 0 |
| **HIGH** | `ASK=0.50`, `BLOCK=0.80` | ALLOW: 4, ASK: 3, BLOCK: 92 | ALLOW: 86, ASK: 6, BLOCK: 9 | ALLOW: 8, ASK: 5, BLOCK: 43 | ALLOW: 56, ASK: 1, BLOCK: 2 |

#### Lenient Profile (Low User Friction - High-Throughput Ops) [band: 0.35, 0.80]

| Risk Level | Thresholds | Dev Attacks (OOF, N=99) | Dev Normal (OOF, N=101) | Fresh Attacks (Evaluation Set, N=56) | Fresh Normal (Evaluation Set, N=59) |
|---|---|---|---|---|---|
| **LOW** | `ASK=None`, `BLOCK=0.95` | ALLOW: 40, ASK: 0, BLOCK: 59 | ALLOW: 98, ASK: 0, BLOCK: 3 | ALLOW: 40, ASK: 0, BLOCK: 16 | ALLOW: 59, ASK: 0, BLOCK: 0 |
| **MEDIUM** | `ASK=0.85`, `BLOCK=0.95` | ALLOW: 17, ASK: 23, BLOCK: 59 | ALLOW: 94, ASK: 4, BLOCK: 3 | ALLOW: 24, ASK: 16, BLOCK: 16 | ALLOW: 59, ASK: 0, BLOCK: 0 |
| **HIGH** | `ASK=0.80`, `BLOCK=0.90` | ALLOW: 6, ASK: 23, BLOCK: 70 | ALLOW: 92, ASK: 3, BLOCK: 6 | ALLOW: 13, ASK: 18, BLOCK: 25 | ALLOW: 57, ASK: 2, BLOCK: 0 |

---

## Fixed-Threshold Ablation Study (Secondary Result, threshold = 0.5)

> [!NOTE]
> Evaluated on the 115-sample evaluation set (partly used for design) with Wilson 95% confidence intervals `[lo, hi]`.
> Differences smaller than the interval overlap are not statistically significant.

| Configuration | Split | Attacks Caught | False Positive | Avg Latency (ms) | Judge Calls | Judge Time Saved (s) | Judge Errors |
|---|---|---|---|---|---|---|---|
| `rules_only` | fresh (evaluation set) | 35.7% [24.5, 48.8] | 3.4% [0.9, 11.5] | 1.23 | 0 | 322.7s | 0 |
| `classifier_only` | fresh (evaluation set) | 76.8% [64.2, 85.9] | 1.7% [0.3, 9.0] | 25.60 | 0 | 322.7s | 0 |
| `judge_only (llama3.2:3b v2)` | fresh (evaluation set) | 76.8% [64.2, 85.9] | 6.8% [2.7, 16.2] | 3363.71 | 115 | -64.1s | 0 |
| `rules_classifier` | fresh (evaluation set) | 83.9% [72.2, 91.3] | 5.1% [1.7, 13.9] | 23.54 | 0 | 322.7s | 0 |
| `full_cascade_max` | fresh (evaluation set) | 92.9% [83.0, 97.2] | 11.9% [5.9, 22.5] | 2829.29 | 96 | 0.0s | 0 |
| `full_cascade_blend` | fresh (evaluation set) | 85.7% [74.3, 92.6] | 8.5% [3.7, 18.4] | 2829.74 | 96 | 0.0s | 0 |
| `full_cascade_verify` | fresh (evaluation set) | 85.7% [74.3, 92.6] | 8.5% [3.7, 18.4] | 3270.53 | 111 | -50.6s | 0 |
| `gated_cascade` | fresh (evaluation set) | 85.7% [74.3, 92.6] | 5.1% [1.7, 13.9] | 802.60 | 27 | 233.0s | 0 |

---

## Future Work: Fresh2 Held-Out Benchmark

> [!NOTE]
> The 115-sample fresh test set is an **evaluation set partly used for design**, not a held-out set. Executing independent evaluation on a separate `data/fresh2_test.jsonl` benchmark remains future work.
