# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-10-30

### Fixed
- 0.1.1: fix README images and badges for PyPI.

## [0.1.0] - 2026-10-25

### Added
- **Core Detection Engine**:
  - Layer 1: High-throughput regex rule scanner (`RulesResult`, score 0.0..1.0, < 1ms latency, stdlib only).
  - Layer 2: TF-IDF + Logistic Regression calibrated classifier with Platt probability scaling (`Classifier`, 5-fold cross-validated sigmoid scaling strictly on dev split).
  - Layer 3: LLM-as-a-Judge abstraction (`BaseJudge`, `OllamaJudge`, `OpenAICompatJudge`, `MockJudge`) supporting grounded `v2` prompt with strict JSON output parsing.
- **Cascade Combinations**:
  - Gated cascade (`combine="gated"`): Invokes LLM judge only within an uncertain score band, saving latency and token cost.
  - Per-profile uncertain bands: `[0.35, 0.75]` for balanced/strict, `[0.35, 0.80]` for lenient.
  - Max mode (`combine="max"`): Judge can only increase suspicion, preventing adversarial downgrade.
  - Blend mode (`combine="blend"`) and Verification mode (`combine="verify"`).
- **Risk-Aware Policy Engine**:
  - `Policy` mapping `(suspicion, risk_level)` to `ALLOW`, `ASK`, or `BLOCK`.
  - Three frozen, calibrated policy profiles: `strict`, `balanced` (default), and `lenient`.
  - Action-aware execution wrapping via `Warden.protect()`.
  - Session taint tracking and structured JSONL security audit event logging.
- **Benchmark & Data**:
  - Benchmarking framework (`benchmark.py`) with Wilson score 95% confidence intervals and breakdown by attack category.
  - Benchmark datasets: `data/attacks.jsonl` and `data/normal.jsonl` (dev split $N=200$, test split $N=65$, exploratory evaluation split $N=115$).
  - Frozen configuration integrity checking with SHA-256 validation (`results/frozen_config.json`).
- **Interactive Tools & Utilities**:
  - Streamlit security dashboard (`dashboard/app.py`).
  - Safe package and symbol rename utility (`rename.py`).
