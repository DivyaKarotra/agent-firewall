# Building agent-firewall: A Risk-Aware Cascade Defense Against Prompt Injection

When AI agents are granted access to tools—reading emails, querying databases, modifying files, and sending network requests—prompt injection changes from a novelty into a critical system vulnerability. An agent that ingests untrusted text (such as an email attachment or customer review) containing an indirect injection payload can be hijacked into exfiltrating credentials or dropping database tables.

Most prompt injection defenses treat this as a binary text classification problem: run every input through a giant LLM-as-a-judge and output `ALLOW` or `BLOCK`. In practice, that paradigm fails enterprise requirements:
1. **Latency & Cost:** Invoking an LLM judge on every untrusted chunk adds 2–5 seconds and significant compute overhead.
2. **False Positives:** Legitimate administrative actions (*"forward your resume to HR"* or *"review this security tutorial"*) get blocked.
3. **Blast Radius Blindness:** Reading a document does not have the same catastrophic potential as sending wire transfers or executing shell commands.

To solve this, I built **`agent-firewall`**: an open-source, risk-aware cascade defense engineered specifically for AI agent tool calls.

---

## Architecture: The Three-Layer Gated Cascade

Instead of relying on a single detection mechanism, `agent-firewall` cascades three distinct layers of increasing sophistication and cost:

1. **Layer 1: High-Speed Regex Rules (< 1 ms, Python stdlib only)**  
   Scans for explicit override markers, exfiltration targets, obfuscated payloads (Base64, leetspeak, zero-width characters), and fence-breaking sequences. If rules detect a clear attack (score $\ge 0.90$), the cascade terminates immediately.
2. **Layer 2: Calibrated TF-IDF Classifier (~25 ms)**  
   A linear logistic regression classifier calibrated using 5-fold cross-validated Platt scaling (sigmoid calibration) strictly on the development split. It outputs well-calibrated posterior probabilities, catching vocabulary and distribution shifts without LLM latency.
3. **Layer 3: Grounded LLM Judge (~3.3 s, local Ollama / OpenAI-compatible)**  
   A grounded LLM judge (evaluated with local `llama3.2:3b`) using a structured `v2` prompt that checks whether injected instructions actually alter agent goals. In `max` mode, the judge can only **raise** suspicion—an adversarial jailbreak that tricks the judge cannot override an earlier rule match.

### The Gated Optimization
The LLM judge is **not** called on every input. It is consulted **only within an uncertain score band** (`[0.35, 0.75]` for default balanced policy; `[0.35, 0.80]` for lenient policy) where earlier fast layers produce borderline or ambiguous confidence. Outside this band, decisions resolve with zero judge overhead.

### Action-Aware Policy Engine
Detection scores ($0.0 \dots 1.0$) are mapped to three discrete decisions:
- **`ALLOW`**: Proceed silently (e.g. read operations, low risk).
- **`ASK`**: Escalate to user confirmation callback (medium/high risk).
- **`BLOCK`**: Deny tool execution and raise `ToolBlocked` (high blast radius).

---

## Empirical Results

All metrics below are generated directly from the reproducible benchmark suite on the 115-sample exploratory evaluation set (`fresh`, 56 attacks, 59 normal) using Wilson 95% confidence intervals:

| Configuration | Split | Attacks Caught | False Positive | Avg Latency | Judge Calls | Execution Time Saved |
|---|---|---|---|---|---|---|
| `rules_only` | fresh (evaluation set) | 35.7% [24.5, 48.8] | 3.4% [0.9, 11.5] | 1.23 ms | 0 | 322.7s |
| `classifier_only` | fresh (evaluation set) | 76.8% [64.2, 85.9] | 1.7% [0.3, 9.0] | 25.60 ms | 0 | 322.7s |
| `judge_only (llama3.2:3b v2)` | fresh (evaluation set) | 76.8% [64.2, 85.9] | 6.8% [2.7, 16.2] | 3363.71 ms | 115 | -64.1s |
| `rules_classifier` | fresh (evaluation set) | 83.9% [72.2, 91.3] | 5.1% [1.7, 13.9] | 23.54 ms | 0 | 322.7s |
| `full_cascade_max` | fresh (evaluation set) | 92.9% [83.0, 97.2] | 11.9% [5.9, 22.5] | 2829.29 ms | 96 | 0.0s |
| **`gated_cascade`** | fresh (evaluation set) | **85.7% [74.3, 92.6]** | **5.1% [1.7, 13.9]** | **802.60 ms** | **27** | **233.0s** |

### Key Benchmark Takeaways
1. **72% Fewer Judge Calls:** The gated cascade invoked the judge only 27 times across 115 evaluation runs (saving 69 calls and 233.0 seconds of CPU execution vs `full_cascade_max`; 27 of 115 judge calls, 802.60 ms vs 3363.71 ms judge-only).
2. **Honest Judge Value:** On the fresh set, the judge adds only one extra attack catch over rules + classifier (47 to 48 of 56, within overlapping confidence intervals [72.2, 91.3] vs [74.3, 92.6]). Its value is concentrated in non-English/semantic cases at about 4x the latency (802.60 ms vs fast layer baseline).
3. **Lower False Positive Rate:** False positives dropped from **11.9%** in `full_cascade_max` to **5.1%** in `gated_cascade`, because benign inputs with low classifier confidence never reach the judge.
4. **Prompt Grounding Halved FP:** The grounded `v2` judge prompt cut false positives by half (from 13.6% in v1 to 6.8% in v2) by requiring specific evidence of goal-hijacking.

---

## What Failed: Honest Engineering Lessons

Building security tooling is about understanding failure modes:

1. **Regex Fails on Non-English:** Rules caught **0/12 (0.0%)** of non-English attacks (Hindi, Marathi, Spanish). Multilingual prompt injection requires statistical classification or LLM semantics.
2. **Small Judges Struggle with Context:** Small 3B models (`llama3.2:3b`) easily mistake benign technical text quoting attack syntax (e.g. security articles) for actual live attacks.
3. **Indirect Injections are Hard for Shallow Models:** Without the LLM judge, rules + classifier caught only 70% of indirect injections. Complex payload indirection requires semantic understanding.
4. **Lexical False Positives:** Combinations like *"forward your resume to hr@example.com"* trigger exfiltration regexes.
5. **Marginal Catch vs Latency Tradeoff:** On the fresh set, the judge adds only one extra attack catch (47 to 48 of 56, within the confidence intervals); its value is mostly non-English/semantic cases at about 4x the latency.

---

## Conclusion & Next Steps

`agent-firewall` demonstrates that cascading fast deterministic filters with targeted, gated LLM reasoning provides both high security and production-grade efficiency.

The library is 100% open source under the MIT license, with zero required runtime dependencies for the core library.

- **GitHub Repository:** [https://github.com/DivyaKarotra/agent-firewall](https://github.com/DivyaKarotra/agent-firewall)
- **Documentation:** [https://DivyaKarotra.github.io/agent-firewall/](https://DivyaKarotra.github.io/agent-firewall/)
- **Install:** `pip install agent-firewall-cascade`
