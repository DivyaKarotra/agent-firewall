# Limitations

## Known Weaknesses & Empirical Failure Modes

1. **Rules catch 0% of non-English attacks:**
   Regex rules rely on English vocabulary; on the multilingual evaluation set, rules alone caught **0/12 (0.0% [0.0, 24.3])** attacks (e.g. Hindi, Marathi, Hinglish, Spanish). The calibrated classifier caught 9/12 (75.0%), demonstrating that non-English inputs require statistical or LLM reasoning.
2. **The 3B judge wrongly flags non-English normal texts and articles that quote attacks:**
   The small local judge (`llama3.2:3b`) produces false positives on benign non-English texts (e.g. `n021` Marathi administrative update) and educational or security documentation quoting sample exploits (e.g. `n013` security tutorial quoting injection payloads).
3. **Indirect attacks around 70% catch rate for rules + classifier:**
   Without the LLM judge, the combined rules + classifier pipeline caught only **7/10 (70.0% [39.7, 89.2])** of indirect prompt injection attacks on the evaluation set. Complex payload indirection (e.g. hiding instructions in email footers or resume attachments) requires semantic LLM reasoning.
4. **Rule false positive on "forward your resume to x@y":**
   Aggressive exfiltration heuristics falsely flag legitimate routine administrative actions (e.g. `"forward your resume to hr@example.com"` triggers credential/email forwarding patterns).
5. **About 3 s per judge call on CPU:**
   Local evaluation of `llama3.2:3b` via Ollama averages **3.36s latency per call on CPU** (vs 1.2ms for rules and 25ms for classifier). While gating saves 69 judge calls on the evaluation set, active judge calls introduce perceptible latency.
6. **Single-author data:**
   The benchmark dataset (dev $N=200$, test $N=65$, fresh evaluation $N=115$) was generated and curated by a single contributor. Real-world corporate traffic distributions may present attack patterns and normal text domains not represented in this dataset.
7. **Session-wide taint:**
   `Warden` taint tracking is monotonic within a session: once tainted by untrusted input, the entire session remains elevated in suspicion until explicitly reset via `warden.reset()`.
8. **Tool arguments not scanned:**
   `Warden.protect()` inspects untrusted *outputs* and protects subsequent tool execution based on session taint and tool risk tier. It does not parse or validate arbitrary outgoing tool argument schemas unless arguments are passed directly as untrusted text.

## No Novelty Claim

agent-firewall does not claim algorithmic novelty. It is an open-source, action-aware firewall combining established engineering practices (regex rules, calibrated ML classification, LLM-as-judge) with reproducible public benchmarks.
