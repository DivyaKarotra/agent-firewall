# Resume Bullet Points: agent-firewall

Three tailored versions highlighting distinct technical angles for specialized resumes.

---

### Version 1: Machine Learning & AI Systems Engineer

- **Architected and open-sourced `agent-firewall`**, a multi-stage cascade defense for LLM agent tool calls combining sub-millisecond regex heuristics, calibrated linear classification, and local LLM judges.
- **Implemented Platt probability calibration** using 5-fold cross-validated sigmoid scaling on development splits, achieving reliable out-of-fold posterior confidence scores (Brier score 0.046) and preventing in-sample overfitting.
- **Engineered an uncertain-band gating mechanism** (`[0.35, 0.75]`) that reduced expensive LLM judge calls by 72% (saving 233.0s CPU runtime over 115 evaluations on the exploratory evaluation set, 27 of 115 judge calls) while improving precision and reducing false-positive rates from 11.9% to 5.1%.
- **Developed a standardized evaluation harness** with Wilson 95% confidence intervals, automated ablation reporting across 7 pipeline variants, and zero-drift metric generation scripts.

---

### Version 2: Senior Software & Backend Infrastructure Engineer

- **Designed and published `agent-firewall-cascade` on PyPI** (`pip install agent-firewall-cascade`), an open-source security middleware for AI agents featuring zero external runtime dependencies in core components.
- **Engineered `Warden` middleware wrapper** to intercept untrusted I/O, maintain thread-safe monotonic session taint tracking, and enforce action-aware risk policies (`ALLOW`, `ASK`, `BLOCK`) before sensitive tool execution.
- **Built an interactive full-stack security dashboard** using Streamlit to visualize layer-by-layer latency, rule activations, and policy thresholds under simulated attack scenarios.
- **Created a production-ready CI/CD and release pipeline** including strict Ruff linting, 89-test Pytest coverage, automated MkDocs documentation deployment, and reproducible packaging with PEP 561 type hints.

---

### Version 3: Cybersecurity & AI Safety / Red-Teaming Engineer

- **Created an action-aware prompt injection firewall** specifically targeting multi-turn tool abuse, credential exfiltration, and indirect injection vectors embedded in third-party text.
- **Curated a 380-sample benchmark dataset** spanning 7 distinct attack categories (direct overrides, indirect payloads, obfuscated Base64/leetspeak, multilingual Marathi/Hindi/Spanish, reworded semantic prompts, judge spoofing, and tutorial framing).
- **Hardened defense architecture against adversarial bypasses**, establishing a monotonic `max` mode to prevent jailbreaks from manipulating LLM judge outputs to override affirmative regex hits.
- **Authored comprehensive vulnerability and threat-modeling documentation**, conducting rigorous failure-mode analysis on boundary conditions including non-English prompt drift and CPU latency bottlenecks.
