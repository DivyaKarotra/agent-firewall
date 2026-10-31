<!--
Pre-posting checklist:
1. Verify published links before sharing.
2. Add live demo URL once deployed.
-->

🚀 Excited to open-source **`agent-firewall`**: A risk-aware cascade defense against prompt injection for LLM agent tool calls!

When AI agents execute real-world tools (reading inboxes, modifying files, executing shell commands, or querying SQL databases), indirect prompt injection becomes a severe security threat.

Most defenses rely on a single, expensive LLM-as-a-judge on every input, introducing 2–4 seconds of latency, high token costs, and high false-positive rates on benign text.

I built `agent-firewall` to solve this with a 3-layer architecture:
⚡ **Layer 1 (< 1 ms):** Fast, zero-dependency regex rules that terminate obvious attacks immediately.
📊 **Layer 2 (~25 ms):** Platt-calibrated TF-IDF classifier trained strictly with 5-fold cross-validation on dev data.
🧠 **Layer 3 (~3.3 s):** Grounded LLM judge (running locally on Ollama with `llama3.2:3b` or OpenAI-compatible APIs).

Key Engineering Innovations:
🔹 **Gated Cascade:** The LLM judge is called ONLY when earlier layers produce uncertain scores (e.g. `[0.35, 0.75]`), saving 72% of judge calls (27 of 115 judge calls, 802.60 ms vs 3363.71 ms judge-only) and cutting CPU evaluation time by 233.0s.
🔹 **Action-Aware Policy Engine:** Maps suspicion to `ALLOW`, `ASK` (human-in-the-loop confirmation), or `BLOCK` based on the tool's blast radius (low vs high risk).
🔹 **Zero Runtime Dependencies:** The core library runs entirely on standard Python 3.11+ library. ML and Streamlit dashboard are completely optional extras.
🔹 **Honest & Reproducible Benchmarks:** Wilson 95% confidence intervals, zero number drift, and fully documented failure modes.

📦 PyPI: `pip install agent-firewall-cascade`
💻 GitHub: https://github.com/DivyaKarotra/agent-firewall
📖 Documentation: https://DivyaKarotra.github.io/agent-firewall/
🤗 Dataset: https://huggingface.co/datasets/DivyaKarotra/agent-firewall-benchmark
✍️ Deep-dive blog post: https://github.com/DivyaKarotra/agent-firewall/blob/main/publish/blog_post.md

Would love your thoughts, feedback, and contributions!

#AI #MachineLearning #Cybersecurity #PromptInjection #LLM #Python #OpenSource #DevSecOps
