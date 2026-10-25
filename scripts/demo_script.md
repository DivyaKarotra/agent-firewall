# agent-firewall: 2-Minute Demo Recording Script

A structured 2-minute walkthrough showing prompt injection defense, risk-aware policy gating, and dashboard exploration.

---

## Preparation (Before Recording)
1. Ensure terminal font is clear and set to 1080p recording window.
2. Ensure Ollama is running in the background: `ollama run llama3.2:3b`.
3. Terminal directory: repo root (`agent-firewall/`).

---

## Timeline & Commands

### [0:00 - 0:25] Introduction & The Problem
**Visual:** Terminal showing clean prompt.  
**Spoken Commentary:**
> *"AI agents are increasingly trusted with sensitive tools: querying databases, executing shell commands, and sending emails. But when an agent reads untrusted web content or emails, indirect prompt injection can hijack its tools. Here is what happens without protection."*

**Command to run:**
```bash
python demo.py --judge none
```

**Highlight on screen:**
Point to **Scenario 1**: The gullible agent reads an email containing hidden instructions and immediately forwards the user's credentials to `attacker@evil.com`.
Point to **Scenario 2**: With `Warden` protecting the tool call, the tainted session is caught and `send_email` is BLOCKED.

---

### [0:25 - 0:55] Cascaded Detection & Risk Policy
**Visual:** Quick slide / diagram or README architecture view.  
**Spoken Commentary:**
> *"agent-firewall does not just do binary blocking. It introduces a three-layer cascade: fast regex rules running in under 1 millisecond, calibrated TF-IDF machine learning running in 20 milliseconds, and an LLM judge running in 3 seconds. Crucially, the LLM judge is gated—only invoked when cheaper layers disagree in an uncertain band between 0.35 and 0.75."*

**Command to run:**
```bash
python examples/01_basic_warden.py
```

**Highlight on screen:**
Show how reading untrusted content taints the session suspicion (0.99), blocking the high-risk `send_email` tool, while allowing safe low-risk actions.

---

### [0:55 - 1:30] Interactive Security Dashboard
**Visual:** Web browser showing Streamlit UI.  
**Spoken Commentary:**
> *"Let's explore this interactively in the agent-firewall dashboard."*

**Command to run:**
```bash
python -m streamlit run dashboard/app.py
```

**Action in browser (`http://localhost:8501`):**
1. Select a pre-canned attack from the dropdown: *"Q3 Report Exfiltration"*.
2. Click **Run Cascade**.
3. Point out the layer scores:
   - Rules Score: 0.99 (decisive early exit)
   - Classifier & Judge: Skipped!
   - Latency: < 1 ms!
4. Select a borderline / reworded prompt:
   - Point out how it falls in the uncertain band `[0.35, 0.75]` and triggers the Judge layer.
5. Toggle the policy profile between **Strict**, **Balanced**, and **Lenient** to show how tool risk level dynamically switches the decision from `ALLOW` to `ASK` to `BLOCK`.

---

### [1:30 - 2:00] Benchmark Reproducibility & Wrap-Up
**Visual:** Return to terminal.  
**Spoken Commentary:**
> *"Every metric in our README is reproducible. You can run the entire test suite in seconds without external dependencies, or benchmark across the full dataset with local Ollama models."*

**Command to run:**
```bash
pytest -v -k "test_firewall"
```

**Closing remarks:**
> *"agent-firewall is 100% open source under the MIT license, with zero required runtime dependencies for the core library. Try it with `pip install agent-firewall` today."*
