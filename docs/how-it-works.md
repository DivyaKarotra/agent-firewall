# How It Works

## Architecture

agent-firewall uses a three-layer detection cascade followed by a
risk-aware policy engine.

```
Untrusted text
      │
      ▼
┌─────────────┐
│  1. Rules    │  Weighted regex + noisy-or (< 1ms)
│  (always)    │  Also decodes: base64, leetspeak, spaced letters
└──────┬──────┘
       │ score >= 0.90? → skip remaining layers
       ▼
┌─────────────┐
│ 2. Classifier│  TF-IDF + LogReg (optional, < 10ms)
│ (optional)   │  Requires scikit-learn
└──────┬──────┘
       │ combined score >= 0.90? → skip judge
       ▼
┌─────────────┐
│  3. Judge    │  LLM call (Ollama / OpenAI-compatible)
│  (optional)  │  Fenced prompt, JSON output, ~1-5s
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Policy     │  (suspicion, risk_level) → ALLOW | ASK | BLOCK
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Warden     │  Session tracking, tool wrapping, JSONL logging
└─────────────┘
```

## Detection Cascade

### Layer 1: Rules

- 20+ weighted regex patterns covering override, jailbreak, exfiltration, etc.
- NFKC normalisation + zero-width character stripping
- Decoded variants: base64 blobs, leetspeak, space-separated letters
- Obfuscation bonus (+0.4) only when a variant reveals NEW rule hits
- Scores combined via noisy-or: `1 - Π(1 - wᵢ)`

### Layer 2: Classifier (optional)

- TF-IDF with word (1-3) and character (3-5) n-grams
- Logistic regression with balanced class weights
- Trained from the provided dataset (`data/*.jsonl`)

### Layer 3: LLM Judge (optional)

- Untrusted text fenced in `<untrusted_text>` tags
- Fence tags stripped from input to prevent escape
- Truncated to 3000 chars
- JSON-only output: `{is_injection, confidence, reason}`
- Errors → suspicion 0.5 with error flag

## Combine Modes

- **max** (default): judge can only raise suspicion
- **blend**: weighted average (judge can also lower)
- **verify**: judge verifies rule hits (>=0.5); lowers only if confident is_injection=false
- **gated**: rules -> classifier -> judge invoked only within uncertain band [0.35, 0.70]

## Policy Engine

Thresholds per risk level:

| Risk   | ASK threshold | BLOCK threshold |
|--------|--------------|-----------------|
| low    | —            | 0.90            |
| medium | 0.50         | 0.85            |
| high   | 0.45         | 0.70            |
