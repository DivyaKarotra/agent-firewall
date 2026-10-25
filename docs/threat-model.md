# Threat Model

## What agent-firewall defends against

1. **Prompt injection via untrusted content**: malicious instructions hidden
   in emails, web pages, documents, or API responses that trick an AI agent
   into performing unintended tool calls.

2. **Obfuscated attacks**: base64-encoded, leetspeak, space-separated, or
   zero-width-character-obfuscated injections.

3. **Judge spoofing**: attempts to dictate the LLM judge's verdict or escape
   the `<untrusted_text>` fence.

## What it does NOT defend against

1. **Direct user attacks**: if the user themselves are the attacker, the
   firewall cannot help (the user controls the confirm callback).

2. **Multi-turn attacks**: sophisticated attacks that spread the injection
   across multiple messages are harder to detect with single-text scanning.

3. **Novel attack patterns**: purely semantic attacks with no lexical
   signals may evade the regex rules. The LLM judge helps here but is not
   perfect.

4. **Non-English attacks**: rule coverage is English-only. The LLM judge
   may catch non-English attacks, but this is model-dependent.

5. **Adversarial examples**: carefully crafted inputs designed to evade
   specific detection methods.

## Trust boundaries

```
┌─────────────────────────────┐
│        Trusted Zone         │
│  User ↔ Agent ↔ Firewall    │
│                             │
│  The firewall trusts:       │
│  - Its own rules            │
│  - The policy configuration │
│  - The confirm callback     │
└───────────┬─────────────────┘
            │
            │ untrusted content flows in
            ▼
┌─────────────────────────────┐
│       Untrusted Zone        │
│  Emails, web pages, docs,   │
│  API responses, user files  │
└─────────────────────────────┘
```

## Assumptions

1. The AI agent correctly marks tool outputs as untrusted when they contain
   external content.
2. The policy thresholds are appropriately set for the deployment context.
3. The LLM judge (when used) is not itself compromised.
