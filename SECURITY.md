# Security Policy

## Reporting Security Vulnerabilities

We take the security of `agent-firewall` seriously. If you discover a security vulnerability in this project, please report it responsibly:

- **Do NOT open a public GitHub issue.**
- Submit your finding via GitHub Private Vulnerability Reporting at:
  `https://github.com/DivyaKarotra/agent-firewall/security/advisories/new`
- Provide detailed steps to reproduce the vulnerability, including Python code snippets or injection payloads.
- We will acknowledge receipt within 48 hours and coordinate a patch and disclosure timeline.

---

## Responsible Use of the Benchmark Dataset

`agent-firewall` includes sample prompt injection and exfiltration payloads in `data/attacks.jsonl`:

1. **Intended Purpose**:
   The attack dataset is provided strictly for academic research, benchmark evaluation, and hardening AI agent defense pipelines.
2. **Harm Minimization**:
   All included attack strings (direct overrides, exfiltration triggers, obfuscated payloads) utilize synthetic domain names (`example.com`, `evil.com`), dummy credentials, and mocked API targets. No live exploit payloads targeting production infrastructure are included.
3. **Prohibited Uses**:
   Do not use this dataset or the software to attack third-party AI systems, bypass unauthorized access controls, or launch malicious prompt injections against unconsenting services.
4. **Defense-in-Depth Principle**:
   `agent-firewall` is designed as one layer in a defense-in-depth architecture. It does not replace principle-of-least-privilege permissions, network isolation, or human supervision for high-impact actions.
