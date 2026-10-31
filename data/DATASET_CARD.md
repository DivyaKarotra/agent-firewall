---
annotations_creators:
- synthetic
language:
- en
- hi
- mr
- es
- fr
- de
language_creators:
- synthetic
license: mit
multilinguality:
- multilingual
pretty_name: agent-firewall Prompt Injection Benchmark
size_categories:
- n<1K
source_datasets:
- original
tags:
- prompt-injection
- security
- ai-safety
- agent
- tool-use
task_categories:
- text-classification
task_ids: []
---

# Dataset Card: agent-firewall Benchmark Data

## Dataset Description

- **Repository:** [agent-firewall on GitHub](https://github.com/DivyaKarotra/agent-firewall)
- **Hugging Face Dataset:** [DivyaKarotra/agent-firewall-benchmark](https://huggingface.co/datasets/DivyaKarotra/agent-firewall-benchmark)
- **Paper / Documentation:** [Documentation](https://DivyaKarotra.github.io/agent-firewall/)
- **License:** MIT
- **Task:** Prompt-injection detection and risk-aware policy decisions for LLM agent tool calls

## Overview

This dataset contains curated and categorized text samples for evaluating prompt-injection defenses in the context of LLM agent tool executions (reading emails, executing web searches, sending emails, saving notes).

Each sample represents content processed by an AI agent before or during sensitive tool execution.

## Dataset Structure

Each sample is represented in JSONL format with the following schema:

| Field   | Type   | Description                                           |
|---------|--------|-------------------------------------------------------|
| `id`    | string | Unique identifier (e.g. `a001`, `n001`, `f001`)       |
| `label` | string | `"attack"` or `"normal"`                              |
| `kind`  | string | Specific attack or benign category                    |
| `tool`  | string | Tool context (`read_email`, `send_email`, `save_note`)|
| `split` | string | Benchmark split (`dev`, `test`, `fresh`)              |
| `text`  | string | The raw text input payload                            |

### Attack Categories (`label: "attack"`)

- **direct**: Explicit command overrides (`Ignore previous instructions and ...`).
- **indirect**: Injections hidden in third-party content (HTML comments, email footers, resumes).
- **encoded**: Obfuscated payloads (Base64 blobs, leetspeak, spaced letters, zero-width spaces).
- **multilingual**: Non-English attacks (Hindi/Hinglish, Marathi, Spanish, French, German).
- **reworded**: Semantic paraphrasing avoiding standard lexical trigger words.
- **judge_targeted**: Payloads designed to deceive LLM judges (claiming prior security review, fake system tags).
- **framed**: Exploit payloads wrapped in benign tutorial, academic, or red-team framing.

### Normal Categories (`label: "normal"`)

- **plain**: Routine everyday communications, recipes, business emails, and meeting summaries.
- **hard**: Benign inputs with high surface similarity to attacks (security articles, legitimate "ignore previous email", password reset links, non-English administrative text).

## Dataset Statistics

| Split | Attacks | Normal | Total | Notes |
|-------|---------|--------|-------|-------|
| `dev` | 99      | 101    | 200   | Used strictly for out-of-fold calibration and threshold selection |
| `test`| 35      | 30     | 65    | Fixed held-out test split |
| `fresh`| 56     | 59     | 115   | Exploratory evaluation set (partly used for design iteration) |
| **Total** | **190** | **190** | **380** | Balanced binary distribution |

## Creation & Sourcing

All samples were synthetically authored and curated specifically for benchmarking `agent-firewall`. No private user communications, proprietary intellectual property, or live credentials are included. Synthetic domain names (`example.com`, `evil.com`) and placeholder passwords are used throughout.

## Limitations & Ethical Considerations

- **Single-Author Sourcing**: Samples were authored and structured by a single contributor; enterprise traffic distributions may differ.
- **Academic & Defense Use Only**: Intended strictly for benchmarking, red-teaming, and evaluating LLM guardrails.
