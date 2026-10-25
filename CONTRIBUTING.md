# Contributing to agent-firewall

Thank you for your interest in contributing to `agent-firewall`!

## Code of Conduct

Please maintain a respectful, constructive, and collaborative tone in all discussions, issues, and pull requests.

## Local Development Setup

Clone the repository and install the development dependencies:

```bash
git clone https://github.com/YOUR_USERNAME/agent-firewall.git
cd agent-firewall

# Create and activate a virtual environment
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Install in editable mode with all extras
pip install -e ".[dev,ml,dashboard]"
```

## Quality Standards & Checks

Before submitting a pull request, ensure all tests and linting checks pass:

```bash
# Code formatting and linting
python -m ruff check .

# Test suite execution
python -m pytest -v

# Documentation validation (strict mode)
python -m mkdocs build --strict

# Build package artifacts and check distribution metadata
python -m build
python -m twine check dist/*
```

## Adding Rules or Dataset Samples

- **Benchmark Dataset Integrity**: Do not modify existing samples in `data/attacks.jsonl` or `data/normal.jsonl` without explicit rationale.
- **Rule Changes**: Any modification to regex rules in `agent_firewall/rules.py` must be verified against false positive regression tests in `tests/test_firewall.py`.
- **Honest Metrics**: When reporting detection numbers, always run the evaluation scripts and include Wilson 95% confidence intervals.
