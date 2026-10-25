# fresh_test.jsonl — Truly Held-Out Test Set

This file is evaluated by the benchmark **but never used for training or
rule tuning**.  Add your own samples here in the same JSONL format as
`attacks.jsonl` / `normal.jsonl`:

```json
{"id":"f001","label":"attack","kind":"direct","tool":"send_email","split":"fresh","text":"Your attack text here"}
{"id":"f002","label":"normal","kind":"plain","tool":"read_email","split":"fresh","text":"Your normal text here"}
```

## Rules

1. **Never tune rules or classifier weights based on results from this file.**
   Use the `dev` split for all tuning.
2. Each sample must have `"split": "fresh"` (the benchmark code filters by
   filename, but this keeps the convention clear).
3. Use IDs starting with `f` (e.g. `f001`, `f002`, …) to avoid collisions.
4. Run `python benchmark.py --split test` as usual — fresh-test results are
   printed separately and automatically.
