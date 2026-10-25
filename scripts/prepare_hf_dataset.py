"""
scripts/prepare_hf_dataset.py - Package benchmark dataset into an upload-ready Hugging Face folder.

Usage:
    python scripts/prepare_hf_dataset.py [--output-dir hf_dataset]
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"


def load_samples(filepath: Path) -> list[dict]:
    if not filepath.exists():
        return []
    samples = []
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare upload-ready Hugging Face dataset")
    parser.add_argument("--output-dir", default="hf_dataset", help="Output directory path")
    args = parser.parse_args()

    out_dir = ROOT / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Preparing Hugging Face dataset in: {out_dir}")

    # Load all sources
    attacks = load_samples(DATA_DIR / "attacks.jsonl")
    normals = load_samples(DATA_DIR / "normal.jsonl")
    fresh = load_samples(DATA_DIR / "fresh_test.jsonl")

    all_samples = attacks + normals

    dev_samples = [s for s in all_samples if s.get("split") == "dev"]
    test_samples = [s for s in all_samples if s.get("split") == "test"]
    fresh_samples = fresh

    print(f"  Dev split   : {len(dev_samples)} samples")
    print(f"  Test split  : {len(test_samples)} samples")
    print(f"  Fresh split : {len(fresh_samples)} samples")

    # Write split jsonl files
    splits = {
        "dev.jsonl": dev_samples,
        "test.jsonl": test_samples,
        "fresh.jsonl": fresh_samples,
    }

    for filename, items in splits.items():
        split_path = out_dir / filename
        with open(split_path, "w", encoding="utf-8") as f:
            for item in items:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"  Wrote {split_path.name} ({len(items)} items)")

    # Copy dataset card as HF README.md
    card_path = DATA_DIR / "DATASET_CARD.md"
    target_readme = out_dir / "README.md"
    shutil.copyfile(card_path, target_readme)
    print(f"  Copied {card_path.name} -> {target_readme.name}")

    print("\nDataset preparation complete! To upload to Hugging Face Hub:")
    print("  huggingface-cli login")
    print(f"  huggingface-cli upload YOUR_USERNAME/agent-firewall-benchmark {args.output_dir} . --repo-type dataset")


if __name__ == "__main__":
    main()
