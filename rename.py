#!/usr/bin/env python3
"""
Utility script to safely rename the package, internal imports, configuration files,
pyproject.toml, and documentation.

Usage:
    python rename.py <new_package_name> [--dry-run]

Example:
    python rename.py secure_guard --dry-run
    python rename.py secure_guard
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Safely rename agent-firewall to a new package name."
    )
    parser.add_argument(
        "new_name",
        type=str,
        help="New snake_case package name (e.g. secure_agent_guard).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without modifying any files or directories.",
    )
    return parser.parse_args()


def validate_name(name: str) -> str:
    """Validate that the new name is a valid Python package identifier."""
    cleaned = name.strip().lower()
    if not re.match(r"^[a-z][a-z0-9_]*$", cleaned):
        print(f"Error: '{name}' is not a valid Python identifier (must match ^[a-z][a-z0-9_]*$).", file=sys.stderr)
        sys.exit(1)
    return cleaned


def find_target_files(root: Path, old_dir_name: str) -> list[Path]:
    """Find all text files (py, toml, md, yml, json) that may contain references."""
    extensions = {".py", ".toml", ".md", ".yml", ".yaml", ".json", ".rst", ".txt"}
    ignored_dirs = {".git", ".pytest_cache", ".ruff_cache", "__pycache__", ".venv", "venv", "dist", "build", "site", ".cache"}

    target_files = []
    for path in root.rglob("*"):
        if path.is_file():
            # Check if any parent is ignored
            if any(part in ignored_dirs or part.endswith(".egg-info") for part in path.parts):
                continue
            if path.suffix.lower() in extensions:
                target_files.append(path)
    return sorted(target_files)


def rename_in_content(
    content: str,
    old_snake: str,
    new_snake: str,
    old_kebab: str,
    new_kebab: str,
) -> tuple[str, int]:
    """Replace occurrences of kebab and snake case names."""
    replacements = 0

    # 1. Replace kebab-case first (e.g. agent-firewall -> new-package)
    new_content, count_kebab = re.subn(re.escape(old_kebab), new_kebab, content)
    replacements += count_kebab

    # 2. Replace snake_case (e.g. agent_firewall -> new_package)
    new_content, count_snake = re.subn(re.escape(old_snake), new_snake, new_content)
    replacements += count_snake

    return new_content, replacements


def main() -> None:
    args = parse_args()
    new_snake = validate_name(args.new_name)
    new_kebab = new_snake.replace("_", "-")

    root = Path(__file__).resolve().parent

    old_snake = "agent_firewall"
    old_kebab = "agent-firewall"

    old_pkg_dir = root / old_snake
    new_pkg_dir = root / new_snake

    if new_snake == old_snake:
        print(f"Package is already named '{old_snake}'. Nothing to rename.")
        return

    print(f"{'PREVIEW: ' if args.dry_run else ''}Renaming '{old_snake}' -> '{new_snake}' (kebab: '{old_kebab}' -> '{new_kebab}')\n")

    # 1. Update text content in all target files
    files = find_target_files(root, old_snake)
    modified_files: list[Path] = []
    total_replacements = 0

    for file_path in files:
        # Skip rename.py itself
        if file_path.resolve() == Path(__file__).resolve():
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            continue

        new_content, count = rename_in_content(content, old_snake, new_snake, old_kebab, new_kebab)
        if count > 0:
            total_replacements += count
            modified_files.append(file_path)
            rel_path = file_path.relative_to(root)
            print(f"  [{'DRY-RUN' if args.dry_run else 'MODIFIED'}] {rel_path} ({count} replacements)")
            if not args.dry_run:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(new_content)

    # 2. Rename directory
    if old_pkg_dir.exists() and old_pkg_dir.is_dir():
        rel_old = old_pkg_dir.relative_to(root)
        rel_new = new_pkg_dir.relative_to(root)
        print(f"  [{'DRY-RUN' if args.dry_run else 'RENAMED DIR'}] {rel_old} -> {rel_new}")
        if not args.dry_run:
            if new_pkg_dir.exists():
                print(f"Error: Destination directory {new_pkg_dir} already exists!", file=sys.stderr)
                sys.exit(1)
            shutil.move(str(old_pkg_dir), str(new_pkg_dir))
    else:
        print(f"Note: Source package directory '{old_pkg_dir.name}' not found. Directory rename skipped.")

    print(f"\nDone! Modified {len(modified_files)} files with {total_replacements} total replacements.")
    if args.dry_run:
        print("\nThis was a dry run. No files or directories were changed.")


if __name__ == "__main__":
    main()
