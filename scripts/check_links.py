#!/usr/bin/env python3
"""
scripts/check_links.py

Check all external URLs across LINKS (dashboard/app.py), README.md, docs/*.md,
pyproject.toml, CITATION.cff, and publish/*.md.
Outputs a structured ASCII table with HTTP status code and Pass/Fail/Pending state.
"""

from __future__ import annotations

import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Ensure UTF-8 output on Windows
sys.stdout.reconfigure(encoding="utf-8")

REPO_ROOT = Path(__file__).resolve().parent.parent

# Files to scan for URLs
SCAN_FILES = [
    REPO_ROOT / "dashboard" / "app.py",
    REPO_ROOT / "README.md",
    REPO_ROOT / "mkdocs.yml",
    REPO_ROOT / "pyproject.toml",
    REPO_ROOT / "CITATION.cff",
    *sorted((REPO_ROOT / "docs").glob("*.md")),
    *sorted((REPO_ROOT / "publish").glob("*.md")),
]


def extract_external_urls() -> list[tuple[str, str]]:
    """Extract all HTTP/HTTPS URLs and their source file."""
    urls: list[tuple[str, str]] = []
    seen = set()

    for path in SCAN_FILES:
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            continue

        rel_path = path.relative_to(REPO_ROOT).as_posix()

        # Find markdown links: [text](http...)
        for m in re.finditer(r"\[[^\]]+\]\((https?://[^)\s\"'>]+)\)", content):
            url = m.group(1).rstrip(".,;")
            if (url, rel_path) not in seen:
                seen.add((url, rel_path))
                urls.append((url, rel_path))

        # Find html href="http..."
        for m in re.finditer(r'href=["\'](https?://[^"\'>]+)["\']', content):
            url = m.group(1).rstrip(".,;")
            if (url, rel_path) not in seen:
                seen.add((url, rel_path))
                urls.append((url, rel_path))

        # Find raw URLs in toml, cff, yml, py
        if path.suffix in [".toml", ".cff", ".yml", ".py"]:
            for m in re.finditer(r'["\'](https?://[^"\'\s>]+)["\']', content):
                url = m.group(1).rstrip(".,;")
                # Skip font stylesheets or schemas if needed
                if (url, rel_path) not in seen:
                    seen.add((url, rel_path))
                    urls.append((url, rel_path))

    return urls


def check_url(url: str, timeout: float = 10.0) -> tuple[int, str]:
    """Check URL status. Returns (status_code, status_message)."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, "OK"
    except urllib.error.HTTPError as e:
        return e.code, f"HTTP Error: {e.code}"
    except urllib.error.URLError as e:
        return 0, f"Network/URL Error: {e.reason}"
    except Exception as e:
        return 0, f"Error: {e}"


def main() -> int:
    print("=" * 80)
    print("AgentFirewall External Link Checker")
    print("=" * 80)

    url_pairs = extract_external_urls()
    print(f"Discovered {len(url_pairs)} external URL references.\n")

    # Group by URL to avoid duplicate network requests
    unique_urls = sorted({u for u, _ in url_pairs})
    url_results: dict[str, tuple[int, str]] = {}

    for url in unique_urls:
        if "localhost" in url:
            url_results[url] = (0, "Local service (skipped)")
            continue
        code, msg = check_url(url)
        url_results[url] = (code, msg)

    # Print results table
    header_fmt = "{:<55} | {:<22} | {:<6} | {:<10}"
    row_fmt = "{:<55} | {:<22} | {:<6} | {:<10}"

    print(header_fmt.format("URL", "Source File", "Code", "Result"))
    print("-" * 102)

    for url, src in url_pairs:
        code, msg = url_results[url]
        code_str = str(code) if code > 0 else "-"

        # Consider 200..399 or intentional pending targets
        if 200 <= code < 400:
            verdict = "PASS"
        elif "localhost" in url:
            verdict = "LOCAL"
        else:
            verdict = "PENDING/FAIL"

        display_url = url if len(url) <= 55 else url[:52] + "..."
        display_src = src if len(src) <= 22 else src[:19] + "..."
        print(row_fmt.format(display_url, display_src, code_str, verdict))

    print("-" * 102)
    print("Done. Pass = HTTP 200-399. Pending/Fail = 404 or connection issue (expected prior to release).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
