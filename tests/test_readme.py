"""Tests for README.md link and image validity for PyPI release."""

import re
from pathlib import Path


def test_readme_no_relative_links_or_images():
    """Verify that README.md contains no relative image paths or file links.

    PyPI cannot resolve relative repository paths; all images and links must be
    absolute URLs (e.g. raw.githubusercontent.com, github.com, docs site, or anchors).
    """
    repo_root = Path(__file__).parent.parent
    readme_path = repo_root / "README.md"
    assert readme_path.exists(), "README.md not found"

    content = readme_path.read_text(encoding="utf-8")

    # Strip fenced code blocks so shell commands/code examples are not treated as links
    content_no_code = re.sub(r"```.*?```", "", content, flags=re.DOTALL)

    # 1. Markdown links & images: ](target)
    # Strips any optional markdown link title e.g. ](target "title")
    md_raw_targets = re.findall(r"\]\(([^)\s]+)", content_no_code)

    # 2. HTML elements: <a href="..."> and <img src="...">
    html_hrefs = re.findall(r'<a\s+[^>]*href=["\']([^"\']+)["\']', content_no_code, re.IGNORECASE)
    html_srcs = re.findall(r'<img\s+[^>]*src=["\']([^"\']+)["\']', content_no_code, re.IGNORECASE)

    all_targets = [t.strip() for t in (md_raw_targets + html_hrefs + html_srcs) if t.strip()]
    assert len(all_targets) > 0, "Expected at least one link or image in README.md"

    allowed_prefixes = ("http://", "https://", "mailto:", "#")
    relative_targets = [
        target for target in all_targets
        if not target.startswith(allowed_prefixes)
    ]

    assert not relative_targets, (
        f"README.md contains relative link/image targets that fail on PyPI: {relative_targets}. "
        "Images must use absolute raw.githubusercontent.com URLs, and repository links must use "
        "absolute GitHub/documentation URLs."
    )


def test_readme_referenced_images_exist_in_repo():
    """Verify that every image referenced in README.md actually exists on disk in the repo."""
    repo_root = Path(__file__).parent.parent
    readme_path = repo_root / "README.md"
    content = readme_path.read_text(encoding="utf-8")

    # Extract raw.githubusercontent.com/DivyaKarotra/agent-firewall/main/<path>
    raw_prefix = "https://raw.githubusercontent.com/DivyaKarotra/agent-firewall/main/"
    image_urls = re.findall(r"\]\((https?://[^)\s]+)", content)

    for url in image_urls:
        if url.startswith(raw_prefix):
            rel_path = url[len(raw_prefix):]
            local_file = repo_root / rel_path
            assert local_file.exists(), f"Image referenced in README.md does not exist locally: {rel_path}"
