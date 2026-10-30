"""Verify README.md images, links, and rendering for PyPI release."""

import re
from pathlib import Path


def main():
    repo_root = Path(__file__).parent.parent
    readme_path = repo_root / "README.md"
    readme_text = readme_path.read_text(encoding="utf-8")

    print("=" * 60)
    print("1. EXTRACTED IMAGE URLS IN README.md")
    print("=" * 60)

    # Markdown images: ![alt](url)
    md_images = re.findall(r'!\[[^\]]*\]\(([^)\s]+)', readme_text)
    for idx, img in enumerate(md_images, 1):
        print(f"  {idx}. {img}")

    # Also list all badge images
    badge_images = [img for img in md_images if "shields.io" in img or "badge.svg" in img]
    content_images = [img for img in md_images if img not in badge_images]

    print("\nContent Images to verify on GitHub once pushed:")
    for img in content_images:
        print(f"  * {img}")

    print("\n" + "=" * 60)
    print("2. HTML RENDERING & RELATIVE SOURCE CHECK")
    print("=" * 60)

    import markdown
    rendered_html = markdown.markdown(readme_text, extensions=["tables", "fenced_code"])
    img_srcs = re.findall(r'<img\s+[^>]*src=["\']([^"\']+)["\']', rendered_html, re.IGNORECASE)
    link_hrefs = re.findall(r'<a\s+[^>]*href=["\']([^"\']+)["\']', rendered_html, re.IGNORECASE)

    print(f"Rendered HTML size: {len(rendered_html)} bytes")
    print(f"Total <img> tags: {len(img_srcs)}")
    print(f"Total <a> tags: {len(link_hrefs)}")

    allowed_prefixes = ("http://", "https://", "mailto:", "#")
    relative_images = [src for src in img_srcs if not src.startswith(allowed_prefixes)]
    relative_links = [href for href in link_hrefs if not href.startswith(allowed_prefixes)]

    if relative_images:
        print(f"\n[FAIL] Found relative image sources in rendered HTML: {relative_images}")
    else:
        print("\n[PASS] No relative image sources found in rendered HTML.")

    if relative_links:
        print(f"[FAIL] Found relative link hrefs in rendered HTML: {relative_links}")
    else:
        print("[PASS] No relative link hrefs found in rendered HTML.")

    assert not relative_images and not relative_links, "Relative URLs detected in rendered HTML!"
    print("\nAll checks passed successfully.")

if __name__ == "__main__":
    main()
