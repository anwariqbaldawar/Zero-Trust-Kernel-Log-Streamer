#!/usr/bin/env python3
"""Check the documentation set for the failures a reader sees and CI does not.

Catches, across README.md and docs/*.md:

  * relative links and images that point at a file that does not exist
  * in-page anchors that point at a heading that does not exist
  * unbalanced fenced code blocks
  * em dashes and en dashes (house style uses commas and full stops)
  * emoji (house style keeps the docs plain)
  * SVGs that are referenced by no document

Exit status is 1 if anything is wrong. No dependencies.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ["README.md", "CONTRIBUTING.md", "SECURITY.md"]
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".pytest_cache"}
ANCHOR_IGNORE = re.compile(r"^\s*(```|~~~)")


def documents() -> list[Path]:
    found = [ROOT / name for name in DOCS if (ROOT / name).exists()]
    found += sorted((ROOT / "docs").glob("*.md"))
    return found


def slug(heading: str) -> str:
    """GitHub's heading anchor: drop formatting, keep word chars and dashes."""
    text = heading.strip().lower()
    text = text.replace("`", "").replace("*", "")
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"\s+", "-", text)


def anchors(path: Path) -> set[str]:
    out: set[str] = set()
    fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if ANCHOR_IGNORE.match(line):
            fence = not fence
            continue
        if fence:
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            out.add(slug(m.group(2)))
    return out


def prose_lines(text: str) -> list[tuple[int, str]]:
    """Lines that are not inside a fenced block. Snippets show syntax, they do not link."""
    out: list[tuple[int, str]] = []
    fence = False
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("```", "~~~")):
            fence = not fence
            continue
        if not fence:
            out.append((lineno, line))
    return out


def prose(path: Path) -> str:
    return "\n".join(line for _, line in prose_lines(path.read_text(encoding="utf-8")))


def check_links(path: Path, problems: list[str], cache: dict[Path, set[str]]) -> None:
    text = prose(path)
    for match in re.finditer(r"(?<!!)\[([^\]]*)\]\(([^)\s]+)\)", text):
        target = match.group(2)
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        rel, _, frag = target.partition("#")
        resolved = (path.parent / rel).resolve() if rel else path
        if rel and not resolved.exists():
            problems.append(f"{path.relative_to(ROOT)}: link to missing file: {target}")
            continue
        if frag and resolved.suffix == ".md" and resolved.exists():
            if resolved not in cache:
                cache[resolved] = anchors(resolved)
            if frag not in cache[resolved]:
                problems.append(f"{path.relative_to(ROOT)}: link to missing anchor: {target}")


def check_images(path: Path, problems: list[str]) -> None:
    text = prose(path)
    for match in re.finditer(r"!\[[^\]]*\]\(([^)\s]+)\)", text):
        target = match.group(1)
        if target.startswith(("http://", "https://")):
            continue
        if not (path.parent / target).exists():
            problems.append(f"{path.relative_to(ROOT)}: image not found: {target}")


def check_style(path: Path, problems: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count("```") % 2:
        problems.append(f"{path.relative_to(ROOT)}: unbalanced fenced code block")
    for lineno, line in enumerate(text.splitlines(), 1):
        if "\u2014" in line:
            problems.append(f"{path.relative_to(ROOT)}:{lineno}: em dash")
        if "\u2013" in line:
            problems.append(f"{path.relative_to(ROOT)}:{lineno}: en dash")
        if re.search(r"[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]", line):
            problems.append(f"{path.relative_to(ROOT)}:{lineno}: emoji")


def check_orphans(docs: list[Path], problems: list[str]) -> None:
    referenced: set[str] = set()
    for path in docs:
        for match in re.finditer(r"!\[[^\]]*\]\(([^)\s]+)\)", prose(path)):
            referenced.add(Path(match.group(1)).name)
    for svg in sorted((ROOT / "docs").glob("*.svg")):
        if svg.name not in referenced:
            problems.append(f"docs/{svg.name}: figured by no document")


def main() -> int:
    problems: list[str] = []
    docs = documents()
    cache: dict[Path, set[str]] = {}
    for path in docs:
        check_links(path, problems, cache)
        check_images(path, problems)
        check_style(path, problems)
    check_orphans(docs, problems)

    if problems:
        print("\n".join(problems))
        print(f"\n{len(problems)} problem(s)")
        return 1
    print(f"ok   {len(docs)} documents: links, anchors, images, fences, style, figure references")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
