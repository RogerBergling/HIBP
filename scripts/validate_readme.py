#!/usr/bin/env python3
"""Validate the repository README without third-party dependencies.

Checks:
  * UTF-8, LF line endings, final newline, and trailing whitespace
  * balanced fenced code blocks
  * a single H1 and no skipped heading levels
  * unique GitHub-style heading anchors
  * local links and in-document anchors
  * table rows with a consistent number of columns
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
IMAGE_RE = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")
INLINE_CODE_RE = re.compile(r"`[^`]*`")


def github_slug(text: str) -> str:
    """Approximate GitHub's heading anchor generation."""
    text = re.sub(r"<[^>]+>", "", text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"-{2,}", "-", text)
    return text.strip("-")


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []

    if not README.is_file():
        print(f"ERROR: {README} does not exist")
        return 1

    raw = README.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        print(f"ERROR: README is not valid UTF-8: {exc}")
        return 1

    if b"\r" in raw:
        errors.append("README contains CR characters; use LF line endings")

    if not text.endswith("\n"):
        errors.append("README does not end with a newline")

    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        if line != line.rstrip():
            errors.append(f"line {number}: trailing whitespace")

    fence: str | None = None
    fence_start = 0
    for number, line in enumerate(lines, start=1):
        match = FENCE_RE.match(line)
        if not match:
            continue
        marker = match.group(1)
        if fence is None:
            fence = marker
            fence_start = number
        elif marker[0] == fence[0] and len(marker) >= len(fence):
            fence = None
    if fence is not None:
        errors.append(f"unclosed fenced code block starting at line {fence_start}")

    headings: list[tuple[int, str, int]] = []
    in_fence = False
    for number, line in enumerate(lines, start=1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING_RE.match(line)
        if match:
            headings.append((len(match.group(1)), match.group(2), number))

    h1 = [h for h in headings if h[0] == 1]
    if len(h1) != 1:
        errors.append(f"expected exactly one H1 heading, found {len(h1)}")
    if headings and headings[0][0] != 1:
        errors.append("the first heading must be H1")

    previous_level = 0
    for level, title, number in headings:
        if previous_level and level > previous_level + 1:
            errors.append(
                f"line {number}: heading level jumps from H{previous_level} to H{level}"
            )
        previous_level = level

    slugs: dict[str, int] = {}
    duplicate_slugs: set[str] = set()
    for _, title, _ in headings:
        slug = github_slug(title)
        if not slug:
            continue
        if slug in slugs:
            duplicate_slugs.add(slug)
        slugs[slug] = slugs.get(slug, 0) + 1

    for slug in sorted(duplicate_slugs):
        warnings.append(f"duplicate heading anchor: #{slug}")

    anchors = set(slugs)
    # GitHub appends -1, -2, ... to duplicate headings. Accept those forms.
    for slug, count in slugs.items():
        for index in range(1, count):
            anchors.add(f"{slug}-{index}")

    local_links = 0
    for number, line in enumerate(lines, start=1):
        stripped = INLINE_CODE_RE.sub("", line)
        for target in LINK_RE.findall(stripped) + IMAGE_RE.findall(stripped):
            target = target.strip()
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            if target.startswith(("http://", "https://", "mailto:", "tel:")):
                continue
            local_links += 1
            if target.startswith("#"):
                anchor = unquote(target[1:])
                if anchor and anchor not in anchors:
                    errors.append(f"line {number}: missing anchor #{anchor}")
                continue
            path_part = unquote(target.split("#", 1)[0].split("?", 1)[0])
            if not path_part:
                continue
            if not (ROOT / path_part).exists():
                errors.append(f"line {number}: local link target does not exist: {path_part}")

    # Check pipe tables outside fenced code blocks.
    in_fence = False
    table_start = 0
    table_columns = 0
    for number, line in enumerate(lines, start=1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            table_start = 0
            continue
        if in_fence:
            continue
        if line.lstrip().startswith("|"):
            columns = line.count("|") - 1
            if table_start == 0:
                table_start = number
                table_columns = columns
            elif columns != table_columns:
                errors.append(
                    f"line {number}: table started at line {table_start} has "
                    f"{table_columns} columns, this row has {columns}"
                )
        else:
            table_start = 0
            table_columns = 0

    if errors:
        print("README validation failed:")
        for error in errors:
            print(f"  ERROR: {error}")
    if warnings:
        print("Warnings:")
        for warning in warnings:
            print(f"  WARN: {warning}")

    if errors:
        return 1

    print(
        "README validation passed "
        f"({len(lines)} lines, {len(headings)} headings, "
        f"{local_links} local links, {len(slugs)} anchors)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
