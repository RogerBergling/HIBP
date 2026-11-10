#!/usr/bin/env python3
"""Validate the repository README without third-party dependencies.

Checks:
  * UTF-8, LF line endings, final newline, and trailing whitespace
  * balanced fenced code blocks
  * a single H1 and no skipped heading levels
  * unique GitHub-style heading anchors
  * local links, image links, and in-document anchors
  * table rows with a consistent number of columns
  * image alt text and basic PNG validity

Requires Python 3.9+.
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

FENCE_RE = re.compile(r"^(\s{0,3})(`{3,}|~{3,})(.*)$")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
INLINE_CODE_RE = re.compile(r"`[^`]*`")
LINK_RE = re.compile(
    r"(?<!!)\[([^\]]*)\]\(\s*(<[^>]*>|[^)\s]+)(?:\s+[\"'][^\"']*[\"'])?\s*\)"
)
IMAGE_RE = re.compile(
    r"!\[([^\]]*)\]\(\s*(<[^>]*>|[^)\s]+)(?:\s+[\"'][^\"']*[\"'])?\s*\)"
)


def github_slug(text: str) -> str:
    """Approximate GitHub's heading anchor generation."""
    text = re.sub(r"<[^>]+>", "", text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    text = re.sub(r"[\s]+", "-", text)
    text = re.sub(r"-{2,}", "-", text)
    return text.strip("-")


def strip_inline_code(line: str) -> str:
    """Replace inline code spans with spaces so pipes inside code are ignored."""
    return INLINE_CODE_RE.sub(lambda m: " " * len(m.group(0)), line)


def table_columns(line: str) -> int:
    """Count pipe-table columns, ignoring escaped pipes and inline code."""
    text = strip_inline_code(line).strip()
    if not text:
        return 0
    pipes = 0
    escaped = False
    for char in text:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "|":
            pipes += 1
    if text.startswith("|") and text.endswith("|"):
        return max(0, pipes - 1)
    return pipes + 1


def is_separator_row(line: str) -> bool:
    cells = [cell.strip() for cell in strip_inline_code(line).strip().strip("|").split("|")]
    if not cells:
        return False
    return all(re.fullmatch(r":?-{3,}:?", cell or "") for cell in cells)


def png_dimensions(path: Path) -> tuple[int, int] | None:
    """Return (width, height) for a PNG, or None if it is not a valid PNG."""
    try:
        with path.open("rb") as handle:
            header = handle.read(24)
    except OSError:
        return None
    if len(header) < 24 or header[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    width, height = struct.unpack(">II", header[16:24])
    return width, height


def parse_fences(lines: list[str]) -> tuple[list[bool], list[str]]:
    """Return per-line in-fence flags and fence errors."""
    in_fence = [False] * len(lines)
    errors: list[str] = []
    fence_char = ""
    fence_len = 0
    fence_start = 0

    for index, line in enumerate(lines):
        match = FENCE_RE.match(line)
        if fence_char:
            in_fence[index] = True
            if match:
                marker = match.group(2)
                if marker[0] == fence_char and len(marker) >= fence_len and not match.group(3).strip():
                    fence_char = ""
                    fence_len = 0
            continue
        if match:
            marker = match.group(2)
            fence_char = marker[0]
            fence_len = len(marker)
            fence_start = index + 1
            in_fence[index] = True

    if fence_char:
        errors.append(f"unclosed fenced code block starting at line {fence_start}")
    return in_fence, errors


def local_target(target: str) -> str:
    target = target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    return target


def check_path(root: Path, target: str, line_number: int, errors: list[str]) -> None:
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https", "mailto", "tel"):
        return
    if target.startswith("#"):
        return
    path_part = unquote(parsed.path)
    if not path_part:
        return
    candidate = (root / path_part).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        errors.append(f"line {line_number}: local link escapes the repository: {path_part}")
        return
    if not candidate.exists():
        errors.append(f"line {line_number}: local link target does not exist: {path_part}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a Markdown README.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--readme", type=Path, default=None)
    args = parser.parse_args(argv)

    root = args.root.resolve()
    readme = args.readme or (root / "README.md")
    if not readme.is_file():
        print(f"ERROR: {readme} does not exist")
        return 1

    raw = readme.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        print(f"ERROR: README is not valid UTF-8: {exc}")
        return 1

    errors: list[str] = []
    warnings: list[str] = []

    if raw.startswith(b"\xef\xbb\xbf"):
        warnings.append("README starts with a UTF-8 BOM")
    if b"\r" in raw:
        errors.append("README contains CR characters; use LF line endings")
    if not text.endswith("\n"):
        errors.append("README does not end with a newline")

    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        if line != line.rstrip():
            errors.append(f"line {number}: trailing whitespace")

    in_fence, fence_errors = parse_fences(lines)
    errors.extend(fence_errors)

    headings: list[tuple[int, str, int]] = []
    for number, line in enumerate(lines, start=1):
        if in_fence[number - 1]:
            continue
        match = HEADING_RE.match(line)
        if match:
            headings.append((len(match.group(1)), match.group(2), number))

    h1 = [heading for heading in headings if heading[0] == 1]
    if len(h1) != 1:
        errors.append(f"expected exactly one H1 heading, found {len(h1)}")
    if headings and headings[0][0] != 1:
        errors.append("the first heading must be H1")

    previous_level = 0
    for level, _title, number in headings:
        if previous_level and level > previous_level + 1:
            errors.append(f"line {number}: heading level jumps from H{previous_level} to H{level}")
        previous_level = level

    slugs: dict[str, int] = {}
    duplicate_slugs: set[str] = set()
    for _level, title, _number in headings:
        slug = github_slug(title)
        if not slug:
            continue
        if slug in slugs:
            duplicate_slugs.add(slug)
        slugs[slug] = slugs.get(slug, 0) + 1

    for slug in sorted(duplicate_slugs):
        warnings.append(f"duplicate heading anchor: #{slug}")

    anchors = set(slugs)
    for slug, count in slugs.items():
        for index in range(1, count):
            anchors.add(f"{slug}-{index}")

    local_links = 0
    for number, line in enumerate(lines, start=1):
        if in_fence[number - 1]:
            continue
        stripped = INLINE_CODE_RE.sub("", line)
        for _label, target in LINK_RE.findall(stripped):
            target = local_target(target)
            if target.startswith("#"):
                local_links += 1
                anchor = unquote(target[1:])
                if anchor and anchor not in anchors:
                    errors.append(f"line {number}: missing anchor #{anchor}")
                continue
            parsed = urlparse(target)
            if parsed.scheme in ("http", "https", "mailto", "tel"):
                continue
            local_links += 1
            check_path(root, target, number, errors)

        for alt, target in IMAGE_RE.findall(stripped):
            target = local_target(target)
            local_links += 1
            if not alt.strip():
                warnings.append(f"line {number}: image has no alt text")
            check_path(root, target, number, errors)
            path_part = unquote(urlparse(target).path)
            candidate = (root / path_part).resolve()
            if candidate.suffix.lower() == ".png" and candidate.exists():
                dimensions = png_dimensions(candidate)
                if dimensions is None:
                    errors.append(f"line {number}: invalid PNG image: {path_part}")
                elif dimensions[0] < 320 or dimensions[1] < 200:
                    warnings.append(
                        f"line {number}: PNG image is small ({dimensions[0]}x{dimensions[1]}): {path_part}"
                    )

    table_start = 0
    table_columns_count = 0
    table_separator_seen = False
    for number, line in enumerate(lines, start=1):
        if in_fence[number - 1]:
            table_start = 0
            table_columns_count = 0
            table_separator_seen = False
            continue
        if line.lstrip().startswith("|"):
            columns = table_columns(line)
            if table_start == 0:
                table_start = number
                table_columns_count = columns
                table_separator_seen = False
            elif columns != table_columns_count:
                errors.append(
                    f"line {number}: table started at line {table_start} has "
                    f"{table_columns_count} columns, this row has {columns}"
                )
            elif not table_separator_seen and number == table_start + 1:
                table_separator_seen = is_separator_row(line)
                if not table_separator_seen:
                    errors.append(f"line {number}: table header is missing a valid separator row")
        else:
            table_start = 0
            table_columns_count = 0
            table_separator_seen = False

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
