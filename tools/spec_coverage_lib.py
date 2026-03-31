#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT_DIR / "SPEC.md"
MANIFEST_PATH = ROOT_DIR / "spec" / "coverage.json"

HEADING_PATTERN = re.compile(r"^\s*(#{2,3})\s+(.+?)\s*$")
BULLET_PATTERN = re.compile(r"^\s*-\s+(.+?)\s*$")
NUMBERED_PATTERN = re.compile(r"^\s*\d+\.\s+(.+?)\s*$")


@dataclass(frozen=True)
class SpecBlock:
    level: int
    title: str
    number: str
    start_line: int
    end_line: int


def section_number(title: str) -> str:
    return title.split(" ", 1)[0].rstrip(".")


def parse_spec_blocks() -> list[SpecBlock]:
    blocks: list[SpecBlock] = []
    lines = SPEC_PATH.read_text().splitlines()

    for lineno, line in enumerate(lines, start=1):
        match = HEADING_PATTERN.match(line)
        if match is None:
            continue
        marks, title = match.groups()
        blocks.append(
            SpecBlock(
                level=len(marks),
                title=title.strip(),
                number=section_number(title),
                start_line=lineno,
                end_line=len(lines),
            )
        )

    finalized: list[SpecBlock] = []
    for index, block in enumerate(blocks):
        end_line = blocks[index + 1].start_line - 1 if index + 1 < len(blocks) else len(lines)
        finalized.append(
            SpecBlock(
                level=block.level,
                title=block.title,
                number=block.number,
                start_line=block.start_line,
                end_line=end_line,
            )
        )
    return finalized


def load_lines() -> list[str]:
    return SPEC_PATH.read_text().splitlines()


def block_claims(block: SpecBlock, lines: list[str]) -> list[str]:
    claims: list[str] = []
    seen: set[str] = set()

    for raw_line in lines[block.start_line : block.end_line]:
        stripped = raw_line.strip()
        if not stripped:
            continue
        bullet = BULLET_PATTERN.match(raw_line)
        if bullet is not None:
            claim = f"{block.number}::{bullet.group(1).strip()}"
        else:
            numbered = NUMBERED_PATTERN.match(raw_line)
            if numbered is not None:
                claim = f"{block.number}::{numbered.group(1).strip()}"
            elif stripped.endswith(":"):
                continue
            else:
                claim = f"{block.number}::{stripped}"

        if claim in seen:
            continue
        claims.append(claim)
        seen.add(claim)

    if claims:
        return claims
    return [block.number]


def expected_headings(blocks: list[SpecBlock]) -> list[str]:
    return [block.title for block in blocks]


def expected_claims_for_section(section_id: str, blocks: list[SpecBlock], lines: list[str]) -> list[str]:
    top_block = next((block for block in blocks if block.number == section_id and block.level == 2), None)
    child_blocks = [block for block in blocks if block.level == 3 and block.number.startswith(f"{section_id}.")]

    claims: list[str] = []
    seen: set[str] = set()

    if top_block is not None:
        top_claims = block_claims(top_block, lines)
        if child_blocks and top_claims == [section_id]:
            top_claims = []
        for claim in top_claims:
            if claim not in seen:
                claims.append(claim)
                seen.add(claim)

    for block in child_blocks:
        for claim in block_claims(block, lines):
            if claim not in seen:
                claims.append(claim)
                seen.add(claim)

    if claims:
        return claims
    return [section_id]


def expected_claims_for_manifest_sections(sections: list[dict]) -> list[str]:
    blocks = parse_spec_blocks()
    lines = load_lines()
    claims: list[str] = []
    for section in sections:
        claims.extend(expected_claims_for_section(section["id"], blocks, lines))
    return claims
