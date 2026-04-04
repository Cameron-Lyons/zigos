#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT_DIR / "SPEC.md"
MANIFEST_PATH = ROOT_DIR / "spec" / "coverage.json"

HEADING_PATTERN = re.compile(r"^\s*(#{2,3})\s+(.+?)\s*$")
REQUIREMENT_PATTERN = re.compile(r"^\s*<!--\s*REQ:\s*([A-Z0-9][A-Z0-9-]*)\s*-->\s*$")


@dataclass(frozen=True)
class SpecBlock:
    level: int
    title: str
    number: str
    start_line: int
    end_line: int
    requirement_id: str | None


def section_number(title: str) -> str:
    return title.split(" ", 1)[0].rstrip(".")


def parse_spec_blocks() -> list[SpecBlock]:
    blocks: list[SpecBlock] = []
    lines = SPEC_PATH.read_text().splitlines()
    pending_requirement_id: str | None = None
    pending_requirement_line: int | None = None
    seen_requirement_ids: set[str] = set()

    for lineno, line in enumerate(lines, start=1):
        requirement_match = REQUIREMENT_PATTERN.match(line)
        if requirement_match is not None:
            if pending_requirement_id is not None:
                raise ValueError(
                    "Requirement marker "
                    f"{pending_requirement_id} on line {pending_requirement_line} "
                    f"must attach to the next heading before line {lineno}"
                )
            pending_requirement_id = requirement_match.group(1)
            pending_requirement_line = lineno
            continue

        match = HEADING_PATTERN.match(line)
        if match is None:
            if pending_requirement_id is not None and line.strip():
                raise ValueError(
                    "Requirement marker "
                    f"{pending_requirement_id} on line {pending_requirement_line} "
                    "must appear immediately before a heading"
                )
            continue
        marks, title = match.groups()
        requirement_id = pending_requirement_id
        if requirement_id is not None:
            if requirement_id in seen_requirement_ids:
                raise ValueError(f"Duplicate spec requirement id: {requirement_id}")
            seen_requirement_ids.add(requirement_id)
        pending_requirement_id = None
        pending_requirement_line = None
        blocks.append(
            SpecBlock(
                level=len(marks),
                title=title.strip(),
                number=section_number(title),
                start_line=lineno,
                end_line=len(lines),
                requirement_id=requirement_id,
            )
        )

    if pending_requirement_id is not None:
        raise ValueError(
            "Requirement marker "
            f"{pending_requirement_id} on line {pending_requirement_line} "
            "must attach to a heading"
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
                requirement_id=block.requirement_id,
            )
        )
    return finalized


def load_lines() -> list[str]:
    return SPEC_PATH.read_text().splitlines()


def expected_headings(blocks: list[SpecBlock]) -> list[str]:
    return [block.title for block in blocks]


def expected_requirements_for_section(section_id: str, blocks: list[SpecBlock]) -> list[str]:
    top_block = next((block for block in blocks if block.number == section_id and block.level == 2), None)
    child_blocks = [block for block in blocks if block.level == 3 and block.number.startswith(f"{section_id}.")]

    requirements: list[str] = []
    seen: set[str] = set()

    if top_block is not None and top_block.requirement_id is not None:
        requirements.append(top_block.requirement_id)
        seen.add(top_block.requirement_id)

    for block in child_blocks:
        requirement_id = block.requirement_id
        if requirement_id is None or requirement_id in seen:
            continue
        requirements.append(requirement_id)
        seen.add(requirement_id)

    return requirements


def expected_requirements_for_manifest_sections(sections: list[dict]) -> list[str]:
    blocks = parse_spec_blocks()
    requirements: list[str] = []
    for section in sections:
        requirements.extend(expected_requirements_for_section(section["id"], blocks))
    return requirements
