#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path

from spec_coverage_lib import (
    MANIFEST_PATH,
    ROOT_DIR,
    expected_claims_for_manifest_sections,
    expected_claims_for_section,
    expected_headings,
    load_lines,
    parse_spec_blocks,
)

TEST_PATTERN = re.compile(r'^\s*test\s+"([^"]+)"', re.MULTILINE)


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text())


def load_test_names(cache: dict[Path, set[str]], path: Path) -> set[str]:
    cached = cache.get(path)
    if cached is not None:
        return cached
    names = {match.group(1) for match in TEST_PATTERN.finditer(path.read_text())}
    cache[path] = names
    return names


def main() -> int:
    errors: list[str] = []
    manifest = load_manifest()
    blocks = parse_spec_blocks()
    lines = load_lines()
    spec_headings = expected_headings(blocks)
    required_headings = manifest["required_headings"]
    required_claims = manifest["required_claims"]

    if required_headings != spec_headings:
        errors.append("required_headings in coverage manifest are out of sync with SPEC.md")

    expected_manifest_claims = expected_claims_for_manifest_sections(manifest["sections"])
    if required_claims != expected_manifest_claims:
        errors.append("required_claims in coverage manifest are out of sync with SPEC.md section requirements")

    for heading in required_headings:
        if heading not in spec_headings:
            errors.append(f"Missing required heading in SPEC.md: {heading}")

    seen_sections: set[str] = set()
    seen_claims: dict[str, str] = {}
    test_cache: dict[Path, set[str]] = {}
    referenced_test_count = 0

    for section in manifest["sections"]:
        section_id = section["id"]
        if section_id in seen_sections:
            errors.append(f"Duplicate section entry in coverage manifest: {section_id}")
        seen_sections.add(section_id)

        heading = section["heading"]
        if heading not in required_headings:
            errors.append(
                f"Coverage section {section_id} uses heading not listed in required_headings: {heading}"
            )

        tests = section.get("tests", [])
        if not tests:
            errors.append(f"Coverage section {section_id} has no test references")

        expected_section_claims = expected_claims_for_section(section_id, blocks, lines)
        if section.get("claims", []) != expected_section_claims:
            errors.append(
                f"Coverage section {section_id} claims are out of sync with SPEC.md for heading {heading}"
            )

        for claim in section.get("claims", []):
            owner = seen_claims.get(claim)
            if owner is not None:
                errors.append(
                    f"Claim {claim} is mapped more than once in coverage manifest: {owner} and {section_id}"
                )
            seen_claims[claim] = section_id

        for test_ref in tests:
            path = ROOT_DIR / test_ref["file"]
            if not path.exists():
                errors.append(
                    f"Coverage section {section_id} references missing file: {test_ref['file']}"
                )
                continue

            test_names = load_test_names(test_cache, path)
            if test_ref["name"] not in test_names:
                errors.append(
                    "Coverage section "
                    f"{section_id} references missing test in {test_ref['file']}: {test_ref['name']}"
                )
            referenced_test_count += 1

    claimed = set(seen_claims)
    required_claim_set = set(required_claims)
    missing_claims = sorted(required_claim_set - claimed)
    extra_claims = sorted(claimed - required_claim_set)

    for claim in missing_claims:
        errors.append(f"Required spec claim is not covered: {claim}")
    for claim in extra_claims:
        errors.append(f"Unexpected spec claim in coverage manifest: {claim}")

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(
        "Spec coverage OK: "
        f"{len(required_headings)} headings, "
        f"{len(required_claims)} claims, "
        f"{len(manifest['sections'])} section groups, "
        f"{referenced_test_count} test references"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
