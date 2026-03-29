#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT_DIR / "SPEC.md"
MANIFEST_PATH = ROOT_DIR / "spec" / "coverage.json"
TEST_PATTERN = re.compile(r'^\s*test\s+"([^"]+)"', re.MULTILINE)


def normalized_heading(line: str) -> str:
    return re.sub(r"^\s*#+\s*", "", line).strip()


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text())


def load_headings() -> set[str]:
    headings: set[str] = set()
    for line in SPEC_PATH.read_text().splitlines():
        heading = normalized_heading(line)
        if heading:
            headings.add(heading)
    return headings


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
    headings = load_headings()
    required_headings = manifest["required_headings"]
    required_claims = set(manifest["required_claims"])

    for heading in required_headings:
        if heading not in headings:
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
    missing_claims = sorted(required_claims - claimed)
    extra_claims = sorted(claimed - required_claims)

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
