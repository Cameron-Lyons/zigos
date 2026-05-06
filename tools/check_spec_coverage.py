#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path

from spec_coverage_lib import (
    MANIFEST_PATH,
    ROOT_DIR,
    expected_requirements_for_manifest_sections,
    expected_requirements_for_section,
    expected_headings,
    parse_spec_blocks,
)
from generate_spec_gap_matrix import GAP_MATRIX_PATH, render_gap_matrix

TEST_PATTERN = re.compile(r'^\s*test\s+"([^"]+)"', re.MULTILINE)
EVIDENCE_STATUSES = {"enforced", "modeled", "scenario", "deferred"}

META_REQUIREMENT_DEPENDENCIES = {
    "REQ-DESIGN-GOALS-AND-NON-GOALS": [
        "REQ-ZERO-AMBIENT-AUTHORITY",
        "REQ-IMMUTABLE-BASE-SYSTEM",
        "REQ-LOCAL-FIRST-REPLICATION",
        "REQ-APP-EXECUTION",
        "REQ-MUTABLE-STATE",
        "REQ-EXPLAINABLE-DENIALS",
        "REQ-USERSPACE-DRIVERS",
        "REQ-NATIVE-PLATFORM",
    ],
    "REQ-ONE-SENTENCE-SUMMARY": [
        "REQ-CAPABILITY-MODEL",
        "REQ-LOCAL-FIRST-REPLICATION",
        "REQ-DEVICE-GRAPH",
        "REQ-IMMUTABLE-BASE-SYSTEM",
        "REQ-DATA-IS-VERSIONED",
        "REQ-PROCESS-ISOLATION",
        "REQ-IDENTITY-FIRST-NETWORKING",
        "REQ-UNIFIED-RESOURCE-SCHEDULER",
    ],
}


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
    spec_headings = expected_headings(blocks)
    required_headings = manifest["required_headings"]
    required_requirements = manifest["required_requirements"]

    if required_headings != spec_headings:
        errors.append("required_headings in coverage manifest are out of sync with SPEC.md")

    expected_manifest_requirements = expected_requirements_for_manifest_sections(manifest["sections"])
    if required_requirements != expected_manifest_requirements:
        errors.append(
            "required_requirements in coverage manifest are out of sync with SPEC.md requirement ids"
        )

    for heading in required_headings:
        if heading not in spec_headings:
            errors.append(f"Missing required heading in SPEC.md: {heading}")

    seen_sections: set[str] = set()
    seen_requirements: dict[str, str] = {}
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

        expected_section_requirements = expected_requirements_for_section(section_id, blocks)
        if section.get("requirements", []) != expected_section_requirements:
            errors.append(
                "Coverage section "
                f"{section_id} requirements are out of sync with SPEC.md for heading {heading}"
            )

        for requirement_id in section.get("requirements", []):
            owner = seen_requirements.get(requirement_id)
            if owner is not None:
                errors.append(
                    "Requirement "
                    f"{requirement_id} is mapped more than once in coverage manifest: {owner} and {section_id}"
                )
            seen_requirements[requirement_id] = section_id

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

    covered_requirements = set(seen_requirements)
    required_requirement_set = set(required_requirements)
    missing_requirements = sorted(required_requirement_set - covered_requirements)
    extra_requirements = sorted(covered_requirements - required_requirement_set)

    for requirement_id in missing_requirements:
        errors.append(f"Required spec requirement is not covered: {requirement_id}")
    for requirement_id in extra_requirements:
        errors.append(f"Unexpected spec requirement in coverage manifest: {requirement_id}")

    evidence = manifest.get("requirement_evidence", {})
    if not isinstance(evidence, dict):
        errors.append("coverage manifest requirement_evidence must be an object")
        evidence = {}

    evidence_requirements = set(evidence)
    missing_evidence = sorted(required_requirement_set - evidence_requirements)
    extra_evidence = sorted(evidence_requirements - required_requirement_set)
    for requirement_id in missing_evidence:
        errors.append(f"Required spec requirement is missing requirement_evidence: {requirement_id}")
    for requirement_id in extra_evidence:
        errors.append(f"Unexpected requirement_evidence entry: {requirement_id}")

    enforced_count = 0
    scenario_count = 0
    negative_test_count = 0
    for requirement_id in required_requirements:
        requirement_evidence = evidence.get(requirement_id)
        if not isinstance(requirement_evidence, dict):
            errors.append(f"Requirement evidence for {requirement_id} must be an object")
            continue

        status = requirement_evidence.get("status")
        if status not in EVIDENCE_STATUSES:
            errors.append(
                f"Requirement evidence for {requirement_id} has invalid status: {status!r}"
            )
            continue

        if status == "scenario":
            scenario_count += 1
        if status == "enforced":
            enforced_count += 1
            enforcement_modules = requirement_evidence.get("enforcement_modules", [])
            if not isinstance(enforcement_modules, list) or not enforcement_modules:
                errors.append(
                    f"Enforced requirement {requirement_id} must list enforcement_modules"
                )
            else:
                for module in enforcement_modules:
                    if not isinstance(module, str):
                        errors.append(
                            f"Enforced requirement {requirement_id} has non-string enforcement module"
                        )
                        continue
                    module_path = ROOT_DIR / module
                    if not module_path.exists():
                        errors.append(
                            f"Enforced requirement {requirement_id} references missing enforcement module: {module}"
                        )
                    elif module_path.match("src/tests/spec/*"):
                        errors.append(
                            f"Enforced requirement {requirement_id} uses a spec test as an enforcement module: {module}"
                        )

            negative_tests = requirement_evidence.get("negative_tests", [])
            if not isinstance(negative_tests, list) or not negative_tests:
                errors.append(f"Enforced requirement {requirement_id} must list negative_tests")
            else:
                for test_ref in negative_tests:
                    if not isinstance(test_ref, dict):
                        errors.append(
                            f"Enforced requirement {requirement_id} has malformed negative test reference"
                        )
                        continue
                    path_value = test_ref.get("file")
                    name_value = test_ref.get("name")
                    if not isinstance(path_value, str) or not isinstance(name_value, str):
                        errors.append(
                            f"Enforced requirement {requirement_id} negative test references need file and name"
                        )
                        continue
                    path = ROOT_DIR / path_value
                    if not path.exists():
                        errors.append(
                            f"Enforced requirement {requirement_id} references missing negative test file: {path_value}"
                        )
                        continue
                    test_names = load_test_names(test_cache, path)
                    if name_value not in test_names:
                        errors.append(
                            f"Enforced requirement {requirement_id} references missing negative test in {path_value}: {name_value}"
                        )
                    negative_test_count += 1
        else:
            if "negative_tests" in requirement_evidence:
                errors.append(
                    f"Requirement {requirement_id} is {status} but lists negative_tests; mark it enforced or remove the enforced evidence"
                )
            if not requirement_evidence.get("coverage_note"):
                errors.append(
                    f"Requirement {requirement_id} is {status} and must include coverage_note explaining why it is not enforced"
                )

    for requirement_id, dependencies in META_REQUIREMENT_DEPENDENCIES.items():
        requirement_evidence = evidence.get(requirement_id, {})
        if requirement_evidence.get("status") != "enforced":
            continue
        for dependency_id in dependencies:
            dependency_evidence = evidence.get(dependency_id)
            if dependency_evidence is None:
                errors.append(
                    f"Meta requirement {requirement_id} depends on missing requirement evidence: {dependency_id}"
                )
                continue
            if dependency_evidence.get("status") != "enforced":
                errors.append(
                    f"Meta requirement {requirement_id} depends on {dependency_id}, which is {dependency_evidence.get('status')!r}, not enforced"
                )

    expected_gap_matrix = render_gap_matrix(manifest)
    actual_gap_matrix = GAP_MATRIX_PATH.read_text() if GAP_MATRIX_PATH.exists() else ""
    if actual_gap_matrix != expected_gap_matrix:
        errors.append(
            "SPEC_GAP_MATRIX.md is out of sync with spec/coverage.json; "
            "run python3 tools/generate_spec_gap_matrix.py"
        )

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(
        "Spec coverage OK: "
        f"{len(required_headings)} headings, "
        f"{len(required_requirements)} requirements, "
        f"{len(manifest['sections'])} section groups, "
        f"{referenced_test_count} test references, "
        f"{enforced_count} enforced requirements, "
        f"{scenario_count} scenario-only requirements, "
        f"{negative_test_count} negative test references"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
