#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path

from spec_coverage_lib import (
    MANIFEST_PATH,
    ROOT_DIR,
    load_lines,
    expected_requirements_for_manifest_sections,
    expected_requirements_for_section,
    expected_headings,
    parse_spec_blocks,
)
from generate_spec_gap_matrix import GAP_MATRIX_PATH, render_gap_matrix

ZIG_TEST_PATTERN = re.compile(r'^\s*test\s+"([^"]+)"', re.MULTILINE)
PY_TEST_PATTERN = re.compile(r"^\s*def\s+(test_[A-Za-z0-9_]+)\s*\(", re.MULTILINE)
EVIDENCE_STATUSES = {"enforced", "modeled", "scenario", "deferred"}
ROADMAP_STATUSES = EVIDENCE_STATUSES - {"enforced"}
ROADMAP_PRIORITIES = {"P0", "P1", "P2"}
ROADMAP_TEXT_FIELDS = ("focus", "graduation_proof")
SUMMARY_REQUIREMENT_ID = "REQ-ONE-SENTENCE-SUMMARY"
SUMMARY_CLAUSE_DEPENDENCIES = (
    (
        "capability-based",
        (
            "REQ-ZERO-AMBIENT-AUTHORITY",
            "REQ-CAPABILITY-MODEL",
            "REQ-CAPABILITY-BASED-ACCESS-CONTROL",
        ),
    ),
    (
        "local-first",
        (
            "REQ-LOCAL-FIRST-REPLICATION",
            "REQ-SYNC-SEMANTICS",
        ),
    ),
    (
        "multi-device",
        (
            "REQ-DEVICE-GRAPH",
            "REQ-SHARING",
        ),
    ),
    (
        "immutable core",
        (
            "REQ-IMMUTABLE-BASE-SYSTEM",
            "REQ-BASE-OS-UPDATES",
        ),
    ),
    (
        "versioned object storage",
        (
            "REQ-DATA-IS-VERSIONED",
            "REQ-OBJECT-STORE",
            "REQ-MUTABLE-STATE",
        ),
    ),
    (
        "strong sandboxing",
        (
            "REQ-PROCESS-ISOLATION",
            "REQ-SECRETS",
        ),
    ),
    (
        "explicit identity",
        (
            "REQ-PRINCIPAL-MODEL",
            "REQ-IDENTITY-FIRST-NETWORKING",
        ),
    ),
    (
        "first-class support for modern accelerators",
        (
            "REQ-UNIFIED-RESOURCE-SCHEDULER",
            "REQ-SHARED-MEMORY-OBJECTS",
            "REQ-THERMAL-AND-POWER-POLICY",
        ),
    ),
)


def summary_clause_dependency_ids() -> list[str]:
    dependency_ids: list[str] = []
    seen: set[str] = set()
    for _, clause_dependencies in SUMMARY_CLAUSE_DEPENDENCIES:
        for dependency_id in clause_dependencies:
            if dependency_id in seen:
                continue
            dependency_ids.append(dependency_id)
            seen.add(dependency_id)
    return dependency_ids


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text())


def load_test_names(cache: dict[Path, set[str]], path: Path) -> set[str]:
    cached = cache.get(path)
    if cached is not None:
        return cached
    source = path.read_text()
    names = {match.group(1) for match in ZIG_TEST_PATTERN.finditer(source)}
    names.update(match.group(1) for match in PY_TEST_PATTERN.finditer(source))
    cache[path] = names
    return names


def requirement_body(blocks, requirement_id: str) -> str:
    block = next((block for block in blocks if block.requirement_id == requirement_id), None)
    if block is None:
        return ""
    lines = load_lines()
    return "\n".join(lines[block.start_line : block.end_line])


def validate_summary_clause_dependencies(
    errors: list[str],
    evidence: dict,
    summary_text: str,
) -> None:
    summary_evidence = evidence.get(SUMMARY_REQUIREMENT_ID, {})
    summary_status = summary_evidence.get("status")
    if summary_status not in {"enforced", "modeled"}:
        return

    normalized_summary = summary_text.lower()
    for clause, dependencies in SUMMARY_CLAUSE_DEPENDENCIES:
        if clause.lower() not in normalized_summary:
            errors.append(
                f"One-sentence summary clause {clause!r} is not present in SPEC.md section 20"
            )
        if not dependencies:
            errors.append(f"One-sentence summary clause {clause!r} has no dependency mapping")
            continue
        for dependency_id in dependencies:
            dependency_evidence = evidence.get(dependency_id)
            if dependency_evidence is None:
                errors.append(
                    "One-sentence summary clause "
                    f"{clause!r} depends on missing requirement evidence: {dependency_id}"
                )
                continue
            dependency_status = dependency_evidence.get("status")
            if dependency_status != "enforced":
                errors.append(
                    "One-sentence summary clause "
                    f"{clause!r} depends on {dependency_id}, which is "
                    f"{dependency_status!r}; expected enforced"
                )


def complete_summary_text() -> str:
    return (
        "Zigos is a capability-based, local-first, multi-device operating system "
        "with an immutable core, versioned object storage, strong sandboxing, "
        "explicit identity, and first-class support for modern accelerators."
    )


def summary_evidence_fixture() -> dict:
    evidence = {
        SUMMARY_REQUIREMENT_ID: {
            "status": "enforced",
        }
    }
    for dependency_id in summary_clause_dependency_ids():
        evidence[dependency_id] = {"status": "enforced"}
    return evidence


def test_summary_clause_gate_rejects_missing_or_modeled_dependencies() -> None:
    evidence = summary_evidence_fixture()
    evidence["REQ-LOCAL-FIRST-REPLICATION"] = {"status": "modeled"}
    del evidence["REQ-SHARED-MEMORY-OBJECTS"]

    errors: list[str] = []
    validate_summary_clause_dependencies(errors, evidence, complete_summary_text())

    assert any(
        "REQ-LOCAL-FIRST-REPLICATION" in error and "expected enforced" in error
        for error in errors
    ), "summary clause gate must reject modeled dependencies"
    assert any(
        "REQ-SHARED-MEMORY-OBJECTS" in error and "missing requirement evidence" in error
        for error in errors
    ), "summary clause gate must reject missing dependencies"


def test_summary_clause_gate_requires_current_summary_phrases() -> None:
    errors: list[str] = []
    validate_summary_clause_dependencies(
        errors,
        summary_evidence_fixture(),
        "Zigos is an operating system.",
    )

    assert any(
        "capability-based" in error and "not present" in error for error in errors
    ), "summary clause gate must reject missing summary phrases"


def run_self_tests() -> list[str]:
    failures: list[str] = []
    for name, candidate in sorted(globals().items()):
        if not name.startswith("test_") or not callable(candidate):
            continue
        try:
            candidate()
        except Exception as exc:  # noqa: BLE001 - report checker self-test failures directly.
            failures.append(f"{name}: {exc}")
    return failures


def validate_roadmap(errors: list[str], requirement_id: str, requirement_evidence: dict) -> bool:
    roadmap = requirement_evidence.get("roadmap")
    if not isinstance(roadmap, dict):
        errors.append(
            f"Requirement {requirement_id} is {requirement_evidence.get('status')} and must include roadmap metadata"
        )
        return False

    priority = roadmap.get("priority")
    if priority not in ROADMAP_PRIORITIES:
        errors.append(
            f"Requirement {requirement_id} roadmap priority must be one of {sorted(ROADMAP_PRIORITIES)}"
        )

    valid = True
    for field in ROADMAP_TEXT_FIELDS:
        value = roadmap.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"Requirement {requirement_id} roadmap must include non-empty {field}")
            valid = False
    return valid and priority in ROADMAP_PRIORITIES


def main() -> int:
    errors: list[str] = []
    for failure in run_self_tests():
        errors.append(f"Spec coverage checker self-test failed: {failure}")

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
    roadmap_count = 0
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
            if "roadmap" in requirement_evidence:
                errors.append(
                    f"Enforced requirement {requirement_id} should not keep roadmap metadata"
                )
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
            if status in ROADMAP_STATUSES and validate_roadmap(errors, requirement_id, requirement_evidence):
                roadmap_count += 1

    validate_summary_clause_dependencies(
        errors,
        evidence,
        requirement_body(blocks, SUMMARY_REQUIREMENT_ID),
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
        f"{negative_test_count} negative test references, "
        f"{roadmap_count} roadmap requirements"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
