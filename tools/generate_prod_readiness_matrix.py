#!/usr/bin/env python3

from __future__ import annotations

from collections import Counter
import argparse
import json
import sys

from spec_coverage_lib import MANIFEST_PATH, ROOT_DIR


PROD_READINESS_MANIFEST_PATH = ROOT_DIR / "spec" / "production_readiness.json"
PROD_READINESS_MATRIX_PATH = ROOT_DIR / "PROD_READINESS_MATRIX.md"

STATUS_LABELS = {
    "prod_ready": "Prod Ready",
    "prod_candidate": "Prod Candidate",
    "prototype": "Prototype",
    "blocked": "Blocked",
}

STATUS_DESCRIPTIONS = {
    "prod_ready": "Production evidence is complete for the first supported product envelope.",
    "prod_candidate": "The implementation has real service or boot paths, but still needs hardening, scale, or operational evidence.",
    "prototype": "The spec invariant is implemented, but production proof still depends on synthetic state, harnesses, emulator roots, or model tests.",
    "blocked": "The track cannot graduate until another production-readiness dependency advances.",
}

PRIORITIES = {"P0", "P1", "P2"}
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2}
LIST_FIELDS = (
    "requirements",
    "implementation_anchors",
    "current_evidence",
    "production_gaps",
    "graduation_criteria",
    "next_actions",
    "verification_commands",
)
OPTIONAL_LIST_FIELDS = ("capacity_envelope",)


def markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", "<br>")


def code(value: str) -> str:
    return f"`{value}`"


def code_list(values: list[str]) -> str:
    return ", ".join(code(value) for value in values)


def bullet_list(values: list[str]) -> list[str]:
    return [f"- {value}" for value in values]


def optional_list_section(track: dict, field: str, title: str) -> list[str]:
    values = track.get(field, [])
    if not values:
        return []
    return [f"{title}:", *bullet_list(values), ""]


def first_item(values: list[str]) -> str:
    return values[0] if values else "_None listed_"


def load_prod_manifest() -> dict:
    return json.loads(PROD_READINESS_MANIFEST_PATH.read_text())


def load_coverage_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text())


def validate_prod_readiness_manifest(prod_manifest: dict, coverage_manifest: dict) -> list[str]:
    errors: list[str] = []
    if prod_manifest.get("schema_version") != 1:
        errors.append("production_readiness.json schema_version must be 1")
    if prod_manifest.get("source_coverage_manifest") != "spec/coverage.json":
        errors.append("production_readiness.json source_coverage_manifest must be spec/coverage.json")

    required_requirements = set(coverage_manifest.get("required_requirements", []))
    requirement_evidence = coverage_manifest.get("requirement_evidence", {})
    tracks = prod_manifest.get("tracks")
    if not isinstance(tracks, list) or not tracks:
        errors.append("production_readiness.json must include at least one track")
        return errors

    seen_track_ids: set[str] = set()
    for index, track in enumerate(tracks):
        if not isinstance(track, dict):
            errors.append(f"Production readiness track at index {index} must be an object")
            continue

        track_id = track.get("id")
        if not isinstance(track_id, str) or not track_id.strip():
            errors.append(f"Production readiness track at index {index} must include id")
            track_id = f"<track-{index}>"
        elif track_id in seen_track_ids:
            errors.append(f"Duplicate production readiness track id: {track_id}")
        seen_track_ids.add(track_id)

        title = track.get("title")
        if not isinstance(title, str) or not title.strip():
            errors.append(f"Production readiness track {track_id} must include title")

        priority = track.get("priority")
        if priority not in PRIORITIES:
            errors.append(f"Production readiness track {track_id} priority must be one of {sorted(PRIORITIES)}")

        status = track.get("status")
        if status not in STATUS_LABELS:
            errors.append(f"Production readiness track {track_id} status must be one of {sorted(STATUS_LABELS)}")

        for field in LIST_FIELDS:
            values = track.get(field)
            if field == "production_gaps" and status == "prod_ready":
                if not isinstance(values, list):
                    errors.append(f"Production readiness track {track_id} must include production_gaps")
                    continue
            elif not isinstance(values, list) or not values:
                errors.append(f"Production readiness track {track_id} must include non-empty {field}")
                continue
            for value in values:
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"Production readiness track {track_id} has an empty or non-string {field} entry")

        for field in OPTIONAL_LIST_FIELDS:
            values = track.get(field, [])
            if values is None:
                continue
            if not isinstance(values, list):
                errors.append(f"Production readiness track {track_id} optional {field} must be a list when present")
                continue
            for value in values:
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"Production readiness track {track_id} has an empty or non-string {field} entry")

        for requirement_id in track.get("requirements", []):
            if requirement_id not in required_requirements:
                errors.append(
                    f"Production readiness track {track_id} references unknown requirement: {requirement_id}"
                )
                continue
            evidence = requirement_evidence.get(requirement_id, {})
            if evidence.get("status") != "enforced":
                errors.append(
                    f"Production readiness track {track_id} references {requirement_id}, "
                    f"which is {evidence.get('status')!r}; production tracks require spec-enforced requirements"
                )

        for anchor in track.get("implementation_anchors", []):
            path = ROOT_DIR / anchor
            if not path.exists():
                errors.append(
                    f"Production readiness track {track_id} references missing implementation anchor: {anchor}"
                )

        if status == "prod_ready" and track.get("production_gaps"):
            errors.append(
                f"Production readiness track {track_id} is prod_ready but still lists production_gaps"
            )

    return errors


def sorted_tracks(prod_manifest: dict) -> list[dict]:
    return sorted(
        prod_manifest["tracks"],
        key=lambda track: (
            PRIORITY_ORDER.get(track.get("priority"), 99),
            track.get("id", ""),
        ),
    )


def render_prod_readiness_matrix(
    prod_manifest: dict | None = None,
    coverage_manifest: dict | None = None,
) -> str:
    if prod_manifest is None:
        prod_manifest = load_prod_manifest()
    if coverage_manifest is None:
        coverage_manifest = load_coverage_manifest()

    status_counts = Counter(track["status"] for track in prod_manifest["tracks"])
    coverage_requirement_count = len(coverage_manifest.get("required_requirements", []))

    lines = [
        "# Zigos Production Readiness Matrix",
        "",
        "<!-- Generated by tools/generate_prod_readiness_matrix.py from spec/production_readiness.json. Do not edit by hand. -->",
        "",
        "This matrix tracks production-readiness evidence separately from spec conformance. `SPEC_GAP_MATRIX.md` answers whether a requirement is enforced in the repository prototype; this file tracks what remains before selected slices should be treated as production-ready.",
        "",
        "## Source Manifests",
        "",
        "- Spec coverage: `spec/coverage.json`",
        "- Production readiness: `spec/production_readiness.json`",
        f"- Spec requirements available for production tracks: {coverage_requirement_count}",
        "",
        "## Status Legend",
        "",
    ]

    for status, label in STATUS_LABELS.items():
        lines.append(f"- **{label}**: {STATUS_DESCRIPTIONS[status]}")

    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Prod Ready: {status_counts['prod_ready']}",
            f"- Prod Candidate: {status_counts['prod_candidate']}",
            f"- Prototype: {status_counts['prototype']}",
            f"- Blocked: {status_counts['blocked']}",
            "",
            "## Priority Backlog",
            "",
            "| Priority | Track | Status | Spec requirements | Primary gap | Graduation proof |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )

    for track in sorted_tracks(prod_manifest):
        lines.append(
            "| "
            + " | ".join(
                [
                    code(track["priority"]),
                    markdown_cell(track["title"]),
                    STATUS_LABELS[track["status"]],
                    markdown_cell(code_list(track["requirements"])),
                    markdown_cell(first_item(track["production_gaps"])),
                    markdown_cell(first_item(track["graduation_criteria"])),
                ]
            )
            + " |"
        )

    lines.extend(["", "## Track Details", ""])

    for track in sorted_tracks(prod_manifest):
        lines.extend(
            [
                f"### {track['title']}",
                "",
                f"- Track: `{track['id']}`",
                f"- Priority: `{track['priority']}`",
                f"- Status: {STATUS_LABELS[track['status']]}",
                f"- Requirements: {code_list(track['requirements'])}",
                f"- Implementation anchors: {code_list(track['implementation_anchors'])}",
                "",
                "Current evidence:",
                *bullet_list(track["current_evidence"]),
                "",
                *optional_list_section(track, "capacity_envelope", "Capacity envelope"),
                "Production gaps:",
                *bullet_list(track["production_gaps"]),
                "",
                "Graduation criteria:",
                *bullet_list(track["graduation_criteria"]),
                "",
                "Next actions:",
                *bullet_list(track["next_actions"]),
                "",
                "Verification commands:",
                *bullet_list([code(command) for command in track["verification_commands"]]),
                "",
            ]
        )

    lines.extend(
        [
            "## Maintenance Rules",
            "",
            "- Keep production-readiness status out of `spec/coverage.json`; that manifest is only for spec evidence.",
            "- Add a production track only when at least one spec requirement is already enforced and the remaining work is production evidence, hardening, scale, operations, or real-hardware proof.",
            "- Mark a track `prod_ready` only when its production gaps are closed, graduation criteria are met, and the first supported product envelope is explicit.",
            "- Regenerate this file with `python3 tools/generate_prod_readiness_matrix.py`; `tools/check_production_readiness.py` rejects stale output.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate PROD_READINESS_MATRIX.md from spec/production_readiness.json"
    )
    parser.add_argument("--check", action="store_true", help="fail if PROD_READINESS_MATRIX.md is stale")
    args = parser.parse_args()

    prod_manifest = load_prod_manifest()
    coverage_manifest = load_coverage_manifest()
    errors = validate_prod_readiness_manifest(prod_manifest, coverage_manifest)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    rendered = render_prod_readiness_matrix(prod_manifest, coverage_manifest)
    if args.check:
        current = PROD_READINESS_MATRIX_PATH.read_text() if PROD_READINESS_MATRIX_PATH.exists() else ""
        if current != rendered:
            print(
                "PROD_READINESS_MATRIX.md is out of date; "
                "run python3 tools/generate_prod_readiness_matrix.py",
                file=sys.stderr,
            )
            return 1
        return 0

    PROD_READINESS_MATRIX_PATH.write_text(rendered)
    print(
        "Generated "
        f"{PROD_READINESS_MATRIX_PATH.relative_to(ROOT_DIR)} from "
        f"{PROD_READINESS_MANIFEST_PATH.relative_to(ROOT_DIR)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
