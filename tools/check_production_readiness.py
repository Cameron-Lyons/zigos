#!/usr/bin/env python3

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from spec_coverage_lib import MANIFEST_PATH, ROOT_DIR


PROD_READINESS_MANIFEST_PATH = ROOT_DIR / "spec" / "production_readiness.json"
STATUS_LABELS = {
    "prod_ready": "Prod Ready",
    "prod_candidate": "Prod Candidate",
    "prototype": "Prototype",
    "blocked": "Blocked",
}
PRIORITIES = {"P0", "P1", "P2"}
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
MODEL_ONLY_SYNTHETIC_IMAGE_MARKER = "prod-readiness: model-only synthetic-userspace-image"
SYNTHETIC_IMAGE_PATTERN = re.compile(r"\b(?:task_runtime\.)?syntheticUserspaceImage\s*\(")
SYNTHETIC_IMAGE_MARKER_LOOKBACK_LINES = 1
CRITICAL_SYNTHETIC_IMAGE_PATHS = (
    Path("src/native/kernel_api/component_port.zig"),
    Path("src/native/kernel_api/native_kernel.zig"),
    Path("src/native/kernel_api/syscall_surface.zig"),
    Path("src/native/services/userspace_service_ipc.zig"),
    Path("src/native/session/service_path_proofs.zig"),
    Path("src/native/storage/storage_service_ipc.zig"),
    Path("src/native/sync/sync_service_test.zig"),
    Path("src/native/task/process_isolation.zig"),
)


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
            errors.append(
                f"Production readiness track {track_id} priority must be one of {sorted(PRIORITIES)}"
            )

        status = track.get("status")
        if status not in STATUS_LABELS:
            errors.append(
                f"Production readiness track {track_id} status must be one of {sorted(STATUS_LABELS)}"
            )

        for field in LIST_FIELDS:
            values = track.get(field)
            if field == "production_gaps" and status == "prod_ready":
                if not isinstance(values, list):
                    errors.append(f"Production readiness track {track_id} must include production_gaps")
                    continue
            elif not isinstance(values, list) or not values:
                errors.append(
                    f"Production readiness track {track_id} must include non-empty {field}"
                )
                continue
            for value in values:
                if not isinstance(value, str) or not value.strip():
                    errors.append(
                        f"Production readiness track {track_id} has an empty or non-string {field} entry"
                    )

        for field in OPTIONAL_LIST_FIELDS:
            values = track.get(field, [])
            if values is None:
                continue
            if not isinstance(values, list):
                errors.append(
                    f"Production readiness track {track_id} optional {field} must be a list when present"
                )
                continue
            for value in values:
                if not isinstance(value, str) or not value.strip():
                    errors.append(
                        f"Production readiness track {track_id} has an empty or non-string {field} entry"
                    )

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


def source_line_has_model_only_marker(lines: list[str], line_index: int) -> bool:
    marker_window_start = max(0, line_index - SYNTHETIC_IMAGE_MARKER_LOOKBACK_LINES)
    return any(
        MODEL_ONLY_SYNTHETIC_IMAGE_MARKER in lines[index]
        for index in range(marker_window_start, line_index + 1)
    )


def validate_synthetic_userspace_image_markers_for_source(
    errors: list[str],
    relative_path: Path,
    source: str,
) -> None:
    lines = source.splitlines()
    for line_index, line in enumerate(lines):
        if SYNTHETIC_IMAGE_PATTERN.search(line) is None:
            continue
        if source_line_has_model_only_marker(lines, line_index):
            continue
        errors.append(
            f"{relative_path}:{line_index + 1} calls syntheticUserspaceImage in a "
            "critical service launch path without the "
            f"{MODEL_ONLY_SYNTHETIC_IMAGE_MARKER!r} marker"
        )


def validate_synthetic_userspace_image_markers(errors: list[str]) -> None:
    for relative_path in CRITICAL_SYNTHETIC_IMAGE_PATHS:
        path = ROOT_DIR / relative_path
        if not path.exists():
            errors.append(f"Critical synthetic userspace image path is missing: {relative_path}")
            continue
        validate_synthetic_userspace_image_markers_for_source(
            errors,
            relative_path,
            path.read_text(),
        )


def test_synthetic_userspace_marker_gate_rejects_unmarked_fixture() -> None:
    errors: list[str] = []
    validate_synthetic_userspace_image_markers_for_source(
        errors,
        Path("src/native/kernel_api/native_kernel.zig"),
        'const image = task_runtime.syntheticUserspaceImage("label", "entry");\n',
    )

    assert errors, "synthetic userspace image gate must reject unmarked critical fixtures"


def test_synthetic_userspace_marker_gate_accepts_model_only_marker() -> None:
    errors: list[str] = []
    validate_synthetic_userspace_image_markers_for_source(
        errors,
        Path("src/native/kernel_api/native_kernel.zig"),
        (
            f"// {MODEL_ONLY_SYNTHETIC_IMAGE_MARKER}\n"
            'const image = task_runtime.syntheticUserspaceImage("label", "entry");\n'
        ),
    )

    assert not errors, "synthetic userspace image gate must accept marked model-only fixtures"


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


def main() -> int:
    errors: list[str] = []
    for failure in run_self_tests():
        errors.append(f"Production readiness checker self-test failed: {failure}")

    prod_manifest = load_prod_manifest()
    coverage_manifest = load_coverage_manifest()
    errors.extend(validate_prod_readiness_manifest(prod_manifest, coverage_manifest))
    validate_synthetic_userspace_image_markers(errors)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(
        "Production readiness OK: "
        f"{len(prod_manifest['tracks'])} tracks, "
        f"{sum(len(track['requirements']) for track in prod_manifest['tracks'])} requirement references"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
