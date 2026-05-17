#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path

from generate_prod_readiness_matrix import (
    PROD_READINESS_MATRIX_PATH,
    load_coverage_manifest,
    load_prod_manifest,
    render_prod_readiness_matrix,
    validate_prod_readiness_manifest,
)
from spec_coverage_lib import ROOT_DIR


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

    if not errors:
        expected = render_prod_readiness_matrix(prod_manifest, coverage_manifest)
        actual = PROD_READINESS_MATRIX_PATH.read_text() if PROD_READINESS_MATRIX_PATH.exists() else ""
        if actual != expected:
            errors.append(
                "PROD_READINESS_MATRIX.md is out of sync with spec/production_readiness.json; "
                "run python3 tools/generate_prod_readiness_matrix.py"
            )

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
