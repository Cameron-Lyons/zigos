#!/usr/bin/env python3

import re
import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
TEST_ROOTS = (
    Path("src/native_host_test.zig"),
    Path("src/zigos_spec_test.zig"),
    Path("src/userspace/runtime.zig"),
)

TEST_PATTERN = re.compile(r'^\s*test\s+"', re.MULTILINE)
IMPORT_PATTERN = re.compile(r'@import\("([^"]+)"\)')
NAMED_IMPORTS = {
    "binary_cursor": Path("src/native/core/binary_cursor.zig"),
    "userspace_wire": Path("src/native/task/userspace_wire.zig"),
}


def tracked_zig_files() -> set[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "src"],
        cwd=ROOT_DIR,
        check=True,
        stdout=subprocess.PIPE,
    )
    return {
        path
        for raw_path in result.stdout.split(b"\0")
        if raw_path
        for path in (Path(raw_path.decode()),)
        if path.suffix == ".zig" and (ROOT_DIR / path).is_file()
    }


def has_tests(path: Path) -> bool:
    return TEST_PATTERN.search((ROOT_DIR / path).read_text()) is not None


def resolve_import(owner: Path, import_path: str) -> Path | None:
    if not import_path.endswith(".zig"):
        return NAMED_IMPORTS.get(import_path)

    resolved = (ROOT_DIR / owner.parent / import_path).resolve()
    try:
        relative = resolved.relative_to(ROOT_DIR)
    except ValueError:
        return None

    if relative.parts[:1] != ("src",):
        return None
    if not resolved.is_file():
        return None
    return relative


def reachable_sources(root: Path, tracked: set[Path]) -> set[Path]:
    seen: set[Path] = set()
    pending = [root]

    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)

        source_path = ROOT_DIR / current
        if not source_path.exists():
            continue

        for import_path in IMPORT_PATTERN.findall(source_path.read_text()):
            resolved = resolve_import(current, import_path)
            if resolved is not None and resolved in tracked and resolved not in seen:
                pending.append(resolved)

    return seen


def main() -> int:
    tracked = tracked_zig_files()
    test_files = {path for path in tracked if has_tests(path)}

    missing_roots = [path for path in TEST_ROOTS if path not in tracked]
    if missing_roots:
        for path in missing_roots:
            print(f"Configured Zig test root is missing: {path}", file=sys.stderr)
        return 1

    reachable: set[Path] = set()
    for root in TEST_ROOTS:
        reachable |= reachable_sources(root, tracked)

    missing = sorted(test_files - reachable)
    if missing:
        print(
            "Zig test root coverage failed: these files contain tests but are not "
            "reachable from the configured test roots.",
            file=sys.stderr,
        )
        for path in missing:
            print(f"  {path}", file=sys.stderr)
        print(
            "Import the file from a test root or add a dedicated test root in "
            "tools/check_zig_test_roots.py and build.zig.",
            file=sys.stderr,
        )
        return 1

    print(
        "Zig test roots OK: "
        f"{len(test_files)} test-bearing source files reachable from "
        f"{len(TEST_ROOTS)} test roots"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
