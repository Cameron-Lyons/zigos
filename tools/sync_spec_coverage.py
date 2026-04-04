#!/usr/bin/env python3

from __future__ import annotations

import json

from spec_coverage_lib import (
    MANIFEST_PATH,
    expected_requirements_for_manifest_sections,
    expected_requirements_for_section,
    expected_headings,
    parse_spec_blocks,
)


def main() -> int:
    manifest = json.loads(MANIFEST_PATH.read_text())
    blocks = parse_spec_blocks()

    manifest["required_headings"] = expected_headings(blocks)
    for section in manifest["sections"]:
        section.pop("claims", None)
        section["requirements"] = expected_requirements_for_section(section["id"], blocks)
    manifest.pop("required_claims", None)
    manifest["required_requirements"] = expected_requirements_for_manifest_sections(manifest["sections"])

    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n")
    print(
        "Synced spec coverage manifest: "
        f"{len(manifest['required_headings'])} headings, "
        f"{len(manifest['required_requirements'])} requirements"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
