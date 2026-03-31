#!/usr/bin/env python3

from __future__ import annotations

import json

from spec_coverage_lib import (
    MANIFEST_PATH,
    expected_claims_for_manifest_sections,
    expected_claims_for_section,
    expected_headings,
    load_lines,
    parse_spec_blocks,
)


def main() -> int:
    manifest = json.loads(MANIFEST_PATH.read_text())
    blocks = parse_spec_blocks()
    lines = load_lines()

    manifest["required_headings"] = expected_headings(blocks)
    for section in manifest["sections"]:
        section["claims"] = expected_claims_for_section(section["id"], blocks, lines)
    manifest["required_claims"] = expected_claims_for_manifest_sections(manifest["sections"])

    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n")
    print(
        "Synced spec coverage manifest: "
        f"{len(manifest['required_headings'])} headings, "
        f"{len(manifest['required_claims'])} claims"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
