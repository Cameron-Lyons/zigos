#!/usr/bin/env python3
"""Regenerate pinned Unicode 18 tables and Zigos Bitmap font, without network access.
Usage: python3 scripts/generate-unicode.py /path/to/downloaded/sources
Source URLs and licensing are documented in src/native/core/unicode_data/README.md.
"""
import gzip
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
PINS = {'GraphemeBreakProperty.txt': '0839dcb79e4ac639ecd538b1abf7c9d22e3f9dd265b7e182d33627aa4d75b45a',
 'DerivedCoreProperties.txt': '09c928886a178fcafd93c29e4bd59073a058e5a100b716d425cb563ab50f68c9',
 'emoji-data.txt': '80d00f8e616a0ef27fd6b8de3b758c06383b5d917e2977709578e68baf733bf1',
 'EastAsianWidth.txt': 'a0cf29eacd00cfcaec4381c6b7c281685f18dbb4e7ff82b4076ccb342ca839aa',
 'GraphemeBreakTest.txt': 'b0cf047ee94485bbdc846de2b902f5f8a815f6b674f9d04223cddadd91c9df31',
 'UNICODE-LICENSE.txt': 'e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96',
 'unifont-18.0.01.hex.gz': 'e66385c79a0b8b24a466f3129930e08a966a935b4bf3b28c6bb17a9df9bf791d',
 'unifont_upper-18.0.01.hex.gz': 'ef531f3675950380a92569beceb3af0a7efea05dbc5755a1d08cbd1dca83210f',
 'UNIFONT-LICENSE.txt': '1e74cb82bf476843e97c2596297b04219b1a7e51f7238944a8c031cb9401fa87'}


def main():
    source = Path(sys.argv[1])
    files = {}
    for name, digest in PINS.items():
        data = (source / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise SystemExit(f"source digest mismatch: {name}")
        files[name] = data
    properties = [0] * 0x110000
    gcb = "Other CR LF Control Extend ZWJ Regional_Indicator Prepend SpacingMark L V T LV LVT".split()

    def entries(name):
        for line in files[name].decode().splitlines():
            fields = [part.strip() for part in line.split("#", 1)[0].split(";")]
            if len(fields) < 2:
                continue
            span = fields[0].split("..")
            yield range(int(span[0], 16), int(span[-1], 16) + 1), fields[1:]

    for span, fields in entries("GraphemeBreakProperty.txt"):
        for cp in span:
            properties[cp] |= gcb.index(fields[0])
    for span, fields in entries("DerivedCoreProperties.txt"):
        if fields[0] == "InCB":
            for cp in span:
                properties[cp] |= {"Consonant": 1, "Extend": 2, "Linker": 3}[fields[1]] << 4
    for span, fields in entries("emoji-data.txt"):
        bit = {"Extended_Pictographic": 6, "Emoji_Presentation": 8}.get(fields[0])
        if bit is not None:
            for cp in span:
                properties[cp] |= 1 << bit
    for span, fields in entries("EastAsianWidth.txt"):
        if fields[0] in ("W", "F"):
            for cp in span:
                properties[cp] |= 1 << 7
    ranges = []
    for cp, bits in enumerate(properties):
        if cp == len(properties) - 1 or bits != properties[cp + 1]:
            ranges.append((cp, bits))
    target = ROOT / "src/native/core/unicode_data"
    # Fixed six-byte little-endian entries: inclusive range end, property bits.
    (target / "properties.bin").write_bytes(b"".join(struct.pack("<IH", *entry) for entry in ranges))
    for name in ("GraphemeBreakTest.txt", "UNICODE-LICENSE.txt"):
        (target / name).write_bytes(files[name])

    glyphs = {}
    for name in ("unifont-18.0.01.hex.gz", "unifont_upper-18.0.01.hex.gz"):
        for line in gzip.decompress(files[name]).decode().splitlines():
            point, bitmap = line.split(":")
            cp = int(point, 16)
            if cp < 0x20 or 0x7f <= cp < 0xa0:
                continue
            if len(bitmap) not in (32, 64):
                raise SystemExit(f"unexpected glyph width: {point}")
            width = len(bitmap) // 4
            rows = [int(bitmap[i:i + width // 4], 16) for i in range(0, len(bitmap), width // 4)]
            glyphs[cp] = struct.pack("<I16H", cp | ((width == 16) << 21), *rows)
    font = ROOT / "src/kernel/platform/fonts"
    (font / "zigos-bitmap.bin").write_bytes(b"".join(glyphs[cp] for cp in sorted(glyphs)))
    (font / "UNIFONT-LICENSE.txt").write_bytes(files["UNIFONT-LICENSE.txt"])
    print(f"{len(ranges)} Unicode ranges; {len(glyphs)} font glyphs")


if __name__ == "__main__":
    main()
