# Unicode 18.0.0 data

`properties.bin` is generated from the Unicode Character Database. Each six-byte
little-endian record stores an inclusive range end (u32) and property bits (u16):
Grapheme_Cluster_Break (0..3), Indic_Conjunct_Break (4..5), Extended_Pictographic
(6), East_Asian_Width W/F (7), and Emoji_Presentation (8). The preceding range
end plus one determines the start. `unicode.zig` defines the property enums.

Sources, pinned by SHA-256 in `scripts/generate-unicode.py`:

- https://www.unicode.org/Public/18.0.0/ucd/auxiliary/GraphemeBreakProperty.txt
- https://www.unicode.org/Public/18.0.0/ucd/auxiliary/GraphemeBreakTest.txt
- https://www.unicode.org/Public/18.0.0/ucd/DerivedCoreProperties.txt
- https://www.unicode.org/Public/18.0.0/ucd/emoji/emoji-data.txt
- https://www.unicode.org/Public/18.0.0/ucd/EastAsianWidth.txt
- https://www.unicode.org/license.txt (save as `UNICODE-LICENSE.txt`)

Copyright © 2026 Unicode, Inc. The accompanying Unicode License V3 applies to
the derived table and the unmodified conformance corpus. The implementation
uses UAX #29 revision 49 extended grapheme clusters, including Unicode 18's GB9c.

Download the pinned sources and the font inputs documented in
`src/kernel/platform/fonts/README.md` into one directory, then run:

```
python3 scripts/generate-unicode.py /path/to/sources
```

Generation is offline and rejects any source whose digest changed. Normal
builds use the checked-in binary tables, without network access or Python.
