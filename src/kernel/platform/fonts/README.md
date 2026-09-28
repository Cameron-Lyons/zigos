# Zigos Bitmap

`zigos-bitmap.bin` repackages the unmodified glyph bitmaps from GNU Unifont
18.0.01, with C0/C1 device-control pictures excluded. This derived font is named
**Zigos Bitmap**. It is distributed under the **SIL Open Font License 1.1**;
the full upstream dual-license text is retained in `UNIFONT-LICENSE.txt`.
The original ASCII 5×7 font in `bitmap_font.zig` remains under this repository's
MIT license. No upstream font-generation program source is included.

Copyright (C) 1998–2026 Roman Czyborra, Paul Hardy, Qianqian Fang, Andrew Miller,
Johnnie Weaver, David Corbett, Ælla Chiana Moskopp, Rebecca Bettencourt, Minseo
Lee, Ho-Seok Ee, et al.

Pinned inputs for `scripts/generate-unicode.py`:

- https://unifoundry.com/pub/unifont/unifont-18.0.01/font-builds/unifont-18.0.01.hex.gz
- https://unifoundry.com/pub/unifont/unifont-18.0.01/font-builds/unifont_upper-18.0.01.hex.gz
- https://www.unifoundry.com/LICENSE.txt (save as `UNIFONT-LICENSE.txt`)

Each sorted 36-byte record contains a little-endian u32 (code point in bits
0..20; bit 21 means 16 pixels wide, otherwise 8), then sixteen little-endian
u16 bitmap rows. Unused high bits of narrow rows are zero. The two source
files contain 114,988 retained glyphs. The generator verifies source hashes.

The scanout renderer centers 8×16 and 16×16 glyphs in one or two 12×20 cells.
Ambiguous-width 16-pixel symbols fit ten horizontal pixels in a single cell.
Combining marks overlay the base glyph. Clusters requiring contextual shaping
or emoji composition use one replacement glyph, while editing, clipboard and
storage retain every original byte. Bidirectional layout, complex-script
shaping, color emoji and input methods remain separate work.
