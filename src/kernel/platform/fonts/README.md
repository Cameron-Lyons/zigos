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

Pinned inputs for `tools/host/unicode.zig`:

- https://unifoundry.com/pub/unifont/unifont-18.0.01/font-builds/unifont-18.0.01.hex.gz
- https://unifoundry.com/pub/unifont/unifont-18.0.01/font-builds/unifont_upper-18.0.01.hex.gz
- https://www.unifoundry.com/LICENSE.txt (save as `UNIFONT-LICENSE.txt`)

The file groups glyphs into sorted runs of consecutive code points that share
one width. All integers are little-endian: a u32 run count, then each run's
first code point as a u32, then per run a u16 glyph count, a u16 width (8 or
16 pixels) and a u32 byte offset into the row data that follows. Each glyph
has sixteen rows: one byte per row for 8-pixel glyphs, one u16 per row for
16-pixel glyphs. The two source files contain 114,988 retained glyphs in 3,199
runs. The generator verifies source hashes.

The scanout renderer centers 8×16 and 16×16 glyphs in one or two 12×20 cells.
Ambiguous-width 16-pixel symbols fit ten horizontal pixels in a single cell.
Combining marks overlay the base glyph. Clusters requiring contextual shaping
or emoji composition use one replacement glyph, while editing, clipboard and
storage retain every original byte. Bidirectional layout, complex-script
shaping, color emoji and input methods remain separate work.
