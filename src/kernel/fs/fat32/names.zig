const std = @import("std");
const unicode_casefold = @import("../unicode_casefold.zig");
const unicode_normalize = @import("../unicode_normalize.zig");
const ondisk = @import("ondisk.zig");

const DirEntry = ondisk.DirEntry;
const LfnEntry = ondisk.LfnEntry;
const ATTR_LONG_NAME = ondisk.ATTR_LONG_NAME;

pub const LFN_LAST_ENTRY: u8 = 0x40;
pub const LFN_CHARS_PER_ENTRY: usize = 13;
pub const MAX_LFN_ENTRIES: usize = 20;
pub const MAX_LFN_CODE_UNITS: usize = MAX_LFN_ENTRIES * LFN_CHARS_PER_ENTRY;
pub const MAX_LFN_NAME_CODE_UNITS: usize = 255;
pub const MAX_VISIBLE_NAME_BYTES: usize = 255;
pub const MAX_COMPARE_CODEPOINTS: usize = MAX_VISIBLE_NAME_BYTES * 4;

pub const LfnState = struct {
    active: bool = false,
    total_entries: u8 = 0,
    checksum: u8 = 0,
    seen_mask: u32 = 0,
    code_units: [MAX_LFN_CODE_UNITS]u16 = [_]u16{0} ** MAX_LFN_CODE_UNITS,
    code_unit_len: usize = 0,
};

pub fn strlen(str: []const u8) usize {
    var i: usize = 0;
    while (i < str.len and str[i] != 0) : (i += 1) {}
    return i;
}

pub fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

pub fn toUpper(c: u8) u8 {
    if (c >= 'a' and c <= 'z') return c - 32;
    return c;
}

pub fn formatDosName(name: []const u8, ext: []const u8, output: []u8) void {
    var out_idx: usize = 0;

    var name_end: usize = 8;
    while (name_end > 0 and name[name_end - 1] == ' ') : (name_end -= 1) {}

    for (0..name_end) |i| {
        if (name[i] != ' ') {
            output[out_idx] = toLower(name[i]);
            out_idx += 1;
        }
    }

    if (ext[0] != ' ') {
        output[out_idx] = '.';
        out_idx += 1;

        var ext_end: usize = 3;
        while (ext_end > 0 and ext[ext_end - 1] == ' ') : (ext_end -= 1) {}

        for (0..ext_end) |i| {
            output[out_idx] = toLower(ext[i]);
            out_idx += 1;
        }
    }

    output[out_idx] = 0;
}

pub fn formatNameTo83(name: []const u8, dos_name: []u8, dos_ext: []u8) void {
    @memset(dos_name[0..8], ' ');
    @memset(dos_ext[0..3], ' ');

    var dot_pos: ?usize = null;
    for (name, 0..) |c, i| {
        if (c == '.') dot_pos = i;
    }

    const base_end = if (dot_pos) |pos| @min(pos, 8) else @min(name.len, 8);
    for (0..base_end) |i| {
        dos_name[i] = toUpper(name[i]);
    }

    if (dot_pos) |pos| {
        const ext_start = pos + 1;
        const ext_len = @min(name.len - ext_start, 3);
        for (0..ext_len) |i| {
            dos_ext[i] = toUpper(name[ext_start + i]);
        }
    }
}

fn asciiLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

pub fn asciiNamesEqualIgnoreCase(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |l, r| {
        if (asciiLower(l) != asciiLower(r)) return false;
    }
    return true;
}

fn appendCanonicalOrderedCodepoint(out: []u21, classes: []u8, len: *usize, segment_start: *usize, codepoint: u21) error{NameTooLong}!void {
    if (len.* >= out.len or len.* >= classes.len) return error.NameTooLong;

    const combining_class = unicode_normalize.canonicalCombiningClass(codepoint);
    out[len.*] = codepoint;
    classes[len.*] = combining_class;

    if (combining_class == 0) {
        segment_start.* = len.*;
        len.* += 1;
        return;
    }

    var index = len.*;
    while (index > 0 and classes[index - 1] > combining_class) : (index -= 1) {
        const prev_codepoint = out[index - 1];
        const prev_class = classes[index - 1];
        out[index - 1] = out[index];
        classes[index - 1] = classes[index];
        out[index] = prev_codepoint;
        classes[index] = prev_class;
    }

    len.* += 1;
}

fn appendFullyDecomposedCodepoint(out: []u21, classes: []u8, len: *usize, segment_start: *usize, codepoint: u21) error{NameTooLong}!void {
    var decomposition: [3]u21 = undefined;
    const decomposition_len = unicode_normalize.canonicalDecompose(codepoint, &decomposition);
    if (decomposition_len == 1 and decomposition[0] == codepoint) {
        try appendCanonicalOrderedCodepoint(out, classes, len, segment_start, codepoint);
        return;
    }

    for (decomposition[0..decomposition_len]) |part| {
        try appendFullyDecomposedCodepoint(out, classes, len, segment_start, part);
    }
}

fn appendCasefoldedCodepoint(out: []u21, classes: []u8, len: *usize, segment_start: *usize, codepoint: u21) error{NameTooLong}!void {
    var decomposition: [3]u21 = undefined;
    const decomposition_len = unicode_normalize.canonicalDecompose(codepoint, &decomposition);
    if (decomposition_len == 1 and decomposition[0] == codepoint) {
        var folded: [3]u21 = undefined;
        const folded_len = unicode_casefold.foldCodepoint(codepoint, &folded);
        for (folded[0..folded_len]) |folded_codepoint| {
            try appendFullyDecomposedCodepoint(out, classes, len, segment_start, folded_codepoint);
        }
        return;
    }

    for (decomposition[0..decomposition_len]) |part| {
        try appendCasefoldedCodepoint(out, classes, len, segment_start, part);
    }
}

fn normalizeNameForCompare(name: []const u8, out: []u21, classes: []u8) error{ InvalidUtf8, NameTooLong }!usize {
    var src_index: usize = 0;
    var out_len: usize = 0;
    var segment_start: usize = 0;

    while (src_index < name.len) {
        const seq_len = std.unicode.utf8ByteSequenceLength(name[src_index]) catch return error.InvalidUtf8;
        const seq_len_usize: usize = seq_len;
        if (src_index + seq_len_usize > name.len) return error.InvalidUtf8;

        const codepoint = std.unicode.utf8Decode(name[src_index .. src_index + seq_len_usize]) catch return error.InvalidUtf8;
        src_index += seq_len_usize;
        try appendCasefoldedCodepoint(out, classes, &out_len, &segment_start, codepoint);
    }

    return out_len;
}

pub fn namesEqualIgnoreCase(left: []const u8, right: []const u8) bool {
    var left_normalized: [MAX_COMPARE_CODEPOINTS]u21 = undefined;
    var right_normalized: [MAX_COMPARE_CODEPOINTS]u21 = undefined;
    var left_classes: [MAX_COMPARE_CODEPOINTS]u8 = undefined;
    var right_classes: [MAX_COMPARE_CODEPOINTS]u8 = undefined;

    const left_len = normalizeNameForCompare(left, &left_normalized, &left_classes) catch return asciiNamesEqualIgnoreCase(left, right);
    const right_len = normalizeNameForCompare(right, &right_normalized, &right_classes) catch return asciiNamesEqualIgnoreCase(left, right);
    return std.mem.eql(u21, left_normalized[0..left_len], right_normalized[0..right_len]);
}

pub fn resetLfnState(state: *LfnState) void {
    state.* = .{};
}

pub fn shortNameChecksum(name: [8]u8, ext: [3]u8) u8 {
    var checksum: u8 = 0;
    for (name) |byte| {
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) +% byte;
    }
    for (ext) |byte| {
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) +% byte;
    }
    return checksum;
}

pub fn decodeLfnChunk(state: *LfnState, offset: usize, chars: anytype) void {
    var idx: usize = 0;
    while (idx < chars.len and offset + idx < state.code_units.len) : (idx += 1) {
        const code_unit = std.mem.littleToNative(u16, chars[idx]);
        if (code_unit == 0x0000) {
            state.code_unit_len = @min(state.code_unit_len, offset + idx);
            break;
        }
        if (code_unit == 0xFFFF) break;
        state.code_units[offset + idx] = code_unit;
        if (offset + idx + 1 > state.code_unit_len) {
            state.code_unit_len = offset + idx + 1;
        }
    }
}

pub fn consumeLfnEntry(state: *LfnState, entry: *const DirEntry) void {
    const lfn: LfnEntry = @bitCast(entry.*);
    const order = lfn.order;
    const sequence = order & 0x1F;
    const is_last = (order & LFN_LAST_ENTRY) != 0;

    if (sequence == 0 or sequence > MAX_LFN_ENTRIES) {
        resetLfnState(state);
        return;
    }

    if (is_last) {
        resetLfnState(state);
        state.active = true;
        state.total_entries = sequence;
        state.checksum = lfn.checksum;
        state.code_unit_len = @as(usize, sequence) * LFN_CHARS_PER_ENTRY;
    } else if (!state.active or lfn.checksum != state.checksum or sequence > state.total_entries) {
        resetLfnState(state);
        return;
    }

    const bit: u32 = @as(u32, 1) << @intCast(sequence - 1);
    state.seen_mask |= bit;

    const chunk_offset = (@as(usize, sequence) - 1) * LFN_CHARS_PER_ENTRY;
    decodeLfnChunk(state, chunk_offset, &lfn.name1);
    decodeLfnChunk(state, chunk_offset + 5, &lfn.name2);
    decodeLfnChunk(state, chunk_offset + 11, &lfn.name3);
}

pub fn completeLfnMask(total_entries: u8) u32 {
    return if (total_entries >= 32) 0xFFFF_FFFF else (@as(u32, 1) << @intCast(total_entries)) - 1;
}

pub fn utf16NameToUtf8(code_units: []const u16, out: []u8) error{ InvalidUtf16, NameTooLong }!usize {
    var it = std.unicode.Utf16LeIterator.init(code_units);
    var out_len: usize = 0;

    while (true) {
        const maybe_codepoint = it.nextCodepoint() catch return error.InvalidUtf16;
        const codepoint = maybe_codepoint orelse break;
        const utf8_len = std.unicode.utf8CodepointSequenceLength(codepoint) catch unreachable;
        if (out_len + utf8_len > out.len) return error.NameTooLong;
        out_len += std.unicode.utf8Encode(codepoint, out[out_len..]) catch unreachable;
    }

    return out_len;
}

pub fn utf8NameToUtf16Units(name: []const u8, storage: *[MAX_LFN_CODE_UNITS]u16) error{InvalidOperation}![]const u16 {
    if (name.len == 0 or name.len > MAX_VISIBLE_NAME_BYTES) return error.InvalidOperation;

    const utf16_len = std.unicode.calcUtf16LeLen(name) catch return error.InvalidOperation;
    if (utf16_len == 0 or utf16_len > MAX_LFN_NAME_CODE_UNITS) return error.InvalidOperation;

    _ = std.unicode.utf8ToUtf16Le(storage[0..utf16_len], name) catch return error.InvalidOperation;
    return storage[0..utf16_len];
}

pub fn finishVisibleName(state: *LfnState, entry: *const DirEntry, out: *[256]u8) struct { len: u16, lfn_count: u8 } {
    const checksum_matches = state.active and state.checksum == shortNameChecksum(entry.name, entry.ext);
    const lfn_complete = checksum_matches and state.seen_mask == completeLfnMask(state.total_entries);
    if (lfn_complete and state.code_unit_len > 0 and state.code_unit_len <= MAX_LFN_NAME_CODE_UNITS) {
        if (utf16NameToUtf8(state.code_units[0..state.code_unit_len], out[0 .. out.len - 1])) |visible_len| {
            out[visible_len] = 0;
            const visible_len_u16: u16 = @intCast(visible_len);
            const lfn_count = state.total_entries;
            resetLfnState(state);
            return .{ .len = visible_len_u16, .lfn_count = lfn_count };
        } else |_| {}

        const lfn_count = state.total_entries;
        resetLfnState(state);
        formatDosName(&entry.name, &entry.ext, out);
        return .{ .len = @intCast(strlen(out)), .lfn_count = lfn_count };
    }

    formatDosName(&entry.name, &entry.ext, out);
    const visible_len: u16 = @intCast(strlen(out));
    resetLfnState(state);
    return .{ .len = visible_len, .lfn_count = 0 };
}

pub fn splitName(name: []const u8) struct { base: []const u8, ext: []const u8 } {
    var dot_pos: ?usize = null;
    for (name, 0..) |char, index| {
        if (char == '.' and index != 0 and index + 1 < name.len) {
            dot_pos = index;
        }
    }

    if (dot_pos) |dot| {
        return .{ .base = name[0..dot], .ext = name[dot + 1 ..] };
    }

    return .{ .base = name, .ext = "" };
}

pub fn sanitizeShortChar(char: u8) u8 {
    const upper = toUpper(char);
    if ((upper >= 'A' and upper <= 'Z') or (upper >= '0' and upper <= '9')) {
        return upper;
    }
    return '_';
}

pub fn requiresLongName(name: []const u8, short_name: [8]u8, short_ext: [3]u8) bool {
    var visible_name: [13]u8 = undefined;
    formatDosName(&short_name, &short_ext, &visible_name);
    return !std.mem.eql(u8, visible_name[0..strlen(&visible_name)], name);
}

pub fn buildLfnDirEntry(name_code_units: []const u16, sequence: u8, total_entries: u8, checksum: u8) DirEntry {
    var units = [_]u16{0xFFFF} ** LFN_CHARS_PER_ENTRY;
    const start = (@as(usize, sequence) - 1) * LFN_CHARS_PER_ENTRY;
    const end = @min(name_code_units.len, start + LFN_CHARS_PER_ENTRY);
    const chunk = name_code_units[start..end];
    for (chunk, 0..) |code_unit, index| {
        units[index] = std.mem.nativeToLittle(u16, code_unit);
    }
    if (sequence == total_entries and chunk.len < LFN_CHARS_PER_ENTRY) {
        units[chunk.len] = 0x0000;
    }

    const lfn = LfnEntry{
        .order = sequence | if (sequence == total_entries) LFN_LAST_ENTRY else 0,
        .name1 = .{ units[0], units[1], units[2], units[3], units[4] },
        .attributes = ATTR_LONG_NAME,
        .entry_type = 0,
        .checksum = checksum,
        .name2 = .{ units[5], units[6], units[7], units[8], units[9], units[10] },
        .first_cluster_low = 0,
        .name3 = .{ units[11], units[12] },
    };
    return @bitCast(lfn);
}
