const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");

pub const CHUNK_SIZE_BYTES: usize = 4096;

pub const File = struct {
    data_bytes: ?[*]const u8 = null,
    byte_len: usize = 0,
    chunk_indices: ?[*]const u32 = null,
    pool_chunk_count: u32 = 0,

    pub fn fromBytes(bytes: []const u8) File {
        return .{
            .data_bytes = bytes.ptr,
            .byte_len = bytes.len,
        };
    }

    pub fn fromChunks(
        byte_len: usize,
        chunk_pool: []const u8,
        chunk_indices: []const u32,
    ) File {
        if (byte_len == 0) {
            if (chunk_pool.len == 0 and chunk_indices.len == 0) return .{};
            return invalid(byte_len);
        }
        if (chunk_pool.len == 0 or chunk_pool.len % CHUNK_SIZE_BYTES != 0) return invalid(byte_len);
        const required_chunks = std.math.divCeil(usize, byte_len, CHUNK_SIZE_BYTES) catch return invalid(byte_len);
        if (chunk_indices.len != required_chunks) return invalid(byte_len);
        const pool_chunk_count = std.math.cast(u32, chunk_pool.len / CHUNK_SIZE_BYTES) orelse return invalid(byte_len);
        for (chunk_indices) |chunk_index| {
            if (chunk_index >= pool_chunk_count) return invalid(byte_len);
        }
        return .{
            .byte_len = byte_len,
            .data_bytes = chunk_pool.ptr,
            .chunk_indices = chunk_indices.ptr,
            .pool_chunk_count = pool_chunk_count,
        };
    }

    pub fn isPresent(self: File) bool {
        return self.byte_len != 0 and self.isValid();
    }

    pub fn reader(self: File) ?Reader {
        if (!self.isValid()) return null;
        return .{ .file = self };
    }

    pub fn isValid(self: File) bool {
        if (self.byte_len == 0) {
            return self.chunk_indices == null and self.pool_chunk_count == 0;
        }
        if (self.data_bytes == null) return false;
        const chunk_indices = self.chunk_indices orelse return self.pool_chunk_count == 0;
        if (self.pool_chunk_count == 0) return false;

        const required_chunks = std.math.divCeil(usize, self.byte_len, CHUNK_SIZE_BYTES) catch return false;
        for (chunk_indices[0..required_chunks]) |chunk_index| {
            if (chunk_index >= self.pool_chunk_count) return false;
        }
        return true;
    }

    pub fn readInto(self: File, offset: usize, output: []u8) bool {
        const validated = self.reader() orelse return false;
        return validated.readInto(offset, output);
    }

    pub fn byteAt(self: File, offset: usize) ?u8 {
        const validated = self.reader() orelse return null;
        return validated.byteAt(offset);
    }

    pub fn sha256(self: File) ?crypto_hash.Digest {
        const validated = self.reader() orelse return null;
        return validated.sha256();
    }

    pub fn logicalSliceAt(self: File, offset: usize) ?[]const u8 {
        const validated = self.reader() orelse return null;
        return validated.logicalSliceAt(offset);
    }

    fn invalid(byte_len: usize) File {
        return .{
            .byte_len = byte_len,
            .pool_chunk_count = std.math.maxInt(u32),
        };
    }
};

pub const Reader = struct {
    file: File,

    pub fn readInto(self: Reader, offset: usize, output: []u8) bool {
        const end = std.math.add(usize, offset, output.len) catch return false;
        if (end > self.file.byte_len) return false;
        if (output.len == 0) return true;
        const data_bytes = self.file.data_bytes orelse unreachable;
        const chunk_indices = self.file.chunk_indices orelse {
            @memcpy(output, data_bytes[offset..end]);
            return true;
        };

        var source_offset = offset;
        var output_offset: usize = 0;
        while (output_offset < output.len) {
            const chunk_ordinal = source_offset / CHUNK_SIZE_BYTES;
            const chunk_offset = source_offset % CHUNK_SIZE_BYTES;
            const pool_offset = @as(usize, chunk_indices[chunk_ordinal]) * CHUNK_SIZE_BYTES + chunk_offset;
            const copy_len = @min(output.len - output_offset, CHUNK_SIZE_BYTES - chunk_offset);
            @memcpy(output[output_offset..][0..copy_len], data_bytes[pool_offset..][0..copy_len]);
            source_offset += copy_len;
            output_offset += copy_len;
        }
        return true;
    }

    pub fn byteAt(self: Reader, offset: usize) ?u8 {
        if (offset >= self.file.byte_len) return null;
        const data_bytes = self.file.data_bytes orelse unreachable;
        const chunk_indices = self.file.chunk_indices orelse return data_bytes[offset];
        const chunk_ordinal = offset / CHUNK_SIZE_BYTES;
        const chunk_offset = offset % CHUNK_SIZE_BYTES;
        const pool_offset = @as(usize, chunk_indices[chunk_ordinal]) * CHUNK_SIZE_BYTES + chunk_offset;
        return data_bytes[pool_offset];
    }

    pub fn sha256(self: Reader) crypto_hash.Digest {
        var hasher = crypto_hash.init();
        if (self.file.byte_len == 0) return crypto_hash.finalize(&hasher);
        const data_bytes = self.file.data_bytes orelse unreachable;
        const chunk_indices = self.file.chunk_indices orelse {
            hasher.update(data_bytes[0..self.file.byte_len]);
            return crypto_hash.finalize(&hasher);
        };

        var remaining = self.file.byte_len;
        const required_chunks = std.math.divCeil(usize, remaining, CHUNK_SIZE_BYTES) catch unreachable;
        for (chunk_indices[0..required_chunks]) |chunk_index| {
            const chunk_len = @min(remaining, CHUNK_SIZE_BYTES);
            const pool_offset = @as(usize, chunk_index) * CHUNK_SIZE_BYTES;
            hasher.update(data_bytes[pool_offset..][0..chunk_len]);
            remaining -= chunk_len;
        }
        std.debug.assert(remaining == 0);
        return crypto_hash.finalize(&hasher);
    }

    pub fn logicalSliceAt(self: Reader, offset: usize) ?[]const u8 {
        if (offset >= self.file.byte_len) return null;
        const data_bytes = self.file.data_bytes orelse unreachable;
        const chunk_indices = self.file.chunk_indices orelse return data_bytes[offset..self.file.byte_len];
        const chunk_ordinal = offset / CHUNK_SIZE_BYTES;
        const chunk_offset = offset % CHUNK_SIZE_BYTES;
        const pool_offset = @as(usize, chunk_indices[chunk_ordinal]) * CHUNK_SIZE_BYTES + chunk_offset;
        const logical_remaining = self.file.byte_len - offset;
        const available = @min(logical_remaining, CHUNK_SIZE_BYTES - chunk_offset);
        return data_bytes[pool_offset..][0..available];
    }
};

test "chunked embedded files preserve logical bytes across shared chunks" {
    const chunk_pool = ([_]u8{'a'} ** CHUNK_SIZE_BYTES) ++ ([_]u8{'A'} ** CHUNK_SIZE_BYTES);
    const chunk_indices = [_]u32{ 0, 1, 0 };
    const byte_len = CHUNK_SIZE_BYTES * 2 + 2;
    const file = File.fromChunks(byte_len, &chunk_pool, &chunk_indices);
    try std.testing.expect(file.isPresent());

    var output: [byte_len]u8 = undefined;
    try std.testing.expect(file.readInto(0, &output));
    try std.testing.expect(std.mem.allEqual(u8, output[0..CHUNK_SIZE_BYTES], 'a'));
    try std.testing.expect(std.mem.allEqual(u8, output[CHUNK_SIZE_BYTES .. CHUNK_SIZE_BYTES * 2], 'A'));
    try std.testing.expectEqualStrings("aa", output[CHUNK_SIZE_BYTES * 2 ..]);
    try std.testing.expectEqual(@as(?u8, 'A'), file.byteAt(CHUNK_SIZE_BYTES));
    try std.testing.expectEqualSlices(u8, "aa", file.logicalSliceAt(CHUNK_SIZE_BYTES - 2).?);

    const contiguous = File.fromBytes(&output);
    const contiguous_digest = contiguous.sha256().?;
    const chunked_digest = file.sha256().?;
    try std.testing.expectEqualSlices(u8, &contiguous_digest, &chunked_digest);
}

test "chunked embedded files reject invalid index layouts" {
    const chunk_pool = [_]u8{0} ** CHUNK_SIZE_BYTES;
    const missing_index = [_]u32{0};
    const out_of_range = [_]u32{ 0, 1 };
    try std.testing.expect(!File.fromChunks(CHUNK_SIZE_BYTES + 1, &chunk_pool, &missing_index).isValid());
    try std.testing.expect(!File.fromChunks(CHUNK_SIZE_BYTES + 1, &chunk_pool, &out_of_range).isValid());
    try std.testing.expect(!(File{ .byte_len = 1 }).isValid());
    try std.testing.expect((File{}).sha256() != null);
}
