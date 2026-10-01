const std = @import("std");
const module = @import("object_chunks");
const objects = module.objects;
const FRAME_BYTES = module.MAX_TRANSFER_CHUNK;
const ITERATIONS = 1_000;
const Lookup = enum { prefix, positioned };
const Order = enum { forward, reverse, retransmit };
const PAYLOAD_LENGTHS = [_]usize{ objects.MAX_CHUNK_BYTES + 17, objects.MAX_CHUNK_BYTES * 14 + 17, objects.MAX_PAYLOAD_BYTES };
const Store = objects.StoreWith(.{
    .max_objects = 4,
    .max_versions = 8,
    .max_blobs = 64,
    .max_chunks = 32,
    .object_index_capacity = 8,
    .version_index_capacity = 16,
    .blob_index_capacity = 128,
    .chunk_index_capacity = 64,
});

pub fn main(init: std.process.Init) !void {
    var bytes: [objects.MAX_PAYLOAD_BYTES]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(i * 19 + i / objects.MAX_CHUNK_BYTES);
    var reconstructed: [objects.MAX_PAYLOAD_BYTES]u8 = undefined;
    var output_buffer: [4_096]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("Object chunk host benchmark: original prefix scan vs positioned cursor, same build, {d}-byte transport chunks\n", .{FRAME_BYTES});
    for (PAYLOAD_LENGTHS) |payload_len| {
        var store = Store.init();
        defer store.reset();
        const result = try store.putLocallySignedVersion(.{
            .object_type = .blob,
            .payload = bytes[0..payload_len],
            .signer = .{ .label = "chunk-benchmark", .seed = module.signing.seedFromByte(0xEC) },
            .label = "range-read",
            .content_type = "application/octet-stream",
            .created_at_ticks = 1,
        });
        const version = store.version(result.version_id).?;
        // Hashing and complete manifest verification stay required; exclude
        // that one-time work equally from both cursor timing paths.
        _ = try store.versionChunkCursor(version);
        inline for (comptime std.meta.tags(Order)) |order| {
            inline for (comptime std.meta.tags(Lookup)) |lookup| {
                const visits = try reconstruct(lookup, order, &store, version, reconstructed[0..payload_len]);
                if (!std.mem.eql(u8, bytes[0..payload_len], reconstructed[0..payload_len])) return error.ReconstructionMismatch;
                var samples: [5]u64 = undefined;
                var checksum: u64 = 0;
                for (&samples) |*sample| {
                    for (0..16) |_| _ = try reconstruct(lookup, order, &store, version, reconstructed[0..payload_len]);
                    const start = std.Io.Clock.awake.now(init.io);
                    for (0..ITERATIONS) |_| {
                        const visited = try reconstruct(lookup, order, &store, version, reconstructed[0..payload_len]);
                        std.mem.doNotOptimizeAway(&reconstructed);
                        checksum +%= reconstructed[0] + @as(u64, reconstructed[payload_len - 1]) + visited;
                    }
                    sample.* = @intCast(start.durationTo(std.Io.Clock.awake.now(init.io)).toNanoseconds());
                }
                std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
                try output.interface.print("{d} bytes, {s}, {s}: {d:.2} ns/payload, {d} chunk visits/payload (median of 5), checksum={d}\n", .{
                    payload_len, @tagName(order), @tagName(lookup), @as(f64, @floatFromInt(samples[2])) / ITERATIONS, visits, checksum,
                });
            }
        }
    }
    try output.interface.flush();
}

fn reconstruct(comptime lookup: Lookup, comptime order: Order, store: *Store, version: *const objects.VersionRecord, output: []u8) !usize {
    std.mem.doNotOptimizeAway(store);
    const frame_count = (output.len + FRAME_BYTES - 1) / FRAME_BYTES;
    var visited: usize = 0;
    for (0..frame_count) |frame| {
        const ordered_frame = if (order == .reverse) frame_count - 1 - frame else frame;
        const offset = ordered_frame * FRAME_BYTES;
        const length = @min(FRAME_BYTES, output.len - offset);
        visited += try copyRange(lookup, store, version, offset, output[offset..][0..length]);
        if (order == .retransmit) visited += try copyRange(lookup, store, version, offset, output[offset..][0..length]);
    }
    return visited;
}

fn copyRange(comptime lookup: Lookup, store: *Store, version: *const objects.VersionRecord, offset: usize, output: []u8) !usize {
    var chunks = if (lookup == .prefix) try store.versionChunkCursor(version) else try store.versionChunkCursorAt(version, offset);
    var copied: usize = 0;
    var visited: usize = 0;
    while (try chunks.next()) |chunk| {
        visited += 1;
        const position = offset + copied;
        if (position >= chunk.offset + chunk.bytes.len) continue;
        if (position < chunk.offset) return error.CorruptBlob;
        const in_chunk = position - chunk.offset;
        const amount = @min(output.len - copied, chunk.bytes.len - in_chunk);
        @memcpy(output[copied..][0..amount], chunk.bytes[in_chunk..][0..amount]);
        copied += amount;
        if (copied == output.len) return visited;
    }
    return error.IncompleteRange;
}
