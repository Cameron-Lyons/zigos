const std = @import("std");
const module = @import("object_chunks");
const objects = module.objects;
const FRAME_BYTES = module.MAX_TRANSFER_CHUNK;
const ITERATIONS = 1_000;
const Lookup = enum { prefix, positioned };
const Order = enum { forward, reverse, retransmit };
const PAYLOAD_LENGTHS = [_]usize{ objects.MAX_CHUNK_BYTES + 17, objects.MAX_CHUNK_BYTES * 14 + 17, objects.MAX_PAYLOAD_BYTES };
const HashOperation = enum { payload_address, merkle_root };
const HashStrategy = enum { previous, current };
const HashSamples = [5]u64;
const HASH_PAYLOAD_LENGTHS = [_]usize{ 0, 1, 63, objects.MAX_CHUNK_BYTES, objects.MAX_CHUNK_BYTES + 1, objects.MAX_CHUNK_BYTES * 3 - 7, objects.MAX_CHUNK_BYTES * 14 + 17, objects.MAX_PAYLOAD_BYTES };
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
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const hashes_only = args.len == 2 and std.mem.eql(u8, args[1], "--hashes-only");
    if (args.len > 2 or (args.len == 2 and !hashes_only)) return error.InvalidArguments;
    var bytes: [objects.MAX_PAYLOAD_BYTES]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(i * 19 + i / objects.MAX_CHUNK_BYTES);
    var reconstructed: [objects.MAX_PAYLOAD_BYTES]u8 = undefined;
    var output_buffer: [4_096]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try benchmarkHashPreparation(init.io, &output.interface, &bytes);
    if (hashes_only) {
        try output.interface.flush();
        return;
    }
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

fn benchmarkHashPreparation(io: std.Io, output: *std.Io.Writer, payload: []const u8) !void {
    try output.print("Object hash preparation ({s}, {s}): frozen cleared scratch vs current public API, same build; complete hash work included\n", .{
        @tagName(@import("builtin").target.cpu.arch), @import("builtin").target.cpu.model.name,
    });
    try output.flush();
    for (HASH_PAYLOAD_LENGTHS) |payload_len| {
        var refs: [objects.MAX_BLOB_CHUNKS]objects.ChunkRef = undefined;
        const count = objects.chunkCountForPayloadLen(payload_len);
        for (refs[0..count], 0..) |*ref, index| {
            const start = index * objects.MAX_CHUNK_BYTES;
            const chunk = payload[start..@min(payload_len, start + objects.MAX_CHUNK_BYTES)];
            ref.* = .{ .address = objects.computeChunkAddress(chunk), .payload_len = @intCast(chunk.len) };
        }
        inline for (comptime std.meta.tags(HashOperation)) |operation| {
            const iterations: usize = if (operation == .merkle_root) 10_000 else if (payload_len <= objects.MAX_CHUNK_BYTES) 30_000 else 5_000;
            const expected = hashIteration(operation, .previous, payload[0..payload_len], refs[0..count]);
            if (!std.mem.eql(u8, &expected, &hashIteration(operation, .current, payload[0..payload_len], refs[0..count]))) return error.HashMismatch;
            var previous: HashSamples = undefined;
            var current: HashSamples = undefined;
            var checksum: u64 = 0;
            for (0..previous.len) |sample| {
                const previous_first = sample % 2 == 0;
                const first = if (previous_first)
                    measureHash(operation, .previous, io, payload[0..payload_len], refs[0..count], iterations)
                else
                    measureHash(operation, .current, io, payload[0..payload_len], refs[0..count], iterations);
                const second = if (previous_first)
                    measureHash(operation, .current, io, payload[0..payload_len], refs[0..count], iterations)
                else
                    measureHash(operation, .previous, io, payload[0..payload_len], refs[0..count], iterations);
                if (first.checksum != second.checksum) return error.HashChecksumMismatch;
                previous[sample] = if (previous_first) first.nanoseconds else second.nanoseconds;
                current[sample] = if (previous_first) second.nanoseconds else first.nanoseconds;
                checksum +%= first.checksum;
            }
            std.mem.sort(u64, &previous, {}, std.sort.asc(u64));
            std.mem.sort(u64, &current, {}, std.sort.asc(u64));
            try output.print("{d} bytes / {d} refs, {s}: previous={d:.2} ns current={d:.2} ns (median of 5 x {d}), checksum={d}\n", .{
                payload_len,                                                                               count,                                                                                   @tagName(operation),
                @as(f64, @floatFromInt(previous[previous.len / 2])) / @as(f64, @floatFromInt(iterations)), @as(f64, @floatFromInt(current[current.len / 2])) / @as(f64, @floatFromInt(iterations)), iterations,
                checksum,
            });
        }
    }
}

fn measureHash(comptime operation: HashOperation, comptime strategy: HashStrategy, io: std.Io, payload: []const u8, refs: []const objects.ChunkRef, iterations: usize) struct { nanoseconds: u64, checksum: u64 } {
    var checksum: u64 = 0;
    for (0..32) |_| checksum +%= std.mem.readInt(u64, hashIteration(operation, strategy, payload, refs)[0..8], .little);
    const start = std.Io.Clock.awake.now(io);
    for (0..iterations) |_| checksum +%= std.mem.readInt(u64, hashIteration(operation, strategy, payload, refs)[0..8], .little);
    return .{
        .nanoseconds = @intCast(start.durationTo(std.Io.Clock.awake.now(io)).toNanoseconds()),
        .checksum = checksum,
    };
}

noinline fn hashIteration(comptime operation: HashOperation, comptime strategy: HashStrategy, payload: []const u8, refs: []const objects.ChunkRef) objects.BlobAddress {
    std.mem.doNotOptimizeAway(payload);
    std.mem.doNotOptimizeAway(refs);
    return switch (operation) {
        .payload_address => if (strategy == .previous) previousBlobAddress(payload) else objects.computeBlobAddress(payload),
        .merkle_root => if (strategy == .previous) previousMerkleRoot(refs) else objects.computeBlobMerkleRoot(refs),
    };
}

// Frozen previous hash preparation. Both sides retain the same SHA-256 tags,
// tree ordering, odd-leaf duplication, and canonical crypto hash primitives.
fn previousBlobAddress(payload: []const u8) objects.BlobAddress {
    if (payload.len > objects.MAX_PAYLOAD_BYTES) return module.crypto_hash.zero_digest;
    var refs = @as([objects.MAX_BLOB_CHUNKS]objects.ChunkRef, @splat(objects.ChunkRef{}));
    const count = objects.chunkCountForPayloadLen(payload.len);
    for (refs[0..count], 0..) |*ref, index| {
        const start = index * objects.MAX_CHUNK_BYTES;
        const chunk = payload[start..@min(start + objects.MAX_CHUNK_BYTES, payload.len)];
        ref.* = .{ .address = objects.computeChunkAddress(chunk), .payload_len = @intCast(chunk.len) };
    }
    const root = previousMerkleRoot(refs[0..count]);
    var hasher = module.crypto_hash.init();
    module.crypto_hash.updateInt(&hasher, "payload-len", payload.len);
    module.crypto_hash.updateInt(&hasher, "chunk-count", count);
    module.crypto_hash.updateBytes(&hasher, "chunk-merkle-root", &root);
    return module.crypto_hash.finalize(&hasher);
}

fn previousMerkleRoot(refs: []const objects.ChunkRef) objects.BlobAddress {
    if (refs.len == 0) {
        var hasher = module.crypto_hash.init();
        module.crypto_hash.updateBytes(&hasher, "blob-merkle-empty", "");
        return module.crypto_hash.finalize(&hasher);
    }
    var level = @as([objects.MAX_BLOB_CHUNKS]objects.BlobAddress, @splat(module.crypto_hash.zero_digest));
    var count = refs.len;
    for (refs, 0..) |ref, index| {
        var hasher = module.crypto_hash.init();
        module.crypto_hash.updateBytes(&hasher, "blob-merkle-leaf", &ref.address);
        module.crypto_hash.updateInt(&hasher, "chunk-len", ref.payload_len);
        level[index] = module.crypto_hash.finalize(&hasher);
    }
    while (count > 1) {
        var next_count: usize = 0;
        var index: usize = 0;
        while (index < count) : (index += 2) {
            const left = level[index];
            const right = if (index + 1 < count) level[index + 1] else left;
            var hasher = module.crypto_hash.init();
            module.crypto_hash.updateBytes(&hasher, "blob-merkle-left", &left);
            module.crypto_hash.updateBytes(&hasher, "blob-merkle-right", &right);
            level[next_count] = module.crypto_hash.finalize(&hasher);
            next_count += 1;
        }
        count = next_count;
    }
    return level[0];
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
