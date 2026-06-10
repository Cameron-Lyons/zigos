const std = @import("std");
const example_apps = @import("../native/sdk/example_apps.zig");
const manifest = @import("../native/policy/manifest.zig");
const package_service = @import("../native/services/package_service.zig");
const signing = @import("../native/core/signing.zig");

pub const Error = error{
    UnknownCommand,
    UnknownExample,
    InvalidHex,
    InvalidHexLength,
    HexOutputTooSmall,
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const io = init.io;
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);

    if (args.len < 2) {
        try printUsage(&stdout_writer.interface);
        try stdout_writer.interface.flush();
        return;
    }

    if (std.mem.eql(u8, args[1], "sign-example")) {
        if (args.len != 3) return error.UnknownExample;
        const package = example_apps.byName(args[2]) orelse return error.UnknownExample;
        try printSignedManifest(&stdout_writer.interface, package.bundle, package.signer);
    } else if (std.mem.eql(u8, args[1], "verify-example")) {
        if (args.len != 3) return error.UnknownExample;
        const package = example_apps.byName(args[2]) orelse return error.UnknownExample;
        const digest = package_service.digestBundle(package.bundle);
        const signature = try signing.signWithDefaultRegistry(.ed25519, package.signer, &digest);
        try stdout_writer.interface.print(
            "bundle={s}\nverified={s}\n",
            .{ package.bundle.bundle_id, if (signing.verifyWithDefaultRegistry(signature, &digest)) "yes" else "no" },
        );
    } else if (std.mem.eql(u8, args[1], "sign-digest")) {
        if (args.len != 5) return error.InvalidHexLength;
        const seed = try decodeFixed(signing.SEED_BYTES, args[3]);
        const digest = try decodeFixed(32, args[4]);
        try printSignature(&stdout_writer.interface, args[2], seed, digest, .ed25519);
    } else if (std.mem.eql(u8, args[1], "sign-hybrid-digest")) {
        if (args.len != 5) return error.InvalidHexLength;
        const seed = try decodeFixed(signing.SEED_BYTES, args[3]);
        const digest = try decodeFixed(32, args[4]);
        try printSignature(&stdout_writer.interface, args[2], seed, digest, .ed25519_ml_dsa65_hybrid_preview);
    } else {
        try printUsage(&stdout_writer.interface);
        return error.UnknownCommand;
    }

    try stdout_writer.interface.flush();
}

fn printUsage(writer: anytype) !void {
    try writer.print(
        \\usage:
        \\  zigos-sign sign-example writer|viewer|zigos-writer|zigos-workbench|zigos-studio
        \\  zigos-sign verify-example writer|viewer|zigos-writer|zigos-workbench|zigos-studio
        \\  zigos-sign sign-digest <label> <seed-hex-64> <digest-hex-64>
        \\  zigos-sign sign-hybrid-digest <label> <seed-hex-64> <digest-hex-64>
        \\
    , .{});
}

fn printSignedManifest(writer: anytype, bundle: manifest.BundleManifest, signer: signing.SignerIdentity) !void {
    const digest = package_service.digestBundle(bundle);
    const signature = try signing.signWithDefaultRegistry(.ed25519, signer, &digest);
    var digest_hex: [32 * 2]u8 = undefined;
    var public_key_hex: [manifest.MAX_SIGNATURE_PUBLIC_KEY_BYTES * 2]u8 = undefined;
    var signature_hex: [manifest.MAX_SIGNATURE_VALUE_BYTES * 2]u8 = undefined;
    try writer.print(
        "bundle={s}\ndigest={s}\nformat={s}\nsigner={s}\npublic_key={s}\nsignature={s}\n",
        .{
            bundle.bundle_id,
            try encodeHex(&digest, &digest_hex),
            signature.format,
            signature.signer,
            try encodeHex(signature.publicKeySlice(), &public_key_hex),
            try encodeHex(signature.valueSlice(), &signature_hex),
        },
    );
}

fn printSignature(
    writer: anytype,
    label: []const u8,
    seed: [signing.SEED_BYTES]u8,
    digest: [32]u8,
    profile: signing.SignatureProfile,
) !void {
    const identity = signing.SignerIdentity{
        .label = label,
        .seed = seed,
    };
    var ed25519_provider_impl = signing.SoftwareEd25519Provider{};
    var hybrid_provider_impl = signing.HybridPreviewProvider{};
    var registry = signing.SignatureProviderRegistry.init();
    try registry.register(ed25519_provider_impl.provider());
    try registry.register(hybrid_provider_impl.provider());
    const provider = registry.find(profile) orelse return error.UnknownCommand;
    const signature = try registry.sign(profile, identity, &digest);
    var public_key_hex: [manifest.MAX_SIGNATURE_PUBLIC_KEY_BYTES * 2]u8 = undefined;
    var signature_hex: [manifest.MAX_SIGNATURE_VALUE_BYTES * 2]u8 = undefined;
    try writer.print(
        "provider={s}\nrole={s}\nprovider_boundary={s}\ncustody={s}\nverifier_protocol={s}\nfips_204={s}\nrelease_eligible={s}\nformat={s}\nsigner={s}\npublic_key={s}\nsignature={s}\n",
        .{
            provider.descriptor.name,
            @tagName(provider.descriptor.role),
            @tagName(provider.descriptor.provider_boundary),
            @tagName(provider.descriptor.custody),
            @tagName(provider.descriptor.verifier_protocol),
            @tagName(provider.descriptor.fips_204),
            if (provider.releaseEligible()) "yes" else "no",
            signature.format,
            signature.signer,
            try encodeHex(signature.publicKeySlice(), &public_key_hex),
            try encodeHex(signature.valueSlice(), &signature_hex),
        },
    );
}

pub fn encodeHex(bytes: []const u8, output: []u8) Error![]const u8 {
    if (output.len < bytes.len * 2) return error.HexOutputTooSmall;
    const digits = "0123456789abcdef";
    var cursor: usize = 0;
    for (bytes) |byte| {
        output[cursor] = digits[byte >> 4];
        output[cursor + 1] = digits[byte & 0x0f];
        cursor += 2;
    }
    return output[0..cursor];
}

pub fn decodeFixed(comptime len: usize, text: []const u8) Error![len]u8 {
    if (text.len != len * 2) return error.InvalidHexLength;
    var result: [len]u8 = undefined;
    var index: usize = 0;
    while (index < len) : (index += 1) {
        const high = try hexValue(text[index * 2]);
        const low = try hexValue(text[index * 2 + 1]);
        result[index] = (high << 4) | low;
    }
    return result;
}

fn hexValue(byte: u8) Error!u8 {
    if (byte >= '0' and byte <= '9') return byte - '0';
    if (byte >= 'a' and byte <= 'f') return 10 + byte - 'a';
    if (byte >= 'A' and byte <= 'F') return 10 + byte - 'A';
    return error.InvalidHex;
}

test "signing CLI helpers encode decode and verify manifest digests" {
    const package = example_apps.writer();
    const digest = package_service.digestBundle(package.bundle);
    const signature = try signing.signWithDefaultRegistry(.ed25519, package.signer, &digest);
    try std.testing.expect(signing.verifyWithDefaultRegistry(signature, &digest));

    const hybrid_signature = try signing.signWithDefaultRegistry(.ed25519_ml_dsa65_hybrid_preview, package.signer, &digest);
    try std.testing.expect(signing.verifyWithDefaultRegistry(hybrid_signature, &digest));
    try std.testing.expect(hybrid_signature.usesHybridPostQuantumProfile());

    var digest_hex: [64]u8 = undefined;
    const encoded = try encodeHex(&digest, &digest_hex);
    const decoded = try decodeFixed(32, encoded);
    try std.testing.expectEqualSlices(u8, &digest, &decoded);
    try std.testing.expectError(error.InvalidHexLength, decodeFixed(32, "abcd"));
}
