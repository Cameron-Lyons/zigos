const std = @import("std");
const example_apps = @import("../native/sdk/example_apps.zig");
const crypto_hash = @import("../native/core/crypto_hash.zig");
const hex = @import("../native/core/hex.zig");
const manifest = @import("../native/policy/manifest.zig");
const package_service = @import("../native/services/package_service.zig");
const signing = @import("../native/core/signing.zig");
const units = @import("../native/core/units.zig");

const stdout_buffer_bytes: usize = units.kibibytes(4);

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const io = init.io;
    var stdout_buffer: [stdout_buffer_bytes]u8 = undefined;
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
        const seed = try hex.decodeFixed(signing.SEED_BYTES, args[3]);
        const digest = try hex.decodeFixed(crypto_hash.digest_bytes, args[4]);
        try printSignature(&stdout_writer.interface, args[2], seed, digest, .ed25519);
    } else if (std.mem.eql(u8, args[1], "provider-policy")) {
        if (args.len != 2) return error.UnknownCommand;
        try printProviderPolicy(&stdout_writer.interface);
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
        \\  zigos-sign provider-policy
        \\
    , .{});
}

fn printSignedManifest(writer: anytype, bundle: manifest.BundleManifest, signer: signing.SignerIdentity) !void {
    const digest = package_service.digestBundle(bundle);
    const signature = try signing.signWithDefaultRegistry(.ed25519, signer, &digest);
    var digest_hex: [crypto_hash.hex_digest_bytes]u8 = undefined;
    var public_key_hex: [hex.encodedLen(manifest.MAX_SIGNATURE_PUBLIC_KEY_BYTES)]u8 = undefined;
    var signature_hex: [hex.encodedLen(manifest.MAX_SIGNATURE_VALUE_BYTES)]u8 = undefined;
    try writer.print(
        "bundle={s}\ndigest={s}\nformat={s}\nsigner={s}\npublic_key={s}\nsignature={s}\n",
        .{
            bundle.bundle_id,
            try hex.encodeLower(&digest, &digest_hex),
            signature.formatSlice(),
            signature.signer,
            try hex.encodeLower(signature.publicKeySlice(), &public_key_hex),
            try hex.encodeLower(signature.valueSlice(), &signature_hex),
        },
    );
}

fn printSignature(
    writer: anytype,
    label: []const u8,
    seed: [signing.SEED_BYTES]u8,
    digest: crypto_hash.Digest,
    profile: signing.SignatureProfile,
) !void {
    const identity = signing.SignerIdentity{
        .label = label,
        .seed = seed,
    };
    var ed25519_provider_impl = signing.SoftwareEd25519Provider{};
    var registry = signing.SignatureProviderRegistry.init();
    try registry.register(ed25519_provider_impl.provider());
    const provider = registry.find(profile) orelse return error.UnknownCommand;
    const signature = try registry.sign(profile, identity, &digest);
    var public_key_hex: [hex.encodedLen(manifest.MAX_SIGNATURE_PUBLIC_KEY_BYTES)]u8 = undefined;
    var signature_hex: [hex.encodedLen(manifest.MAX_SIGNATURE_VALUE_BYTES)]u8 = undefined;
    try writer.print(
        "provider={s}\nrole={s}\nprovider_boundary={s}\ncustody={s}\nverifier_protocol={s}\nfips_standard={s}\npost_quantum_algorithm={s}\nfips_204={s}\nfips_140_validated_module={s}\nvalidation_certificate={s}\nrelease_eligible={s}\nformat={s}\nsigner={s}\npublic_key={s}\nsignature={s}\n",
        .{
            provider.descriptor.name,
            @tagName(provider.descriptor.role),
            @tagName(provider.descriptor.provider_boundary),
            @tagName(provider.descriptor.custody),
            @tagName(provider.descriptor.verifier_protocol),
            @tagName(provider.descriptor.fips_standard),
            @tagName(provider.descriptor.post_quantum_algorithm),
            @tagName(provider.descriptor.fips_204),
            if (provider.descriptor.fips_140_validated_module) "yes" else "no",
            provider.descriptor.validation_certificate,
            if (provider.releaseEligible()) "yes" else "no",
            signature.formatSlice(),
            signature.signer,
            try hex.encodeLower(signature.publicKeySlice(), &public_key_hex),
            try hex.encodeLower(signature.valueSlice(), &signature_hex),
        },
    );
}

fn printProviderPolicy(writer: anytype) !void {
    var ed25519_provider_impl = signing.SoftwareEd25519Provider{};
    var registry = signing.SignatureProviderRegistry.init();
    try registry.register(ed25519_provider_impl.provider());

    try writer.print(
        \\standards=FIPS 203 ML-KEM key establishment; FIPS 204 ML-DSA signatures; FIPS 205 SLH-DSA hash-based signature fallback
        \\classical_baseline=ed25519 is the classical DSSE baseline; production PQC requires a separate ml-dsa-65 FIPS 204 provider
        \\default_ed25519_release_eligible={s}
        \\production_ml_dsa_profile=ml-dsa-65
        \\production_ml_dsa_required_boundary=hardware key handle through TPM, secure enclave, HSM, or KMS backed by a FIPS 140 validated module
        \\production_ml_dsa_required_metadata=FIPS 204 algorithm, ML-DSA-65 parameter set, validation certificate, rotation, revocation, DSSE verifier support
        \\release_verifier_metadata_schema=zigos.release-verifier-metadata
        \\attestation_verifier_metadata_schema=zigos.attestation-verifier-metadata
        \\
    , .{
        if ((registry.find(.ed25519) orelse unreachable).releaseEligible()) "yes" else "no",
    });
}

test "signing CLI helpers encode decode and verify manifest digests" {
    const package = example_apps.writer();
    const digest = package_service.digestBundle(package.bundle);
    const signature = try signing.signWithDefaultRegistry(.ed25519, package.signer, &digest);
    try std.testing.expect(signing.verifyWithDefaultRegistry(signature, &digest));

    var digest_hex: [crypto_hash.hex_digest_bytes]u8 = undefined;
    const encoded = try hex.encodeLower(&digest, &digest_hex);
    const decoded = try hex.decodeFixed(crypto_hash.digest_bytes, encoded);
    try std.testing.expectEqualSlices(u8, &digest, &decoded);
    try std.testing.expectError(error.InvalidHexLength, hex.decodeFixed(32, "abcd"));
}
