const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const package_service = @import("../services/package_service.zig");
const signing = @import("../core/signing.zig");

pub fn signBundle(bundle: manifest.BundleManifest) !manifest.Signature {
    return signing.signWithDefaultRegistry(
        .ed25519,
        try identityForPublisher(bundle.publisher),
        &package_service.digestBundle(bundle),
    );
}

pub fn verifyBundle(bundle: manifest.BundleManifest) bool {
    return signing.verifyWithDefaultRegistry(bundle.signature, &package_service.digestBundle(bundle));
}

pub fn identityForPublisher(publisher: []const u8) error{UnknownPublisherIdentity}!signing.SignerIdentity {
    if (std.mem.eql(u8, publisher, "zigos.system")) {
        return .{
            .label = "zigos-system-key",
            .seed = signing.seedFromByte(0x91),
        };
    }
    if (std.mem.eql(u8, publisher, "zigos.dev")) {
        return .{
            .label = "zigos-dev-key",
            .seed = signing.seedFromByte(0x92),
        };
    }
    if (std.mem.eql(u8, publisher, "zigos.spec")) {
        return .{
            .label = "zigos-spec-key",
            .seed = signing.seedFromByte(0x93),
        };
    }
    return error.UnknownPublisherIdentity;
}

test "userspace manifest signing verifies deterministic bundle signatures" {
    var bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "notes", .entry = "app.notes" },
        },
    };
    bundle.signature = try signBundle(bundle);

    try std.testing.expect(verifyBundle(bundle));
    bundle.display_name = "Tampered";
    try std.testing.expect(!verifyBundle(bundle));
}
