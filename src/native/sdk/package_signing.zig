const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const package_service = @import("../services/package_service.zig");
const signing = @import("../core/signing.zig");
const manifest_linter = @import("manifest_linter.zig");

pub const SigningFlow = struct {
    profile: signing.SignatureProfile = .ed25519,
    identity: signing.SignerIdentity,
    require_clean_lint: bool = true,
};

pub const SignedPackage = struct {
    bundle: manifest.BundleManifest,
    digest: package_service.Digest,
    lint: manifest_linter.Report,

    pub fn verify(self: *const SignedPackage) bool {
        return signing.verifyWithDefaultRegistry(self.bundle.signature, &self.digest);
    }
};

pub fn digest(bundle: manifest.BundleManifest) package_service.Digest {
    return package_service.digestBundle(bundle);
}

pub fn sign(bundle: manifest.BundleManifest, flow: SigningFlow) !SignedPackage {
    const lint_report = manifest_linter.lint(bundle);
    if (flow.require_clean_lint and lint_report.hasErrors()) {
        return error.ManifestLintFailed;
    }

    var signed_bundle = bundle;
    const package_digest = digest(signed_bundle);
    signed_bundle.signature = try signing.signWithDefaultRegistry(flow.profile, flow.identity, &package_digest);
    return .{
        .bundle = signed_bundle,
        .digest = package_digest,
        .lint = lint_report,
    };
}

pub fn verifySignedBundle(bundle: manifest.BundleManifest) bool {
    const package_digest = digest(bundle);
    return signing.verifyWithDefaultRegistry(bundle.signature, &package_digest);
}

test "package signing flow lints signs and verifies installable manifests" {
    const examples = @import("example_apps.zig");
    const package = examples.firstPartyWriter();
    const signed = try sign(package.bundle, .{
        .identity = package.signer,
    });
    try std.testing.expect(!signed.lint.hasErrors());
    try std.testing.expect(signed.bundle.signature.isComplete());
    try std.testing.expect(signed.verify());
    try std.testing.expect(verifySignedBundle(signed.bundle));
}
