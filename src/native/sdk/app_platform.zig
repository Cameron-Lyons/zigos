const std = @import("std");
const example_apps = @import("example_apps.zig");
const idl = @import("idl.zig");
const manifest = @import("../policy/manifest.zig");
const package_service = @import("../services/package_service.zig");
const signing = @import("../core/signing.zig");

pub const Error = idl.Error || manifest.ValidationError || error{
    PackageMissingIdl,
    IdlInterfaceNotDeclaredInManifest,
    IdlNativeDeclarationsMissing,
};

pub const CompiledPackage = struct {
    package: example_apps.ExamplePackage,
    document: idl.Document,
    generated: idl.GeneratedSource,

    pub fn interfaceCount(self: *const CompiledPackage) usize {
        return self.document.interface_count;
    }

    pub fn operationCount(self: *const CompiledPackage) usize {
        return self.document.operation_count;
    }

    pub fn requiredPermissionCount(self: *const CompiledPackage) usize {
        return manifest.requiredPermissionCount(self.package.bundle);
    }

    pub fn generatedSlice(self: *const CompiledPackage) []const u8 {
        return self.generated.slice();
    }
};

pub fn compile(package: example_apps.ExamplePackage) Error!CompiledPackage {
    if (package.idl_source.len == 0) return error.PackageMissingIdl;
    try manifest.validate(package.bundle);
    try manifest.validateApplicationPackaging(package.bundle);

    const document = try idl.parse(package.idl_source);
    if (!document.allOperationsTyped()) return error.UntypedOperation;
    if (document.nativeDeclarationCount() == 0) return error.IdlNativeDeclarationsMissing;
    for (document.interfaces[0..document.interface_count]) |*interface| {
        if (!bundleDeclaresInterface(package.bundle, interface.manifestDecl())) {
            return error.IdlInterfaceNotDeclaredInManifest;
        }
    }

    return .{
        .package = package,
        .document = document,
        .generated = try idl.generate(&document),
    };
}

pub fn signedBundle(
    package: example_apps.ExamplePackage,
    profile: signing.SignatureProfile,
) !manifest.BundleManifest {
    var bundle = package.bundle;
    bundle.signature = try signing.signWithDefaultRegistry(
        profile,
        package.signer,
        &package_service.digestBundle(bundle),
    );
    return bundle;
}

pub const bundleDeclaresInterface = manifest.bundleDeclaresInterface;

test "app platform compiles IDL validates manifest declarations and signs packages" {
    const package = example_apps.firstPartyWriter();
    const compiled = try compile(package);
    try std.testing.expectEqual(@as(usize, 1), compiled.interfaceCount());
    try std.testing.expect(compiled.operationCount() >= 4);
    try std.testing.expect(compiled.requiredPermissionCount() >= 1);
    try std.testing.expect(std.mem.indexOf(u8, compiled.generatedSlice(), "OperationDescriptor") != null);

    const signed = try signedBundle(package, .ed25519);
    try std.testing.expect(signing.verifyWithDefaultRegistry(
        signed.signature,
        &package_service.digestBundle(signed),
    ));
}
