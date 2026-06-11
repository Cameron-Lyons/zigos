const std = @import("std");

const native_app_sdk = @import("../../native/sdk/native_app_sdk.zig");

test "SDK host tests import native developer platform modules" {
    std.testing.refAllDecls(native_app_sdk);
}

test "native SDK provides the full app developer loop" {
    const package = native_app_sdk.example_apps.firstPartyWriter();

    const compiled = try native_app_sdk.app_platform.compile(package);
    try std.testing.expect(compiled.interfaceCount() >= 1);
    try std.testing.expect(compiled.operationCount() >= 4);
    try std.testing.expect(compiled.document.allOperationsTyped());
    try std.testing.expect(compiled.document.record_count >= compiled.interfaceCount());
    try std.testing.expect(compiled.document.nativeDeclarationCount() >= 3);

    const abi_header = try native_app_sdk.component_abi.header(.package_install, .package_install, 10, 20);
    try native_app_sdk.component_abi.validateHeader(
        .package_install,
        .package_install,
        abi_header,
        @sizeOf(native_app_sdk.component_abi.PackageInstallRequest),
        @sizeOf(native_app_sdk.component_abi.PackageInstallResponse),
    );

    const lint = native_app_sdk.manifest_linter.lint(package.bundle);
    try std.testing.expect(!lint.hasErrors());
    const native_lint = native_app_sdk.manifest_linter.lintWithIdl(package.bundle, package.idl_source);
    try std.testing.expect(!native_lint.hasErrors());

    const signed = try native_app_sdk.package_signing.sign(package.bundle, .{
        .identity = package.signer,
    });
    try std.testing.expect(signed.verify());

    const review = try native_app_sdk.permissions.buildReviewPlan(501, &package.bundle, &.{});
    try std.testing.expect(review.grantSlice().len >= native_app_sdk.manifest.requiredPermissionCount(package.bundle));
    var permission_harness = native_app_sdk.permissions.Harness.init(502, &package.bundle);
    try permission_harness.deny(.clipboard);
    const permission_result = try permission_harness.run();
    try std.testing.expect(permission_result.allRequiredGranted());
    try std.testing.expect(permission_result.denied_optional_count >= 1);
    var review_ui_buffer: [native_app_sdk.ui.MAX_RENDER_BYTES]u8 = undefined;
    const rendered_review = try native_app_sdk.permissions.renderReviewUi(&review, &review_ui_buffer);
    try std.testing.expect(std.mem.indexOf(u8, rendered_review, "role=permission_row") != null);

    var sim = native_app_sdk.simulator.Simulator.init();
    _ = try sim.install(.{
        .bundle = package.bundle,
        .signer = package.signer,
        .data_schema_version = package.data_schema_version,
    });
    const launched = try sim.launchNativeApp(package.bundle.bundle_id);
    try std.testing.expect(launched.signed_provenance);

    var objects = native_app_sdk.object_store_api.Client.init(package.signer);
    const put = try objects.putDocument("writer-note.md", "text/markdown", "# Writer");
    try std.testing.expectEqualStrings("# Writer", try objects.latestPayload(put.object_id));
    const handle = try objects.putDocumentObject("writer-native-note.md", "text/markdown", "# Native Writer");
    const updated_handle = try objects.compareAndUpdate(handle, "# Native Writer\n\nUpdated");
    try std.testing.expect(updated_handle.version_id.raw() > handle.version_id.raw());

    var sync = native_app_sdk.sync_api.DevNode.init();
    const workspace = try sync.openLocalFirstWorkspace(42, &.{"documents/"});
    try sync.recordReplicaVersion(42, "documents/writer-note.md", put.object_id, put.version_id);
    try std.testing.expectEqual(@as(?u64, put.version_id.raw()), sync.replicaVersion(42, "documents/writer-note.md"));
    try sync.publishObject(workspace, "documents/writer-native-note.md", updated_handle);
    try std.testing.expectEqual(@as(?u64, updated_handle.version_id.raw()), sync.replicaVersionFor(workspace, "documents/writer-native-note.md"));

    const fixture = try native_app_sdk.fixtures.app();
    try std.testing.expect(fixture.hasExecutableSegments());
}

test "native SDK simulator harness completes the no-POSIX app loop" {
    const package = native_app_sdk.example_apps.firstPartyWriter();
    var sim = native_app_sdk.simulator.Simulator.init();
    const harness_result = try sim.runNativeAppHarness(package);
    try std.testing.expect(harness_result.completedNativeLoop());
}
