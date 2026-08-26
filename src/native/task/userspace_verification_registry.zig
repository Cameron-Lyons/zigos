const std = @import("std");
const component_abi_schema = @import("../services/component_abi_schema.zig");
const id_index = @import("../core/id_index.zig");
const native_util = @import("../core/util.zig");
const production_registry = @import("userspace_registry.zig");
const userspace_mailbox = @import("userspace_bootstrap_mailbox.zig");

pub const ImageSpec = production_registry.ImageSpec;

pub const verification_only_build_image_specs = [_]production_registry.BuildImageSpec{
    production_registry.standaloneBuildImageSpec(.{
        .bundle_id = "app.notes.daily",
        .artifact_name = "userspace-notes-daily.elf",
        .display_name = "Notes Daily",
        .publisher = "zigos.dev",
        .label = "notes-daily",
        .entry = "app.notes",
        .provided_interfaces = &.{.{ .name = "zigos.workspace.document" }},
        .consumed_interfaces = &.{component_abi_schema.interfaceDecl(.object_workspace)},
        .assets = &.{.{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" }},
        .update_channel = .stable,
        .role_tag = 0xA11D,
        .heartbeat_increment = 27,
        .contract_flags = production_registry.FLAG_OWNS_UI_SURFACE,
    }),
    production_registry.standaloneBuildImageSpec(.{
        .bundle_id = "zigos.system.transport-probe",
        .artifact_name = "userspace-transport-probe.elf",
        .display_name = "Transport Probe",
        .label = "transport-probe",
        .entry = "app.transport.probe",
        .role_tag = 0xA104,
        .heartbeat_increment = 4,
        .contract_flags = production_registry.FLAG_OWNS_UI_SURFACE,
    }),
    production_registry.standaloneBuildImageSpec(.{
        .bundle_id = "zigos.system.termination-probe",
        .artifact_name = "userspace-termination-probe.elf",
        .display_name = "Termination Probe",
        .label = "termination-probe",
        .entry = "app.termination.probe",
        .role_tag = 0xA105,
        .heartbeat_increment = 5,
        .contract_flags = production_registry.FLAG_GP_PROOF_PROBE,
    }),
    production_registry.standaloneBuildImageSpec(.{
        .bundle_id = "zigos.system.service-client",
        .artifact_name = "userspace-service-client.elf",
        .display_name = "Service Client",
        .label = "service-client",
        .entry = "app.service.client",
        .role_tag = 0xA114,
        .heartbeat_increment = 20,
        .contract_flags = production_registry.FLAG_OWNS_UI_SURFACE,
    }),
    production_registry.standaloneBuildImageSpec(.{
        .bundle_id = "zigos.proof.mmu-isolation",
        .artifact_name = "userspace-mmu-isolation-proof.elf",
        .display_name = "MMU Isolation Proof",
        .label = "mmu-isolation-proof",
        .entry = "zigos.proof.mmu-isolation",
        .role_tag = userspace_mailbox.MMU_ISOLATION_PROOF_ROLE_TAG,
        .heartbeat_increment = 22,
        .contract_flags = production_registry.FLAG_MMU_PROOF_PROBE | production_registry.FLAG_NX_PROOF_PROBE,
    }),
};

pub const verification_only_boot_image_specs = production_registry.runtimeImageSpecs(verification_only_build_image_specs);
pub const verification_boot_image_specs = production_registry.production_boot_image_specs ++ verification_only_boot_image_specs;
pub const role_boot_image_specs = verification_boot_image_specs;

comptime {
    if (verification_only_boot_image_specs.len != 5) {
        @compileError("verification-only userspace catalog must contain exactly five proof and journey images");
    }
    if (verification_boot_image_specs.len != 29) {
        @compileError("verification userspace catalog must contain 24 production and five proof or journey images");
    }
}

const BUNDLE_INDEX_CAPACITY: usize = verification_boot_image_specs.len * 2;
const bundle_index = buildBundleIndex();

pub fn findVerification(bundle_id: []const u8) ?*const ImageSpec {
    const spec_index = indexForRole(bundle_id) orelse return null;
    return &verification_boot_image_specs[spec_index];
}

pub fn indexForRole(bundle_id: []const u8) ?usize {
    const key = production_registry.bundleIndexKey(bundle_id);
    const spec_index = id_index.lookup(BUNDLE_INDEX_CAPACITY, &bundle_index, key) orelse {
        debugAssertBundleIndexMissAbsent(bundle_id);
        return null;
    };
    if (spec_index >= verification_boot_image_specs.len) {
        native_util.impossibleByInvariant("verification boot bundle id index points outside registry specs");
    }
    if (!std.mem.eql(u8, verification_boot_image_specs[spec_index].bundle_id, bundle_id)) {
        native_util.impossibleByInvariant("verification boot bundle id index points at the wrong registry spec");
    }
    return spec_index;
}

pub fn findForRole(bundle_id: []const u8) ?*const ImageSpec {
    return findVerification(bundle_id);
}

fn buildBundleIndex() id_index.Table(BUNDLE_INDEX_CAPACITY) {
    @setEvalBranchQuota(10_000);
    var index = id_index.emptyTable(BUNDLE_INDEX_CAPACITY);
    for (verification_boot_image_specs, 0..) |spec, spec_index| {
        id_index.insert(BUNDLE_INDEX_CAPACITY, &index, production_registry.bundleIndexKey(spec.bundle_id), spec_index, "verification boot bundle id index covers userspace registry");
    }
    return index;
}

fn debugAssertBundleIndexMissAbsent(bundle_id: []const u8) void {
    if (@import("builtin").mode != .Debug) return;
    for (verification_boot_image_specs) |spec| {
        if (std.mem.eql(u8, spec.bundle_id, bundle_id)) {
            native_util.impossibleByInvariant("verification boot bundle id index missed a registry spec");
        }
    }
}

test "verification userspace registry extends production with proof and journey images" {
    try std.testing.expectEqual(@as(usize, 24), production_registry.production_boot_image_specs.len);
    try std.testing.expectEqual(@as(usize, 5), verification_only_boot_image_specs.len);
    try std.testing.expectEqual(@as(usize, 29), verification_boot_image_specs.len);

    for (verification_only_boot_image_specs) |spec| {
        try std.testing.expect(production_registry.findProduction(spec.bundle_id) == null);
        const verification_spec = findVerification(spec.bundle_id) orelse return error.MissingVerificationImage;
        try std.testing.expectEqualStrings(spec.bundle_id, verification_spec.bundle_id);
    }

    for (verification_boot_image_specs, 0..) |spec, spec_index| {
        try std.testing.expectEqual(spec_index, indexForRole(spec.bundle_id).?);
    }

    for (production_registry.production_boot_image_specs) |spec| {
        const production_spec = production_registry.findProduction(spec.bundle_id) orelse return error.MissingProductionImage;
        const verification_spec = findVerification(spec.bundle_id) orelse return error.MissingVerificationImage;
        try std.testing.expectEqualStrings(spec.bundle_id, production_spec.bundle_id);
        try std.testing.expectEqualStrings(spec.bundle_id, verification_spec.bundle_id);
    }
}

test "verification registry keeps the freestanding MMU isolation proof" {
    const proof = findVerification("zigos.proof.mmu-isolation") orelse return error.MissingMmuIsolationProof;
    const build_spec = verificationOnlyBuildImage("zigos.proof.mmu-isolation") orelse return error.MissingMmuIsolationBuildSpec;

    try std.testing.expectEqual(userspace_mailbox.MMU_ISOLATION_PROOF_ROLE_TAG, proof.role_tag);
    try std.testing.expect((proof.contract_flags & production_registry.FLAG_MMU_PROOF_PROBE) != 0);
    try std.testing.expect((proof.contract_flags & production_registry.FLAG_NX_PROOF_PROBE) != 0);
    try std.testing.expectEqual(production_registry.ComponentClass.app_component, proof.component_class);
    try std.testing.expectEqualStrings("userspace-mmu-isolation-proof.elf", build_spec.artifact_name);
    try std.testing.expectEqualStrings("zigos.proof.mmu-isolation", proof.entry);
}

fn verificationOnlyBuildImage(bundle_id: []const u8) ?*const production_registry.BuildImageSpec {
    for (&verification_only_build_image_specs) |*spec| {
        if (std.mem.eql(u8, spec.image.bundle_id, bundle_id)) return spec;
    }
    return null;
}

test "verification registry keeps the ring-three exception containment proof" {
    const proof = findVerification("zigos.system.termination-probe") orelse return error.MissingTerminationProof;
    try std.testing.expect((proof.contract_flags & production_registry.FLAG_GP_PROOF_PROBE) != 0);
    try std.testing.expectEqual(production_registry.ComponentClass.app_component, proof.component_class);
}
