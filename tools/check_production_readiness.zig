const std = @import("std");
const common = @import("check_common.zig");

const COVERAGE_MANIFEST_PATH = "spec/coverage.json";
const PROD_READINESS_MANIFEST_PATH = "spec/production_readiness.json";

const STATUS_LABELS = [_][]const u8{ "prod_ready", "prod_candidate", "prototype", "blocked" };
const PRIORITIES = [_][]const u8{ "P0", "P1", "P2" };
const SECURE_BY_DESIGN_CONTROL_STATUSES = [_][]const u8{ "satisfied", "partial", "blocked" };
const SECURE_BY_DESIGN_REQUIRED_CONTROLS = [_][]const u8{
    "fuzzing",
    "fault-injection",
    "reproducible-builds",
    "sbom-provenance",
    "threat-model-tests",
    "memory-safety-audits",
    "crash-dump-redaction",
    "vulnerability-disclosure",
};
const FIRST_HARDWARE_TARGET_ID = "intel-nuc11tnki5";
const FIRST_HARDWARE_TARGET_STATUSES = [_][]const u8{ "selected", "hardware_required", "hardware_passed" };
const FIRST_HARDWARE_TARGET_STRING_FIELDS = [_][]const u8{
    "id",
    "vendor",
    "product",
    "sku",
    "status",
    "selection_reason",
    "boot_medium",
    "serial_capture",
};
const FIRST_HARDWARE_TARGET_REQUIRED_SUBSYSTEMS = [_][]const u8{
    "uefi_boot",
    "acpi_tables",
    "apic_timer",
    "framebuffer_gop",
    "usb_input_xhci",
    "nvme_block",
    "network_i225_lm",
    "compositor_framebuffer",
    "suspend_resume",
    "crash_recovery",
    "crash_persistence",
    "update_rollback_power_cycle",
};
const FIRST_HARDWARE_TARGET_REQUIRED_MARKERS = [_][]const u8{
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:UEFI_BOOT:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_TABLES:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:APIC_TIMER:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:FRAMEBUFFER_GOP:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:USB_INPUT_XHCI:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:NVME_BLOCK:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:NETWORK_I225_LM:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:SUSPEND_RESUME:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:CRASH_RECOVERY:PASS",
};
const FIRST_HARDWARE_TARGET_REQUIRED_FACT_MARKERS = [_][]const u8{
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:SMBIOS_SKU:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:MULTIBOOT_MEMORY_MAP:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_RSDP:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_MADT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_FADT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:APIC_TIMER_INTERRUPT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:FRAMEBUFFER_GOP_SCANOUT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:XHCI_BOOT_KEYBOARD_REPORT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:NVME_WRITE_READ_COMPLETION:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:I225_LM_FRAME_INTERRUPT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:SUSPEND_RESUME_POWER:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:CRASH_RECORD_REBOOT_PERSISTENCE:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:UPDATE_ROLLBACK_POWER_CYCLE:OBSERVED",
};
const FIRST_HARDWARE_TARGET_REQUIRED_BOOTED_PROOF_MARKERS = [_][]const u8{
    "ZIGOS:USERSPACE:ARTIFACTS:READY",
    "ZIGOS:USERSPACE:SCHEDULER:READY",
    "ZIGOS:USERSPACE:EXEC_PROBE:OK",
    "ZIGOS:USERSPACE:RESUME:OK",
    "ZIGOS:SERVICE_BOOT:SERVICE_CONTRACTS:READY",
    "ZIGOS:SERVICE_BOOT:IPC_CONNECT:ALL_OK",
    "ZIGOS:SERVICE_BOOT:DRIVER:STORAGE_REBIND_OK",
    "ZIGOS:SERVICE_BOOT:DRIVER:BROKER_REVOKE_REJECTED",
    "ZIGOS:SERVICE_BOOT:DRIVER:STORAGE_REPUBLISH_AFTER_REVOKE_OK",
    "ZIGOS:COMPOSITOR:SERVICE:READY",
    "ZIGOS:COMPOSITOR:FRAMEBUFFER:PRESENTED",
    "ZIGOS:COMPOSITOR:PERMISSION_REVIEW:RENDERED",
    "ZIGOS:PERMISSION:REVIEW_PORT:READY",
    "ZIGOS:PERMISSION:POLICY_PORT:READY",
    "ZIGOS:PERMISSION:UI:REVIEW_RENDERED",
    "ZIGOS:PERMISSION:XHCI_KEYBOARD:REPORT",
    "ZIGOS:PERMISSION:XHCI_KEYBOARD:REVIEW_COMMAND",
    "ZIGOS:PERMISSION:XHCI_KEYBOARD:BOOT_FLOW_COMMANDS",
    "ZIGOS:PERMISSION:LEASE:EXPIRED",
    "ZIGOS:SYNC:DEVICE_GRAPH:ROOTED",
    "ZIGOS:SYNC:SYNC:DEVICE_TO_DEVICE",
    "ZIGOS:SYNC:SYNC:RELAY",
    "ZIGOS:SYNC:SYNC_SERVICE:RECOVERED",
    "ZIGOS:PLATFORM:ACTIVATION:ROLLBACK_OK",
    "ZIGOS:PLATFORM:BASE_SELECTOR:ROLLBACK_BEFORE_SERVICE",
    "ZIGOS:PLATFORM:HEALTH_CHECKS:STORAGE_ROLLBACK",
    "ZIGOS:PLATFORM:CRASH_RECORD:PERSISTED",
    "ZIGOS:PLATFORM:UPDATE_ROLLBACK:POWER_CYCLE_OK",
};
const FIRST_HARDWARE_TARGET_REQUIRED_REFERENCE_ARTIFACTS = [_][]const u8{
    "src/native/platform/hardware_target.zig",
    "spec/hardware/nuc11tnki5-required-markers.txt",
    "spec/hardware/nuc11tnki5-proof-bundle.md",
    "scripts/prepare-nuc11tnki5-hardware-proof.sh",
    "scripts/check-nuc11tnki5-hardware-proof.sh",
    "scripts/test-nuc11tnki5-hardware-proof-checker.sh",
};
const FIRST_HARDWARE_TARGET_LIST_FIELDS = [_][]const u8{
    "required_subsystems",
    "reference_artifacts",
    "qemu_preflight_commands",
    "proof_bundle_requirements",
    "hardware_exit_criteria",
};
const SECURE_BY_DESIGN_CONTROL_LIST_FIELDS = [_][]const u8{
    "scope",
    "current_evidence",
    "graduation_criteria",
    "verification_commands",
    "cisa_alignment",
};
const LIST_FIELDS = [_][]const u8{
    "requirements",
    "implementation_anchors",
    "current_evidence",
    "production_gaps",
    "graduation_criteria",
    "next_actions",
    "verification_commands",
};
const OPTIONAL_LIST_FIELDS = [_][]const u8{"capacity_envelope"};
const MODEL_ONLY_SYNTHETIC_IMAGE_MARKER = "prod-readiness: model-only synthetic-userspace-image";
const CRITICAL_SYNTHETIC_IMAGE_PATHS = [_][]const u8{
    "src/native/kernel_api/component_port.zig",
    "src/native/kernel_api/native_kernel.zig",
    "src/native/kernel_api/syscall_surface.zig",
    "src/native/services/userspace_service_ipc.zig",
    "src/native/session/service_path_proofs.zig",
    "src/native/storage/storage_service_ipc.zig",
    "src/native/sync/sync_service_test.zig",
    "src/native/task/process_isolation.zig",
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var errors = std.ArrayList([]const u8).empty;
    try runSelfTests(allocator, io, &errors);

    const prod_source = try common.readFileAlloc(allocator, io, PROD_READINESS_MANIFEST_PATH, common.production_readiness_manifest_max_bytes);
    var parsed_prod = try std.json.parseFromSlice(std.json.Value, allocator, prod_source, .{});
    defer parsed_prod.deinit();

    const coverage_source = try common.readFileAlloc(allocator, io, COVERAGE_MANIFEST_PATH, common.coverage_manifest_max_bytes);
    var parsed_coverage = try std.json.parseFromSlice(std.json.Value, allocator, coverage_source, .{});
    defer parsed_coverage.deinit();

    try validateSecureByDesignReleaseGate(allocator, io, &errors, parsed_prod.value);
    try validateFirstHardwareTarget(allocator, io, &errors, parsed_prod.value);
    try validateProdReadinessManifest(allocator, io, &errors, parsed_prod.value, parsed_coverage.value);
    try validateSyntheticUserspaceImageMarkers(allocator, io, &errors);

    if (errors.items.len > 0) {
        common.printErrors(errors.items);
        std.process.exit(1);
    }

    const tracks = common.field(parsed_prod.value, "tracks").?.array.items;
    var requirement_refs: usize = 0;
    for (tracks) |track| {
        if (common.field(track, "requirements")) |requirements| {
            if (requirements == .array) requirement_refs += requirements.array.items.len;
        }
    }
    try common.printStdout(
        io,
        "Production readiness OK: {d} tracks, {d} requirement references\n",
        .{ tracks.len, requirement_refs },
    );
}

fn validateSecureByDesignReleaseGate(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    prod_manifest: std.json.Value,
) !void {
    const gate = common.field(prod_manifest, "secure_by_design_release_gate") orelse {
        try common.addError(errors, allocator, "production_readiness.json must include secure_by_design_release_gate", .{});
        return;
    };
    if (gate != .object) {
        try common.addError(errors, allocator, "secure_by_design_release_gate must be an object", .{});
        return;
    }

    const release_status = try common.expectStringField(
        allocator,
        errors,
        gate,
        "secure_by_design_release_gate",
        "release_status",
    ) orelse "";
    if (release_status.len > 0 and !isOneOf(release_status, &.{ "blocked", "ready" })) {
        try common.addError(errors, allocator, "secure_by_design_release_gate release_status must be one of [blocked, ready]", .{});
    }

    const external_bar = try common.expectObjectField(
        allocator,
        errors,
        gate,
        "secure_by_design_release_gate",
        "external_bar",
    ) orelse return;
    const external_bar_url = try common.expectStringField(
        allocator,
        errors,
        external_bar,
        "secure_by_design_release_gate external_bar",
        "url",
    ) orelse "";
    if (external_bar_url.len > 0 and std.mem.indexOf(u8, external_bar_url, "cisa.gov") == null) {
        try common.addError(errors, allocator, "secure_by_design_release_gate external_bar url must point at cisa.gov guidance", .{});
    }
    _ = try common.expectStringField(
        allocator,
        errors,
        external_bar,
        "secure_by_design_release_gate external_bar",
        "name",
    );
    _ = try common.expectStringField(
        allocator,
        errors,
        external_bar,
        "secure_by_design_release_gate external_bar",
        "last_reviewed",
    );

    const policy_artifacts = try common.collectStringArray(
        allocator,
        errors,
        common.field(gate, "policy_artifacts"),
        "secure_by_design_release_gate policy_artifacts",
        true,
    );
    for (policy_artifacts) |artifact| {
        if (!common.pathExists(io, artifact)) {
            try common.addError(errors, allocator, "secure_by_design_release_gate references missing policy artifact: {s}", .{artifact});
        }
    }

    const controls_value = common.field(gate, "controls") orelse {
        try common.addError(errors, allocator, "secure_by_design_release_gate controls must be an array", .{});
        return;
    };
    const controls = switch (controls_value) {
        .array => |array| array.items,
        else => {
            try common.addError(errors, allocator, "secure_by_design_release_gate controls must be an array", .{});
            return;
        },
    };

    var seen_controls = std.StringHashMap(void).init(allocator);
    var satisfied_controls: usize = 0;
    for (controls, 0..) |control, index| {
        const status = try validateSecureByDesignControl(
            allocator,
            io,
            errors,
            control,
            index,
            &seen_controls,
        );
        if (status != null and std.mem.eql(u8, status.?, "satisfied")) {
            satisfied_controls += 1;
        }
    }

    var missing_required_control = false;
    for (SECURE_BY_DESIGN_REQUIRED_CONTROLS) |required_control| {
        if (!seen_controls.contains(required_control)) {
            missing_required_control = true;
            try common.addError(errors, allocator, "secure_by_design_release_gate missing required secure-by-design control: {s}", .{required_control});
        }
    }

    const hardware_gate_blocked = firstHardwareTargetBlocksRelease(prod_manifest);
    if (!missing_required_control and std.mem.eql(u8, release_status, "ready") and satisfied_controls != controls.len) {
        try common.addError(errors, allocator, "secure_by_design_release_gate cannot be ready until every control status is satisfied", .{});
    }
    if (!missing_required_control and std.mem.eql(u8, release_status, "ready") and hardware_gate_blocked) {
        try common.addError(errors, allocator, "secure_by_design_release_gate cannot be ready until first_hardware_target status is hardware_passed", .{});
    }
    if (!missing_required_control and std.mem.eql(u8, release_status, "blocked") and controls.len > 0 and satisfied_controls == controls.len and !hardware_gate_blocked) {
        try common.addError(errors, allocator, "secure_by_design_release_gate is blocked but every control is satisfied", .{});
    }
}

fn firstHardwareTargetBlocksRelease(prod_manifest: std.json.Value) bool {
    const target = common.field(prod_manifest, "first_hardware_target") orelse return true;
    if (target != .object) return true;
    const status = common.field(target, "status") orelse return true;
    if (status != .string) return true;
    return !std.mem.eql(u8, status.string, "hardware_passed");
}

fn validateSecureByDesignControl(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    control: std.json.Value,
    index: usize,
    seen_controls: *std.StringHashMap(void),
) !?[]const u8 {
    if (control != .object) {
        try common.addError(errors, allocator, "secure_by_design_release_gate control at index {d} must be an object", .{index});
        return null;
    }

    const fallback_control_id = try std.fmt.allocPrint(allocator, "<control-{d}>", .{index});
    const control_id = try common.expectStringField(
        allocator,
        errors,
        control,
        "secure_by_design_release_gate control",
        "id",
    ) orelse fallback_control_id;
    if (!std.mem.eql(u8, control_id, fallback_control_id)) {
        const gop = try seen_controls.getOrPut(control_id);
        if (gop.found_existing) {
            try common.addError(errors, allocator, "Duplicate secure-by-design control id: {s}", .{control_id});
        }
    }

    const status = try common.expectStringField(
        allocator,
        errors,
        control,
        try std.fmt.allocPrint(allocator, "secure_by_design_release_gate control {s}", .{control_id}),
        "status",
    );
    if (status != null and !isOneOf(status.?, &SECURE_BY_DESIGN_CONTROL_STATUSES)) {
        try common.addError(errors, allocator, "secure_by_design_release_gate control {s} status must be one of [satisfied, partial, blocked]", .{control_id});
    }

    const release_blocking = try expectBoolField(
        allocator,
        errors,
        control,
        try std.fmt.allocPrint(allocator, "secure_by_design_release_gate control {s}", .{control_id}),
        "release_blocking",
    );
    if (release_blocking != null and !release_blocking.?) {
        try common.addError(errors, allocator, "secure_by_design_release_gate control {s} must be release_blocking", .{control_id});
    }

    for (SECURE_BY_DESIGN_CONTROL_LIST_FIELDS) |field_name| {
        _ = try common.collectStringArray(
            allocator,
            errors,
            common.field(control, field_name),
            try std.fmt.allocPrint(allocator, "secure_by_design_release_gate control {s} {s}", .{ control_id, field_name }),
            true,
        );
    }

    const open_gaps = try common.collectStringArray(
        allocator,
        errors,
        common.field(control, "open_gaps"),
        try std.fmt.allocPrint(allocator, "secure_by_design_release_gate control {s} open_gaps", .{control_id}),
        false,
    );
    if (status != null and std.mem.eql(u8, status.?, "satisfied") and open_gaps.len > 0) {
        try common.addError(errors, allocator, "secure_by_design_release_gate control {s} is satisfied but still lists open_gaps", .{control_id});
    }
    if (status != null and !std.mem.eql(u8, status.?, "satisfied") and open_gaps.len == 0) {
        try common.addError(errors, allocator, "secure_by_design_release_gate control {s} is not satisfied and must list open_gaps", .{control_id});
    }

    const anchors = try common.collectStringArray(
        allocator,
        errors,
        common.field(control, "implementation_anchors"),
        try std.fmt.allocPrint(allocator, "secure_by_design_release_gate control {s} implementation_anchors", .{control_id}),
        true,
    );
    for (anchors) |anchor| {
        if (!common.pathExists(io, anchor)) {
            try common.addError(
                errors,
                allocator,
                "secure_by_design_release_gate control {s} references missing implementation anchor: {s}",
                .{ control_id, anchor },
            );
        }
    }

    return status;
}

fn expectBoolField(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    object: std.json.Value,
    context: []const u8,
    name: []const u8,
) !?bool {
    const value = common.field(object, name) orelse {
        try common.addError(errors, allocator, "{s} must include {s}", .{ context, name });
        return null;
    };
    return switch (value) {
        .bool => |flag| flag,
        else => {
            try common.addError(errors, allocator, "{s} {s} must be a bool", .{ context, name });
            return null;
        },
    };
}

fn validateFirstHardwareTarget(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    prod_manifest: std.json.Value,
) !void {
    const target = common.field(prod_manifest, "first_hardware_target") orelse {
        try common.addError(errors, allocator, "production_readiness.json must include first_hardware_target", .{});
        return;
    };
    if (target != .object) {
        try common.addError(errors, allocator, "first_hardware_target must be an object", .{});
        return;
    }

    for (FIRST_HARDWARE_TARGET_STRING_FIELDS) |field_name| {
        _ = try common.expectStringField(
            allocator,
            errors,
            target,
            "first_hardware_target",
            field_name,
        );
    }

    const target_id = try common.expectStringField(
        allocator,
        errors,
        target,
        "first_hardware_target",
        "id",
    ) orelse "";
    if (target_id.len > 0 and !std.mem.eql(u8, target_id, FIRST_HARDWARE_TARGET_ID)) {
        try common.addError(errors, allocator, "first_hardware_target id must be {s}", .{FIRST_HARDWARE_TARGET_ID});
    }

    const status = try common.expectStringField(
        allocator,
        errors,
        target,
        "first_hardware_target",
        "status",
    ) orelse "";
    if (status.len > 0 and !isOneOf(status, &FIRST_HARDWARE_TARGET_STATUSES)) {
        try common.addError(errors, allocator, "first_hardware_target status must be one of [selected, hardware_required, hardware_passed]", .{});
    }

    for (FIRST_HARDWARE_TARGET_LIST_FIELDS) |field_name| {
        _ = try common.collectStringArray(
            allocator,
            errors,
            common.field(target, field_name),
            try std.fmt.allocPrint(allocator, "first_hardware_target {s}", .{field_name}),
            true,
        );
    }

    const required_subsystems = try common.collectStringArray(
        allocator,
        errors,
        common.field(target, "required_subsystems"),
        "first_hardware_target required_subsystems",
        true,
    );
    var subsystem_set = try common.collectUniqueStrings(allocator, errors, required_subsystems, "first hardware target subsystem");
    for (FIRST_HARDWARE_TARGET_REQUIRED_SUBSYSTEMS) |required_subsystem| {
        if (!subsystem_set.contains(required_subsystem)) {
            try common.addError(errors, allocator, "first_hardware_target missing required subsystem: {s}", .{required_subsystem});
        }
    }
    if (subsystem_set.count() > FIRST_HARDWARE_TARGET_REQUIRED_SUBSYSTEMS.len) {
        for (required_subsystems) |subsystem| {
            if (!isOneOf(subsystem, &FIRST_HARDWARE_TARGET_REQUIRED_SUBSYSTEMS)) {
                try common.addError(errors, allocator, "first_hardware_target lists unsupported subsystem: {s}", .{subsystem});
            }
        }
    }

    const reference_artifacts = try common.collectStringArray(
        allocator,
        errors,
        common.field(target, "reference_artifacts"),
        "first_hardware_target reference_artifacts",
        true,
    );
    var reference_artifact_set = try common.collectUniqueStrings(allocator, errors, reference_artifacts, "first hardware target reference artifact");
    for (FIRST_HARDWARE_TARGET_REQUIRED_REFERENCE_ARTIFACTS) |required_artifact| {
        if (!reference_artifact_set.contains(required_artifact)) {
            try common.addError(errors, allocator, "first_hardware_target missing required reference artifact: {s}", .{required_artifact});
        }
    }
    for (reference_artifacts) |artifact| {
        if (!common.pathExists(io, artifact)) {
            try common.addError(errors, allocator, "first_hardware_target references missing artifact: {s}", .{artifact});
        }
    }
    try validateNuc11tnki5MarkerFile(allocator, io, errors);
    try validateNuc11tnki5ProofPreparation(allocator, io, errors);
    try validateNuc11tnki5ProofChecker(allocator, io, errors);
    try validateNuc11tnki5KernelProofSources(allocator, io, errors);

    const current_hardware_evidence = try common.collectStringArray(
        allocator,
        errors,
        common.field(target, "current_hardware_evidence"),
        "first_hardware_target current_hardware_evidence",
        false,
    );
    const open_gaps = try common.collectStringArray(
        allocator,
        errors,
        common.field(target, "open_gaps"),
        "first_hardware_target open_gaps",
        false,
    );
    if (std.mem.eql(u8, status, "hardware_passed") and current_hardware_evidence.len == 0) {
        try common.addError(errors, allocator, "first_hardware_target cannot be hardware_passed without current_hardware_evidence", .{});
    }
    if (std.mem.eql(u8, status, "hardware_passed")) {
        for (current_hardware_evidence) |artifact| {
            if (!common.pathExists(io, artifact)) {
                try common.addError(errors, allocator, "first_hardware_target references missing hardware evidence artifact: {s}", .{artifact});
            }
        }
    }
    if (std.mem.eql(u8, status, "hardware_passed") and open_gaps.len > 0) {
        try common.addError(errors, allocator, "first_hardware_target is hardware_passed but still lists open_gaps", .{});
    }
    if (!std.mem.eql(u8, status, "hardware_passed") and open_gaps.len == 0) {
        try common.addError(errors, allocator, "first_hardware_target must list open_gaps until hardware_passed", .{});
    }
}

fn validateNuc11tnki5KernelProofSources(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const hardware_proof_path = "src/kernel/platform/hardware_proof.zig";
    const apic_path = "src/kernel/platform/apic.zig";
    const crash_record_path = "src/kernel/platform/crash_record.zig";
    const fadt_path = "src/kernel/platform/fadt.zig";
    const framebuffer_path = "src/kernel/platform/framebuffer.zig";
    const hardware_target_path = "src/native/platform/hardware_target.zig";
    const first_target_telemetry_path = "src/kernel/drivers/first_target_telemetry.zig";
    const platform_policy_signals_path = "src/native/platform/platform_policy_signals.zig";
    const xhci_path = "src/kernel/drivers/xhci.zig";
    const nvme_path = "src/kernel/drivers/nvme.zig";
    const i225_path = "src/kernel/drivers/intel_i225.zig";
    if (!common.pathExists(io, hardware_proof_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 hardware proof source is missing: {s}", .{hardware_proof_path});
        return;
    }
    if (!common.pathExists(io, apic_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 APIC proof source is missing: {s}", .{apic_path});
        return;
    }
    if (!common.pathExists(io, crash_record_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 crash persistence proof source is missing: {s}", .{crash_record_path});
        return;
    }
    if (!common.pathExists(io, fadt_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 FADT suspend proof source is missing: {s}", .{fadt_path});
        return;
    }
    if (!common.pathExists(io, framebuffer_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 framebuffer proof source is missing: {s}", .{framebuffer_path});
        return;
    }
    if (!common.pathExists(io, hardware_target_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 update rollback proof source is missing: {s}", .{hardware_target_path});
        return;
    }
    if (!common.pathExists(io, first_target_telemetry_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 first-target telemetry source is missing: {s}", .{first_target_telemetry_path});
        return;
    }
    if (!common.pathExists(io, platform_policy_signals_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 platform policy signal source is missing: {s}", .{platform_policy_signals_path});
        return;
    }
    if (!common.pathExists(io, nvme_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 NVMe proof source is missing: {s}", .{nvme_path});
        return;
    }
    if (!common.pathExists(io, xhci_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 xHCI proof source is missing: {s}", .{xhci_path});
        return;
    }
    if (!common.pathExists(io, i225_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 I225 proof source is missing: {s}", .{i225_path});
        return;
    }
    const hardware_proof_source = try common.readFileAlloc(allocator, io, hardware_proof_path, common.source_file_max_bytes);
    const apic_source = try common.readFileAlloc(allocator, io, apic_path, common.source_file_max_bytes);
    const crash_record_source = try common.readFileAlloc(allocator, io, crash_record_path, common.source_file_max_bytes);
    const fadt_source = try common.readFileAlloc(allocator, io, fadt_path, common.source_file_max_bytes);
    const framebuffer_source = try common.readFileAlloc(allocator, io, framebuffer_path, common.source_file_max_bytes);
    const hardware_target_source = try common.readFileAlloc(allocator, io, hardware_target_path, common.source_file_max_bytes);
    const first_target_telemetry_source = try common.readFileAlloc(allocator, io, first_target_telemetry_path, common.source_file_max_bytes);
    const platform_policy_signals_source = try common.readFileAlloc(allocator, io, platform_policy_signals_path, common.source_file_max_bytes);
    const xhci_source = try common.readFileAlloc(allocator, io, xhci_path, common.source_file_max_bytes);
    const nvme_source = try common.readFileAlloc(allocator, io, nvme_path, common.source_file_max_bytes);
    const i225_source = try common.readFileAlloc(allocator, io, i225_path, common.source_file_max_bytes);
    const required_hardware_proof_snippets = [_][]const u8{
        "recordApicTimerProof",
        "recordFramebufferProof",
        "recordInputProof",
        "recordStorageProof",
        "recordNetworkProof",
        "recordSuspendResumeProof",
        "recordCrashPersistenceProof",
        "recordUpdateRollbackProof",
        "productionHardwareVerified",
    };
    for (required_hardware_proof_snippets) |snippet| {
        if (std.mem.indexOf(u8, hardware_proof_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 hardware proof source must enforce snippet: {s}", .{snippet});
        }
    }
    const required_apic_snippets = [_][]const u8{
        "TimerEvidenceSource",
        "hardware_lapic_timer",
        "HardwareTimerInterruptEvidence",
        "initial_count_register_writes",
        "divide_register_writes",
        "lvt_timer_register_writes",
        "current_count_register_reads",
        "isr_vector_observations",
        "interrupt_handler_entries",
        "eoi_register_writes",
        "tsc_delta_ticks",
        "productionHardwareVerified",
        "withHardwareTimerEvidence",
    };
    for (required_apic_snippets) |snippet| {
        if (std.mem.indexOf(u8, apic_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 APIC proof source must enforce hardware LAPIC timer snippet: {s}", .{snippet});
        }
    }
    const required_crash_record_snippets = [_][]const u8{
        "PersistenceEvidenceSource",
        "hardware_reboot_persistence",
        "HardwarePersistenceEvidence",
        "crash_handler_entries",
        "persistent_record_writes",
        "persistent_record_flushes",
        "reboot_observations",
        "recovery_boot_reads",
        "recovered_record_validations",
        "redacted_report_emissions",
        "persistent_bytes_written",
        "persistent_bytes_read",
        "productionHardwareVerified",
        "withHardwarePersistenceEvidence",
    };
    for (required_crash_record_snippets) |snippet| {
        if (std.mem.indexOf(u8, crash_record_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 crash persistence proof source must enforce hardware reboot-persistence snippet: {s}", .{snippet});
        }
    }
    const required_fadt_snippets = [_][]const u8{
        "SuspendEvidenceSource",
        "hardware_power_transition",
        "HardwareSuspendResumeEvidence",
        "pm1_control_sleep_writes",
        "s_state_entry_observations",
        "s0_resume_observations",
        "pm_timer_resume_reads",
        "sci_wake_interrupts",
        "resumed_timer_probes",
        "resumed_framebuffer_probes",
        "resumed_xhci_probes",
        "resumed_nvme_probes",
        "resumed_i225_probes",
        "productionHardwareVerified",
        "withHardwareSuspendResumeEvidence",
    };
    for (required_fadt_snippets) |snippet| {
        if (std.mem.indexOf(u8, fadt_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 FADT suspend proof source must enforce hardware power-transition snippet: {s}", .{snippet});
        }
    }
    const required_framebuffer_snippets = [_][]const u8{
        "ScanoutEvidenceSource",
        "hardware_gop_scanout",
        "HardwareScanoutEvidence",
        "gop_mode_info_reads",
        "framebuffer_base_observations",
        "framebuffer_stride_observations",
        "framebuffer_memory_read_bytes",
        "display_scanout_observations",
        "expected_pixel_observations",
        "captured_scanline_bytes",
        "sink_signal_observations",
        "productionHardwareVerified",
        "withHardwareScanoutEvidence",
    };
    for (required_framebuffer_snippets) |snippet| {
        if (std.mem.indexOf(u8, framebuffer_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 framebuffer proof source must enforce hardware GOP scanout snippet: {s}", .{snippet});
        }
    }
    const required_update_rollback_snippets = [_][]const u8{
        "UpdateRollbackEvidenceSource",
        "hardware_power_cycle",
        "HardwareUpdateRollbackEvidence",
        "candidate_activation_writes",
        "selector_record_flushes",
        "power_cycle_observations",
        "failure_detector_observations",
        "rollback_decision_records",
        "stable_slot_boot_observations",
        "recovered_slot_reads",
        "persisted_state_verifications",
        "service_start_suppression_observations",
        "productionHardwareVerified",
        "withHardwareUpdateRollbackEvidence",
    };
    for (required_update_rollback_snippets) |snippet| {
        if (std.mem.indexOf(u8, hardware_target_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 update rollback proof source must enforce hardware power-cycle snippet: {s}", .{snippet});
        }
    }
    const required_first_target_telemetry_snippets = [_][]const u8{
        "TelemetrySampleSequenceStale",
        "telemetrySampleSequenceStale",
        "thermal_sample_sequence",
        "battery_sample_sequence",
        "accelerator_sample_sequence",
        "grid_carbon_sample_sequence",
        "reading.thermal.sample_sequence <= recorded.thermal_sample_sequence",
        "reading.battery.sample_sequence <= recorded.battery_sample_sequence",
        "reading.accelerators.sample_sequence <= recorded.accelerator_sample_sequence",
        "reading.grid_carbon.sample_sequence <= recorded.grid_carbon_sample_sequence",
    };
    for (required_first_target_telemetry_snippets) |snippet| {
        if (std.mem.indexOf(u8, first_target_telemetry_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 first-target telemetry recorder must reject stale source sequence snippet: {s}", .{snippet});
        }
    }
    const required_platform_policy_signal_snippets = [_][]const u8{
        "freshAfter",
        "thermal_sample_sequence",
        "battery_sample_sequence",
        "accelerator_sample_sequence",
        "grid_carbon_sample_sequence",
        "error.TelemetryObservationStale",
        "rejected_observation_count += 1",
        "self.reader_generation < previous.reader_generation",
        "self.thermal_sample_sequence > previous.thermal_sample_sequence",
        "self.grid_carbon_sample_sequence > previous.grid_carbon_sample_sequence",
    };
    for (required_platform_policy_signal_snippets) |snippet| {
        if (std.mem.indexOf(u8, platform_policy_signals_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 platform telemetry provider must reject stale reader snapshot snippet: {s}", .{snippet});
        }
    }
    const required_xhci_snippets = [_][]const u8{
        "InputEvidenceSource",
        "hardware_event_ring",
        "HardwareInputEvidence",
        "controller_event_trbs",
        "event_ring_dma_writes",
        "device_context_reads_by_controller",
        "endpoint_context_reads_by_controller",
        "interrupt_assertions",
        "port_status_change_events",
        "input_report_dma_bytes",
        "productionHardwareVerified",
        "withHardwareInputEvidence",
    };
    for (required_xhci_snippets) |snippet| {
        if (std.mem.indexOf(u8, xhci_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 xHCI proof source must enforce hardware-owned event-ring snippet: {s}", .{snippet});
        }
    }
    const required_nvme_snippets = [_][]const u8{
        "CompletionEvidenceSource",
        "hardware_dma",
        "HardwareCompletionEvidence",
        "controller_completion_writes",
        "dma_read_bytes",
        "dma_write_bytes",
        "interrupt_count",
        "phase_tag_observations",
        "productionHardwareVerified",
        "withHardwareCompletionEvidence",
    };
    for (required_nvme_snippets) |snippet| {
        if (std.mem.indexOf(u8, nvme_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 NVMe proof source must enforce hardware-owned completion snippet: {s}", .{snippet});
        }
    }
    const required_i225_snippets = [_][]const u8{
        "PacketEvidenceSource",
        "hardware_descriptor_ring",
        "HardwarePacketEvidence",
        "tx_descriptors_owned_by_device",
        "rx_descriptors_owned_by_device",
        "tx_dma_bytes",
        "rx_dma_bytes",
        "asserted_interrupts",
        "phy_packet_observations",
        "productionHardwareVerified",
        "withHardwarePacketEvidence",
    };
    for (required_i225_snippets) |snippet| {
        if (std.mem.indexOf(u8, i225_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 I225 proof source must enforce hardware-owned descriptor-ring snippet: {s}", .{snippet});
        }
    }
}

fn validateNuc11tnki5MarkerFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const marker_path = "spec/hardware/nuc11tnki5-required-markers.txt";
    if (!common.pathExists(io, marker_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 marker file is missing: {s}", .{marker_path});
        return;
    }
    const source = try common.readFileAlloc(allocator, io, marker_path, common.source_file_max_bytes);
    for (FIRST_HARDWARE_TARGET_REQUIRED_MARKERS) |marker| {
        if (std.mem.indexOf(u8, source, marker) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 marker file is missing required marker: {s}", .{marker});
        }
    }
    for (FIRST_HARDWARE_TARGET_REQUIRED_FACT_MARKERS) |marker| {
        if (std.mem.indexOf(u8, source, marker) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 marker file is missing required hardware fact marker: {s}", .{marker});
        }
    }
    for (FIRST_HARDWARE_TARGET_REQUIRED_BOOTED_PROOF_MARKERS) |marker| {
        if (std.mem.indexOf(u8, source, marker) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 marker file is missing required booted proof marker: {s}", .{marker});
        }
    }
}

fn validateNuc11tnki5ProofPreparation(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const prep_path = "scripts/prepare-nuc11tnki5-hardware-proof.sh";
    if (!common.pathExists(io, prep_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 proof preparation script is missing: {s}", .{prep_path});
        return;
    }
    const source = try common.readFileAlloc(allocator, io, prep_path, common.source_file_max_bytes);
    const required_snippets = [_][]const u8{
        "operator-metadata-markers.txt",
        "$TARGET_PREFIX:EVIDENCE_SOURCE:REAL_HARDWARE",
        "$TARGET_PREFIX:BOARD_SKU:NUC11TNKi5",
        "$TARGET_PREFIX:PROOF_MANIFEST:RECORDED",
        "$TARGET_PREFIX:FIRMWARE_SETTINGS:RECORDED",
        "$TARGET_PREFIX:POWER_CYCLE_NOTES:RECORDED",
        "$TARGET_PREFIX:ARTIFACT_DIGESTS:RECORDED",
    };
    for (required_snippets) |snippet| {
        if (std.mem.indexOf(u8, source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 proof preparation script must emit metadata marker snippet: {s}", .{snippet});
        }
    }
}

fn validateNuc11tnki5ProofChecker(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const checker_path = "scripts/check-nuc11tnki5-hardware-proof.sh";
    if (!common.pathExists(io, checker_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 proof checker is missing: {s}", .{checker_path});
        return;
    }
    const source = try common.readFileAlloc(allocator, io, checker_path, common.source_file_max_bytes);
    const required_snippets = [_][]const u8{
        "EVIDENCE_SOURCE:REAL_HARDWARE",
        "BOARD_SKU:NUC11TNKi5",
        "PROOF_MANIFEST:RECORDED",
        "FIRMWARE_SETTINGS:RECORDED",
        "POWER_CYCLE_NOTES:RECORDED",
        "ARTIFACT_DIGESTS:RECORDED",
        "proof-manifest.txt",
        "target_id",
        "REQUIRED_MARKERS_PATH",
        "EXPECTED_MARKER_FILE",
        "absolute_path",
        "EXPECTED_LOG_PATH",
        "EXPECTED_PROOF_MANIFEST_PATH",
        "EXPECTED_FIRMWARE_SETTINGS_PATH",
        "EXPECTED_POWER_CYCLE_NOTES_PATH",
        "EXPECTED_ATTESTATION_LIFECYCLE_PATH",
        "EXPECTED_ARTIFACT_DIGESTS_PATH",
        "require_expected_bundle_path",
        "does not match proof bundle path",
        "does not match proof manifest required_markers",
        "non-real proof evidence text",
        "synthetic|simulated|mock|fake|fixture|test[-_ ]only|emulated",
        "captured_at_utc",
        "require_timestamp_not_before",
        "require_timestamp_value_not_before",
        "require_timestamp_value_not_after",
        "is before",
        "is after",
        "proof_prepared_at",
        "proof_captured_at",
        "power_started_at",
        "power_completed_at",
        "attestation_captured_at",
        "proof manifest prepared_at_utc",
        "proof manifest captured_at_utc",
        "started_at_utc",
        "completed_at_utc",
        "changed_options",
        "disabled-for-local-proof-media",
        "\"storage_mode\" \"nvme\"",
        "\"notes\"",
        "repo_vcs",
        "repo_change_id",
        "repo_commit",
        "ZIGOS_EXPECTED_REPO_CHANGE_ID",
        "ZIGOS_EXPECTED_REPO_COMMIT",
        "ZIGOS_ARTIFACT_ROOT",
        "sha256_file",
        "artifact digest mismatch",
        "require_digest_manifest_format",
        "malformed artifact digest line",
        "digest_count",
        "sha256 lines for",
        "grep -Fxc",
        "marker_line_number",
        "require_marker_before",
        "must appear before",
        "APIC_TIMER_INTERRUPT:OBSERVED",
        "APIC_TIMER:PASS",
        "FRAMEBUFFER_GOP_SCANOUT:OBSERVED",
        "FRAMEBUFFER_GOP:PASS",
        "XHCI_BOOT_KEYBOARD_REPORT:OBSERVED",
        "USB_INPUT_XHCI:PASS",
        "NVME_WRITE_READ_COMPLETION:OBSERVED",
        "NVME_BLOCK:PASS",
        "I225_LM_FRAME_INTERRUPT:OBSERVED",
        "NETWORK_I225_LM:PASS",
        "SUSPEND_RESUME_POWER:OBSERVED",
        "SUSPEND_RESUME:PASS",
        "CRASH_RECORD_REBOOT_PERSISTENCE:OBSERVED",
        "CRASH_RECOVERY:PASS",
        "UPDATE_ROLLBACK_POWER_CYCLE:OBSERVED",
        "ZIGOS:PLATFORM:UPDATE_ROLLBACK:POWER_CYCLE_OK",
        "ZIGOS:PLATFORM:CRASH_RECORD:PERSISTED",
        "ZIGOS:PERMISSION:XHCI_KEYBOARD:REPORT",
        "ZIGOS:SYNC:NATIVE_DRIVER:FRAME_SENT",
        "key_line_count",
        "require_unique_key",
        "jj -R \"$ROOT_DIR\" log -r @ --no-graph",
        "COLD_BOOTS",
        "WARM_REBOOTS",
        "STORAGE_WRITE_READ_CYCLES",
        "NETWORK_FRAME_CYCLES",
        "SUSPEND_RESUME_CYCLES",
        "CRASH_RECOVERY_CYCLES",
        "CRASH_RECORD_PERSISTENCE_CYCLES",
        "UPDATE_ROLLBACK_CYCLES",
        "repo_dirty_files",
        "require_unique_counter",
        "appears",
        "require_counter_matches_sidecar",
        "does not match serial counter",
        "attestation-lifecycle.txt",
        "attestation_lifecycle",
        "initial_generation",
        "active_generation",
        "revoked_generation_count",
        "stale_generation_rejected",
        "revoked_generation_rejected",
        "verifier_rejected_stale_attestation",
        "verifier_metadata_digest_bound",
        "verifier_metadata_digest",
        "attestation_request_digest",
        "artifact-digests.sha256",
        "zig-out/bin/kernel-zigos-native.elf",
        "zig-out/bin/userspace-network-stack.elf",
        "zig-out/bin/userspace-policy-mediation.elf",
        "zig-out/bin/userspace-storage-driver.elf",
        "SECURITY.md",
        "spec/release_security/release_artifacts.json",
        "spec/release_security/release_keyring.json",
        "spec/release_security/revoked_release_keys.json",
        "QEMU",
    };
    for (required_snippets) |snippet| {
        if (std.mem.indexOf(u8, source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 proof checker must enforce snippet: {s}", .{snippet});
        }
    }
}

fn validateProdReadinessManifest(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    prod_manifest: std.json.Value,
    coverage_manifest: std.json.Value,
) !void {
    if (prod_manifest != .object) {
        try common.addError(errors, allocator, "production_readiness.json must contain a JSON object", .{});
        return;
    }
    if (coverage_manifest != .object) {
        try common.addError(errors, allocator, "coverage.json must contain a JSON object", .{});
        return;
    }

    const schema_version = common.field(prod_manifest, "schema_version");
    if (schema_version == null or schema_version.? != .integer or schema_version.?.integer != 1) {
        try common.addError(errors, allocator, "production_readiness.json schema_version must be 1", .{});
    }

    const source_coverage_manifest = try common.expectStringField(
        allocator,
        errors,
        prod_manifest,
        "production_readiness.json",
        "source_coverage_manifest",
    ) orelse "";
    if (source_coverage_manifest.len > 0 and !std.mem.eql(u8, source_coverage_manifest, COVERAGE_MANIFEST_PATH)) {
        try common.addError(errors, allocator, "production_readiness.json source_coverage_manifest must be spec/coverage.json", .{});
    }

    const required_requirements = try common.collectStringArray(
        allocator,
        errors,
        common.field(coverage_manifest, "required_requirements"),
        "coverage manifest required_requirements",
        true,
    );
    var required_requirement_set = try common.collectUniqueStrings(allocator, errors, required_requirements, "required requirement");

    const requirement_evidence = try common.expectObjectField(
        allocator,
        errors,
        coverage_manifest,
        "coverage manifest",
        "requirement_evidence",
    ) orelse return;

    const tracks_value = common.field(prod_manifest, "tracks") orelse {
        try common.addError(errors, allocator, "production_readiness.json must include at least one track", .{});
        return;
    };
    const tracks = switch (tracks_value) {
        .array => |array| array.items,
        else => {
            try common.addError(errors, allocator, "production_readiness.json tracks must be an array", .{});
            return;
        },
    };
    if (tracks.len == 0) {
        try common.addError(errors, allocator, "production_readiness.json must include at least one track", .{});
        return;
    }

    var seen_track_ids = std.StringHashMap(void).init(allocator);
    for (tracks, 0..) |track, index| {
        try validateTrack(
            allocator,
            io,
            errors,
            track,
            index,
            &seen_track_ids,
            &required_requirement_set,
            requirement_evidence,
        );
    }
}

fn validateTrack(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    track: std.json.Value,
    index: usize,
    seen_track_ids: *std.StringHashMap(void),
    required_requirement_set: *const std.StringHashMap(void),
    requirement_evidence: std.json.Value,
) !void {
    if (track != .object) {
        try common.addError(errors, allocator, "Production readiness track at index {d} must be an object", .{index});
        return;
    }

    const fallback_track_id = try std.fmt.allocPrint(allocator, "<track-{d}>", .{index});
    const track_id = try common.expectStringField(allocator, errors, track, "Production readiness track", "id") orelse fallback_track_id;
    if (std.mem.eql(u8, track_id, fallback_track_id)) {
        try common.addError(errors, allocator, "Production readiness track at index {d} must include id", .{index});
    } else {
        const gop = try seen_track_ids.getOrPut(track_id);
        if (gop.found_existing) {
            try common.addError(errors, allocator, "Duplicate production readiness track id: {s}", .{track_id});
        }
    }

    const title = try common.expectStringField(allocator, errors, track, try std.fmt.allocPrint(allocator, "Production readiness track {s}", .{track_id}), "title");
    if (title != null and title.?.len == 0) {
        try common.addError(errors, allocator, "Production readiness track {s} must include title", .{track_id});
    }

    const priority = try common.expectStringField(allocator, errors, track, try std.fmt.allocPrint(allocator, "Production readiness track {s}", .{track_id}), "priority") orelse "";
    if (priority.len > 0 and !isOneOf(priority, &PRIORITIES)) {
        try common.addError(errors, allocator, "Production readiness track {s} priority must be one of [P0, P1, P2]", .{track_id});
    }

    const status = try common.expectStringField(allocator, errors, track, try std.fmt.allocPrint(allocator, "Production readiness track {s}", .{track_id}), "status") orelse "";
    if (status.len > 0 and !isOneOf(status, &STATUS_LABELS)) {
        try common.addError(errors, allocator, "Production readiness track {s} status must be one of [blocked, prod_candidate, prod_ready, prototype]", .{track_id});
    }

    for (LIST_FIELDS) |field_name| {
        const required_non_empty = !std.mem.eql(u8, field_name, "production_gaps") or !std.mem.eql(u8, status, "prod_ready");
        _ = try common.collectStringArray(
            allocator,
            errors,
            common.field(track, field_name),
            try std.fmt.allocPrint(allocator, "Production readiness track {s} {s}", .{ track_id, field_name }),
            required_non_empty,
        );
    }

    for (OPTIONAL_LIST_FIELDS) |field_name| {
        const value = common.field(track, field_name) orelse continue;
        if (value == .null) continue;
        _ = try common.collectStringArray(
            allocator,
            errors,
            value,
            try std.fmt.allocPrint(allocator, "Production readiness track {s} optional {s}", .{ track_id, field_name }),
            false,
        );
    }

    const requirements = try common.collectStringArray(
        allocator,
        errors,
        common.field(track, "requirements"),
        try std.fmt.allocPrint(allocator, "Production readiness track {s} requirements", .{track_id}),
        true,
    );
    for (requirements) |requirement_id| {
        if (!required_requirement_set.contains(requirement_id)) {
            try common.addError(
                errors,
                allocator,
                "Production readiness track {s} references unknown requirement: {s}",
                .{ track_id, requirement_id },
            );
            continue;
        }
        const evidence = common.field(requirement_evidence, requirement_id) orelse continue;
        const evidence_status = common.field(evidence, "status");
        if (evidence_status == null or evidence_status.? != .string or !std.mem.eql(u8, evidence_status.?.string, "enforced")) {
            try common.addError(
                errors,
                allocator,
                "Production readiness track {s} references {s}, which is '{s}'; production tracks require spec-enforced requirements",
                .{ track_id, requirement_id, if (evidence_status != null and evidence_status.? == .string) evidence_status.?.string else "<missing>" },
            );
        }
    }

    const anchors = try common.collectStringArray(
        allocator,
        errors,
        common.field(track, "implementation_anchors"),
        try std.fmt.allocPrint(allocator, "Production readiness track {s} implementation_anchors", .{track_id}),
        true,
    );
    for (anchors) |anchor| {
        if (!common.pathExists(io, anchor)) {
            try common.addError(
                errors,
                allocator,
                "Production readiness track {s} references missing implementation anchor: {s}",
                .{ track_id, anchor },
            );
        }
    }

    const production_gaps = common.field(track, "production_gaps");
    if (std.mem.eql(u8, status, "prod_ready") and production_gaps != null and production_gaps.? == .array and production_gaps.?.array.items.len > 0) {
        try common.addError(errors, allocator, "Production readiness track {s} is prod_ready but still lists production_gaps", .{track_id});
    }
}

fn validateSyntheticUserspaceImageMarkers(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    for (CRITICAL_SYNTHETIC_IMAGE_PATHS) |relative_path| {
        if (!common.pathExists(io, relative_path)) {
            try common.addError(errors, allocator, "Critical synthetic userspace image path is missing: {s}", .{relative_path});
            continue;
        }
        const source = try common.readFileAlloc(allocator, io, relative_path, common.source_file_max_bytes);
        try validateSyntheticUserspaceImageMarkersForSource(allocator, errors, relative_path, source);
    }
}

fn validateSyntheticUserspaceImageMarkersForSource(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    relative_path: []const u8,
    source: []const u8,
) !void {
    var previous_line: []const u8 = "";
    var lines = std.mem.splitScalar(u8, source, '\n');
    var line_number: usize = 1;
    while (lines.next()) |line| : (line_number += 1) {
        if (lineCallsSyntheticUserspaceImage(line) and
            std.mem.indexOf(u8, line, MODEL_ONLY_SYNTHETIC_IMAGE_MARKER) == null and
            std.mem.indexOf(u8, previous_line, MODEL_ONLY_SYNTHETIC_IMAGE_MARKER) == null)
        {
            try common.addError(
                errors,
                allocator,
                "{s}:{d} calls syntheticUserspaceImage in a critical service launch path without the '{s}' marker",
                .{ relative_path, line_number, MODEL_ONLY_SYNTHETIC_IMAGE_MARKER },
            );
        }
        previous_line = line;
    }
}

fn lineCallsSyntheticUserspaceImage(line: []const u8) bool {
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, line, offset, "syntheticUserspaceImage")) |start| {
        const after_name = start + "syntheticUserspaceImage".len;
        var cursor = after_name;
        while (cursor < line.len and (line[cursor] == ' ' or line[cursor] == '\t')) : (cursor += 1) {}
        if (cursor < line.len and line[cursor] == '(') return true;
        offset = after_name;
    }
    return false;
}

fn runSelfTests(allocator: std.mem.Allocator, io: std.Io, errors: *std.ArrayList([]const u8)) !void {
    var unmarked_errors = std.ArrayList([]const u8).empty;
    try validateSyntheticUserspaceImageMarkersForSource(
        allocator,
        &unmarked_errors,
        "src/native/kernel_api/native_kernel.zig",
        "const image = task_runtime.syntheticUserspaceImage(\"label\", \"entry\");\n",
    );
    if (unmarked_errors.items.len == 0) {
        try common.addError(errors, allocator, "Production readiness checker self-test failed: synthetic userspace image gate accepted unmarked critical fixture", .{});
    }

    var marked_errors = std.ArrayList([]const u8).empty;
    try validateSyntheticUserspaceImageMarkersForSource(
        allocator,
        &marked_errors,
        "src/native/kernel_api/native_kernel.zig",
        "// " ++ MODEL_ONLY_SYNTHETIC_IMAGE_MARKER ++ "\nconst image = task_runtime.syntheticUserspaceImage(\"label\", \"entry\");\n",
    );
    if (marked_errors.items.len != 0) {
        try common.addError(errors, allocator, "Production readiness checker self-test failed: synthetic userspace image gate rejected marked model-only fixture", .{});
    }

    const missing_control_gate_json =
        \\{
        \\  "secure_by_design_release_gate": {
        \\    "release_status": "blocked",
        \\    "external_bar": {
        \\      "name": "CISA Product Security Bad Practices",
        \\      "url": "https://www.cisa.gov/resources-tools/resources/product-security-bad-practices",
        \\      "last_reviewed": "2026-05-23"
        \\    },
        \\    "policy_artifacts": [],
        \\    "controls": []
        \\  }
        \\}
    ;
    var parsed_missing_control_gate = try std.json.parseFromSlice(std.json.Value, allocator, missing_control_gate_json, .{});
    defer parsed_missing_control_gate.deinit();
    var missing_control_errors = std.ArrayList([]const u8).empty;
    try validateSecureByDesignReleaseGate(allocator, io, &missing_control_errors, parsed_missing_control_gate.value);
    if (!common.errorContains(missing_control_errors.items, "missing required secure-by-design control: fuzzing")) {
        try common.addError(errors, allocator, "Production readiness checker self-test failed: secure-by-design gate accepted a manifest without required controls", .{});
    }

    const incomplete_hardware_target_json =
        \\{
        \\  "first_hardware_target": {
        \\    "id": "intel-nuc11tnki5",
        \\    "vendor": "Intel",
        \\    "product": "NUC 11 Pro Kit",
        \\    "sku": "NUC11TNKi5",
        \\    "status": "hardware_required",
        \\    "selection_reason": "self-test",
        \\    "boot_medium": "UEFI",
        \\    "serial_capture": "self-test",
        \\    "required_subsystems": ["uefi_boot"],
        \\    "reference_artifacts": [
        \\      "src/native/platform/hardware_target.zig",
        \\      "spec/hardware/nuc11tnki5-required-markers.txt",
        \\      "scripts/check-nuc11tnki5-hardware-proof.sh"
        \\    ],
        \\    "qemu_preflight_commands": ["./scripts/zig.sh build iso"],
        \\    "hardware_exit_criteria": ["self-test"],
        \\    "current_hardware_evidence": [],
        \\    "open_gaps": ["self-test"]
        \\  }
        \\}
    ;
    var parsed_incomplete_hardware_target = try std.json.parseFromSlice(std.json.Value, allocator, incomplete_hardware_target_json, .{});
    defer parsed_incomplete_hardware_target.deinit();
    var incomplete_hardware_errors = std.ArrayList([]const u8).empty;
    try validateFirstHardwareTarget(allocator, io, &incomplete_hardware_errors, parsed_incomplete_hardware_target.value);
    if (!common.errorContains(incomplete_hardware_errors.items, "missing required subsystem: acpi_tables")) {
        try common.addError(errors, allocator, "Production readiness checker self-test failed: first hardware target gate accepted an incomplete subsystem list", .{});
    }
}

fn isOneOf(value: []const u8, allowed: []const []const u8) bool {
    for (allowed) |candidate| {
        if (std.mem.eql(u8, value, candidate)) return true;
    }
    return false;
}

test "synthetic userspace marker gate rejects unmarked fixture" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var errors = std.ArrayList([]const u8).empty;
    try validateSyntheticUserspaceImageMarkersForSource(
        allocator,
        &errors,
        "src/native/kernel_api/native_kernel.zig",
        "const image = task_runtime.syntheticUserspaceImage(\"label\", \"entry\");\n",
    );
    try std.testing.expect(errors.items.len > 0);
}

test "synthetic userspace marker gate accepts model-only marker" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var errors = std.ArrayList([]const u8).empty;
    try validateSyntheticUserspaceImageMarkersForSource(
        allocator,
        &errors,
        "src/native/kernel_api/native_kernel.zig",
        "// " ++ MODEL_ONLY_SYNTHETIC_IMAGE_MARKER ++ "\nconst image = task_runtime.syntheticUserspaceImage(\"label\", \"entry\");\n",
    );
    try std.testing.expectEqual(@as(usize, 0), errors.items.len);
}
