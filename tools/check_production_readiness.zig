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
    "BOOT:ROLE:verification",
    "ZIGOS:USERSPACE:ARTIFACTS:READY",
    "ZIGOS:USERSPACE:SCHEDULER:READY",
    "ZIGOS:USERSPACE:EXEC_PROBE:OK",
    "ZIGOS:USERSPACE:RESUME:OK",
    "ZIGOS:SERVICE_BOOT:SERVICE_CONTRACTS:READY",
    "ZIGOS:SERVICE_BOOT:IPC_CONNECT:ALL_OK",
    "ZIGOS:SERVICE_BOOT:DRIVER:STORAGE_REBIND_OK",
    "ZIGOS:SERVICE_BOOT:DRIVER:CONTROLLER_REVOKE_REJECTED",
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
    "ZIGOS:NATIVE:READY",
};
const FIRST_HARDWARE_TARGET_REQUIRED_PRODUCTION_MARKERS = [_][]const u8{
    "BOOT:START",
    "BOOT:PROFILE:zigos_native",
    "BOOT:ROLE:production",
    "BOOT:CORE_READY",
    "ZIGOS:KERNEL_NETWORK:DEFERRED",
    "ZIGOS:NATIVE:BOOTSTRAP",
    "ZIGOS:TCB:DEFINED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:EVIDENCE_SOURCE:REAL_HARDWARE",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:BOARD_SKU:NUC11TNKi5",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:SMBIOS_SKU:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:MULTIBOOT_MEMORY_MAP:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_RSDP:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_MADT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_FADT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_TABLES:PASS",
    "ZIGOS:USERSPACE:SCHEDULER:READY",
    "ZIGOS:USERSPACE:ARTIFACTS:READY",
    "ZIGOS:USERSPACE:EXEC_PROBE:OK",
    "ZIGOS:USERSPACE:RESUME:OK",
    "ZIGOS:TRANSPORT:NATIVE_KERNEL:READY",
    "ZIGOS:TRANSPORT:NO_ROOT",
    "ZIGOS:TRANSPORT:COMPONENT_ABI:READY",
    "ZIGOS:SUPERVISOR:READY",
    "ZIGOS:SERVICE_BOOT:CONTRACT_MAP:READY",
    "ZIGOS:POLICY:READY",
    "ZIGOS:SERVICE_BOOT:DRIVER_SERVICE:NETWORK_READY",
    "ZIGOS:SERVICE_BOOT:DRIVER_SERVICE:STORAGE_READY",
    "ZIGOS:SERVICE_BOOT:SERVICE_CONTRACTS:READY",
    "ZIGOS:PLATFORM:BOOTLOADER_MEASUREMENT:PROVIDED",
    "ZIGOS:PLATFORM:BUILD_ARTIFACT_MANIFEST:VERIFIED",
    "ZIGOS:PLATFORM:BOOTLOADER_HANDOFF:VERIFIED",
    "ZIGOS:PLATFORM:ARTIFACT_MANIFEST:VERIFIED",
    "ZIGOS:PLATFORM:MEASURED_BOOT:RECORDED",
    "ZIGOS:PLATFORM:MEASURED_BOOT:VERIFIED_ROOT",
    "ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false",
    "ZIGOS:TASK:SESSION_READY",
    "ZIGOS:NATIVE:READY",
};
const FIRST_HARDWARE_TARGET_FORBIDDEN_PRODUCTION_MARKERS = [_][]const u8{
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:UEFI_BOOT:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:APIC_TIMER_INTERRUPT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:APIC_TIMER:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:FRAMEBUFFER_GOP_SCANOUT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:FRAMEBUFFER_GOP:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:XHCI_BOOT_KEYBOARD_REPORT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:USB_INPUT_XHCI:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:NVME_WRITE_READ_COMPLETION:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:NVME_BLOCK:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:I225_LM_FRAME_INTERRUPT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:NETWORK_I225_LM:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:SUSPEND_RESUME_POWER:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:SUSPEND_RESUME:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:CRASH_RECORD_REBOOT_PERSISTENCE:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:CRASH_RECOVERY:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:UPDATE_ROLLBACK_POWER_CYCLE:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ATTESTATION_ROOT_LIFECYCLE:OBSERVED",
};
const FIRST_HARDWARE_TARGET_REQUIRED_REFERENCE_ARTIFACTS = [_][]const u8{
    "src/native/platform/hardware_target.zig",
    "spec/hardware/nuc11tnki5-production-required-markers.txt",
    "spec/hardware/nuc11tnki5-required-markers.txt",
    "spec/hardware/nuc11tnki5-proof-bundle.md",
    "scripts/prepare-nuc11tnki5-hardware-proof.sh",
    "scripts/write-nuc11tnki5-capture-statement.sh",
    "scripts/check-nuc11tnki5-hardware-proof.sh",
    "scripts/test-nuc11tnki5-hardware-proof-checker.sh",
};
const FIRST_HARDWARE_TARGET_REQUIRED_QEMU_PREFLIGHT_COMMANDS = [_][]const u8{
    "./scripts/zig.sh build iso",
    "./scripts/zig.sh build iso-verification",
    "./scripts/zig.sh build uefi-qemu-test",
    "./scripts/zig.sh build uefi-verification-qemu-test",
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
    "src/native/platform/os_contract.zig",
    "src/native/platform/compositor_session.zig",
    "src/native/platform/rendered_shell/task_launch.zig",
    "src/native/task/process_isolation.zig",
    "src/kernel/boot/benchmark/suite.zig",
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
    const qemu_preflight_commands = try common.collectStringArray(
        allocator,
        errors,
        common.field(target, "qemu_preflight_commands"),
        "first_hardware_target qemu_preflight_commands",
        true,
    );
    var qemu_preflight_command_set = try common.collectUniqueStrings(allocator, errors, qemu_preflight_commands, "first hardware target QEMU preflight command");
    for (FIRST_HARDWARE_TARGET_REQUIRED_QEMU_PREFLIGHT_COMMANDS) |required_command| {
        if (!qemu_preflight_command_set.contains(required_command)) {
            try common.addError(errors, allocator, "first_hardware_target missing required QEMU preflight command: {s}", .{required_command});
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
    const devices_path = "src/kernel/boot/init/devices.zig";
    const crash_record_path = "src/kernel/platform/crash_record.zig";
    const fadt_path = "src/kernel/platform/fadt.zig";
    const framebuffer_path = "src/kernel/platform/framebuffer.zig";
    const hardware_target_path = "src/native/platform/hardware_target.zig";
    const first_target_telemetry_path = "src/kernel/drivers/first_target_telemetry.zig";
    const platform_policy_signals_path = "src/native/platform/platform_policy_signals.zig";
    const device_inventory_path = "src/native/drivers/device_inventory.zig";
    const service_bootstrap_path = "src/native/session/service_bootstrap.zig";
    const session_service_bootstrap_path = "src/native/session/session_service_bootstrap.zig";
    const keyboard_path = "src/kernel/drivers/keyboard.zig";
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
    if (!common.pathExists(io, devices_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 boot device inventory source is missing: {s}", .{devices_path});
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
    if (!common.pathExists(io, device_inventory_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 device inventory source is missing: {s}", .{device_inventory_path});
        return;
    }
    if (!common.pathExists(io, service_bootstrap_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 service bootstrap source is missing: {s}", .{service_bootstrap_path});
        return;
    }
    if (!common.pathExists(io, session_service_bootstrap_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 session service bootstrap source is missing: {s}", .{session_service_bootstrap_path});
        return;
    }
    if (!common.pathExists(io, keyboard_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 keyboard bootstrap source is missing: {s}", .{keyboard_path});
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
    const devices_source = try common.readFileAlloc(allocator, io, devices_path, common.source_file_max_bytes);
    const crash_record_source = try common.readFileAlloc(allocator, io, crash_record_path, common.source_file_max_bytes);
    const fadt_source = try common.readFileAlloc(allocator, io, fadt_path, common.source_file_max_bytes);
    const framebuffer_source = try common.readFileAlloc(allocator, io, framebuffer_path, common.source_file_max_bytes);
    const hardware_target_source = try common.readFileAlloc(allocator, io, hardware_target_path, common.source_file_max_bytes);
    const first_target_telemetry_source = try common.readFileAlloc(allocator, io, first_target_telemetry_path, common.source_file_max_bytes);
    const platform_policy_signals_source = try common.readFileAlloc(allocator, io, platform_policy_signals_path, common.source_file_max_bytes);
    const device_inventory_source = try common.readFileAlloc(allocator, io, device_inventory_path, common.source_file_max_bytes);
    const service_bootstrap_source = try common.readFileAlloc(allocator, io, service_bootstrap_path, common.source_file_max_bytes);
    const session_service_bootstrap_source = try common.readFileAlloc(allocator, io, session_service_bootstrap_path, common.source_file_max_bytes);
    const keyboard_source = try common.readFileAlloc(allocator, io, keyboard_path, common.source_file_max_bytes);
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
    const required_device_inventory_snippets = [_][]const u8{
        "requireProductionDriverDeviceId",
        "sourceCanBindProductionDriver",
        "NonProductionDeviceBinding",
        "intel_i225_lm_inventory",
        "nvme_pci_inventory",
        "sourceCanBindProductionDriver(record.device_class, record.source, record.device_id)",
        "isStablePciVendorDevice(device_id, PCI_VENDOR_INTEL, PCI_DEVICE_INTEL_I225_LM)",
        ".storage_controller => source == .nvme_pci_inventory and isStablePciId(device_id)",
        ".input_device => source == .xhci_inventory and isStablePciVendor(device_id, PCI_VENDOR_INTEL)",
        "if (source == .absent or source == .synthetic or device_id == 0) return false",
        ".absent => \"absent\"",
        "device inventory starts absent until hardware is discovered",
        "if (!sourceCanBindProductionDriver(device_class, source, device_id)) return",
        ".platform_policy",
        "device inventory refuses synthetic records for production driver binding",
        "device inventory requires target-grade NVMe for production storage binding",
        "device inventory refuses PS/2 bootstrap for production input binding",
    };
    for (required_device_inventory_snippets) |snippet| {
        if (std.mem.indexOf(u8, device_inventory_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 device inventory source must enforce production binding snippet: {s}", .{snippet});
        }
    }
    const retired_device_inventory_snippets = [_][]const u8{
        "defaultRecord(.network_adapter, 100)",
        "defaultRecord(.storage_controller, 200)",
        "defaultRecord(.usb_controller, 300)",
        "defaultRecord(.input_device, 600)",
    };
    for (retired_device_inventory_snippets) |snippet| {
        if (std.mem.indexOf(u8, device_inventory_source, snippet) != null) {
            try common.addError(errors, allocator, "NUC11TNKi5 device inventory source must not reintroduce stable synthetic fallback ids: {s}", .{snippet});
        }
    }
    const retired_device_inventory_binding_snippets = [_][]const u8{
        ".input_device => source == .ps2_bootstrap",
        ".ata_bootstrap",
        "AtaBrokerGrant",
    };
    for (retired_device_inventory_binding_snippets) |snippet| {
        if (std.mem.indexOf(u8, device_inventory_source, snippet) != null) {
            try common.addError(errors, allocator, "NUC11TNKi5 device inventory source must not bind production input through PS/2 bootstrap: {s}", .{snippet});
        }
    }
    const required_boot_device_inventory_snippets = [_][]const u8{
        "pci.firstIntelI225Lm()",
        ".intel_i225_lm_inventory",
        "pci.firstNvmeController()",
        ".nvme_pci_inventory",
        "pci.firstXhciController()",
        "device_inventory.registerDetected(.input_device, xhci_device_id, .xhci_inventory, false)",
    };
    for (required_boot_device_inventory_snippets) |snippet| {
        if (std.mem.indexOf(u8, devices_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 boot device inventory source must capture target-specific PCI snippet: {s}", .{snippet});
        }
    }
    const required_service_bootstrap_snippets = [_][]const u8{
        "device_inventory.requireProductionDriverDeviceId(device_class)",
        "const device_id = try",
        "driver_service.authorityTarget(device_id)",
        ".device_id = device_id",
    };
    for (required_service_bootstrap_snippets) |snippet| {
        if (std.mem.indexOf(u8, service_bootstrap_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 service bootstrap source must bind drivers through detected inventory snippet: {s}", .{snippet});
        }
    }
    const required_session_service_bootstrap_snippets = [_][]const u8{
        "seedHostedModelDeviceInventory",
        "builtin.target.os.tag == .freestanding",
        ".intel_i225_lm_inventory",
        ".nvme_pci_inventory",
        "hosted_xhci_device_id",
        "device_inventory.registerDetected(.input_device, hosted_xhci_device_id, .xhci_inventory, false)",
        ".platform_policy",
    };
    for (required_session_service_bootstrap_snippets) |snippet| {
        if (std.mem.indexOf(u8, session_service_bootstrap_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 hosted service bootstrap source must keep explicit modeled inventory snippet: {s}", .{snippet});
        }
    }
    const Ps2SeedSource = struct {
        label: []const u8,
        source: []const u8,
    };
    const retired_ps2_input_seed_snippets = [_][]const u8{
        "device_inventory.registerDetected(.input_device, 0x8042_0001, .ps2_bootstrap, false)",
    };
    const ps2_seed_sources = [_]Ps2SeedSource{
        .{ .label = devices_path, .source = devices_source },
        .{ .label = session_service_bootstrap_path, .source = session_service_bootstrap_source },
        .{ .label = keyboard_path, .source = keyboard_source },
    };
    for (ps2_seed_sources) |source_check| {
        for (retired_ps2_input_seed_snippets) |snippet| {
            if (std.mem.indexOf(u8, source_check.source, snippet) != null) {
                try common.addError(errors, allocator, "NUC11TNKi5 source {s} must not seed production input through PS/2 bootstrap: {s}", .{ source_check.label, snippet });
            }
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

fn markerFileHasActiveLine(source: []const u8, expected: []const u8) bool {
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.eql(u8, line, expected)) return true;
    }
    return false;
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
        if (!markerFileHasActiveLine(source, marker)) {
            try common.addError(errors, allocator, "NUC11TNKi5 marker file is missing required marker: {s}", .{marker});
        }
    }
    for (FIRST_HARDWARE_TARGET_REQUIRED_FACT_MARKERS) |marker| {
        if (!markerFileHasActiveLine(source, marker)) {
            try common.addError(errors, allocator, "NUC11TNKi5 marker file is missing required hardware fact marker: {s}", .{marker});
        }
    }
    for (FIRST_HARDWARE_TARGET_REQUIRED_BOOTED_PROOF_MARKERS) |marker| {
        if (!markerFileHasActiveLine(source, marker)) {
            try common.addError(errors, allocator, "NUC11TNKi5 marker file is missing required booted proof marker: {s}", .{marker});
        }
    }

    const production_marker_path = "spec/hardware/nuc11tnki5-production-required-markers.txt";
    if (!common.pathExists(io, production_marker_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 production marker file is missing: {s}", .{production_marker_path});
        return;
    }
    const production_source = try common.readFileAlloc(allocator, io, production_marker_path, common.source_file_max_bytes);
    for (FIRST_HARDWARE_TARGET_REQUIRED_PRODUCTION_MARKERS) |marker| {
        if (!markerFileHasActiveLine(production_source, marker)) {
            try common.addError(errors, allocator, "NUC11TNKi5 production marker file is missing required marker: {s}", .{marker});
        }
    }
    for (FIRST_HARDWARE_TARGET_FORBIDDEN_PRODUCTION_MARKERS) |marker| {
        if (markerFileHasActiveLine(production_source, marker)) {
            try common.addError(errors, allocator, "NUC11TNKi5 production marker file must not require unreachable exhaustive marker: {s}", .{marker});
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
        "build/os.iso",
        "build/os-verification.iso",
        "zig-out/bin/kernel-zigos-native.elf",
        "zig-out/bin/kernel-zigos-native-verification.elf",
        "--nonce",
        "ZIGOS_HARDWARE_PROOF_NONCE",
        "zigos-nuc11tnki5-proof-v2",
        "capture_nonce=$CAPTURE_NONCE",
        "device_identity=device-identity.txt",
        "production_serial_log=production-serial.log",
        "production_boot_medium=build/os.iso",
        "production_boot_kernel=zig-out/bin/kernel-zigos-native.elf",
        "production_required_markers=spec/hardware/nuc11tnki5-production-required-markers.txt",
        "verification_serial_log=verification-serial.log",
        "verification_boot_medium=build/os-verification.iso",
        "verification_boot_kernel=zig-out/bin/kernel-zigos-native-verification.elf",
        "verification_required_markers=spec/hardware/nuc11tnki5-required-markers.txt",
        "cycle_manifest=cycle-manifest.txt",
        "production_quote=production-attestation.quote",
        "production_signature=production-attestation.sig",
        "verification_quote=verification-attestation.quote",
        "verification_signature=verification-attestation.sig",
        "capture_statement=capture-statement.txt",
        "release-bundle-check",
        "-Drelease-verifier=",
        "-Drelease-verifier-sha256=",
        "is_safe_proof_output_dir",
        "use a fresh --output directory",
        "write_new_file",
        "Perform two separate single-boot captures",
        "production-serial.log",
        "verification-serial.log",
        "cycle-manifest.txt",
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

    const statement_writer_path = "scripts/write-nuc11tnki5-capture-statement.sh";
    if (!common.pathExists(io, statement_writer_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 capture-statement writer is missing: {s}", .{statement_writer_path});
        return;
    }
    const statement_source = try common.readFileAlloc(allocator, io, statement_writer_path, common.source_file_max_bytes);
    const statement_snippets = [_][]const u8{
        "format=zigos-nuc11tnki5-capture-statement-v1",
        "capture_nonce=$nonce",
        "device_identity_sha256=",
        "production_serial_sha256=",
        "verification_serial_sha256=",
        "cycle_manifest_sha256=",
        "production_iso_sha256=",
        "production_kernel_sha256=",
        "verification_iso_sha256=",
        "verification_kernel_sha256=",
        "production_marker_contract_sha256=",
        "verification_marker_contract_sha256=",
        "firmware_settings_sha256=",
        "power_cycle_notes_sha256=",
        "attestation_lifecycle_sha256=",
        "artifact_digests_sha256=",
        "production_quote_sha256=",
        "production_signature_sha256=",
        "verification_quote_sha256=",
        "verification_signature_sha256=",
    };
    for (statement_snippets) |snippet| {
        if (std.mem.indexOf(u8, statement_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 capture-statement writer must bind snippet: {s}", .{snippet});
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
        "zigos-nuc11tnki5-proof-v2",
        "proof-manifest.txt",
        "device-identity.txt",
        "production-serial.log",
        "verification-serial.log",
        "cycle-manifest.txt",
        "production-attestation.quote",
        "production-attestation.sig",
        "verification-attestation.quote",
        "verification-attestation.sig",
        "capture-statement.txt",
        "ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE",
        "ZIGOS_HARDWARE_PROOF_VERIFIER",
        "ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256",
        "externally pinned lowercase SHA-256 digest",
        "fresh externally issued 64-hex capture nonce",
        "actual_verifier_sha256",
        "trusted verifier executable digest does not match",
        "trusted hardware verifier must be obtained independently of the proof bundle and artifact root",
        "release verifier must be obtained independently of the proof bundle and artifact root",
        "format=zigos-nuc11tnki5-capture-statement-v1",
        "write_expected_statement",
        "production_serial_sha256=",
        "verification_serial_sha256=",
        "cycle_manifest_sha256=",
        "production_iso_sha256=",
        "production_kernel_sha256=",
        "verification_iso_sha256=",
        "verification_kernel_sha256=",
        "production_marker_contract_sha256=",
        "verification_marker_contract_sha256=",
        "production_quote_sha256=",
        "production_signature_sha256=",
        "verification_quote_sha256=",
        "verification_signature_sha256=",
        "capture statement is not the canonical statement recomputed",
        "format=zigos-nuc11tnki5-cycle-manifest-v1",
        "zigos-nuc11tnki5-cycle-log-v1",
        "cycle manifest is malformed, non-canonical, out of order, non-contiguous, or contains duplicate evidence",
        "cycles directory must contain exactly the logs named",
        "cycle log digest mismatch",
        "valid unique",
        "does not match $count valid cycle entries",
        "COLD_BOOTS",
        "WARM_REBOOTS",
        "STORAGE_WRITE_READ_CYCLES",
        "NETWORK_FRAME_CYCLES",
        "SUSPEND_RESUME_CYCLES",
        "CRASH_RECOVERY_CYCLES",
        "CRASH_RECORD_PERSISTENCE_CYCLES",
        "UPDATE_ROLLBACK_CYCLES",
        "BOOT:ROLE:production",
        "BOOT:ROLE:verification",
        "ZIGOS:NATIVE:READY",
        "exactly one BOOT:ROLE marker",
        "ZIGOS:STORAGE:CHECKPOINT:FINAL",
        "enabled=true",
        "dirty=false",
        "generation=[0-9]+",
        "error=none",
        "ZIGOS:TASK:SESSION_READY",
        "require_marker_before",
        "EVIDENCE_SOURCE:REAL_HARDWARE",
        "BOARD_SKU:NUC11TNKi5",
        "APIC_TIMER_INTERRUPT:OBSERVED",
        "FRAMEBUFFER_GOP_SCANOUT:OBSERVED",
        "XHCI_BOOT_KEYBOARD_REPORT:OBSERVED",
        "NVME_WRITE_READ_COMPLETION:OBSERVED",
        "I225_LM_FRAME_INTERRUPT:OBSERVED",
        "SUSPEND_RESUME_POWER:OBSERVED",
        "CRASH_RECORD_REBOOT_PERSISTENCE:OBSERVED",
        "active_marker_lines",
        "production marker contract under artifact root differs",
        "verification marker contract under artifact root differs",
        "app.notes.daily",
        "userspace-notes-daily.elf",
        "artifact digest mismatch",
        "stale_generation_rejected",
        "revoked_generation_rejected",
        "verifier_rejected_stale_attestation",
        "format=zigos-trusted-hardware-verifier-response-v1",
        "assertion=signed-response",
        "statement_sha256=$statement_sha256",
        "nonce=$capture_nonce",
        "production_role=verified",
        "verification_role=verified",
        "cmp -s \"$expected_response\" \"$verifier_response\"",
        "did not return the exact signed-response assertion",
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

    try validateSecretVaultHardwareProviderBoundary(allocator, io, errors);
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

    if (std.mem.eql(u8, track_id, "storage-object-store-durability")) {
        try validateStorageModernOnlyTrack(allocator, io, errors, track);
    }
    if (std.mem.eql(u8, track_id, "boot-attestation-update-chain")) {
        try validateBootAttestationProviderTrack(allocator, io, errors);
    }
    if (std.mem.eql(u8, track_id, "userspace-launch-provenance")) {
        try validateNativeOnlyLaunchTrack(allocator, io, errors);
    }
    if (std.mem.eql(u8, track_id, "sync-private-overlay")) {
        try validateSyncPrivateOverlayTrack(allocator, io, errors);
    }
    if (std.mem.eql(u8, track_id, "resource-scheduler-telemetry")) {
        try validateResourceSchedulerTelemetryTrack(allocator, io, errors);
    }
    if (std.mem.eql(u8, track_id, "userspace-driver-data-path")) {
        try validateUserspaceDriverDataPathTrack(allocator, io, errors);
    }
}

fn validateStorageModernOnlyTrack(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    track: std.json.Value,
) !void {
    const source_path = "src/native/storage/storage_volume.zig";
    if (!common.pathExists(io, source_path)) {
        try common.addError(errors, allocator, "Storage production track references missing source: {s}", .{source_path});
        return;
    }
    const source = try common.readFileAlloc(allocator, io, source_path, common.source_file_max_bytes);
    const required_snippets = [_][]const u8{
        "if (image.len < image_bytes) return error.ImageTooSmall",
        "workspaces.workspaces.get(workspace_id)",
        "workspaces.snapshots.slotIndexOf(snapshot_id)",
    };
    for (required_snippets) |snippet| {
        if (std.mem.indexOf(u8, source, snippet) == null) {
            try common.addError(errors, allocator, "Storage production track must keep modern-only/indexed replay snippet: {s}", .{snippet});
        }
    }
    const production_attachment_snippets = [_][]const u8{
        "pub fn attachNvmePciBackend(self: *Volume, backend: Backend) void",
        "pub fn hasProductionStorageBackend(self: *const Volume) bool",
        "self.attached_backend_kind == .nvme_pci",
    };
    for (production_attachment_snippets) |snippet| {
        if (std.mem.indexOf(u8, source, snippet) == null) {
            try common.addError(errors, allocator, "Storage production track must keep target NVMe attachment snippet: {s}", .{snippet});
        }
    }

    const backend_source_path = "src/native/storage/volume/backend.zig";
    const backend_source = try readRequiredSource(allocator, io, errors, backend_source_path) orelse return;
    const backend_snippets = [_][]const u8{"nvme_pci"};
    for (backend_snippets) |snippet| {
        if (std.mem.indexOf(u8, backend_source, snippet) == null) {
            try common.addError(errors, allocator, "Storage production track must keep distinct backend kind: {s}", .{snippet});
        }
    }

    const driver_port_path = "src/native/drivers/bootstrap_driver_port.zig";
    const driver_port_source = try readRequiredSource(allocator, io, errors, driver_port_path) orelse return;
    const driver_port_snippets = [_][]const u8{
        "attachPublishedStorageBackend(publication, publication.backend.?)",
        "storagePublicationMatchesTargetNvme",
        "storage_volume.attachNvmePciBackend(backend)",
        "StorageControllerSession",
        "device_broker.publishPciController(publication.device_id)",
    };
    for (driver_port_snippets) |snippet| {
        if (std.mem.indexOf(u8, driver_port_source, snippet) == null) {
            try common.addError(errors, allocator, "Storage production track must gate attached storage backend activation: {s}", .{snippet});
        }
    }

    const storage_test_path = "src/native/storage/storage_volume_test.zig";
    const storage_test_source = try readRequiredSource(allocator, io, errors, storage_test_path) orelse return;
    if (std.mem.indexOf(u8, storage_test_source, "storage volume separates generic and target nvme attachments") == null) {
        try common.addError(errors, allocator, "Storage production track must keep regression coverage for production storage attachment kinds", .{});
    }
    if (std.mem.indexOf(u8, backend_source, "ata_bootstrap_broker") != null or
        std.mem.indexOf(u8, driver_port_source, "attachAtaBootstrap") != null)
    {
        try common.addError(errors, allocator, "Storage production track must not reintroduce the retired ATA attachment bridge", .{});
    }

    const native_store_mount_path = "src/native/session/native_store_mount.zig";
    const native_store_mount_source = try readRequiredSource(allocator, io, errors, native_store_mount_path) orelse return;
    const native_store_mount_snippets = [_][]const u8{
        "pub fn canAdoptProductionRootVolume(root_volume: anytype) bool",
        "return root_volume.hasProductionStorageBackend()",
        "if (!canAdoptProductionRootVolume(root_volume)) return false",
        "checkpoint_store.adoptRootVolume(root_volume)",
        "native store root adoption only accepts production NVMe PCI volumes",
    };
    for (native_store_mount_snippets) |snippet| {
        if (std.mem.indexOf(u8, native_store_mount_source, snippet) == null) {
            try common.addError(errors, allocator, "Storage production track must keep NVMe-only native store adoption snippet: {s}", .{snippet});
        }
    }
    const retired_native_store_mount_snippets = [_][]const u8{
        "checkpoint_store.volume.attachBackendFns(",
        "checkpoint_store.volume.attachAtaBootstrapDevice(",
        "checkpoint_store.volume.attachAtaBootstrapBrokerBackendFns(",
    };
    for (retired_native_store_mount_snippets) |snippet| {
        if (std.mem.indexOf(u8, native_store_mount_source, snippet) != null) {
            try common.addError(errors, allocator, "Storage production track must not adopt non-NVMe root storage into the native store: {s}", .{snippet});
        }
    }

    const checkpoint_source_path = "src/native/storage/storage_service_checkpoint.zig";
    const checkpoint_source = try readRequiredSource(allocator, io, errors, checkpoint_source_path) orelse return;
    const shared_root_volume_snippets = [_][]const u8{
        "const shares_root_volume = builtin.target.os.tag == .freestanding and @hasDecl(root, \"storage_volume\")",
        "const CheckpointVolume = if (shares_root_volume) void else storage_volume.Volume",
        "return storage_volume.defaultVolume()",
        "if (comptime !shares_root_volume)",
    };
    for (shared_root_volume_snippets) |snippet| {
        if (std.mem.indexOf(u8, checkpoint_source, snippet) == null) {
            try common.addError(errors, allocator, "Storage production track must keep the freestanding checkpoint store on the shared root volume: {s}", .{snippet});
        }
    }

    const removed_snippets = [_][]const u8{
        "findWorkspaceSlotById",
        "findSnapshotSlotIndexById",
    };
    for (removed_snippets) |snippet| {
        if (std.mem.indexOf(u8, source, snippet) != null) {
            try common.addError(errors, allocator, "Storage production track must not reintroduce replay scan helper: {s}", .{snippet});
        }
    }

    const retired_manifest_claims = [_][]const u8{
        "demo-image migration",
        "migration inputs",
    };
    for (retired_manifest_claims) |claim| {
        if (trackListContains(track, "current_evidence", claim) or
            trackListContains(track, "graduation_criteria", claim) or
            trackListContains(track, "next_actions", claim))
        {
            try common.addError(errors, allocator, "Storage production track must not claim migration support: {s}", .{claim});
        }
    }
}

fn validateBootAttestationProviderTrack(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const source_path = "src/native/platform/attestation_service.zig";
    const source = try readRequiredSource(allocator, io, errors, source_path) orelse return;

    const required_snippets = [_][]const u8{
        "hasTestOnlyOperationalName",
        "containsNameTokenIgnoreCase",
        "isOperationalNameSeparator",
        "containsAsciiIgnoreCase",
        "!self.hasProductionUnsafeName()",
        "hasTestOnlyOperationalName(key.label)",
        "hasTestOnlyOperationalName(provider.label())",
        "AttestationVerifierMetadata.fromProvider",
        "ExternalAttestationRootProvider.init",
        "production attestation descriptors reject test-only operational names",
    };
    for (required_snippets) |snippet| {
        if (std.mem.indexOf(u8, source, snippet) == null) {
            try common.addError(errors, allocator, "Boot attestation production track must keep provider hardening snippet: {s}", .{snippet});
        }
    }
}

fn validateSyncPrivateOverlayTrack(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const harness_path = "src/native/sync/sync_transport_harness.zig";
    const harness_source = try readRequiredSource(allocator, io, errors, harness_path) orelse return;

    const required_snippets = [_][]const u8{
        "evidence.hasVerifiedRemoteAttestation() and",
        "evidence.hasAttestationVerifierMetadataDigest()",
        "root-pinned-without-metadata",
        "SessionTrustPosture.local_lab_only, root_pinned_session.trust_posture",
        "root_pinned_session.requireProductionAttestation()",
    };
    for (required_snippets) |snippet| {
        if (std.mem.indexOf(u8, harness_source, snippet) == null) {
            try common.addError(errors, allocator, "Sync private overlay track must keep production attestation posture snippet: {s}", .{snippet});
        }
    }

    const policy_path = "src/native/sync/network_policy.zig";
    const policy_source = try readRequiredSource(allocator, io, errors, policy_path) orelse return;
    const policy_snippets = [_][]const u8{
        "pub fn hasAttestationVerifierMetadataDigest(self: *const ConnectionEvidence) bool",
        "self.attestation_verifier_metadata_digest_bound",
        "pinned_attestation_verifier_metadata_digest_present",
    };
    for (policy_snippets) |snippet| {
        if (std.mem.indexOf(u8, policy_source, snippet) == null) {
            try common.addError(errors, allocator, "Sync private overlay track must keep verifier metadata policy snippet: {s}", .{snippet});
        }
    }
}

fn validateSecretVaultHardwareProviderBoundary(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const store_path = "src/native/platform/secure_secret_store.zig";
    const store_source = try readRequiredSource(allocator, io, errors, store_path) orelse return;
    const store_snippets = [_][]const u8{
        "HardwareProviderUnavailable",
        "self.hardware_provider.seal(label, raw) orelse return error.HardwareProviderUnavailable",
        "secret.hardware_provider_used = true",
        "self.secrets.insertIndex(secret_id, .{ .secret = secret })",
        "secure secret store requires a hardware provider before hardware-backed imports",
    };
    for (store_snippets) |snippet| {
        if (std.mem.indexOf(u8, store_source, snippet) == null) {
            try common.addError(errors, allocator, "Secret vault hardware-backed boundary must keep store snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, store_source, "digestSecretMaterial") != null) {
        try common.addError(errors, allocator, "Secret vault hardware-backed boundary must not reintroduce software digest fallback for hardware-backed secrets", .{});
    }

    const service_path = "src/native/services/secret_vault_service.zig";
    const service_source = try readRequiredSource(allocator, io, errors, service_path) orelse return;
    const service_snippets = [_][]const u8{
        "service.attachHardwareProvider(testHardwareProvider())",
        "expiry_service.attachHardwareProvider(testHardwareProvider())",
        "export_service.attachHardwareProvider(testHardwareProvider())",
    };
    for (service_snippets) |snippet| {
        if (std.mem.indexOf(u8, service_source, snippet) == null) {
            try common.addError(errors, allocator, "Secret vault hardware-backed boundary must keep service provider test snippet: {s}", .{snippet});
        }
    }

    const identity_path = "src/native/platform/os_identity.zig";
    const identity_source = try readRequiredSource(allocator, io, errors, identity_path) orelse return;
    const identity_snippets = [_][]const u8{
        "testHardwareProvider() secure_secret_store.HardwareSealProvider",
        "secrets.attachHardwareProvider(testHardwareProvider())",
    };
    for (identity_snippets) |snippet| {
        if (std.mem.indexOf(u8, identity_source, snippet) == null) {
            try common.addError(errors, allocator, "Secret vault hardware-backed boundary must keep identity provider test snippet: {s}", .{snippet});
        }
    }

    const contract_path = "src/native/platform/os_contract.zig";
    const contract_source = try readRequiredSource(allocator, io, errors, contract_path) orelse return;
    const contract_snippets = [_][]const u8{
        "credentialContractHardwareProvider",
        "secrets.attachHardwareProvider(credentialContractHardwareProvider())",
        "secretVaultContractHardwareProvider",
        "service.attachHardwareProvider(secretVaultContractHardwareProvider())",
        "secret.hardware_provider_used",
    };
    for (contract_snippets) |snippet| {
        if (std.mem.indexOf(u8, contract_source, snippet) == null) {
            try common.addError(errors, allocator, "Secret vault hardware-backed boundary must keep contract provider evidence snippet: {s}", .{snippet});
        }
    }

    const benchmark_path = "src/kernel/boot/benchmark/suite.zig";
    const benchmark_source = try readRequiredSource(allocator, io, errors, benchmark_path) orelse return;
    const benchmark_snippets = [_][]const u8{
        "secret_store_context.store.attachHardwareProvider(.{ .available = true })",
        "const secret = secret_store_context.store.importSecret(",
    };
    for (benchmark_snippets) |snippet| {
        if (std.mem.indexOf(u8, benchmark_source, snippet) == null) {
            try common.addError(errors, allocator, "Secret vault hardware-backed boundary must keep benchmark provider snippet: {s}", .{snippet});
        }
    }
}

fn validateResourceSchedulerTelemetryTrack(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const accelerator_path = "src/native/task/accelerator_scheduler.zig";
    const userspace_path = "src/native/task/userspace_scheduler.zig";
    const platform_policy_signals_path = "src/native/platform/platform_policy_signals.zig";
    const benchmark_path = "src/kernel/boot/benchmark/suite.zig";
    const accelerator_source = try readRequiredSource(allocator, io, errors, accelerator_path) orelse return;
    const userspace_source = try readRequiredSource(allocator, io, errors, userspace_path) orelse return;
    const platform_policy_signals_source = try readRequiredSource(allocator, io, errors, platform_policy_signals_path) orelse return;
    const benchmark_source = try readRequiredSource(allocator, io, errors, benchmark_path) orelse return;

    const accelerator_snippets = [_][]const u8{
        "production_hardware_telemetry_required: bool = false",
        "requireProductionHardwareTelemetryForAccelerators",
        "self.last_telemetry_source == .hardware and self.last_hardware_evidence_complete",
        "accelerator scheduler production mode requires complete hardware telemetry before accelerator claims",
    };
    for (accelerator_snippets) |snippet| {
        if (std.mem.indexOf(u8, accelerator_source, snippet) == null) {
            try common.addError(errors, allocator, "Resource scheduler telemetry track must keep production hardware gate snippet: {s}", .{snippet});
        }
    }

    const userspace_snippets = [_][]const u8{
        "return self.resource_telemetry_source == .hardware and self.resource_hardware_evidence_complete",
        "userspace scheduler requires complete hardware telemetry before waking hardware queues",
        "scheduler.grantNextAcceleratorClaim(.media, 9) == null",
    };
    for (userspace_snippets) |snippet| {
        if (std.mem.indexOf(u8, userspace_source, snippet) == null) {
            try common.addError(errors, allocator, "Resource scheduler telemetry track must keep complete-hardware queue gate snippet: {s}", .{snippet});
        }
    }

    if (std.mem.indexOf(u8, userspace_source, "return self.resource_telemetry_source != .hardware or self.resource_hardware_evidence_complete") != null) {
        try common.addError(errors, allocator, "Resource scheduler telemetry track must not let emulator or boot-provider telemetry wake hardware queues", .{});
    }

    const platform_policy_signal_snippets = [_][]const u8{
        "const generated_image_fixtures = @import(\"../task/generated_image_fixtures.zig\")",
        "const foreground_image = try generated_image_fixtures.appImage()",
        "const private_image = try generated_image_fixtures.appImage()",
    };
    for (platform_policy_signal_snippets) |snippet| {
        if (std.mem.indexOf(u8, platform_policy_signals_source, snippet) == null) {
            try common.addError(errors, allocator, "Resource scheduler telemetry track must keep generated-image runtime counter fixture snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, platform_policy_signals_source, "syntheticUserspaceImage(") != null) {
        try common.addError(errors, allocator, "Resource scheduler telemetry track must not derive hardware policy counters from synthetic executable descriptors", .{});
    }

    const benchmark_snippets = [_][]const u8{
        "const generated_image_fixtures = @import(\"../../../native/task/generated_image_fixtures.zig\")",
        "benchmark_image_context.app_image = generated_image_fixtures.appImage() catch |err| benchmark_reporting.benchStepFailure(\"benchmark suite\", err)",
        "const image = if (service_task) benchmarkServiceImage() else benchmarkAppImage()",
    };
    for (benchmark_snippets) |snippet| {
        if (std.mem.indexOf(u8, benchmark_source, snippet) == null) {
            try common.addError(errors, allocator, "Resource scheduler telemetry track must keep generated-image benchmark fixture snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, benchmark_source, "syntheticUserspaceImage(") != null) {
        try common.addError(errors, allocator, "Resource scheduler telemetry track must not benchmark scheduler load tasks with synthetic executable descriptors", .{});
    }
}

fn validateUserspaceDriverDataPathTrack(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const broker_path = "src/native/kernel_api/device_broker.zig";
    const native_abi_path = "src/native/core/abi.zig";
    const component_port_path = "src/native/kernel_api/component_port.zig";
    const native_kernel_path = "src/native/kernel_api/native_kernel.zig";
    const device_syscalls_path = "src/native/kernel_api/device_syscalls.zig";
    const syscall_surface_path = "src/native/kernel_api/syscall_surface.zig";
    const bootstrap_driver_port_path = "src/native/drivers/bootstrap_driver_port.zig";
    const driver_runtime_path = "src/native/drivers/driver_runtime.zig";
    const driver_spec_path = "src/tests/spec/drivers_storage_sync.zig";
    const backlog_gate_path = "src/tests/spec/backlog_gates.zig";
    const broker_source = try readRequiredSource(allocator, io, errors, broker_path) orelse return;
    const native_abi_source = try readRequiredSource(allocator, io, errors, native_abi_path) orelse return;
    const component_port_source = try readRequiredSource(allocator, io, errors, component_port_path) orelse return;
    const native_kernel_source = try readRequiredSource(allocator, io, errors, native_kernel_path) orelse return;
    const device_syscalls_source = try readRequiredSource(allocator, io, errors, device_syscalls_path) orelse return;
    const syscall_surface_source = try readRequiredSource(allocator, io, errors, syscall_surface_path) orelse return;
    const bootstrap_driver_port_source = try readRequiredSource(allocator, io, errors, bootstrap_driver_port_path) orelse return;
    const driver_runtime_source = try readRequiredSource(allocator, io, errors, driver_runtime_path) orelse return;
    const driver_spec_source = try readRequiredSource(allocator, io, errors, driver_spec_path) orelse return;
    const backlog_gate_source = try readRequiredSource(allocator, io, errors, backlog_gate_path) orelse return;

    const broker_snippets = [_][]const u8{
        "UnsupportedBusMasterDma",
        "if (request.bus_master_dma_enabled and request.mode != .brokered_dma_buffers)",
        "device broker records AMD-Vi evidence and confines bus-master DMA",
        "try std.testing.expectError(error.UnsupportedBusMasterDma, programDmaIsolation",
        "try std.testing.expect(!status.bus_master_dma_enabled)",
        "pub fn programBusMasterStorageDmaIsolation",
        "pub fn publishPciController",
        "device broker publishes only PCI controllers",
    };
    for (broker_snippets) |snippet| {
        if (std.mem.indexOf(u8, broker_source, snippet) == null) {
            try common.addError(errors, allocator, "Userspace driver data path must keep bus-master DMA confinement snippet: {s}", .{snippet});
        }
    }
    const retired_broker_snippets = [_][]const u8{
        "publishAtaController",
        "HostedAtaControllerState",
        "storage_driver_protocol",
        "x86.inb",
        "x86.outb",
    };
    for (retired_broker_snippets) |snippet| {
        if (std.mem.indexOf(u8, broker_source, snippet) != null) {
            try common.addError(errors, allocator, "Userspace driver data path must not reintroduce the retired ATA broker surface: {s}", .{snippet});
        }
    }
    const device_abi_snippets = [_][]const u8{
        "pub const ABI_VERSION: u16 = 2",
        "pub const DEVICE_DESCRIPTOR_RESERVED_BYTES: usize = 7",
        "pub const DeviceDescriptor = ex" ++ "tern struct",
        "mmio_window_count: u8",
    };
    for (device_abi_snippets) |snippet| {
        if (std.mem.indexOf(u8, native_abi_source, snippet) == null) {
            try common.addError(errors, allocator, "Userspace driver data path must keep the compact PCI/MMIO native ABI snippet: {s}", .{snippet});
        }
    }
    const port_abi_sources = [_]struct {
        path: []const u8,
        source: []const u8,
    }{
        .{ .path = native_abi_path, .source = native_abi_source },
        .{ .path = broker_path, .source = broker_source },
        .{ .path = component_port_path, .source = component_port_source },
        .{ .path = native_kernel_path, .source = native_kernel_source },
        .{ .path = device_syscalls_path, .source = device_syscalls_source },
        .{ .path = syscall_surface_path, .source = syscall_surface_source },
    };
    const retired_port_abi_snippets = [_][]const u8{
        "device_port_read",
        "device_port_write",
        "DevicePortRead",
        "DevicePortWrite",
        "DevicePortWidth",
        "devicePortRead",
        "devicePortWrite",
    };
    for (port_abi_sources) |source| {
        for (retired_port_abi_snippets) |snippet| {
            if (std.mem.indexOf(u8, source.source, snippet) != null) {
                try common.addError(errors, allocator, "Userspace driver data path must not reintroduce port-I/O ABI snippet in {s}: {s}", .{ source.path, snippet });
            }
        }
    }

    const storage_dma_wiring_snippets = [_][]const u8{
        "fn programStorageDmaIsolation(device_id: u64, dma_domain_id: u64) bool",
        "device_broker.programBusMasterStorageDmaIsolation(device_id, dma_domain_id, windows[0..count])",
        "windows[0] = device_broker.defaultBrokeredDmaWindow(device_id)",
    };
    for (storage_dma_wiring_snippets) |snippet| {
        if (std.mem.indexOf(u8, bootstrap_driver_port_source, snippet) == null) {
            try common.addError(errors, allocator, "Userspace driver data path must confine the real storage DMA engine through the broker: {s}", .{snippet});
        }
    }

    const network_activation_snippets = [_][]const u8{
        "networkPublicationMatchesTargetI225",
        "device_inventory.requireProductionDriverDeviceId(.network_adapter)",
        "if (!networkPublicationMatchesTargetI225(device_id)) return false",
        "try std.testing.expect(!activateNetworkDevice(i225_device_id, 9))",
    };
    for (network_activation_snippets) |snippet| {
        if (std.mem.indexOf(u8, bootstrap_driver_port_source, snippet) == null) {
            try common.addError(errors, allocator, "Userspace driver data path must keep I225-only network activation snippet: {s}", .{snippet});
        }
    }
    const network_driver_spec_snippets = [_][]const u8{
        "device_inventory.registerDetected(.network_adapter, network_device_id, .intel_i225_lm_inventory, false)",
        "\"i225-userspace\"",
        "try std.testing.expect(!bootstrap_driver_port.activateNetworkDevice(i225_device_id, 800))",
    };
    for (network_driver_spec_snippets) |snippet| {
        if (std.mem.indexOf(u8, driver_spec_source, snippet) == null) {
            try common.addError(errors, allocator, "Userspace driver data path spec must keep I225-only network fixture snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, driver_spec_source, "e1000-userspace") != null) {
        try common.addError(errors, allocator, "Userspace driver data path spec must not use e1000 as a production network fixture", .{});
    }

    const generated_driver_fixture_sources = [_]struct {
        path: []const u8,
        source: []const u8,
        snippets: []const []const u8,
    }{
        .{
            .path = bootstrap_driver_port_path,
            .source = bootstrap_driver_port_source,
            .snippets = &.{"try generated_image_fixtures.storageDriverImage()"},
        },
        .{
            .path = driver_runtime_path,
            .source = driver_runtime_source,
            .snippets = &.{"try generated_image_fixtures.storageDriverImage()"},
        },
        .{
            .path = backlog_gate_path,
            .source = backlog_gate_source,
            .snippets = &.{
                "try generated_image_fixtures.serviceClientImage()",
                "try generated_image_fixtures.storageDriverImage()",
                "try generated_image_fixtures.appImage()",
            },
        },
    };
    for (generated_driver_fixture_sources) |fixture_source| {
        if (std.mem.indexOf(u8, fixture_source.source, "syntheticUserspaceImage(") != null) {
            try common.addError(errors, allocator, "Userspace driver data path must not use synthetic executable descriptors in {s}", .{fixture_source.path});
        }
        for (fixture_source.snippets) |snippet| {
            if (std.mem.indexOf(u8, fixture_source.source, snippet) == null) {
                try common.addError(errors, allocator, "Userspace driver data path must keep generated image fixture snippet in {s}: {s}", .{ fixture_source.path, snippet });
            }
        }
    }
}

fn trackListContains(track: std.json.Value, field_name: []const u8, needle: []const u8) bool {
    const value = common.field(track, field_name) orelse return false;
    if (value != .array) return false;
    for (value.array.items) |item| {
        if (item == .string and std.mem.indexOf(u8, item.string, needle) != null) return true;
    }
    return false;
}

fn validateNativeOnlyLaunchTrack(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const manifest_path = "src/native/policy/manifest.zig";
    const linter_path = "src/native/sdk/manifest_linter.zig";
    const contract_path = "src/native/platform/os_contract.zig";
    const boot_registry_path = "src/native/task/userspace_boot_registry.zig";
    const archive_index_path = "src/native/task/userspace_archive_index.zig";
    const loader_path = "src/native/task/userspace_loader.zig";
    const launch_path = "src/native/task/userspace_launch.zig";
    const rendered_shell_launch_path = "src/native/platform/rendered_shell/task_launch.zig";

    const manifest_source = try readRequiredSource(allocator, io, errors, manifest_path) orelse return;
    const linter_source = try readRequiredSource(allocator, io, errors, linter_path) orelse return;
    const contract_source = try readRequiredSource(allocator, io, errors, contract_path) orelse return;
    const boot_registry_source = try readRequiredSource(allocator, io, errors, boot_registry_path) orelse return;
    const archive_index_source = try readRequiredSource(allocator, io, errors, archive_index_path) orelse return;
    const loader_source = try readRequiredSource(allocator, io, errors, loader_path) orelse return;
    const launch_source = try readRequiredSource(allocator, io, errors, launch_path) orelse return;
    const rendered_shell_launch_source = try readRequiredSource(allocator, io, errors, rendered_shell_launch_path) orelse return;

    const required_manifest_snippets = [_][]const u8{
        "CompatibilityNamespaceUnsupported",
        "try validateNativeOnlyNaming(bundle)",
        "isUnsupportedCompatibilityNamespace",
        "return !isReservedPlatformBundle(bundle_id) and",
        "!isUnsupportedCompatibilityNamespace(bundle_id)",
    };
    for (required_manifest_snippets) |snippet| {
        if (std.mem.indexOf(u8, manifest_source, snippet) == null) {
            try common.addError(errors, allocator, "Native-only launch track must keep manifest validation snippet: {s}", .{snippet});
        }
    }

    const required_linter_snippets = [_][]const u8{
        "manifest.isUnsupportedCompatibilityNamespace(bundle.bundle_id)",
        "manifest.isUnsupportedCompatibilityNamespace(component.entry)",
        "idlMentionsPosix",
        "idlMentionsCompat",
    };
    for (required_linter_snippets) |snippet| {
        if (std.mem.indexOf(u8, linter_source, snippet) == null) {
            try common.addError(errors, allocator, "Native-only launch track must keep SDK linter manifest-policy snippet: {s}", .{snippet});
        }
    }

    const required_contract_snippets = [_][]const u8{
        "!manifest.isApplicationBundle(\"compat.posix\")",
        "error.CompatibilityNamespaceUnsupported",
    };
    for (required_contract_snippets) |snippet| {
        if (std.mem.indexOf(u8, contract_source, snippet) == null) {
            try common.addError(errors, allocator, "Native-only launch track must keep OS contract snippet: {s}", .{snippet});
        }
    }

    const required_boot_registry_snippets = [_][]const u8{
        "const archive_index = @import(\"userspace_archive_index.zig\")",
        "GeneratedArtifactMissing",
        "validateGeneratedArchiveHasOnlyRegisteredSpecs",
        "generatedArtifactFor(spec.bundle_id) orelse return error.GeneratedArtifactMissing",
        "catalog.registerEmbeddedArtifactWithInfo",
        "try std.testing.expect(catalog.findByBundleId(\"zigos.system.session-manager\").?.embedsElf())",
    };
    for (required_boot_registry_snippets) |snippet| {
        if (std.mem.indexOf(u8, boot_registry_source, snippet) == null) {
            try common.addError(errors, allocator, "Native-only launch track must keep archive-backed boot registry snippet: {s}", .{snippet});
        }
    }
    const required_archive_index_snippets = [_][]const u8{
        "const archive = @import(\"userspace_archive\")",
        "const bundle_index = buildBundleIndex()",
        "id_index.lookup",
        "return artifact",
        "test \"userspace archive index resolves every generated artifact bundle\"",
    };
    for (required_archive_index_snippets) |snippet| {
        if (std.mem.indexOf(u8, archive_index_source, snippet) == null) {
            try common.addError(errors, allocator, "Native-only launch track must keep indexed archive lookup snippet: {s}", .{snippet});
        }
    }

    const required_loader_snippets = [_][]const u8{
        "const embedded_info = embedded orelse return error.EmbeddedArtifactRequired",
        "if (!has_embedded_artifact) {",
        "test \"catalog rejects metadata-only executable registration\"",
    };
    for (required_loader_snippets) |snippet| {
        if (std.mem.indexOf(u8, loader_source, snippet) == null) {
            try common.addError(errors, allocator, "Native-only launch track must keep embedded-artifact catalog snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, loader_source, "syntheticExecutableImage") != null) {
        try common.addError(errors, allocator, "Native-only launch track must not synthesize catalog executable images from metadata-only requests", .{});
    }

    const required_launch_snippets = [_][]const u8{
        "if (!image.embedsElf()) {",
        "try userspace_boot_registry.registerAll(catalog)",
        "if (!image.embedsElf()) return error.EmbeddedArtifactRequired",
        "logLaunchFailure(bundle.bundle_id, failure_phase, error.EmbeddedArtifactRequired)",
    };
    for (required_launch_snippets) |snippet| {
        if (std.mem.indexOf(u8, launch_source, snippet) == null) {
            try common.addError(errors, allocator, "Native-only launch track must keep archive-backed launch guard snippet: {s}", .{snippet});
        }
    }

    const required_rendered_shell_launch_snippets = [_][]const u8{
        "generated_image_fixtures.imageByBundleId(config.bundle_id)",
        "const image = try imageForConfig(config, builtin.is_test)",
        "if (!allow_model_only_fallback) return err",
        "test \"rendered shell task launch requires generated image outside model-only tests\"",
    };
    for (required_rendered_shell_launch_snippets) |snippet| {
        if (std.mem.indexOf(u8, rendered_shell_launch_source, snippet) == null) {
            try common.addError(errors, allocator, "Native-only launch track must keep rendered-shell archive image snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, rendered_shell_launch_source, "const image = task_runtime.syntheticUserspaceImage(config.task_label, config.task_entry)") != null) {
        try common.addError(errors, allocator, "Native-only launch track must not synthesize rendered-shell task launch descriptors unconditionally", .{});
    }
}

fn readRequiredSource(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    path: []const u8,
) !?[]const u8 {
    if (!common.pathExists(io, path)) {
        try common.addError(errors, allocator, "Required production-readiness source is missing: {s}", .{path});
        return null;
    }
    return try common.readFileAlloc(allocator, io, path, common.source_file_max_bytes);
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

test "hardware marker lookup ignores commented requirements" {
    const source =
        "# ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:UEFI_BOOT:PASS\n" ++
        "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_TABLES:PASS\n";

    try std.testing.expect(!markerFileHasActiveLine(source, "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:UEFI_BOOT:PASS"));
    try std.testing.expect(markerFileHasActiveLine(source, "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_TABLES:PASS"));
}

test "hardware marker lookup requires a complete active line" {
    const source = "prefix ZIGOS:NATIVE:READY suffix\nZIGOS:NATIVE:READY_EXTRA\n";
    try std.testing.expect(!markerFileHasActiveLine(source, "ZIGOS:NATIVE:READY"));
}
