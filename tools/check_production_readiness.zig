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
const FIRST_HARDWARE_TARGET_ID = "asus-nuc15crsu7";
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
    "vtd_discovery",
    "vtd_storage_isolation",
    "vtd_interrupt_isolation",
    "vtd_fault_capture",
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
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:UEFI_BOOT:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ACPI_TABLES:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:VT_D_DISCOVERY:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:VT_D_STORAGE_ISOLATION:ENFORCED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:VT_D_INTERRUPT_ISOLATION:ENFORCED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:VT_D_BLOCKED_DMA_FAULT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:APIC_TIMER:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:FRAMEBUFFER_GOP:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:USB_INPUT_XHCI:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:NVME_BLOCK:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:NETWORK_I225_LM:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:SUSPEND_RESUME:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:CRASH_RECOVERY:PASS",
};
const FIRST_HARDWARE_TARGET_REQUIRED_FACT_MARKERS = [_][]const u8{
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:SMBIOS_SKU:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:MULTIBOOT_MEMORY_MAP:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ACPI_XSDT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ACPI_MADT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ACPI_FADT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ACPI_DMAR:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:VT_D_SEGMENT_ZERO:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:VT_D_BLOCKED_DMA_FAULT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:APIC_TIMER_INTERRUPT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:FRAMEBUFFER_GOP_SCANOUT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:XHCI_BOOT_KEYBOARD_REPORT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:NVME_WRITE_READ_COMPLETION:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:I225_LM_FRAME_INTERRUPT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:SUSPEND_RESUME_POWER:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:CRASH_RECORD_REBOOT_PERSISTENCE:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:UPDATE_ROLLBACK_POWER_CYCLE:OBSERVED",
};
const FIRST_HARDWARE_TARGET_REQUIRED_BOOTED_PROOF_MARKERS = [_][]const u8{
    "BOOT:ROLE:verification",
    "ZIGOS:CPU:PGE:ENABLED",
    "ZIGOS:CPU:FRED:ENABLED",
    "ZIGOS:CPU:PCID:ENABLED",
    "ZIGOS:USERSPACE:ARTIFACTS:READY",
    "ZIGOS:USERSPACE:SCHEDULER:READY",
    "ZIGOS:USERSPACE:SCHEDULER:EVENT_WAIT:READY",
    "ZIGOS:USERSPACE:UI_STATE:READY",
    "ZIGOS:USERSPACE:EXEC_PROBE:OK",
    "ZIGOS:USERSPACE:RESUME:OK",
    "ZIGOS:SERVICE_BOOT:SERVICE_CONTRACTS:READY",
    "ZIGOS:SERVICE_BOOT:IPC_CONNECT:ALL_OK",
    "ZIGOS:SERVICE_BOOT:DRIVER:STORAGE_REBIND_OK",
    "ZIGOS:SERVICE_BOOT:DRIVER:CONTROLLER_REVOKE_REJECTED",
    "ZIGOS:SERVICE_BOOT:DRIVER:STORAGE_REPUBLISH_AFTER_REVOKE_OK",
    "ZIGOS:COMPOSITOR:SERVICE:READY",
    "ZIGOS:COMPOSITOR:INPUT_ROUTER:READY",
    "ZIGOS:USERSPACE:INPUT_ABI:READY",
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
    "ZIGOS:CPU:PGE:ENABLED",
    "ZIGOS:CPU:FRED:ENABLED",
    "ZIGOS:CPU:PCID:ENABLED",
    "BOOT:CORE_READY",
    "ZIGOS:KERNEL_NETWORK:DEFERRED",
    "ZIGOS:NATIVE:BOOTSTRAP",
    "ZIGOS:TCB:DEFINED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:EVIDENCE_SOURCE:REAL_HARDWARE",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:BOARD_SKU:RNUC15CRSU7",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:SMBIOS_SKU:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:MULTIBOOT_MEMORY_MAP:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ACPI_XSDT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ACPI_MADT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ACPI_FADT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ACPI_DMAR:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:VT_D_SEGMENT_ZERO:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ACPI_TABLES:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:VT_D_DISCOVERY:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:VT_D_STORAGE_ISOLATION:ENFORCED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:VT_D_INTERRUPT_ISOLATION:ENFORCED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:VT_D_BLOCKED_DMA_FAULT:OBSERVED",
    "ZIGOS:USERSPACE:SCHEDULER:READY",
    "ZIGOS:USERSPACE:SCHEDULER:EVENT_WAIT:READY",
    "ZIGOS:USERSPACE:UI_STATE:READY",
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
    "ZIGOS:COMPOSITOR:INPUT_ROUTER:READY",
    "ZIGOS:USERSPACE:INPUT_ABI:READY",
    "ZIGOS:PLATFORM:BOOT_DESCRIPTOR:VERIFIED",
    "ZIGOS:PLATFORM:BUILD_ARTIFACT_MANIFEST:VERIFIED",
    "ZIGOS:PLATFORM:MEASUREMENT_SNAPSHOT:VERIFIED",
    "ZIGOS:PLATFORM:ARTIFACT_MANIFEST:VERIFIED",
    "ZIGOS:PLATFORM:MEASURED_BOOT:RECORDED",
    "ZIGOS:PLATFORM:MEASURED_BOOT:VERIFIED_ROOT",
    "ZIGOS:PLATFORM:BOOT_IMAGE:FIRMWARE_AUTHENTICATED",
    "ZIGOS:TPM2:BOOT_MEASUREMENT:VERIFIED",
    "ZIGOS:TPM2:FINAL_EVENTS:VERIFIED",
    "ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false",
    "ZIGOS:TASK:SESSION_READY",
    "ZIGOS:NATIVE:READY",
};
const FIRST_HARDWARE_TARGET_FORBIDDEN_PRODUCTION_MARKERS = [_][]const u8{
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:UEFI_BOOT:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:APIC_TIMER_INTERRUPT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:APIC_TIMER:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:FRAMEBUFFER_GOP_SCANOUT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:FRAMEBUFFER_GOP:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:XHCI_BOOT_KEYBOARD_REPORT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:USB_INPUT_XHCI:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:NVME_WRITE_READ_COMPLETION:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:NVME_BLOCK:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:I225_LM_FRAME_INTERRUPT:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:NETWORK_I225_LM:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:SUSPEND_RESUME_POWER:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:SUSPEND_RESUME:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:CRASH_RECORD_REBOOT_PERSISTENCE:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:CRASH_RECOVERY:PASS",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:UPDATE_ROLLBACK_POWER_CYCLE:OBSERVED",
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ATTESTATION_ROOT_LIFECYCLE:OBSERVED",
};
const FIRST_HARDWARE_TARGET_REQUIRED_REFERENCE_ARTIFACTS = [_][]const u8{
    "src/native/platform/hardware_target.zig",
    "src/kernel/platform/dmar.zig",
    "spec/hardware/nuc15crsu7-production-required-markers.txt",
    "spec/hardware/nuc15crsu7-required-markers.txt",
    "spec/hardware/nuc15crsu7-proof-bundle.md",
    "tools/host/hardware.zig",
    "tools/host/hardware/fixtures.zig",
};
const FIRST_HARDWARE_TARGET_REQUIRED_QEMU_PREFLIGHT_COMMANDS = [_][]const u8{
    "zig build iso",
    "zig build iso-verification",
    "zig build uefi-qemu-test",
    "zig build uefi-verification-qemu-test",
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
    try validateBenchmarkEnvironmentGate(allocator, io, &errors);
    try validateSyntheticUserspaceImageMarkers(allocator, io, &errors);
    try validateEventLedgerRollover(allocator, io, &errors);
    try validateKernelTcbImports(allocator, io, &errors);

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

fn validateKernelTcbImports(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const tcb_path = "src/kernel/tcb.zig";
    const tcb_source = try readRequiredSource(allocator, io, errors, tcb_path) orelse return;
    const required_tcb_snippets = [_][]const u8{
        "pub const FORBIDS_PRODUCT_IMPORTS = true",
        "pub const KERNEL_PORT_REQUIRES_PUBLISHED_GS = true",
        "pub const IDLE_NEVER_SERVICES_DEVICE_QUEUES = true",
        "native/storage/",
        "native/sync/",
        "native/policy/",
        "native/services/",
        "native/demo/",
        "native/platform/compositor",
    };
    for (required_tcb_snippets) |snippet| {
        if (std.mem.indexOf(u8, tcb_source, snippet) == null) {
            try common.addError(errors, allocator, "kernel TCB contract must retain snippet: {s}", .{snippet});
        }
    }

    const native_profile_path = "src/kernel/boot/profiles/zigos_native.zig";
    const native_profile_source = try readRequiredSource(allocator, io, errors, native_profile_path) orelse return;
    if (std.mem.indexOf(u8, native_profile_source, "_ = xhci_driver_task.dispatch();") != null) {
        try common.addError(errors, allocator, "native idle loop must not service xHCI from the kernel", .{});
    }

    try walkKernelTcbDir(allocator, io, errors, "src/kernel");
}

fn walkKernelTcbDir(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    path: []const u8,
) !void {
    var dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true, .follow_symlinks = false }) catch |err| {
        try common.addError(errors, allocator, "kernel TCB scan could not open {s}: {s}", .{ path, @errorName(err) });
        return;
    };
    defer dir.close(io);

    var iterator = dir.iterate();
    while (iterator.next(io) catch |err| {
        try common.addError(errors, allocator, "kernel TCB scan failed in {s}: {s}", .{ path, @errorName(err) });
        return;
    }) |entry| {
        const child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ path, entry.name });
        switch (entry.kind) {
            .directory => {
                if (kernelTcbDirIsExcluded(child)) continue;
                try walkKernelTcbDir(allocator, io, errors, child);
            },
            .file => {
                if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;
                if (kernelTcbFileIsExcluded(child)) continue;
                try scanKernelTcbFile(allocator, io, errors, child);
            },
            else => {},
        }
    }
}

fn kernelTcbDirIsExcluded(path: []const u8) bool {
    return std.mem.eql(u8, path, "src/kernel/boot/benchmark");
}

fn kernelTcbFileIsExcluded(path: []const u8) bool {
    return std.mem.eql(u8, path, "src/kernel/tcb.zig") or
        std.mem.eql(u8, path, "src/kernel/boot/recovery_suite.zig") or
        std.mem.eql(u8, path, "src/kernel/boot/profiles/recovery.zig") or
        std.mem.eql(u8, path, "src/kernel/boot/profiles/benchmark.zig");
}

fn scanKernelTcbFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    path: []const u8,
) !void {
    const source = try common.readFileAlloc(allocator, io, path, common.source_file_max_bytes);
    const forbidden_prefixes = [_][]const u8{
        "native/storage/",
        "native/sync/",
        "native/policy/",
        "native/services/",
        "native/demo/",
        "native/platform/compositor",
        "native/platform/rendered_shell",
        "native/platform/os_contract",
    };
    for (forbidden_prefixes) |prefix| {
        if (std.mem.indexOf(u8, source, prefix) == null) continue;
        try common.addError(errors, allocator, "kernel TCB forbids product import {s} in {s}", .{ prefix, path });
    }
}

fn validateEventLedgerRollover(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const source_path = "src/native/platform/event_ledger.zig";
    const test_path = "src/native/platform/event_ledger_test.zig";
    const source = try readRequiredSource(allocator, io, errors, source_path) orelse return;
    const test_source = try readRequiredSource(allocator, io, errors, test_path) orelse return;
    const required_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = source_path, .source = source, .snippet = "oldest_retained_sequence: u64 = 0" },
        .{ .path = source_path, .source = source, .snippet = "backing.event_order_index.head(EVENT_ORDER_KEY)" },
        .{ .path = source_path, .source = source, .snippet = "fn nextOldestSequence(" },
        .{ .path = source_path, .source = source, .snippet = "pub const RECORDS_EVENTS_IN_PLACE = true" },
        .{ .path = source_path, .source = source, .snippet = "reserveIndexForOverwrite(sequence)" },
        .{ .path = test_path, .source = test_source, .snippet = "event ledger evicts oldest events instead of jamming past MAX_EVENTS" },
        .{ .path = test_path, .source = test_source, .snippet = "expect(event_ledger.RECORDS_EVENTS_IN_PLACE)" },
        .{ .path = test_path, .source = test_source, .snippet = "ledger.oldest_retained_sequence" },
    };
    for (required_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Indexed event-ledger rollover must retain snippet in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    if (std.mem.indexOf(u8, source, "for (&self.events.slots, 0..) |*slot, index|") != null) {
        try common.addError(errors, allocator, "Event-ledger rollover must not restore the full-slot oldest-event scan", .{});
    }
}

fn validateBenchmarkEnvironmentGate(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const capture_path = "tools/host/qemu.zig";
    const capture_source = try readRequiredSource(allocator, io, errors, capture_path) orelse return;
    const capture_snippets = [_][]const u8{
        "h.accelerator()",
        "absentGroup(h.ctx, bytes, &.{\"BENCH:ENV:\"})",
        "BENCH:ENV:accelerator={s}",
    };
    for (capture_snippets) |snippet| {
        if (std.mem.indexOf(u8, capture_source, snippet) == null) {
            try common.addError(errors, allocator, "Benchmark capture must retain host-owned accelerator evidence: {s}", .{snippet});
        }
    }

    const checker_path = "tools/check_kernel_benchmarks.zig";
    const checker_source = try readRequiredSource(allocator, io, errors, checker_path) orelse return;
    const checker_snippets = [_][]const u8{
        "BENCH:ENV:",
        "performanceGatesEnforced",
        "software-emulation functional run",
        "Duplicate benchmark accelerator record",
    };
    for (checker_snippets) |snippet| {
        if (std.mem.indexOf(u8, checker_source, snippet) == null) {
            try common.addError(errors, allocator, "Typed benchmark gate must retain accelerator-scoped validation: {s}", .{snippet});
        }
    }

    const workflow_path = ".github/workflows/ci.yml";
    const workflow_source = try readRequiredSource(allocator, io, errors, workflow_path) orelse return;
    if (std.mem.indexOf(u8, workflow_source, "command: QEMU_ACCELERATOR=kvm zig build -Doptimize=fast benchmark") == null) {
        try common.addError(errors, allocator, "Hosted benchmark CI must require KVM for cycle-regression enforcement", .{});
    }

    const baseline_path = "benchmarks/kernel-baseline.txt";
    const baseline_source = try readRequiredSource(allocator, io, errors, baseline_path) orelse return;
    if (std.mem.indexOf(u8, baseline_source, "# KVM baselines") == null) {
        try common.addError(errors, allocator, "Kernel benchmark baselines must remain KVM-calibrated instead of software-emulator-derived", .{});
    }
    try validateKvmBaselineAllowances(allocator, errors, baseline_source);
}

fn validateKvmBaselineAllowances(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    source: []const u8,
) !void {
    var lines = std.mem.splitScalar(u8, source, '\n');
    var line_number: usize = 0;
    while (lines.next()) |raw_line| {
        line_number += 1;
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var tokens = std.mem.tokenizeAny(u8, line, " \t");
        _ = tokens.next() orelse {
            try common.addError(errors, allocator, "KVM baseline line {d} is malformed", .{line_number});
            continue;
        };
        _ = tokens.next() orelse {
            try common.addError(errors, allocator, "KVM baseline line {d} is malformed", .{line_number});
            continue;
        };
        const allowance_text = tokens.next() orelse {
            try common.addError(errors, allocator, "KVM baseline line {d} is malformed", .{line_number});
            continue;
        };
        if (tokens.next() != null) {
            try common.addError(errors, allocator, "KVM baseline line {d} is malformed", .{line_number});
            continue;
        }
        const allowance = std.fmt.parseInt(u64, allowance_text, 10) catch {
            try common.addError(errors, allocator, "KVM baseline line {d} has an invalid regression allowance", .{line_number});
            continue;
        };
        if (allowance > 50) {
            try common.addError(errors, allocator, "KVM baseline line {d} exceeds the 50 percent regression allowance", .{line_number});
        }
    }
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
    const acpi_path = "src/kernel/platform/acpi.zig";
    const fadt_path = "src/kernel/platform/fadt.zig";
    const mcfg_path = "src/kernel/platform/mcfg.zig";
    const framebuffer_path = "src/kernel/platform/framebuffer.zig";
    const handoff_path = "src/kernel/boot/handoff.zig";
    const multiboot2_path = "src/kernel/boot/multiboot2.zig";
    const hardware_target_path = "src/native/platform/hardware_target.zig";
    const first_target_telemetry_path = "src/kernel/drivers/first_target_telemetry.zig";
    const platform_policy_signals_path = "src/native/platform/platform_policy_signals.zig";
    const device_inventory_path = "src/native/drivers/device_inventory.zig";
    const service_bootstrap_path = "src/native/session/service_bootstrap.zig";
    const session_service_bootstrap_path = "src/native/session/session_service_bootstrap.zig";
    const isr_path = "src/kernel/interrupts/isr.zig";
    const interrupt_stubs_path = "src/kernel/interrupts/interrupt64.S";
    const syscall_path = "src/kernel/interrupts/syscall64.zig";
    const syscall_entry_path = "src/kernel/interrupts/syscall64.S";
    const fred_entry_path = "src/kernel/interrupts/fred64.S";
    const fred_frame_path = "src/kernel/interrupts/fred_frame64.inc";
    const xstate_entry_path = "src/arch/xstate64.inc";
    const userspace_syscall_path = "src/arch/x86/syscall_trap.S";
    const gdt_path = "src/kernel/interrupts/gdt64.zig";
    const runtime_init_path = "src/kernel/boot/init/runtime.zig";
    const core_init_path = "src/kernel/boot/init/core.zig";
    const x2apic_path = "src/kernel/interrupts/x2apic.zig";
    const smp_path = "src/kernel/smp.zig";
    const smp_bringup_path = "src/kernel/smp_bringup.zig";
    const smp_trampoline_path = "src/kernel/smp/trampoline.zig";
    const ap_trampoline_path = "src/kernel/smp/ap_trampoline.S";
    const tlb_request_path = "src/kernel/smp/tlb_request.zig";
    const cache_rendezvous_path = "src/kernel/smp/cache_rendezvous.zig";
    const cache_policy_path = "src/arch/cache_policy.zig";
    const mtrr_bootstrap_path = "src/arch/x86_64/mtrr_bootstrap.inc";
    const native_profile_path = "src/kernel/boot/profiles/zigos_native.zig";
    const timer_path = "src/kernel/timer/timer.zig";
    const qemu_harness_path = "tools/host/qemu.zig";
    const kernel_build_path = "build_support/kernel.zig";
    const bootloader_path = "src/boot/boot_x86_64.S";
    const efi_stub_path = "src/boot/efi_stub.zig";
    const efi_handoff_path = "src/boot/efi_handoff.zig";
    const efi_elf_path = "src/boot/efi_elf.zig";
    const efi_iso_path = "tools/host/images.zig";
    const efi_image_check_path = "tools/host/images.zig";
    const kernel_linker_path = "src/arch/x86_64/linker.ld";
    const qemu_grub_path = "src/boot/grub-x86_64-qemu.cfg";
    const production_cmdline_path = "src/boot/cmdline.txt";
    const production_grub_path = "src/boot/grub-x86_64-kernel.cfg";
    const ci_setup_path = ".github/actions/setup-zigos-ci/action.yml";
    const cpu_baseline_path = "src/arch/cpu_baseline.zig";
    const x86_path = "src/arch/x86.zig";
    const invpcid_path = "src/arch/x86/invpcid.S";
    const user_access_path = "src/arch/x86/user_access.S";
    const xsaves_path = "src/arch/x86/xsaves.S";
    const cpu_features_path = "src/arch/cpu_features.zig";
    const boot_entry_path = "src/kernel/boot/entry.zig";
    const cpu_policy_path = "src/kernel/boot/cpu_policy.zig";
    const paging_path = "src/kernel/memory/paging64.zig";
    const pcid_allocator_path = "src/kernel/memory/pcid_allocator.zig";
    const userspace_executor_path = "src/native/task/userspace_executor.zig";
    const userspace_scheduler_path = "src/native/task/userspace_scheduler.zig";
    const userspace_runtime_path = "src/userspace/runtime.zig";
    const userspace_ui_state_path = "src/userspace/ui_surface_state.zig";
    const permission_review_path = "src/native/policy/permission_review_service.zig";
    const input_driver_task_path = "src/native/drivers/input_driver_task.zig";
    const xhci_driver_task_path = "src/native/drivers/xhci_driver_task.zig";
    const input_router_path = "src/native/platform/input_router.zig";
    const console_path = "src/kernel/utils/console.zig";
    const legacy_vga_path = "src/kernel/drivers/vga.zig";
    const xhci_path = "src/kernel/drivers/xhci.zig";
    const xhci_hw_path = "src/kernel/drivers/xhci_hw.zig";
    const nvme_path = "src/kernel/drivers/nvme.zig";
    const i225_path = "src/kernel/drivers/intel_i225.zig";
    const pci_path = "src/kernel/drivers/pci.zig";
    const mmio_windows_path = "src/kernel/memory/mmio_windows.zig";
    if (!common.pathExists(io, hardware_proof_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 hardware proof source is missing: {s}", .{hardware_proof_path});
        return;
    }
    if (!common.pathExists(io, apic_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 APIC proof source is missing: {s}", .{apic_path});
        return;
    }
    if (!common.pathExists(io, devices_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 boot device inventory source is missing: {s}", .{devices_path});
        return;
    }
    if (!common.pathExists(io, crash_record_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 crash persistence proof source is missing: {s}", .{crash_record_path});
        return;
    }
    if (!common.pathExists(io, acpi_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 ACPI parser is missing: {s}", .{acpi_path});
        return;
    }
    if (!common.pathExists(io, fadt_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 FADT suspend proof source is missing: {s}", .{fadt_path});
        return;
    }
    if (!common.pathExists(io, mcfg_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 PCIe firmware parser is missing: {s}", .{mcfg_path});
        return;
    }
    if (!common.pathExists(io, framebuffer_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 framebuffer proof source is missing: {s}", .{framebuffer_path});
        return;
    }
    if (!common.pathExists(io, handoff_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 boot handoff source is missing: {s}", .{handoff_path});
        return;
    }
    if (!common.pathExists(io, multiboot2_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 Multiboot2 parser is missing: {s}", .{multiboot2_path});
        return;
    }
    if (!common.pathExists(io, hardware_target_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 update rollback proof source is missing: {s}", .{hardware_target_path});
        return;
    }
    if (!common.pathExists(io, first_target_telemetry_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 first-target telemetry source is missing: {s}", .{first_target_telemetry_path});
        return;
    }
    if (!common.pathExists(io, platform_policy_signals_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 platform policy signal source is missing: {s}", .{platform_policy_signals_path});
        return;
    }
    if (!common.pathExists(io, device_inventory_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 device inventory source is missing: {s}", .{device_inventory_path});
        return;
    }
    if (!common.pathExists(io, service_bootstrap_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 service bootstrap source is missing: {s}", .{service_bootstrap_path});
        return;
    }
    if (!common.pathExists(io, session_service_bootstrap_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 session service bootstrap source is missing: {s}", .{session_service_bootstrap_path});
        return;
    }
    if (!common.pathExists(io, isr_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 interrupt source is missing: {s}", .{isr_path});
        return;
    }
    if (!common.pathExists(io, interrupt_stubs_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 interrupt stubs are missing: {s}", .{interrupt_stubs_path});
        return;
    }
    if (!common.pathExists(io, runtime_init_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 runtime initialization source is missing: {s}", .{runtime_init_path});
        return;
    }
    if (!common.pathExists(io, core_init_path)) {
        try common.addError(errors, allocator, "native descriptor and paging initialization source is missing: {s}", .{core_init_path});
        return;
    }
    for ([_][]const u8{ x2apic_path, smp_path }) |path| {
        if (!common.pathExists(io, path)) {
            try common.addError(errors, allocator, "native interprocessor interrupt source is missing: {s}", .{path});
            return;
        }
    }
    if (!common.pathExists(io, native_profile_path)) {
        try common.addError(errors, allocator, "native scheduler loop source is missing: {s}", .{native_profile_path});
        return;
    }
    if (!common.pathExists(io, timer_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 timer source is missing: {s}", .{timer_path});
        return;
    }
    if (!common.pathExists(io, qemu_harness_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 QEMU harness is missing: {s}", .{qemu_harness_path});
        return;
    }
    if (!common.pathExists(io, kernel_build_path)) {
        try common.addError(errors, allocator, "kernel build support is missing: {s}", .{kernel_build_path});
        return;
    }
    if (!common.pathExists(io, bootloader_path)) {
        try common.addError(errors, allocator, "x86-64 bootloader source is missing: {s}", .{bootloader_path});
        return;
    }
    if (!common.pathExists(io, efi_stub_path)) {
        try common.addError(errors, allocator, "native EFI long-mode stub is missing: {s}", .{efi_stub_path});
        return;
    }
    if (!common.pathExists(io, kernel_linker_path)) {
        try common.addError(errors, allocator, "x86-64 kernel linker source is missing: {s}", .{kernel_linker_path});
        return;
    }
    if (!common.pathExists(io, efi_stub_path)) {
        try common.addError(errors, allocator, "native EFI stub is missing: {s}", .{efi_stub_path});
        return;
    }
    if (!common.pathExists(io, efi_handoff_path)) {
        try common.addError(errors, allocator, "EFI firmware handoff encoder is missing: {s}", .{efi_handoff_path});
        return;
    }
    if (!common.pathExists(io, efi_elf_path)) {
        try common.addError(errors, allocator, "EFI kernel ELF loader is missing: {s}", .{efi_elf_path});
        return;
    }
    if (!common.pathExists(io, efi_iso_path)) {
        try common.addError(errors, allocator, "EFI production ISO builder is missing: {s}", .{efi_iso_path});
        return;
    }
    if (!common.pathExists(io, efi_image_check_path)) {
        try common.addError(errors, allocator, "EFI PE/COFF image checker is missing: {s}", .{efi_image_check_path});
        return;
    }
    if (!common.pathExists(io, qemu_grub_path)) {
        try common.addError(errors, allocator, "QEMU boot configuration is missing: {s}", .{qemu_grub_path});
        return;
    }
    if (!common.pathExists(io, production_cmdline_path)) {
        try common.addError(errors, allocator, "production EFI command line is missing: {s}", .{production_cmdline_path});
        return;
    }
    if (!common.pathExists(io, production_grub_path)) {
        try common.addError(errors, allocator, "production GRUB configuration is missing: {s}", .{production_grub_path});
        return;
    }
    if (!common.pathExists(io, ci_setup_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 CI setup action is missing: {s}", .{ci_setup_path});
        return;
    }
    if (!common.pathExists(io, cpu_baseline_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 CPU baseline source is missing: {s}", .{cpu_baseline_path});
        return;
    }
    if (!common.pathExists(io, x86_path)) {
        try common.addError(errors, allocator, "x86 process-context source is missing: {s}", .{x86_path});
        return;
    }
    if (!common.pathExists(io, invpcid_path)) {
        try common.addError(errors, allocator, "x86 process-context invalidation assembly is missing: {s}", .{invpcid_path});
        return;
    }
    if (!common.pathExists(io, user_access_path)) {
        try common.addError(errors, allocator, "x86 supervisor user-memory access assembly is missing: {s}", .{user_access_path});
        return;
    }
    if (!common.pathExists(io, xsaves_path)) {
        try common.addError(errors, allocator, "x86 XSAVES extended-state assembly is missing: {s}", .{xsaves_path});
        return;
    }
    if (!common.pathExists(io, cpu_features_path)) {
        try common.addError(errors, allocator, "modern CPU feature enablement source is missing: {s}", .{cpu_features_path});
        return;
    }
    if (!common.pathExists(io, boot_entry_path)) {
        try common.addError(errors, allocator, "modern CPU boot gate source is missing: {s}", .{boot_entry_path});
        return;
    }
    if (!common.pathExists(io, paging_path)) {
        try common.addError(errors, allocator, "PCID-aware paging source is missing: {s}", .{paging_path});
        return;
    }
    if (!common.pathExists(io, pcid_allocator_path)) {
        try common.addError(errors, allocator, "bounded PCID allocator source is missing: {s}", .{pcid_allocator_path});
        return;
    }
    if (!common.pathExists(io, userspace_executor_path)) {
        try common.addError(errors, allocator, "userspace address-space switching source is missing: {s}", .{userspace_executor_path});
        return;
    }
    if (!common.pathExists(io, userspace_runtime_path)) {
        try common.addError(errors, allocator, "userspace runtime source is missing: {s}", .{userspace_runtime_path});
        return;
    }
    if (!common.pathExists(io, userspace_ui_state_path)) {
        try common.addError(errors, allocator, "userspace UI state source is missing: {s}", .{userspace_ui_state_path});
        return;
    }
    if (!common.pathExists(io, permission_review_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 permission review source is missing: {s}", .{permission_review_path});
        return;
    }
    if (!common.pathExists(io, input_router_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 focused input router source is missing: {s}", .{input_router_path});
        return;
    }
    if (!common.pathExists(io, console_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 early console source is missing: {s}", .{console_path});
        return;
    }
    if (common.pathExists(io, legacy_vga_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 early console must not restore the legacy VGA text driver: {s}", .{legacy_vga_path});
    }
    if (!common.pathExists(io, nvme_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 NVMe proof source is missing: {s}", .{nvme_path});
        return;
    }
    if (!common.pathExists(io, xhci_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 xHCI proof source is missing: {s}", .{xhci_path});
        return;
    }
    if (!common.pathExists(io, xhci_hw_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 xHCI hardware probe source is missing: {s}", .{xhci_hw_path});
        return;
    }
    if (!common.pathExists(io, i225_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 I225 proof source is missing: {s}", .{i225_path});
        return;
    }
    if (!common.pathExists(io, pci_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 PCI inventory source is missing: {s}", .{pci_path});
        return;
    }
    if (!common.pathExists(io, mmio_windows_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 kernel MMIO layout source is missing: {s}", .{mmio_windows_path});
        return;
    }
    const hardware_proof_source = try common.readFileAlloc(allocator, io, hardware_proof_path, common.source_file_max_bytes);
    const apic_source = try common.readFileAlloc(allocator, io, apic_path, common.source_file_max_bytes);
    const devices_source = try common.readFileAlloc(allocator, io, devices_path, common.source_file_max_bytes);
    const crash_record_source = try common.readFileAlloc(allocator, io, crash_record_path, common.source_file_max_bytes);
    const acpi_source = try common.readFileAlloc(allocator, io, acpi_path, common.source_file_max_bytes);
    const fadt_source = try common.readFileAlloc(allocator, io, fadt_path, common.source_file_max_bytes);
    const mcfg_source = try common.readFileAlloc(allocator, io, mcfg_path, common.source_file_max_bytes);
    const framebuffer_source = try common.readFileAlloc(allocator, io, framebuffer_path, common.source_file_max_bytes);
    const handoff_source = try common.readFileAlloc(allocator, io, handoff_path, common.source_file_max_bytes);
    const multiboot2_source = try common.readFileAlloc(allocator, io, multiboot2_path, common.source_file_max_bytes);
    const hardware_target_source = try common.readFileAlloc(allocator, io, hardware_target_path, common.source_file_max_bytes);
    const first_target_telemetry_source = try common.readFileAlloc(allocator, io, first_target_telemetry_path, common.source_file_max_bytes);
    const platform_policy_signals_source = try common.readFileAlloc(allocator, io, platform_policy_signals_path, common.source_file_max_bytes);
    const device_inventory_source = try common.readFileAlloc(allocator, io, device_inventory_path, common.source_file_max_bytes);
    const service_bootstrap_source = try common.readFileAlloc(allocator, io, service_bootstrap_path, common.source_file_max_bytes);
    const session_service_bootstrap_source = try common.readFileAlloc(allocator, io, session_service_bootstrap_path, common.source_file_max_bytes);
    const isr_source = try common.readFileAlloc(allocator, io, isr_path, common.source_file_max_bytes);
    const interrupt_stubs_source = try common.readFileAlloc(allocator, io, interrupt_stubs_path, common.source_file_max_bytes);
    const syscall_source = try common.readFileAlloc(allocator, io, syscall_path, common.source_file_max_bytes);
    const syscall_entry_source = try common.readFileAlloc(allocator, io, syscall_entry_path, common.source_file_max_bytes);
    const fred_entry_source = try common.readFileAlloc(allocator, io, fred_entry_path, common.source_file_max_bytes);
    const fred_frame_source = try common.readFileAlloc(allocator, io, fred_frame_path, common.source_file_max_bytes);
    const xstate_entry_source = try common.readFileAlloc(allocator, io, xstate_entry_path, common.source_file_max_bytes);
    const userspace_syscall_source = try common.readFileAlloc(allocator, io, userspace_syscall_path, common.source_file_max_bytes);
    const gdt_source = try common.readFileAlloc(allocator, io, gdt_path, common.source_file_max_bytes);
    const runtime_init_source = try common.readFileAlloc(allocator, io, runtime_init_path, common.source_file_max_bytes);
    const core_init_source = try common.readFileAlloc(allocator, io, core_init_path, common.source_file_max_bytes);
    const x2apic_source = try common.readFileAlloc(allocator, io, x2apic_path, common.source_file_max_bytes);
    const smp_source = try common.readFileAlloc(allocator, io, smp_path, common.source_file_max_bytes);
    const smp_bringup_source = try common.readFileAlloc(allocator, io, smp_bringup_path, common.source_file_max_bytes);
    const smp_trampoline_source = try common.readFileAlloc(allocator, io, smp_trampoline_path, common.source_file_max_bytes);
    const ap_trampoline_source = try common.readFileAlloc(allocator, io, ap_trampoline_path, common.source_file_max_bytes);
    const tlb_request_source = try common.readFileAlloc(allocator, io, tlb_request_path, common.source_file_max_bytes);
    const cache_rendezvous_source = try common.readFileAlloc(allocator, io, cache_rendezvous_path, common.source_file_max_bytes);
    const cache_policy_source = try common.readFileAlloc(allocator, io, cache_policy_path, common.source_file_max_bytes);
    const mtrr_bootstrap_source = try common.readFileAlloc(allocator, io, mtrr_bootstrap_path, common.source_file_max_bytes);
    const native_profile_source = try common.readFileAlloc(allocator, io, native_profile_path, common.source_file_max_bytes);
    const timer_source = try common.readFileAlloc(allocator, io, timer_path, common.source_file_max_bytes);
    const qemu_harness_source = try common.readFileAlloc(allocator, io, qemu_harness_path, common.source_file_max_bytes);
    const kernel_build_source = try common.readFileAlloc(allocator, io, kernel_build_path, common.source_file_max_bytes);
    const bootloader_source = try common.readFileAlloc(allocator, io, bootloader_path, common.source_file_max_bytes);
    const efi_stub_source = try common.readFileAlloc(allocator, io, efi_stub_path, common.source_file_max_bytes);
    const efi_handoff_source = try common.readFileAlloc(allocator, io, efi_handoff_path, common.source_file_max_bytes);
    const efi_iso_source = try common.readFileAlloc(allocator, io, efi_iso_path, common.source_file_max_bytes);
    const kernel_linker_source = try common.readFileAlloc(allocator, io, kernel_linker_path, common.source_file_max_bytes);
    const qemu_grub_source = try common.readFileAlloc(allocator, io, qemu_grub_path, common.source_file_max_bytes);
    const production_cmdline_source = try common.readFileAlloc(allocator, io, production_cmdline_path, common.source_file_max_bytes);
    const production_grub_source = try common.readFileAlloc(allocator, io, production_grub_path, common.source_file_max_bytes);
    const ci_setup_source = try common.readFileAlloc(allocator, io, ci_setup_path, common.source_file_max_bytes);
    const cpu_baseline_source = try common.readFileAlloc(allocator, io, cpu_baseline_path, common.source_file_max_bytes);
    const x86_source = try common.readFileAlloc(allocator, io, x86_path, common.source_file_max_bytes);
    const invpcid_source = try common.readFileAlloc(allocator, io, invpcid_path, common.source_file_max_bytes);
    const user_access_source = try common.readFileAlloc(allocator, io, user_access_path, common.source_file_max_bytes);
    const xsaves_source = try common.readFileAlloc(allocator, io, xsaves_path, common.source_file_max_bytes);
    const cpu_features_source = try common.readFileAlloc(allocator, io, cpu_features_path, common.source_file_max_bytes);
    const boot_entry_source = try common.readFileAlloc(allocator, io, boot_entry_path, common.source_file_max_bytes);
    const cpu_policy_source = try common.readFileAlloc(allocator, io, cpu_policy_path, common.source_file_max_bytes);
    const paging_source = try common.readFileAlloc(allocator, io, paging_path, common.source_file_max_bytes);
    const sparse_source = try common.readFileAlloc(allocator, io, "src/arch/sparse_physical_map.zig", common.source_file_max_bytes);
    const efi_paging_source = try common.readFileAlloc(allocator, io, "src/boot/efi_paging.zig", common.source_file_max_bytes);
    const sparse_contracts = [_]struct { source: []const u8, snippet: []const u8 }{
        .{ .source = sparse_source, .snippet = "countInto(config, &counts)" },
        .{ .source = sparse_source, .snippet = "MAX_ARENA_PAGES: usize = 4096" },
        .{ .source = sparse_source, .snippet = "segment.memory_type == .write_back" },
        .{ .source = sparse_source, .snippet = "requireReadOnlyDirect" },
        .{ .source = efi_paging_source, .snippet = "efiTypeIsRam(entry.firmware_type)" },
        .{ .source = paging_source, .snippet = "validateBootOwnedRanges" },
        .{ .source = paging_source, .snippet = "sparse.build" },
        .{ .source = paging_source, .snippet = "captureTargetSku" },
        .{ .source = paging_source, .snippet = "mappedRamSpan" },
    };
    for (sparse_contracts) |contract| {
        if (std.mem.indexOf(u8, contract.source, contract.snippet) == null)
            try common.addError(errors, allocator, "sparse native paging must retain contract: {s}", .{contract.snippet});
    }
    try validateBootArenaRetirementSource(allocator, errors, paging_source);
    const firmware_memory_map_source = try common.readFileAlloc(allocator, io, "src/kernel/memory/firmware_memory_map.zig", common.source_file_max_bytes);
    try validateBootArenaRetirementPreflightSource(allocator, errors, firmware_memory_map_source);
    try validateCountSizedEfiArenaSource(allocator, errors, efi_stub_source);
    const paging_info_source = try common.readFileAlloc(allocator, io, "src/boot/paging_info.zig", common.source_file_max_bytes);
    try validatePagingArenaCapacitySource(allocator, errors, paging_info_source, .metadata);
    try validatePagingArenaCapacitySource(allocator, errors, efi_paging_source, .transition);
    try validatePagingArenaCapacitySource(allocator, errors, paging_source, .final);
    const ap_cache_source_paths = [_]struct { path: []const u8, kind: ApCacheProbeSourceKind }{
        .{ .path = "src/arch/x86_64/smp_cache_enabled_probe.zig", .kind = .enabled },
        .{ .path = "src/arch/x86_64/ap_cache_rejection_probe.zig", .kind = .rejection },
        .{ .path = "src/arch/x86_64/ap_cache_probe_support.zig", .kind = .support },
        .{ .path = qemu_harness_path, .kind = .harness },
        .{ .path = kernel_build_path, .kind = .build },
    };
    for (ap_cache_source_paths) |contract| {
        const source = try common.readFileAlloc(allocator, io, contract.path, common.source_file_max_bytes);
        try validateApCacheProbeSource(allocator, errors, source, contract.kind);
    }
    const enabled_ap_assembly = try common.readFileAlloc(allocator, io, "src/arch/x86_64/smp_cache_enabled_probe.S", common.source_file_max_bytes);
    try validateEnabledApCacheAssemblySource(allocator, errors, enabled_ap_assembly, mtrr_bootstrap_source);

    const pcid_allocator_source = try common.readFileAlloc(allocator, io, pcid_allocator_path, common.source_file_max_bytes);
    const userspace_executor_source = try common.readFileAlloc(allocator, io, userspace_executor_path, common.source_file_max_bytes);
    const userspace_scheduler_source = try common.readFileAlloc(allocator, io, userspace_scheduler_path, common.source_file_max_bytes);
    const userspace_runtime_source = try common.readFileAlloc(allocator, io, userspace_runtime_path, common.source_file_max_bytes);
    const userspace_ui_state_source = try common.readFileAlloc(allocator, io, userspace_ui_state_path, common.source_file_max_bytes);
    const permission_review_source = try common.readFileAlloc(allocator, io, permission_review_path, common.source_file_max_bytes);
    const input_driver_task_source = try common.readFileAlloc(allocator, io, input_driver_task_path, common.source_file_max_bytes);
    const input_router_source = try common.readFileAlloc(allocator, io, input_router_path, common.source_file_max_bytes);
    const console_source = try common.readFileAlloc(allocator, io, console_path, common.source_file_max_bytes);
    const xhci_source = try common.readFileAlloc(allocator, io, xhci_path, common.source_file_max_bytes);
    const xhci_hw_source = try common.readFileAlloc(allocator, io, xhci_hw_path, common.source_file_max_bytes);
    const xhci_driver_task_source = try common.readFileAlloc(allocator, io, xhci_driver_task_path, common.source_file_max_bytes);
    const nvme_source = try common.readFileAlloc(allocator, io, nvme_path, common.source_file_max_bytes);
    const i225_source = try common.readFileAlloc(allocator, io, i225_path, common.source_file_max_bytes);
    const pci_source = try common.readFileAlloc(allocator, io, pci_path, common.source_file_max_bytes);
    const mmio_windows_source = try common.readFileAlloc(allocator, io, mmio_windows_path, common.source_file_max_bytes);
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
            try common.addError(errors, allocator, "RNUC15CRSU7 hardware proof source must enforce snippet: {s}", .{snippet});
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
        "device inventory accepts only target xHCI input hardware",
    };
    for (required_device_inventory_snippets) |snippet| {
        if (std.mem.indexOf(u8, device_inventory_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 device inventory source must enforce production binding snippet: {s}", .{snippet});
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
            try common.addError(errors, allocator, "RNUC15CRSU7 device inventory source must not reintroduce stable synthetic fallback ids: {s}", .{snippet});
        }
    }
    const retired_device_inventory_binding_snippets = [_][]const u8{
        "ps2_bootstrap",
        ".ata_bootstrap",
        "AtaBrokerGrant",
    };
    for (retired_device_inventory_binding_snippets) |snippet| {
        if (std.mem.indexOf(u8, device_inventory_source, snippet) != null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 device inventory source must not bind production input through PS/2 bootstrap: {s}", .{snippet});
        }
    }
    const required_boot_device_inventory_snippets = [_][]const u8{
        "hardware_proof.capturePlatformFirmwareEvidence()",
        "pci.init(ecam_allocation)",
        "pci.firstIntelI225Lm()",
        ".intel_i225_lm_inventory",
        "pci.firstNvmeController()",
        ".nvme_pci_inventory",
        "pci.firstXhciController()",
        "device_inventory.registerDetected(.usb_controller, xhci_device_id, .xhci_inventory, false)",
    };
    for (required_boot_device_inventory_snippets) |snippet| {
        if (std.mem.indexOf(u8, devices_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 boot device inventory source must capture target-specific PCI snippet: {s}", .{snippet});
        }
    }
    const required_xhci_driver_task_snippets = [_][]const u8{
        "xhci_hw.probe(dev)",
        "ZIGOS:XHCI:HW:OWNERSHIP_OK",
        "ZIGOS:XHCI:HW:RESET_OK",
        "ZIGOS:XHCI:HW:SLOTS_OK",
        "xhci_hw.isolationDomain()",
        "isolation_domains[0..isolation_domain_count]",
        "ZIGOS:XHCI:HW:DMA_OK",
        "xhci_prepared = true",
        "xhci_hw.activate()",
        "ZIGOS:XHCI:HW:REMAP_MSI_OK",
        "ZIGOS:XHCI:HW:RUN_OK",
        "KERNEL_LATCHES_ONLY",
    };
    for (required_xhci_driver_task_snippets) |snippet| {
        if (std.mem.indexOf(u8, xhci_driver_task_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 xHCI userspace driver task must capture dataplane snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, devices_source, "device_inventory.registerDetected(.input_device, xhci_device_id, .xhci_inventory, false)") != null) {
        try common.addError(errors, allocator, "RNUC15CRSU7 PCI discovery must not publish input authority before keyboard enumeration and hardware event-ring evidence", .{});
    }
    const required_pci_inventory_snippets = [_][]const u8{
        "mcfg.Allocation",
        "pub const PCI_DEVICE_SIZE_CEILING_BYTES: usize = 20",
        "const PCI_INVENTORY_SIZE_CEILING_BYTES: usize = 5_120",
        "pub const HEAP_BACKED_PCI_INVENTORY_ON_FREESTANDING = true",
        "pub const PCI_INVENTORY_HANDLE_SIZE_CEILING_BYTES: usize = 8",
        "mmio_windows.pci_ecam.base",
        "paging.mapKernelDeviceRange",
        "mapped_configuration_page",
        "configuration_lock",
        "boot_inventory_initialized",
        "ensureBootInventory",
        "PCI_SECONDARY_BUS_OFFSET",
        "enqueueSecondaryBus",
        "return firstMatchingIn(Query, bootDevices(), query, matches)",
    };
    for (required_pci_inventory_snippets) |snippet| {
        if (std.mem.indexOf(u8, pci_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 PCI discovery must retain its cached topology-aware inventory: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, pci_source, "var boot_inventory: [PCI_INVENTORY_CAPACITY]PCIDevice") != null) {
        try common.addError(errors, allocator, "PCI inventory must remain heap-backed on freestanding kernels", .{});
    }
    if (std.mem.indexOf(u8, pci_source, "while (bus < PCI_MAX_BUS_COUNT)") != null) {
        try common.addError(errors, allocator, "RNUC15CRSU7 PCI discovery must not restore repeated exhaustive 256-bus scans", .{});
    }
    const retired_cached_pci_bar_snippets = [_][]const u8{
        "PCI_BAR2_OFFSET",
        "PCI_BAR3_OFFSET",
        "PCI_BAR4_OFFSET",
        "PCI_BAR5_OFFSET",
        "bar2: u32",
        "bar3: u32",
        "bar4: u32",
        "bar5: u32",
    };
    for (retired_cached_pci_bar_snippets) |snippet| {
        if (std.mem.indexOf(u8, pci_source, snippet) != null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 PCI discovery must not recache unused BAR words: {s}", .{snippet});
        }
    }
    const required_mmio_layout_snippets = [_][]const u8{
        "pub const nvme = Region",
        "pub const pci_ecam = Region",
        "pub const intel_i225 = Region",
        "pub const xhci = Region",
        "pub const acpi_root = Region",
        "pub const acpi_entry = Region",
        "pub const intel_vtd = Region",
        "pub fn validLayout",
        "region.base % PAGE_BYTES != 0",
        "region.bytes % PAGE_BYTES != 0",
        "if (region.base < prior_end and prior.base < region_end) return false",
        "@compileError(\"kernel MMIO windows overlap or are invalid\")",
    };
    for (required_mmio_layout_snippets) |snippet| {
        if (std.mem.indexOf(u8, mmio_windows_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 kernel MMIO layout must retain bounded non-overlap enforcement: {s}", .{snippet});
        }
    }
    const retired_pci_config_port_snippets = [_][]const u8{
        "CONFIG_ADDRESS",
        "CONFIG_DATA",
        "../utils/io.zig",
        "io.outl",
        "io.inl",
    };
    for (retired_pci_config_port_snippets) |snippet| {
        if (std.mem.indexOf(u8, pci_source, snippet) != null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 PCI discovery must not restore legacy configuration-port access: {s}", .{snippet});
        }
    }
    const required_mcfg_snippets = [_][]const u8{
        "MCFG_SIGNATURE",
        "segmentZeroAllocation",
        "acpi.parseSdtHeader",
        "allocation.base_address % ECAM_BUS_BYTES",
        "error.MissingSegmentZero",
    };
    for (required_mcfg_snippets) |snippet| {
        if (std.mem.indexOf(u8, mcfg_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 PCIe discovery must retain validated ACPI MCFG parsing: {s}", .{snippet});
        }
    }
    const required_service_bootstrap_snippets = [_][]const u8{
        "device_inventory.requireProductionDriverDeviceId(device_class)",
        "const device_id = try",
        "driver_service.authorityTarget(device_id)",
        ".device_id = device_id",
        ".issued_at_ticks = 0",
    };
    for (required_service_bootstrap_snippets) |snippet| {
        if (std.mem.indexOf(u8, service_bootstrap_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 service bootstrap source must bind drivers through detected inventory snippet: {s}", .{snippet});
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
            try common.addError(errors, allocator, "RNUC15CRSU7 hosted service bootstrap source must keep explicit modeled inventory snippet: {s}", .{snippet});
        }
    }
    const retired_legacy_input_snippets = [_][]const u8{
        "keyboard.zig",
        "KEYBOARD_IRQ_VECTOR",
        "PIC_KEYBOARD_IRQ_BIT",
        "deferInputDataPlaneToUserspace",
        "keyboard.has_char()",
    };
    const modern_input_sources = [_]struct {
        label: []const u8,
        source: []const u8,
    }{
        .{ .label = isr_path, .source = isr_source },
        .{ .label = runtime_init_path, .source = runtime_init_source },
        .{ .label = permission_review_path, .source = permission_review_source },
    };
    for (modern_input_sources) |source_check| {
        for (retired_legacy_input_snippets) |snippet| {
            if (std.mem.indexOf(u8, source_check.source, snippet) != null) {
                try common.addError(errors, allocator, "RNUC15CRSU7 input path must not reintroduce legacy kernel keyboard snippet in {s}: {s}", .{ source_check.label, snippet });
            }
        }
    }
    const required_x2apic_interrupt_snippets = [_][]const u8{
        "const PIC_MASK_ALL: u8 = 0xFF",
        "io.outb(PIC_MASTER_DATA_PORT, PIC_MASK_ALL)",
        "io.outb(PIC_SLAVE_DATA_PORT, PIC_MASK_ALL)",
        "setKernelGate(timer.INTERRUPT_VECTOR, &isr64)",
        "setKernelGate(xhci_hw.INTERRUPT_VECTOR, &isr67)",
        "setKernelGate(timer.SPURIOUS_VECTOR, &isr255)",
    };
    for (required_x2apic_interrupt_snippets) |snippet| {
        if (std.mem.indexOf(u8, isr_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 interrupt path must use x2APIC timer vectors with both legacy PICs masked: {s}", .{snippet});
        }
    }
    const required_compact_handler_dispatch_snippets = [_][]const u8{
        "exception_handlers: [EXCEPTION_VECTOR_COUNT]?InterruptHandler",
        "external_handlers: [external_handler_vectors.len]?InterruptHandler",
        "fn externalHandlerIndex(vector: usize) ?usize",
        "const HANDLER_STORAGE_SIZE_CEILING_BYTES: usize = 320",
    };
    for (required_compact_handler_dispatch_snippets) |snippet| {
        if (std.mem.indexOf(u8, isr_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 interrupt dispatch must retain compact handler storage: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, isr_source, "custom_handlers: [idt.IDT_ENTRIES]") != null) {
        try common.addError(errors, allocator, "RNUC15CRSU7 interrupt dispatch must not restore a full-IDT function-pointer table", .{});
    }
    const retired_pic_surface_snippets = [_][]const u8{
        "PIC_EOI",
        "PIC_ICW",
        "PIC_TIMER_IRQ_BIT",
        "PIC_MASTER_NO_SLAVE",
        "IRQ_SLAVE_BASE_VECTOR",
        "irq_stubs",
        "remapPIC",
        "irqHandler",
        "extern fn irq0",
        "extern fn irq1()",
    };
    for (retired_pic_surface_snippets) |snippet| {
        if (std.mem.indexOf(u8, isr_source, snippet) != null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 interrupt path must not restore legacy PIC dispatch or IRQ stub surface: {s}", .{snippet});
        }
    }
    const required_x2apic_stubs = [_][]const u8{
        "ISR_NOERRCODE 64",
        "ISR_NOERRCODE 67",
        "ISR_NOERRCODE 112",
        "ISR_NOERRCODE 255",
    };
    for (required_x2apic_stubs) |snippet| {
        if (std.mem.indexOf(u8, interrupt_stubs_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 interrupt assembly must expose the x2APIC timer surface: {s}", .{snippet});
        }
    }
    const required_interrupt_return_guard_snippets = [_][]const u8{
        "#include \"idt_return64.inc\"",
        "ZIGOS_IDT_VALIDATE_RETURN_PREFIX %r12",
        "ZIGOS_IDT_VALIDATE_RETURN_RIP_FLAGS %r12",
        "FRAME_USER_SS",
        "RFLAGS_FORBIDDEN_RETURN",
        "larl %eax, %eax",
        "call zigos_handle_invalid_interrupt_return",
    };
    for (required_interrupt_return_guard_snippets) |snippet| {
        if (std.mem.indexOf(u8, interrupt_stubs_source, snippet) == null) {
            try common.addError(errors, allocator, "x86 interrupt return must retain its privilege-state guard: {s}", .{snippet});
        }
    }
    const retired_irq_assembly_snippets = [_][]const u8{
        ".macro IRQ",
        "irq_common_stub",
        ".extern irqHandler",
        "IRQ 0, 32",
    };
    for (retired_irq_assembly_snippets) |snippet| {
        if (std.mem.indexOf(u8, interrupt_stubs_source, snippet) != null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 interrupt assembly must not restore legacy PIC IRQ dispatch: {s}", .{snippet});
        }
    }
    try validateCpuTimerSource(allocator, errors, timer_source, .timer);
    try validateCpuTimerSource(allocator, errors, isr_source, .isr);
    try validateCpuTimerSource(allocator, errors, smp_bringup_source, .ap);
    try validateNativeSchedulerLoopSource(allocator, errors, native_profile_source);
    const required_accelerated_qemu_snippets = [_][]const u8{
        "fn accelerator(",
        "/dev/kvm",
        ".character_device",
        "\"-accel\"",
        "return \"host\"",
        "max,+x2apic,+pdpe1gb,+pcid,+invpcid,+smap,+smep,+umip,+pku,+xsaves,+cet,+fred,+lkgs,+lass,tsc-frequency=2400000000",
    };
    for (required_accelerated_qemu_snippets) |snippet| {
        if (std.mem.indexOf(u8, qemu_harness_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 QEMU validation must use hardware-backed x2APIC when KVM is available: {s}", .{snippet});
        }
    }
    const required_compact_kernel_boot_snippets = [_][]const u8{
        "const boot_link = b.addRunFile(std.Build.LazyPath.zig_exe)",
        "--strip-debug",
        "const boot_kernel = boot_link.addOutputFileArg",
        "addEfiImage(b, .small, boot_kernel",
        "host_tools.addRun(b, \"build-efi-iso\")",
        "host_tools.addRun(b, \"check-efi-image\")",
        "src/boot/cmdline-qemu.txt",
    };
    for (required_compact_kernel_boot_snippets) |snippet| {
        if (std.mem.indexOf(u8, kernel_build_source, snippet) == null) {
            try common.addError(errors, allocator, "kernel boot media must use a debug-stripped diagnostic-ELF derivative: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, kernel_build_source, "const boot_kernel = if") != null) {
        try common.addError(errors, allocator, "debug stripping must apply to every kernel boot profile", .{});
    }
    if (std.mem.indexOf(u8, qemu_grub_source, "qemu_software_cpu_fallback") == null) {
        try common.addError(errors, allocator, "QEMU boot configuration must explicitly request the software-emulator CPU fallback", .{});
    }
    try validateProductionBootFlags(allocator, errors, production_cmdline_path, production_cmdline_source);
    try validateProductionBootFlags(allocator, errors, production_grub_path, production_grub_source);
    if (std.mem.indexOf(u8, kernel_build_source, "addEfiImage") == null or
        std.mem.indexOf(u8, kernel_build_source, ".os_tag = .uefi") == null)
    {
        try common.addError(errors, allocator, "kernel build must emit a native x86-64 UEFI stub", .{});
    }
    if (std.mem.indexOf(u8, efi_iso_source, "EFI/BOOT/BOOTX64.EFI") == null or
        std.mem.indexOf(u8, efi_iso_source, "exitBootServices") != null)
    {
        try common.addError(errors, allocator, "production ISO builder must install BOOTX64.EFI", .{});
    }
    const required_efi_stub_snippets = [_][]const u8{
        "NATIVE_EFI_LONG_MODE_ENTRY",
        "DROPS_MULTIBOOT2_PROTECTED_MODE_ENTRY",
        "exitBootServices",
        "GraphicsOutput",
        "acpi_20_table_guid",
        "efi_elf.load",
        "efi_handoff.encode",
        "enterKernel",
        "payload.kernel",
        "payload.cmdline",
        "embeddedCommandLine",
        "authenticatedFirmwareState",
        "readFirmwareByte",
        "segment.pageCount()",
        "HANDOFF_MAX_ADDRESS",
        "128 * 1024 * 1024",
        "efi_paging.validateTransition",
        "efi_paging.buildForMode",
        "cpu-pages-1g",
        "payload.isolated_low_proof",
        "bootstrap_physical",
    };
    for (required_efi_stub_snippets) |snippet| {
        if (std.mem.indexOf(u8, efi_stub_source, snippet) == null) {
            try common.addError(errors, allocator, "native EFI stub must retain snippet: {s}", .{snippet});
        }
    }
    const required_efi_handoff_snippets = [_][]const u8{
        "kindFromEfiMemoryType",
        "SYNTHESIZES_MULTIBOOT2_HANDOFF",
        "EXITS_BOOT_SERVICES",
        "TAG_ACPI_NEW",
        "TAG_EFI64_SYSTEM_TABLE",
        "embeddedCommandLine",
        "boot_image",
    };
    for (required_efi_handoff_snippets) |snippet| {
        if (std.mem.indexOf(u8, efi_handoff_source, snippet) == null) {
            try common.addError(errors, allocator, "EFI firmware handoff must retain snippet: {s}", .{snippet});
        }
    }
    const required_ci_kvm_snippets = [_][]const u8{
        "Enable KVM acceleration when available",
        "run: zig build tool -- ci-enable-kvm",
    };
    for (required_ci_kvm_snippets) |snippet| {
        if (std.mem.indexOf(u8, ci_setup_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 CI setup must expose KVM to QEMU jobs when the runner supports it: {s}", .{snippet});
        }
    }
    const ci_tools_source = try readRequiredSource(allocator, io, errors, "tools/host/ci.zig") orelse return;
    const required_native_ci_kvm_snippets = [_][]const u8{
        "if (std.mem.eql(u8, command, \"ci-enable-kvm\")) return enableKvm(ctx);",
        "fn enableKvm(ctx: *common.Context)",
        "try ctx.run(&.{ \"sudo\", \"chmod\", \"0666\", \"/dev/kvm\" });",
        "try std.Io.Dir.cwd().access(ctx.io, \"/dev/kvm\", .{ .read = true, .write = true });",
    };
    for (required_native_ci_kvm_snippets) |snippet| {
        if (std.mem.indexOf(u8, ci_tools_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 native CI setup must grant and verify KVM access: {s}", .{snippet});
        }
    }
    const retired_pit_timer_snippets = [_][]const u8{
        "PIT_CHANNEL0",
        "PIT_COMMAND",
        "PIT_FREQUENCY",
        "io.outb",
    };
    for (retired_pit_timer_snippets) |snippet| {
        if (std.mem.indexOf(u8, timer_source, snippet) != null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 timer must not restore PIT programming: {s}", .{snippet});
        }
    }
    const required_modern_cpu_baseline_snippets = [_][]const u8{
        "x2apic",
        "xsave",
        "xsaves",
        "cet_ibt",
        "cet_ss",
        "tsc_deadline",
        "invariant_tsc",
        "tsc_frequency_hz",
        "decodeTscFrequency",
        "pcid",
        "invpcid",
        "pge",
        "pages_1g",
        "syscall",
        "smep",
        "smap",
        "umip",
        "pku",
        "lass",
        "fred",
        "lkgs",
    };
    for (required_modern_cpu_baseline_snippets) |snippet| {
        if (std.mem.indexOf(u8, cpu_baseline_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 CPU baseline must expose the modern timer and process-context contract: {s}", .{snippet});
        }
    }
    const required_x86_pcid_snippets = [_][]const u8{
        "CR4_PCIDE",
        "CR4_PGE",
        "CR4_OSXSAVE",
        "CR4_CET",
        "CR3_NO_FLUSH",
        "pcidCr3Value",
        "writeCr3WithPcid",
        "invalidatePcid",
        "invalidateAllTranslations",
        "enableProcessContextIdentifiers",
        "processContextIdentifiersEnabled",
        "enableXsaves",
        "xsavesEnabled",
        "enableCet",
        "cetEnabled",
        "globalPagesEnabled",
        "CR4_SMEP",
        "CR4_SMAP",
        "CR4_UMIP",
        "CR4_PKE",
        "CR4_LASS",
        "CR4_FRED",
        "supervisorAccessPreventionEnabled",
        "allowSupervisorUserMemory",
        "forbidSupervisorUserMemory",
        "EFER_SCE",
        "IA32_STAR_MSR",
        "IA32_LSTAR_MSR",
        "IA32_FMASK_MSR",
        "IA32_KERNEL_GS_BASE_MSR",
        "IA32_FRED_CONFIG_MSR",
        "syscallExtensionEnabled",
        "enablePku",
        "enableLass",
        "enableFred",
        "fredEnabled",
        "pkuEnabled",
        "if (!pkuEnabled()) return",
        "lassEnabled",
    };
    for (required_x86_pcid_snippets) |snippet| {
        if (std.mem.indexOf(u8, x86_source, snippet) == null) {
            try common.addError(errors, allocator, "x86 process-context support must retain snippet: {s}", .{snippet});
        }
    }
    const required_invpcid_assembly_snippets = [_][]const u8{
        "x86_invalidate_pcid",
        "mov $1, %rcx",
        ".byte 0x66, 0x0f, 0x38, 0x82, 0x0f",
    };
    for (required_invpcid_assembly_snippets) |snippet| {
        if (std.mem.indexOf(u8, invpcid_source, snippet) == null) {
            try common.addError(errors, allocator, "x86 process-context invalidation must retain snippet: {s}", .{snippet});
        }
    }
    const required_user_access_assembly_snippets = [_][]const u8{
        "x86_allow_supervisor_user_memory",
        "stac",
        "x86_forbid_supervisor_user_memory",
        "clac",
    };
    for (required_user_access_assembly_snippets) |snippet| {
        if (std.mem.indexOf(u8, user_access_source, snippet) == null) {
            try common.addError(errors, allocator, "x86 SMAP user-memory access support must retain snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, kernel_build_source, "src/arch/x86/user_access.S") == null) {
        try common.addError(errors, allocator, "kernel build must include the x86 SMAP user-memory access assembly", .{});
    }
    const required_xsaves_assembly_snippets = [_][]const u8{
        "x86_write_xcr0",
        "x86_read_xcr0",
        "0x0f, 0x01, 0xd1",
        "0x0f, 0x01, 0xd0",
    };
    for (required_xsaves_assembly_snippets) |snippet| {
        if (std.mem.indexOf(u8, xsaves_source, snippet) == null) {
            try common.addError(errors, allocator, "x86 XSAVES support must retain snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, kernel_build_source, "src/arch/x86/xsaves.S") == null) {
        try common.addError(errors, allocator, "kernel build must include the x86 XSAVES assembly", .{});
    }
    if (std.mem.indexOf(u8, kernel_build_source, "src/kernel/interrupts/fred64.S") == null) {
        try common.addError(errors, allocator, "kernel build must include the FRED event-delivery assembly", .{});
    }
    if (std.mem.indexOf(u8, kernel_build_source, "src/boot/efi_stub.zig") == null or
        std.mem.indexOf(u8, kernel_build_source, "addEfiImage") == null)
    {
        try common.addError(errors, allocator, "kernel build must compile the native EFI long-mode stub", .{});
    }
    if (std.mem.indexOf(u8, interrupt_stubs_source, "isr_common_stub:") == null or
        std.mem.indexOf(u8, interrupt_stubs_source, "endbr64") == null or
        std.mem.indexOf(u8, interrupt_stubs_source, "clac") == null)
    {
        try common.addError(errors, allocator, "x86 interrupt entry must land on endbr64 and clear AC before entering kernel handlers", .{});
    }
    for ([_][]const u8{ "#include \"../../arch/xstate64.inc\"", "ENTER_KERNEL_XSTATE", "LEAVE_KERNEL_XSTATE" }) |snippet| {
        if (std.mem.indexOf(u8, interrupt_stubs_source, snippet) == null) {
            try common.addError(errors, allocator, "x86 interrupt entry must use owned extended state: {s}", .{snippet});
        }
    }
    for ([_][]const u8{ "xsaves64", "xrstors64", "xsave64", "xrstor64", "CPU_USERSPACE_XSTATE", "CPU_KERNEL_XSTATE", "CPU_NATIVE_ENTRY_MODES", "wrpkru", "ENTER_KERNEL_XSTATE", "LEAVE_KERNEL_XSTATE" }) |snippet| {
        if (std.mem.indexOf(u8, xstate_entry_source, snippet) == null) {
            try common.addError(errors, allocator, "owned extended-state assembly must retain snippet: {s}", .{snippet});
        }
    }
    // Native return state belongs to the interrupted logical CPU. Shared
    // mutable assembly exports would reintroduce cross-CPU continuation aliasing.
    const retired_shared_entry_symbols = [_][]const u8{
        "zigos_userspace_resume_requested",
        "zigos_userspace_resume_esp",
        "zigos_userspace_resume_eip",
        "zigos_userspace_xstate",
        "zigos_kernel_xstate",
    };
    for ([_][]const u8{ userspace_executor_source, xstate_entry_source, interrupt_stubs_source, syscall_entry_source, fred_entry_source }) |source| {
        for (retired_shared_entry_symbols) |symbol| {
            if (std.mem.indexOf(u8, source, symbol) != null) {
                try common.addError(errors, allocator, "native entry must not restore shared continuation state: {s}", .{symbol});
            }
        }
    }
    for ([_]struct { source: []const u8, retired: []const u8 }{
        .{ .source = paging_source, .retired = "var current_page_directory:" },
        .{ .source = userspace_executor_source, .retired = "var registered_executor:" },
        .{ .source = userspace_executor_source, .retired = "var trap_stack:" },
    }) |entry| {
        if (std.mem.indexOf(u8, entry.source, entry.retired) != null) {
            try common.addError(errors, allocator, "native runtime must not restore a shared CPU owner: {s}", .{entry.retired});
        }
    }
    for ([_]struct { source: []const u8, snippet: []const u8 }{
        .{ .source = userspace_executor_source, .snippet = "const source = registeredDomainExecutor(claim.key.ticket.cpu, owner, runtime) orelse return false" },
        .{ .source = userspace_executor_source, .snippet = "freestanding.paging.checkedUserAddressSpacePhysicalRoot(&mapping.address_space.?) != bound.physical_root" },
        .{ .source = userspace_executor_source, .snippet = "@atomicLoad(?*Executor, &executor_registrations[cpu].executor, .acquire)" },
        .{ .source = userspace_executor_source, .snippet = "pub fn releaseRegisteredDomain(owner: *const anyopaque, runtime: *task_runtime.Runtime) bool" },
        .{ .source = userspace_executor_source, .snippet = "decodeMappingLifetimeToken(registration_token, &decoded)" },
        .{ .source = userspace_scheduler_source, .snippet = "userspace_executor.retireRegisteredAddressSpace(self, runtime, event)" },
        .{ .source = userspace_scheduler_source, .snippet = "userspace_executor.releaseRegisteredDomain(self, bound_runtime)" },
        .{ .source = paging_source, .snippet = "physical_frames.isAllocated(physical) and !cachedFrame(physical)" },
        .{ .source = paging_source, .snippet = "mappedRamSpanForAccess(physical, PAGE_SIZE, true)" },
    }) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null)
            try common.addError(errors, allocator, "remote mapping ownership must retain its exact domain and allocated physical root: {s}", .{required.snippet});
    }
    const required_cpu_feature_pcid_snippets = [_][]const u8{
        "enableModernFeatures",
        "ProcessContextMode",
        "software_flush",
        "CetMode",
        "CR4_PGE",
        "globalPagesEnabled",
        "CR4_SMEP",
        "CR4_SMAP",
        "CR4_UMIP",
        "supervisorAccessPreventionEnabled",
        "enableProcessContextIdentifiers",
        "processContextIdentifiersEnabled",
        "enableXsaves",
        "xsavesEnabled",
        "enableCet",
        "cetEnabled",
        "enablePku",
        "x86.writeCr4(cr4);",
        "x86.forbidSupervisorUserMemory();",
    };
    for (required_cpu_feature_pcid_snippets) |snippet| {
        if (std.mem.indexOf(u8, cpu_features_source, snippet) == null) {
            try common.addError(errors, allocator, "modern CPU feature enablement must retain snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, cpu_features_source, "x86.enableLass(") != null) {
        try common.addError(errors, allocator, "LASS activation must wait for native descriptor and entry initialization", .{});
    }
    if (std.mem.indexOf(u8, cpu_features_source, "x86.writeCr4(cr4);")) |cr4_write| {
        if (std.mem.indexOfPos(u8, cpu_features_source, cr4_write, "x86.forbidSupervisorUserMemory();") == null) {
            try common.addError(errors, allocator, "SMAP enablement must clear inherited AC before admission", .{});
        }
    }
    var core_init_offset: usize = 0;
    for ([_][]const u8{ "gdt.init();", "syscall64.init();", "isr.init();", "try x86.enableLass();", "paging.init();" }) |snippet| {
        if (std.mem.indexOfPos(u8, core_init_source, core_init_offset, snippet)) |position| {
            core_init_offset = position + snippet.len;
        } else {
            try common.addError(errors, allocator, "native descriptor, entry, LASS and paging initialization must retain ordered step: {s}", .{snippet});
        }
    }
    for ([_][]const u8{ "lassAddressPartitionSupported", "sgdt (%[table])", "sidt (%[table])", "if (!lassAddressPartitionSupported()) return error.UnsupportedKernelAddressPartition;" }) |snippet| {
        if (std.mem.indexOf(u8, x86_source, snippet) == null) {
            try common.addError(errors, allocator, "LASS activation must verify the live kernel address partition: {s}", .{snippet});
        }
    }
    try validateX2apicIpiPublicationSource(allocator, errors, x2apic_source);
    for ([_][]const u8{
        "if (!isRuntimeOwner())",
        "MAX_CPUS != tlb_request.CAPACITY",
        "tlb_requests.begin(self, target, participants)",
        "tlb_requests.complete(request.generation)",
        "tlb_requests.finish(self, request.generation)",
        "tlb_requests.fail(self)",
        "tlb_requests.pending(cpu)",
        "tlb_requests.acknowledge(cpu, request.generation)",
        ".kernel => x86.invalidateAllTranslations()",
    }) |snippet| {
        if (std.mem.indexOf(u8, smp_source, snippet) == null) {
            try common.addError(errors, allocator, "remote TLB requests must retain ownership, generations and global retirement: {s}", .{snippet});
        }
    }
    var shootdown_offset = std.mem.indexOf(u8, smp_source, "fn shootdown(") orelse smp_source.len;
    for ([_][]const u8{ "x86.cli();", "tlb_requests.begin(", "sendParticipantIpis(self, participants)", "tlb_requests.complete(", "tlb_requests.finish(" }) |snippet| {
        if (std.mem.indexOfPos(u8, smp_source, shootdown_offset, snippet)) |position| {
            shootdown_offset = position + snippet.len;
        } else {
            try common.addError(errors, allocator, "remote TLB requests must mask owner interrupt reentry and finish exact acknowledgements: {s}", .{snippet});
        }
    }
    for ([_][]const u8{
        "beginDeviceAliasTransition",      "flushDeviceAliasTransition",              "endDeviceAliasTransition",
        "cache_transitions.parked(",       "cache_transitions.flushed(",              "cache_transitions.released(",
        "cache_transitions.fail(",         "cache_transitions.pending(cpu)",          "x86.writeBackInvalidateCaches()",
        "x86.invalidateAllTranslations()", "sendParticipantIpis(self, participants)", "x2apic.sendIpi(",
    }) |snippet| {
        if (std.mem.indexOf(u8, smp_source, snippet) == null)
            try common.addError(errors, allocator, "device cache transitions must hold participants through cache retirement and publication: {s}", .{snippet});
    }
    for ([_][]const u8{
        "parked: u64 align(64)", "flushed: u64",        "released: u64",       "last_generation",  "std.math.add(u64",
        "@cmpxchgWeak(u64",      "GenerationExhausted", "InvalidParticipants", "self.allStamped(", "Phase.failed",
    }) |snippet| {
        if (std.mem.indexOf(u8, cache_rendezvous_source, snippet) == null)
            try common.addError(errors, allocator, "cache transition epochs must retain exact per-CPU phase authority: {s}", .{snippet});
    }
    for ([_][]const u8{
        "0x0007_0406_0007_0406", "UNCACHEABLE_SELECTOR",      "CACHE_CONTROL_MASK",          "validateBootstrap",
        "UnsupportedPatLayout",  "InvalidPatEncoding",        "MtrrState",                   "requireWriteBack",
        "UndefinedMtrrOverlap",  "sameConfiguration",         "UninitializedBspCachePolicy", "ApplicationProcessorCacheMismatch",
        "BootstrapMtrrSnapshot", "copyBootstrapMtrrSnapshot", "validateWritable",
    }) |snippet| {
        if (std.mem.indexOf(u8, cache_policy_source, snippet) == null)
            try common.addError(errors, allocator, "native cache policy must admit one immutable BSP/AP configuration: {s}", .{snippet});
    }
    for ([_][]const u8{
        "ZIGOS_INITIALIZE_AP_MTRRS", "ZIGOS_MTRR_SNAPSHOT_BYTES 624", "ZIGOS_MTRR_MAX_VARIABLE 32",
        "ZIGOS_CACHE_CR0_PG",        "ZIGOS_MTRR_CAP_OFFSET",         "ZIGOS_MTRR_WIDTH_OFFSET",
        ".Lmtrr_pair_preflight",     ".Lmtrr_fixed_preflight",        ".Lmtrr_compare",
        ".Lmtrr_repair",             "ZIGOS_ENABLE_AP_CACHES",        "rdmsr",
        "wrmsr",                     "wbinvd",
    }) |snippet| {
        if (std.mem.indexOf(u8, mtrr_bootstrap_source, snippet) == null)
            try common.addError(errors, allocator, "AP startup must preserve bounded pre-paging MTRR initialization and readback: {s}", .{snippet});
    }
    if (std.mem.indexOf(u8, x86_source, "readMtrrStateInto") == null or
        std.mem.indexOf(u8, ap_trampoline_source, "ZIGOS_INITIALIZE_AP_MTRRS") == null or
        std.mem.indexOf(u8, smp_trampoline_source, "copyBootstrapMtrrSnapshot") == null or
        std.mem.indexOf(u8, smp_trampoline_source, "cpu_features.clflushLineBytes()") == null or
        std.mem.indexOf(u8, smp_trampoline_source, "offset < PAGE_BYTES") == null or
        std.mem.indexOf(u8, smp_trampoline_source, "x86.flushCacheLine(") == null or
        std.mem.indexOf(u8, smp_trampoline_source, "asm volatile (\"mfence\"") == null or
        std.mem.indexOf(u8, ap_trampoline_source, "    wbinvd\n    jmpq *%rax") == null)
        try common.addError(errors, allocator, "AP startup must publish the SIPI page from caches and consume the immutable BSP MTRR snapshot before paging", .{});
    for ([_][]const u8{ "generation: u64", "generation: u64 align(64)", "last_generation", "std.math.add(u64", "@cmpxchgWeak(u64", "InvalidParticipants", "GenerationExhausted", "self.isActive(generation)" }) |snippet| {
        if (std.mem.indexOf(u8, tlb_request_source, snippet) == null) {
            try common.addError(errors, allocator, "TLB completion must use unique nonwrapping per-CPU generation acknowledgements: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, invpcid_source, "mov $2, %rcx") == null or
        std.mem.indexOf(u8, x86_source, "writeCr4(cr4 & ~CR4_PGE)") == null)
    {
        try common.addError(errors, allocator, "global retirement must invalidate all contexts including PGE translations", .{});
    }
    const required_boot_process_context_snippets = [_][]const u8{
        "cpuModelRequest",
        "cpu_policy.AdmissionPolicy.init(detected_features, model_request)",
        "admission_policy.firstMissing(detected_features)",
        "admission_policy.resolveFeatures(detected_features)",
        "admission_policy.process_context_mode",
        "admission_policy.featureMode()",
        "model_inventory",
        "qemu_software_cpu_fallback",
        "qemu_tsc_frequency_hz",
        "hardware_process_contexts",
        "cpu_pcid_enabled",
        "cpu_pcid_software_fallback",
        "cpu_pcid_ready",
        "cpu_pge_enabled",
        "cpu_smep_enabled",
        "cpu_smap_enabled",
        "cpu_umip_enabled",
        "cpu_syscall_enabled",
        "cpu_fred_enabled",
        "cpu_pku_enabled",
        "cpu_lass_enabled",
        "cpu_lass_address_partition_rejected",
        "init_core.init(hardware_lass)",
    };
    for (required_boot_process_context_snippets) |snippet| {
        if (std.mem.indexOf(u8, boot_entry_source, snippet) == null) {
            try common.addError(errors, allocator, "CPU boot process-context gate must retain snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, boot_entry_source, "init_core.init(hardware_lass)")) |core_init| {
        if (std.mem.indexOf(u8, boot_entry_source, "common.printBootMarker(boot_markers.cpu_lass_enabled)")) |success_marker| {
            if (success_marker < core_init) {
                try common.addError(errors, allocator, "LASS success must follow descriptor and entry admission", .{});
            }
        }
    }
    const required_boot_timer_snippets = [_][]const u8{
        "cpuModelRequest",
        "qemu_software_cpu_fallback",
        "admission_policy.hardware_tsc_timer",
        "hardware_tsc_timer",
        ".tsc_deadline else .calibrated_countdown",
    };
    for (required_boot_timer_snippets) |snippet| {
        if (std.mem.indexOf(u8, boot_entry_source, snippet) == null) {
            try common.addError(errors, allocator, "CPU boot timer gate must retain snippet: {s}", .{snippet});
        }
    }
    const required_boot_cet_snippets = [_][]const u8{
        "admission_policy.cet_mode",
        ".init(hardware_proof.madtTable(), admission_policy)",
    };
    for (required_boot_cet_snippets) |snippet| {
        if (std.mem.indexOf(u8, boot_entry_source, snippet) == null) {
            try common.addError(errors, allocator, "CPU boot CET gate must retain snippet: {s}", .{snippet});
        }
    }
    for ([_][]const u8{
        "pub const AdmissionPolicy",
        "model_request: ModelRequest",
        "model_request.enabled()",
        "resolveTscFrequency",
        "firstMissingForEnablement",
        "hardware_lass",
        "hardware_fred",
        "hardware_tsc_timer",
        "tsc_frequency_hz",
    }) |snippet| {
        if (std.mem.indexOf(u8, cpu_policy_source, snippet) == null) {
            try common.addError(errors, allocator, "BSP and AP admission must share immutable CPU and clock policy: {s}", .{snippet});
        }
    }
    var ap_admission_offset: usize = std.mem.indexOf(u8, smp_bringup_source, "fn apEntry(") orelse smp_bringup_source.len;
    for ([_][]const u8{
        "admission_policy.firstMissing(detected_features)",
        "cpu_identity.initialize(index);",
        "gdt.initCpu(index);",
        "cpu_features.enableModernFeatures(",
        "syscall64.initApplicationProcessor(",
        "idt.init();",
        "x86.enableLass()",
        "@atomicStore(bool, &bringup_cpus[index].online, true, .release)",
    }) |snippet| {
        if (std.mem.indexOfPos(u8, smp_bringup_source, ap_admission_offset, snippet)) |position| {
            ap_admission_offset = position + snippet.len;
        } else {
            try common.addError(errors, allocator, "AP CPU admission and control activation must retain ordered step: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, ap_trampoline_source, "movl $(CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT), %eax") == null or
        std.mem.indexOf(u8, ap_trampoline_source, "smp_trampoline_cr4") != null or
        std.mem.indexOf(u8, smp_trampoline_source, "smp_trampoline_cr4") != null)
    {
        try common.addError(errors, allocator, "AP trampoline must enter with minimal CR4 controls instead of copying BSP state", .{});
    }
    if (std.mem.indexOf(u8, x86_source, "cet_programmed") != null) {
        try common.addError(errors, allocator, "CET enablement must use admitted per-CPU policy instead of shared programming state", .{});
    }
    const required_pcid_allocator_snippets = [_][]const u8{
        "KERNEL_IDENTIFIER",
        "MAX_IDENTIFIER",
        "next_hint",
        "NotAllocated",
    };
    for (required_pcid_allocator_snippets) |snippet| {
        if (std.mem.indexOf(u8, pcid_allocator_source, snippet) == null) {
            try common.addError(errors, allocator, "bounded PCID allocation must retain snippet: {s}", .{snippet});
        }
    }
    const required_pcid_paging_snippets = [_][]const u8{
        "pcid_allocator.Allocator",
        "tryAllocProcessContext",
        "releaseRetiredProcessContext",
        "setRemoteKernelShootdown",
        "publishLeafMutation",
        "unmapBorrowedKernelRange",
        "retireOwnedHierarchy",
        "releaseDetachedHierarchy",
        "x86.invalidatePcid",
        "CACHES_PROCESS_CONTEXT_MODE",
        "PRECOMPUTES_ADDRESS_SPACE_CR3",
        "x86.processContextIdentifiersEnabled",
        "x86.pcidCr3Value",
        "x86.writeCr3",
        ".switch_cr3 = addressSpaceCr3",
        "switchToUserAddressSpace",
        "switchToKernelAddressSpace",
        "switchAddressSpace",
        "ENTRY_GLOBAL",
        "leafFlags(flags, global)",
        "USES_RUNTIME_2M_PAGES",
        "mapOwnedUserHugePage",
        "LARGE_2M_PAGE_SIZE",
        "ENTRY_LARGE_PAGE",
    };
    for (required_pcid_paging_snippets) |snippet| {
        if (std.mem.indexOf(u8, paging_source, snippet) == null) {
            try common.addError(errors, allocator, "PCID-aware paging must retain snippet: {s}", .{snippet});
        }
    }
    const retired_flush_switch_snippets = [_][]const u8{
        "switchPageDirectory",
    };
    const address_space_switch_sources = [_]struct {
        label: []const u8,
        source: []const u8,
    }{
        .{ .label = paging_path, .source = paging_source },
        .{ .label = userspace_executor_path, .source = userspace_executor_source },
    };
    for (address_space_switch_sources) |source_check| {
        for (retired_flush_switch_snippets) |snippet| {
            if (std.mem.indexOf(u8, source_check.source, snippet) != null) {
                try common.addError(errors, allocator, "address-space switching must not restore the flush-on-every-switch API in {s}: {s}", .{ source_check.label, snippet });
            }
        }
    }
    const required_userspace_switch_snippets = [_][]const u8{
        "switchToUserAddressSpace",
        "switchToKernelAddressSpace",
    };
    for (required_userspace_switch_snippets) |snippet| {
        if (std.mem.indexOf(u8, userspace_executor_source, snippet) == null) {
            try common.addError(errors, allocator, "userspace execution must use the typed PCID-aware switch surface: {s}", .{snippet});
        }
    }
    const required_address_space_benchmark_snippets = [_][]const u8{
        "paging.address_space_roundtrip",
        "benchmarkAddressSpaceRoundtrip",
        "switchToUserAddressSpace",
        "switchToKernelAddressSpace",
    };
    const benchmark_cases_path = "src/kernel/boot/benchmark/cases.zig";
    const benchmark_suite_path = "src/kernel/boot/benchmark/suite.zig";
    if (!common.pathExists(io, benchmark_cases_path) or !common.pathExists(io, benchmark_suite_path)) {
        try common.addError(errors, allocator, "address-space benchmark sources are missing", .{});
    } else {
        const benchmark_cases_source = try common.readFileAlloc(allocator, io, benchmark_cases_path, common.source_file_max_bytes);
        const benchmark_suite_source = try common.readFileAlloc(allocator, io, benchmark_suite_path, common.source_file_max_bytes);
        for (required_address_space_benchmark_snippets) |snippet| {
            if (std.mem.indexOf(u8, benchmark_cases_source, snippet) == null and
                std.mem.indexOf(u8, benchmark_suite_source, snippet) == null)
            {
                try common.addError(errors, allocator, "address-space benchmark must retain snippet: {s}", .{snippet});
            }
        }
        const required_syscall_benchmark_snippets = [_][]const u8{
            "syscall.fast_entry_roundtrip",
            "operations_per_iteration",
            "benchmarkSyscallFastEntryRoundtrip",
            "SYSCALL_BENCHMARK_BATCH_SIZE",
        };
        for (required_syscall_benchmark_snippets) |snippet| {
            if (std.mem.indexOf(u8, benchmark_cases_source, snippet) == null and
                std.mem.indexOf(u8, benchmark_suite_source, snippet) == null)
            {
                try common.addError(errors, allocator, "native syscall benchmark must retain snippet: {s}", .{snippet});
            }
        }
    }
    const required_syscall_configuration_snippets = [_][]const u8{
        "FRED_ONLY_TRAPS",
        "USER_STAR_BASE_SELECTOR",
        "SYSCALL_RFLAGS_MASK",
        "IA32_GS_BASE_MSR",
        "IA32_KERNEL_GS_BASE_MSR",
        "IA32_STAR_MSR",
        "IA32_LSTAR_MSR",
        "IA32_FMASK_MSR",
        "EFER_SCE",
        "enableFred",
        "updateFredStack",
        "fredEnabled",
        "syscallExtensionEnabled",
        "setKernelStack",
        "setActiveTaskId",
        "currentActiveTaskId",
        "setKernelPort",
    };
    for (required_syscall_configuration_snippets) |snippet| {
        if (std.mem.indexOf(u8, syscall_source, snippet) == null) {
            try common.addError(errors, allocator, "native x86-64 syscall configuration must retain snippet: {s}", .{snippet});
        }
    }
    const required_fred_entry_snippets = [_][]const u8{
        "zigos_fred_entry",
        "zigos_fred_kernel_entry",
        ".balign 4096",
        ".balign 256",
        "#include \"fred_frame64.inc\"",
        "#include \"../../arch/xstate64.inc\"",
        "ZIGOS_FRED_TEST_SYSCALL",
        "ZIGOS_FRED_COPY_RETURN_FRAME",
        "ENTER_KERNEL_XSTATE",
        "LEAVE_KERNEL_XSTATE",
        "call syscall_handler",
        "call isrHandler",
        "0xf2, 0x0f, 0x01, 0xca",
        "0xf3, 0x0f, 0x01, 0xca",
    };
    for (required_fred_entry_snippets) |snippet| {
        if (std.mem.indexOf(u8, fred_entry_source, snippet) == null) {
            try common.addError(errors, allocator, "native x86-64 FRED entry must retain snippet: {s}", .{snippet});
        }
    }
    const required_fred_frame_snippets = [_][]const u8{
        "FRED_ERROR, 0",
        "FRED_RIP, 8",
        "FRED_CS, 16",
        "FRED_RFLAGS, 24",
        "FRED_RSP, 32",
        "FRED_SS, 40",
        "FRED_EVENT_DATA, 48",
        "FRED_RESERVED, 56",
        "FRED_FRAME_BYTES, 64",
        "FRED_VECTOR_SHIFT, 32",
        "FRED_EVENT_TYPE_SHIFT, 48",
        "FRED_SYSCALL_CLASS, 0x70001",
        "ZIGOS_FRED_TEST_SYSCALL",
        "ZIGOS_FRED_COPY_RETURN_FRAME",
        ".Lfred_reject_user_software_event",
    };
    for (required_fred_frame_snippets) |snippet| {
        if (std.mem.indexOf(u8, fred_frame_source, snippet) == null) {
            try common.addError(errors, allocator, "architectural FRED frame must retain snippet: {s}", .{snippet});
        }
    }
    const required_syscall_entry_snippets = [_][]const u8{
        "zigos_syscall_entry",
        "swapgs",
        "CPU_KERNEL_STACK_TOP",
        "CPU_USER_STACK_POINTER",
        "#include \"../../arch/xstate64.inc\"",
        "ENTER_KERNEL_XSTATE",
        "LEAVE_KERNEL_XSTATE",
        "endbr64",
        "sysretq",
        "call syscall_handler",
        "call isrHandler",
        "zigos_syscall_benchmark_user_start",
        "syscall",
    };
    for (required_syscall_entry_snippets) |snippet| {
        if (std.mem.indexOf(u8, syscall_entry_source, snippet) == null) {
            try common.addError(errors, allocator, "native x86-64 syscall entry must retain snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, syscall_entry_source, "xorq %rdi") != null) {
        try common.addError(errors, allocator, "legacy syscall entry must keep the userspace request pointer in %rdi", .{});
    }
    const scheduler_source = try common.readFileAlloc(allocator, io, "src/native/task/userspace_scheduler.zig", common.source_file_max_bytes);
    const forbidden_scheduler_imports = [_][]const u8{
        "policy/manifest.zig",
        "session/service_catalog.zig",
        "xhci_driver_task.zig",
    };
    for (forbidden_scheduler_imports) |snippet| {
        if (std.mem.indexOf(u8, scheduler_source, snippet) != null) {
            try common.addError(errors, allocator, "userspace scheduler must not import {s}", .{snippet});
        }
    }
    const required_sysret_gdt_snippets = [_][]const u8{
        "USER_DATA_SEG: u16 = 0x18",
        "USER_CODE_SEG: u16 = 0x20",
        "USER_DATA_DESCRIPTOR_INDEX = 3",
        "USER_CODE_DESCRIPTOR_INDEX = 4",
    };
    for (required_sysret_gdt_snippets) |snippet| {
        if (std.mem.indexOf(u8, gdt_source, snippet) == null) {
            try common.addError(errors, allocator, "SYSRET-compatible GDT ordering must retain snippet: {s}", .{snippet});
        }
    }
    const required_userspace_syscall_snippets = [_][]const u8{
        "syscall3_asm",
        "syscall_yield_asm",
        "syscall",
    };
    for (required_userspace_syscall_snippets) |snippet| {
        if (std.mem.indexOf(u8, userspace_syscall_source, snippet) == null) {
            try common.addError(errors, allocator, "userspace syscall ABI must retain snippet: {s}", .{snippet});
        }
    }
    const retired_software_interrupt_snippets = [_][]const u8{
        "setUserGate",
        "ISR_NOERRCODE 128",
        "ISR_NOERRCODE 129",
        "int $0x80",
        "int $129",
    };
    const syscall_transition_sources = [_]struct {
        label: []const u8,
        source: []const u8,
    }{
        .{ .label = isr_path, .source = isr_source },
        .{ .label = interrupt_stubs_path, .source = interrupt_stubs_source },
        .{ .label = userspace_syscall_path, .source = userspace_syscall_source },
        .{ .label = userspace_executor_path, .source = userspace_executor_source },
    };
    for (syscall_transition_sources) |source_check| {
        for (retired_software_interrupt_snippets) |snippet| {
            if (std.mem.indexOf(u8, source_check.source, snippet) != null) {
                try common.addError(errors, allocator, "userspace entry must not restore the software-interrupt ABI in {s}: {s}", .{ source_check.label, snippet });
            }
        }
    }
    const required_permission_input_snippets = [_][]const u8{
        "const xhci = @import",
        "const input_driver_task = @import",
        "const input_router = @import",
        "input_driver_task.Decoder",
        "self.decoder.decode",
        "ModeledInputSource",
        "controller: xhci.HidController",
        "focused_input",
        "router.service",
        "router.pollForTask(self.task_id)",
        "focused_commands.submit",
        "bindSystemInputRouter",
        "error.UnsupportedTextInput",
    };
    for (required_permission_input_snippets) |snippet| {
        if (std.mem.indexOf(u8, permission_review_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 permission review must retain hardware xHCI input snippet: {s}", .{snippet});
        }
    }
    const required_input_router_snippets = [_][]const u8{
        "pub const MAX_KEYBOARDS",
        "pub const MAX_QUEUED_EVENTS",
        "pub const MAX_EVENTS_PER_INBOX",
        "KeyboardIdentity",
        "event_slots",
        "free_event_head",
        "report.sequence <= self.last_report_sequence",
        "std.math.add(u64, self.last_event_sequence, 1) catch return false",
        "self.last_event_sequence = sequence",
        "window.modal and window.reviewer_task_id != 0",
        "window.subject_task_id",
        "compositor.switchVisible",
        "pruneStaleInboxes",
        "pollWakeTarget",
        "pollAbiForTask",
        "abi.InputEventDescriptor",
        "pub const HEAP_BACKED_EVENT_SLOTS_ON_FREESTANDING = true",
        "const EventSlotBacking = if (heap_backed_event_slots) ?*EventSlotArray else EventSlotArray",
        "const allocation = kernel_memory.kmalloc(@sizeOf(EventSlotArray)) orelse return null",
        "kernel_memory.kfree(@ptrCast(slots))",
        "pub fn deinit(self: *Router) void",
        "for (0..report_budget) |_|",
    };
    for (required_input_router_snippets) |snippet| {
        if (std.mem.indexOf(u8, input_router_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 compositor input ownership must retain focused-router snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, input_router_source, "event_slots: [MAX_QUEUED_EVENTS]EventSlot =") != null) {
        try common.addError(errors, allocator, "RNUC15CRSU7 input event slots must not return to inline freestanding router storage", .{});
    }
    const retired_input_router_telemetry_snippets = [_][]const u8{
        "pub const ServiceResult",
        "reports_polled: usize",
        "untracked_keyboard_reports: usize",
        "invalid_reports: usize",
        "stale_reports: usize",
        "events_dropped: usize",
        "stale_events_dropped: usize",
        "focus_switches: usize",
        "result.reports_accepted += 1",
        "result.events_routed += 1",
        "result.events_dropped += 1",
        "result.focus_switches =",
        "self.reports_polled += 1",
        "self.untracked_keyboard_reports += 1",
        "self.events_routed += 1",
        "self.invalid_reports += 1",
        "self.stale_reports += 1",
        "self.events_dropped += 1",
        "self.stale_events_dropped += inbox.count",
        "self.focus_switches += 1",
    };
    for (retired_input_router_telemetry_snippets) |snippet| {
        if (std.mem.indexOf(u8, input_router_source, snippet) != null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 input router must not restore unobserved telemetry: {s}", .{snippet});
        }
    }
    const required_input_decoder_snippets = [_][]const u8{
        "pub const BATCHED_DECODER_OUTPUT = true",
        "pub const DECODED_EVENTS_SIZE_CEILING_BYTES: usize = 13",
        "pub const DECODER_SIZE_CEILING_BYTES: usize = 6",
        "pub const DecodedEvents = struct",
        "pub fn decode(",
    };
    for (required_input_decoder_snippets) |snippet| {
        if (std.mem.indexOf(u8, input_driver_task_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 input decoder must return bounded event batches: {s}", .{snippet});
        }
    }
    const retired_input_decoder_snippets = [_][]const u8{
        "EVENT_QUEUE_CAPACITY",
        "COMPACT_EVENT_QUEUE_METADATA",
        "QUEUE_ONLY_DECODER_STATE",
        "SINGLE_REPORT_EVENT_QUEUE",
        "EventQueueFull",
        "pub fn poll(",
        "pub fn pendingCount(",
        "reports_consumed: usize",
        "events_emitted: usize",
    };
    for (retired_input_decoder_snippets) |snippet| {
        if (std.mem.indexOf(u8, input_driver_task_source, snippet) != null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 input decoder must not restore queued state or duplicate telemetry: {s}", .{snippet});
        }
    }
    const required_userspace_input_snippets = [_]struct {
        label: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .label = userspace_executor_path, .source = userspace_executor_source, .snippet = "granted.rights.has(.input_recv)" },
        .{ .label = userspace_executor_path, .source = userspace_executor_source, .snippet = "mailbox.input_capability_id = update.authorities.input_capability_id" },
        .{ .label = userspace_executor_path, .source = userspace_executor_source, .snippet = "last_yield_disposition" },
        .{ .label = userspace_executor_path, .source = userspace_executor_source, .snippet = "last_yield_ui_revision" },
        .{ .label = userspace_scheduler_path, .source = userspace_scheduler_source, .snippet = "outcome == .wait_for_event" },
        .{ .label = userspace_scheduler_path, .source = userspace_scheduler_source, .snippet = "executionRemainsReady(outcome)" },
        .{ .label = userspace_scheduler_path, .source = userspace_scheduler_source, .snippet = "ui_revision > accounting.last_ui_state_revision" },
        .{ .label = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "const INPUT_EVENTS_PER_DISPATCH: usize = 8" },
        .{ .label = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "fn drainFocusedInput(ui: *UiRuntime, comptime saves_documents: bool)" },
        .{ .label = userspace_runtime_path, .source = userspace_runtime_source, .snippet = ".wait_for_event" },
        .{ .label = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "recordInputEvent" },
        .{ .label = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "publishUiState" },
        .{ .label = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "mailbox.FLAG_OWNS_UI_SURFACE" },
        .{ .label = userspace_ui_state_path, .source = userspace_ui_state_source, .snippet = "pub const TEXT_CAPACITY: usize = 512" },
        .{ .label = userspace_ui_state_path, .source = userspace_ui_state_source, .snippet = "pub fn modelForBundle" },
        .{ .label = userspace_ui_state_path, .source = userspace_ui_state_source, .snippet = "test \"Notes UI state requests a save without claiming durability\"" },
    };
    for (required_userspace_input_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 userspace input delivery must retain snippet in {s}: {s}", .{ required.label, required.snippet });
        }
    }
    try validateVoluntaryYieldSource(allocator, errors, userspace_runtime_source, .runtime);
    try validateVoluntaryYieldSource(allocator, errors, userspace_executor_source, .executor);
    const dispatch_ownership_source = try readRequiredSource(allocator, io, errors, "src/native/task/dispatch_ownership.zig") orelse return;
    try validatePreparedDispatchSource(allocator, errors, dispatch_ownership_source, .coordinator);
    try validatePreparedDispatchSource(allocator, errors, userspace_executor_source, .executor);
    try validatePreparedDispatchSource(allocator, errors, userspace_scheduler_source, .scheduler);
    try validatePreparedArchitectureProofSource(allocator, errors, userspace_executor_source, .executor);
    try validateDurableTransportSource(allocator, errors, userspace_executor_source, .executor);
    try validateDurableTransportSource(allocator, errors, dispatch_ownership_source, .coordinator);
    for ([_]struct { path: []const u8, kind: DurableTransportSourceKind }{
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core },
        .{ .path = "src/kernel/smp.zig", .kind = .smp },
        .{ .path = "src/kernel/interrupts/isr.zig", .kind = .isr },
        .{ .path = "src/kernel/interrupts/interrupt64.S", .kind = .entry_assembly },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .prompt_assembly },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .prompt_probe },
        .{ .path = "src/native/task/task_runtime.zig", .kind = .runtime },
        .{ .path = "src/native/session/session_manager_boot_flow.zig", .kind = .session },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe },
        .{ .path = "tools/host/qemu.zig", .kind = .harness },
    }) |item| {
        const source = try readRequiredSource(allocator, io, errors, item.path) orelse continue;
        try validateDurableTransportSource(allocator, errors, source, item.kind);
    }
    for ([_]struct { path: []const u8, kind: PreparedArchitectureProofSourceKind }{
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe },
        .{ .path = "tools/host/qemu.zig", .kind = .harness },
        .{ .path = "src/high_half_entry.zig", .kind = .proof_root },
        .{ .path = "src/main.zig", .kind = .native_root },
        .{ .path = "src/efi_entry.zig", .kind = .native_root },
    }) |item| {
        const source = try readRequiredSource(allocator, io, errors, item.path) orelse continue;
        try validatePreparedArchitectureProofSource(allocator, errors, source, item.kind);
    }
    for ([_]struct { path: []const u8, kind: TrapStackArchitectureSourceKind }{
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .window_assembly },
        .{ .path = "src/kernel/interrupts/interrupt64.S", .kind = .entry_assembly },
        .{ .path = "src/arch/xstate64.inc", .kind = .xstate_assembly },
        .{ .path = "src/arch/xstate.zig", .kind = .xstate_policy },
        .{ .path = "build_support/kernel.zig", .kind = .build },
        .{ .path = "tools/host/qemu.zig", .kind = .harness },
    }) |item| {
        const source = try readRequiredSource(allocator, io, errors, item.path) orelse continue;
        try validateTrapStackArchitectureSource(allocator, errors, source, item.kind);
    }
    for ([_]struct { path: []const u8, kind: EntryStackSourceKind }{
        .{ .path = "src/arch/x86.zig", .kind = .x86 },
        .{ .path = "src/kernel/interrupts/gdt64.zig", .kind = .gdt },
        .{ .path = "src/kernel/interrupts/syscall64.zig", .kind = .syscall },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor },
        .{ .path = "src/kernel/boot/benchmark/suite.zig", .kind = .benchmark },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe },
        .{ .path = "build_support/kernel.zig", .kind = .build },
        .{ .path = "src/high_half_entry.zig", .kind = .proof_root },
    }) |item| {
        const source = try readRequiredSource(allocator, io, errors, item.path) orelse continue;
        try validateEntryStackSource(allocator, errors, source, item.kind);
    }
    for (mapping_xstate_gate_sources) |item| {
        const source = try readRequiredSource(allocator, io, errors, item.path) orelse continue;
        try validateMappingXstateSource(allocator, errors, source, item.kind);
    }
    const operation_metadata_source = try readRequiredSource(allocator, io, errors, "src/native/kernel_api/operation_metadata.zig") orelse return;
    try validateVoluntaryYieldSource(allocator, errors, operation_metadata_source, .metadata);
    const required_early_console_snippets = [_][]const u8{
        "const serial = @import(\"../drivers/serial.zig\")",
        "serial.init()",
        "serial.print(str)",
        "serial.putChar(c)",
    };
    for (required_early_console_snippets) |snippet| {
        if (std.mem.indexOf(u8, console_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 early console must remain serial-backed: {s}", .{snippet});
        }
    }
    const required_boot_handoff_snippets = [_][]const u8{
        "MULTIBOOT2_BOOTLOADER_MAGIC",
        "parseMultiboot2Info",
        "multiboot2MemoryMap",
        "capturedAcpi2Rsdp",
        "efi64SystemTableAddress",
        "zigos_multiboot_magic != MULTIBOOT2_BOOTLOADER_MAGIC",
        "BOOT_HANDOFF_PHYSICAL_BYTES",
        "128 * 1024 * 1024",
    };
    for (required_boot_handoff_snippets) |snippet| {
        if (std.mem.indexOf(u8, handoff_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 boot handoff must parse firmware memory map tags: {s}", .{snippet});
        }
    }
    const required_bootloader_load_contract_snippets = [_][]const u8{
        "zigos_efi_entry",
        "0x36D76289",
        ".code64",
        "call kernel_main",
        "ZIGOS_REQUIRE_NATIVE",
        "ZIGOS_ENABLE_NATIVE_XSTATE",
        "leaq stack_top(%rip), %rsp",
    };
    for (required_bootloader_load_contract_snippets) |snippet| {
        if (std.mem.indexOf(u8, bootloader_source, snippet) == null) {
            try common.addError(errors, allocator, "x86-64 bootloader must retain its native upper-half EFI entry contract: {s}", .{snippet});
        }
    }
    const required_kernel_load_contract_snippets = [_][]const u8{
        "PHDRS",
        "text PT_LOAD FLAGS(5);",
        "readonly PT_LOAD FLAGS(4);",
        "writable PT_LOAD FLAGS(6);",
        "ENTRY(zigos_efi_entry)",
        "__kernel_start = .;",
        "__kernel_data_end = .;",
        "__kernel_end = .;",
        "__kernel_image_bias = 0xffffffff80000000;",
        ". = __kernel_image_bias + 32M;",
    };
    for (required_kernel_load_contract_snippets) |snippet| {
        if (std.mem.indexOf(u8, kernel_linker_source, snippet) == null) {
            try common.addError(errors, allocator, "x86-64 linker must retain its contiguous RX/RO/RW boot payload: {s}", .{snippet});
        }
    }
    if (std.mem.count(u8, kernel_linker_source, ":text") != 1 or
        std.mem.count(u8, kernel_linker_source, ":readonly") != 3 or
        std.mem.count(u8, kernel_linker_source, ":writable") != 2)
    {
        try common.addError(errors, allocator, "x86-64 linker must bind all six runtime regions to the RX/RO/RW segments", .{});
    }
    if (std.mem.count(u8, kernel_linker_source, "AT(ADDR(") != 6) {
        try common.addError(errors, allocator, "x86-64 linker must retain explicit physical load addresses for all six runtime regions", .{});
    }
    const retired_bootloader_address_tag_snippets = [_][]const u8{
        "MULTIBOOT2_HEADER_TAG_ADDRESS",
        ".long multiboot2_header_start",
        ".long __kernel_data_end",
        "MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS",
        ".long _start",
        ".code32",
    };
    for (retired_bootloader_address_tag_snippets) |snippet| {
        if (std.mem.indexOf(u8, bootloader_source, snippet) != null) {
            try common.addError(errors, allocator, "native x86-64 bootloader must not restore the retired protected-mode Multiboot entry: {s}", .{snippet});
        }
    }
    const required_multiboot2_acpi_snippets = [_][]const u8{
        "TAG_ACPI_NEW",
        "ACPI_RSDP_V2_MIN_BYTES",
        "parsed.acpi2_rsdp_addr",
        "seen_acpi_new",
    };
    for (required_multiboot2_acpi_snippets) |snippet| {
        if (std.mem.indexOf(u8, multiboot2_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 boot handoff must retain the ACPI RSDP tag path: {s}", .{snippet});
        }
    }
    const retired_multiboot2_acpi_snippets = [_][]const u8{
        "TAG_ACPI_OLD",
        "ACPI_RSDP_V1_BYTES",
        "seen_acpi_old",
    };
    for (retired_multiboot2_acpi_snippets) |snippet| {
        if (std.mem.indexOf(u8, multiboot2_source, snippet) != null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 boot handoff must not restore the ACPI 1 compatibility tag: {s}", .{snippet});
        }
    }
    const required_acpi2_xsdt_snippets = [_][]const u8{
        "RSDP_BASE_CHECKSUM_LENGTH",
        "RSDP_V2_MIN_LENGTH",
        "UnsupportedRevision",
        "MissingXsdt",
        "xsdtEntryCount",
        "xsdtEntryAddress",
    };
    for (required_acpi2_xsdt_snippets) |snippet| {
        if (std.mem.indexOf(u8, acpi_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 ACPI parser must require ACPI 2+ with XSDT entries: {s}", .{snippet});
        }
    }
    const retired_acpi_compatibility_snippets = [_][]const u8{
        "RSDT_SIGNATURE",
        "rsdt_address",
        "findRsdp(",
        "rootEntrySize",
    };
    for (retired_acpi_compatibility_snippets) |snippet| {
        if (std.mem.indexOf(u8, acpi_source, snippet) != null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 ACPI parser must not restore RSDT or BIOS scanning compatibility: {s}", .{snippet});
        }
    }
    const required_mapped_acpi_snippets = [_][]const u8{
        "capturePlatformFirmwareEvidence",
        "capturedRsdp",
        "mappedPhysicalTableBytes",
        "paging.mapKernelFirmwareRange",
        "madt_table_physical",
        "validatedMadtMapping(mappedPhysicalTableBytes)",
        "acpi.xsdtEntryCount",
        "mcfg.segmentZeroAllocation",
        "hardware_target.nuc15crsu7_hardware_fact_markers[2]",
    };
    for (required_mapped_acpi_snippets) |snippet| {
        if (std.mem.indexOf(u8, hardware_proof_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 firmware discovery must retain mapped ACPI table access: {s}", .{snippet});
        }
    }
    const retired_hardware_acpi_compatibility_snippets = [_][]const u8{
        "BIOS_RSDP_SCAN",
        "acpi.findRsdp",
        "rsdp.rsdt_address",
        "rootTableEntry",
        ":ACPI_RSDP:OBSERVED",
    };
    for (retired_hardware_acpi_compatibility_snippets) |snippet| {
        if (std.mem.indexOf(u8, hardware_proof_source, snippet) != null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 firmware discovery must not restore BIOS ACPI scanning or RSDT fallback: {s}", .{snippet});
        }
    }
    const retired_boot_handoff_snippets = [_][]const u8{
        "multiboot1",
        "MULTIBOOT_BOOTLOADER_MAGIC",
        "parseInfo(",
    };
    for (retired_boot_handoff_snippets) |snippet| {
        if (std.mem.indexOf(u8, handoff_source, snippet) != null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 boot handoff must not restore legacy Multiboot1 parsing: {s}", .{snippet});
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
            try common.addError(errors, allocator, "RNUC15CRSU7 APIC proof source must enforce hardware LAPIC timer snippet: {s}", .{snippet});
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
            try common.addError(errors, allocator, "RNUC15CRSU7 crash persistence proof source must enforce hardware reboot-persistence snippet: {s}", .{snippet});
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
            try common.addError(errors, allocator, "RNUC15CRSU7 FADT suspend proof source must enforce hardware power-transition snippet: {s}", .{snippet});
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
            try common.addError(errors, allocator, "RNUC15CRSU7 framebuffer proof source must enforce hardware GOP scanout snippet: {s}", .{snippet});
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
            try common.addError(errors, allocator, "RNUC15CRSU7 update rollback proof source must enforce hardware power-cycle snippet: {s}", .{snippet});
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
            try common.addError(errors, allocator, "RNUC15CRSU7 first-target telemetry recorder must reject stale source sequence snippet: {s}", .{snippet});
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
            try common.addError(errors, allocator, "RNUC15CRSU7 platform telemetry provider must reject stale reader snapshot snippet: {s}", .{snippet});
        }
    }
    const required_xhci_snippets = [_][]const u8{
        "MIN_SUPPORTED_INTERFACE_VERSION: u16 = 0x0110",
        "HCSPARAMS1_MAX_INTERRUPTERS_MASK: u32 = 0x7FF",
        "HCSPARAMS2_OFFSET: usize = 0x08",
        "HCCPARAMS1_64_BIT_ADDRESSING: u32 = 1 << 0",
        "HCCPARAMS1_CONTEXT_SIZE: u32 = 1 << 2",
        "ContextSize = enum(u8)",
        "Unsupported32BitAddressing",
        "InvalidScratchpadRestore",
        "max_scratchpad_buffers",
        "context_size.byteCount()",
        "XHCI_PAGE_BYTES: u64 = 4096",
        "DEVICE_CONTEXT_ENTRIES: u32 = 32",
        "INPUT_CONTEXT_ENTRIES: u32 = 33",
        "DmaArenaPlan",
        "planDmaArena",
        "deviceContextAddress",
        "RingAddressOverlap",
        "DmaLayoutOverflow",
        "dmaArenaPlan",
        "ControllerDmaPlan",
        "initializeControllerDma",
        "controllerDmaAccessRegions",
        "programControllerDmaRegisters",
        "EventRingConsumer",
        "decodeEvent",
        "startOwnedController",
        "acknowledgePrimaryEventRing",
        "controllerRunningHealthy",
        "EVENT_RING_SEGMENT_TABLE_ENTRIES: u32 = 1",
        "INTERRUPTER_MODERATION_INTERVAL_125_MICROSECONDS: u32 = 500",
        "UnsupportedPageSize",
        "DmaRegisterRejected",
        "InvalidDoorbellOffset",
        "InvalidRuntimeRegisterOffset",
        "MAX_EXTENDED_CAPABILITIES: usize = 64",
        "FirmwareOwnsController",
        "inspectLegacyOwnership",
        "FirmwareOwnershipTimeout",
        "claimLegacyOwnership",
        "CONTROLLER_HALT_TIMEOUT_MILLISECONDS: u64 = 16",
        "ControllerResetTimeout",
        "resetOwnedController",
        "OPERATIONAL_CONFIGURE_OFFSET: u32 = 0x38",
        "CONFIG_MAX_DEVICE_SLOTS_ENABLED_MASK: u32 = 0xFF",
        "ControllerConfigurationUnavailable",
        "DeviceSlotConfigurationRejected",
        "configureDeviceSlots",
        "SUPPORTED_PROTOCOL_CAPABILITY_ID: u8 = 2",
        "SUPPORTED_PROTOCOL_USB_NAME_STRING: u32 = 0x2042_5355",
        "COMPACT_SUPPORTED_PROTOCOL_METADATA = true",
        "SUPPORTED_PROTOCOLS_SIZE_CEILING_BYTES: usize = 452",
        "speed_classes: [MAX_EXTENDED_CAPABILITIES]u32",
        "encodeSpeedClasses",
        "parseSupportedProtocols",
        "OverlappingSupportedProtocolPorts",
        "endpointZeroMaxPacketSize",
        "deviceDescriptorEndpointZeroMaxPacketSize",
        "portStatusAcknowledge",
        "TrbRingProducer",
        "ringLinkControl",
        "enableSlotCommand",
        "addressDeviceCommand",
        "configureEndpointCommand",
        "evaluateContextCommand",
        "disableSlotCommand",
        "initializeAddressDeviceInputContext",
        "initializeConfigureInterruptInEndpointInputContext",
        "initializeEvaluateEndpointZeroInputContext",
        "USB_DEVICE_DESCRIPTOR_BYTES",
        "UsbDeviceDescriptor",
        "parseUsbDeviceDescriptor",
        "USB_CONFIGURATION_DESCRIPTOR_BYTES",
        "USB_ENUMERATION_BUFFER_BYTES",
        "XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES",
        "maximum_frames",
        "UsbConfigurationDescriptor",
        "UsbBootKeyboardConfiguration",
        "UsbBootKeyboardSelection",
        "ConfigurationDescriptorParser",
        "parseUsbConfigurationDescriptorHeader",
        "parseUsbConfigurationDescriptor",
        "parseUsbBootKeyboardConfiguration",
        "getDescriptorSetupStage",
        "setConfigurationSetupStage",
        "controlInDataStage",
        "TRB_INTERRUPT_ON_SHORT_PACKET",
        "controlOutStatusStage",
        "controlInStatusStage",
        "ENDPOINT_ZERO_DCI",
        "enumeration_buffer_address",
        "controlTransferRingAddress",
        "interruptTransferRingAddress",
        "interruptReportBufferAddress",
        "interrupt_report_buffers_address",
        "interruptInTransfer",
        "validateInterruptTransferEvent",
        "resetTransferRing",
        "BootKeyboardReportPublisher",
        "HARDWARE_HID_REPORT_QUEUE_CAPACITY",
        "ringCommandDoorbell",
        "ringDeviceDoorbell",
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
            try common.addError(errors, allocator, "RNUC15CRSU7 xHCI proof source must enforce hardware-owned event-ring snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, xhci_source, "ports: [256]?PortProtocol") != null) {
        try common.addError(errors, allocator, "xHCI supported protocols must remain stored as capability ranges", .{});
    }
    const required_xhci_hw_snippets = [_][]const u8{
        "pci.memoryBar0(device_info)",
        "bar.address % PAGE_BYTES != 0",
        "mmio_windows.xhci.base",
        "paging.mapKernelDeviceRange",
        "pci.probeMemoryBars(device_info)",
        "validateControllerAperture",
        "mapping_error",
        "readCapabilitySnapshot",
        "xhci.parseCapabilityRegisters(&snapshot)",
        "validateExtendedCapabilityRange",
        "ExtendedCapabilityReader",
        "probedLegacyOwnership",
        "OWNERSHIP_TIMEOUT_MILLISECONDS: u64 = 1_000",
        "writeOsOwnedByte",
        "tsc_clock.initialized",
        "tsc_clock.afterMilliseconds",
        "controllerReset",
        "enabledDeviceSlots",
        "writeReg32",
        "writeReg64",
        "InvariantClock",
        "BusMasteringNotRevoked",
        "controllerDmaFrameCount",
        "paging.allocIdentityDmaFrames(dma_frame_count)",
        "dma_plan.frameCount() > dma_frame_count",
        "initializeControllerDma",
        "publishDmaStructures",
        "programControllerDmaRegisters",
        "buildDmaWindows",
        "isolationDomain",
        "requesterIsolated",
        "pub const INTERRUPT_VECTOR: u8 = 67",
        "PORT_RUNTIME_STATE_SIZE_CEILING_BYTES: usize = 104",
        "CONTROLLER_RUNTIME_STATE_MAX_FRAME_COUNT: usize = 7",
        "COLOCATED_BOOT_KEYBOARD_REPORT_STATE = true",
        "COLOCATED_SUPPORTED_PROTOCOL_STATE = true",
        "CONTROLLER_RUNTIME_STATE_USES_GENERAL_MEMORY = true",
        "allocateControllerRuntimeState(",
        "paging.allocGeneralFrames(frame_count)",
        "paging.directMapAddress(frames.base)",
        "controllerRuntimeStateFrameCountFor",
        "active_keyboard_reports = controller_runtime_state.keyboard_reports",
        "active_protocols = controller_runtime_state.protocols",
        "ports.len == @as(usize, capabilities.max_ports) + 1",
        "resetControllerRuntimeState",
        "intel_vtd.routeInterrupt",
        "pci.enableSingleMsi",
        "pci.enableMemoryBusMastering",
        "servicePendingEvents",
        "EVENT_RING_STATE_CONTAINED",
        "intel_vtd.pollFaultForDevice",
        "active_protocols",
        "PORT_RESET_TIMEOUT_MILLISECONDS: u64 = 1_000",
        "COMMAND_TIMEOUT_MILLISECONDS: u64 = 1_000",
        "CONTROL_TRANSFER_TIMEOUT_MILLISECONDS: u64 = 1_000",
        "handlePortStatusChange",
        "handleCommandCompletion",
        "handleControlTransferCompletion",
        "handleInterruptTransferCompletion",
        "submitNextPortAction",
        "submitDescriptorTransfer",
        "submitSetConfigurationTransfer",
        "submitSetBootProtocolTransfer",
        "submitInterruptReportTransfer",
        "scheduleUnarmedInterruptReports",
        "resetSlotTransferRings",
        "parseConfigurationDescriptorFromDma",
        "prepareAddressDeviceInputContext",
        "prepareConfigureBootKeyboardInputContext",
        "prepareEvaluateEndpointZeroInputContext",
        ".address_device",
        ".read_device_descriptor_prefix",
        ".read_device_descriptor",
        ".read_configuration_descriptor_header",
        ".read_configuration_descriptor",
        ".set_configuration",
        ".configure_endpoint",
        ".evaluate_context",
        "deviceDescriptorForPort",
        "configurationDescriptorForPort",
        "bootKeyboardConfigurationForPort",
        "setConfigurationCount",
        "configureEndpointCount",
        "configurationDescriptorCount",
        "keyboardReportAfter",
        "pollKeyboardReport",
        "inputProof",
        "writeDcbaaSlot",
        "PORT_RESET_TIMEOUT_CONTAINED",
        "COMMAND_TIMEOUT_CONTAINED",
        "TRANSFER_TIMEOUT_CONTAINED",
    };
    for (required_xhci_hw_snippets) |snippet| {
        if (std.mem.indexOf(u8, xhci_hw_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 xHCI hardware probe must retain read-only capability validation snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, xhci_hw_source, "var ports: [256]PortRuntimeState") != null) {
        try common.addError(errors, allocator, "xHCI port runtime state must remain sized to reported hardware capacity", .{});
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
            try common.addError(errors, allocator, "RNUC15CRSU7 NVMe proof source must enforce hardware-owned completion snippet: {s}", .{snippet});
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
            try common.addError(errors, allocator, "RNUC15CRSU7 I225 proof source must enforce hardware-owned descriptor-ring snippet: {s}", .{snippet});
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
    const marker_path = "spec/hardware/nuc15crsu7-required-markers.txt";
    if (!common.pathExists(io, marker_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 marker file is missing: {s}", .{marker_path});
        return;
    }
    const source = try common.readFileAlloc(allocator, io, marker_path, common.source_file_max_bytes);
    for (FIRST_HARDWARE_TARGET_REQUIRED_MARKERS) |marker| {
        if (!markerFileHasActiveLine(source, marker)) {
            try common.addError(errors, allocator, "RNUC15CRSU7 marker file is missing required marker: {s}", .{marker});
        }
    }
    for (FIRST_HARDWARE_TARGET_REQUIRED_FACT_MARKERS) |marker| {
        if (!markerFileHasActiveLine(source, marker)) {
            try common.addError(errors, allocator, "RNUC15CRSU7 marker file is missing required hardware fact marker: {s}", .{marker});
        }
    }
    for (FIRST_HARDWARE_TARGET_REQUIRED_BOOTED_PROOF_MARKERS) |marker| {
        if (!markerFileHasActiveLine(source, marker)) {
            try common.addError(errors, allocator, "RNUC15CRSU7 marker file is missing required booted proof marker: {s}", .{marker});
        }
    }

    const production_marker_path = "spec/hardware/nuc15crsu7-production-required-markers.txt";
    if (!common.pathExists(io, production_marker_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 production marker file is missing: {s}", .{production_marker_path});
        return;
    }
    const production_source = try common.readFileAlloc(allocator, io, production_marker_path, common.source_file_max_bytes);
    for (FIRST_HARDWARE_TARGET_REQUIRED_PRODUCTION_MARKERS) |marker| {
        if (!markerFileHasActiveLine(production_source, marker)) {
            try common.addError(errors, allocator, "RNUC15CRSU7 production marker file is missing required marker: {s}", .{marker});
        }
    }
    for (FIRST_HARDWARE_TARGET_FORBIDDEN_PRODUCTION_MARKERS) |marker| {
        if (markerFileHasActiveLine(production_source, marker)) {
            try common.addError(errors, allocator, "RNUC15CRSU7 production marker file must not require unreachable exhaustive marker: {s}", .{marker});
        }
    }
}

fn validateNuc11tnki5ProofPreparation(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const prep_path = "tools/host/hardware.zig";
    if (!common.pathExists(io, prep_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 proof preparation script is missing: {s}", .{prep_path});
        return;
    }
    const implementation = try common.readFileAlloc(allocator, io, prep_path, common.source_file_max_bytes);
    const template = try common.readFileAlloc(allocator, io, "tools/host/hardware/proof-manifest.template", common.source_file_max_bytes);
    const source = try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ implementation, template });
    const required_snippets = [_][]const u8{
        "build/os.iso",
        "build/os-verification.iso",
        "zig-out/bin/kernel-zigos-native.elf",
        "zig-out/bin/kernel-zigos-native-verification.elf",
        "--nonce",
        "ZIGOS_HARDWARE_PROOF_NONCE",
        "zigos-nuc15crsu7-proof-v2",
        "capture_nonce={s}",
        "device_identity=device-identity.txt",
        "production_serial_log=production-serial.log",
        "production_boot_medium=build/os.iso",
        "production_boot_kernel=zig-out/bin/kernel-zigos-native.elf",
        "production_required_markers=spec/hardware/nuc15crsu7-production-required-markers.txt",
        "verification_serial_log=verification-serial.log",
        "verification_boot_medium=build/os-verification.iso",
        "verification_boot_kernel=zig-out/bin/kernel-zigos-native-verification.elf",
        "verification_required_markers=spec/hardware/nuc15crsu7-required-markers.txt",
        "cycle_manifest=cycle-manifest.txt",
        "production_quote=production-attestation.quote",
        "production_signature=production-attestation.sig",
        "verification_quote=verification-attestation.quote",
        "verification_signature=verification-attestation.sig",
        "capture_statement=capture-statement.txt",
        "release-bundle-check",
        "release-verifier",
        "release-verifier-sha256",
        "UnsafeProofOutput",
        "ProofOutputNotEmpty",
        "atomicWrite",
        "Capture separate production and verification boots",
        "production-serial.log",
        "verification-serial.log",
        "cycle-manifest.txt",
        "operator-metadata-markers.txt",
        ":EVIDENCE_SOURCE:REAL_HARDWARE",
        ":BOARD_SKU:RNUC15CRSU7",
        ":PROOF_MANIFEST:RECORDED",
        ":FIRMWARE_SETTINGS:RECORDED",
        ":POWER_CYCLE_NOTES:RECORDED",
        ":ARTIFACT_DIGESTS:RECORDED",
    };
    for (required_snippets) |snippet| {
        if (std.mem.indexOf(u8, source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 proof preparation script must emit metadata marker snippet: {s}", .{snippet});
        }
    }

    const statement_writer_path = "tools/host/hardware.zig";
    if (!common.pathExists(io, statement_writer_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 capture-statement writer is missing: {s}", .{statement_writer_path});
        return;
    }
    const statement_source = try common.readFileAlloc(allocator, io, statement_writer_path, common.source_file_max_bytes);
    const statement_snippets = [_][]const u8{
        "format=zigos-nuc15crsu7-capture-statement-v1",
        "capture_nonce",
        "{s}_sha256={s}",
        "device_identity",
        "production_serial",
        "verification_serial",
        "cycle_manifest",
        "production_iso",
        "production_kernel",
        "verification_iso",
        "verification_kernel",
        "production_marker_contract",
        "verification_marker_contract",
        "firmware_settings",
        "power_cycle_notes",
        "attestation_lifecycle",
        "artifact_digests",
        "production_quote",
        "production_signature",
        "verification_quote",
        "verification_signature",
    };
    for (statement_snippets) |snippet| {
        if (std.mem.indexOf(u8, statement_source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 capture-statement writer must bind snippet: {s}", .{snippet});
        }
    }
}

fn validateNuc11tnki5ProofChecker(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const checker_path = "tools/host/hardware.zig";
    if (!common.pathExists(io, checker_path)) {
        try common.addError(errors, allocator, "RNUC15CRSU7 proof checker is missing: {s}", .{checker_path});
        return;
    }
    const implementation = try common.readFileAlloc(allocator, io, checker_path, common.source_file_max_bytes);
    const sidecar_template = try common.readFileAlloc(allocator, io, "tools/host/hardware/power-cycle-notes.template", common.source_file_max_bytes);
    const source = try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ implementation, sidecar_template });
    const required_snippets = [_][]const u8{
        "zigos-nuc15crsu7-proof-v2",
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
        "FreshNonceRequired",
        "PinnedTrustDigestRequired",
        "PinnedVerifierDigestMismatch",
        "IndependentTrustRequired",
        "format=zigos-nuc15crsu7-capture-statement-v1",
        "NonCanonicalCaptureStatement",
        "production_serial",
        "verification_serial",
        "cycle_manifest",
        "production_iso",
        "production_kernel",
        "verification_iso",
        "verification_kernel",
        "production_marker_contract",
        "verification_marker_contract",
        "production_quote",
        "production_signature",
        "verification_quote",
        "verification_signature",
        "format=zigos-nuc15crsu7-cycle-manifest-v1",
        "zigos-nuc15crsu7-cycle-log-v1",
        "NonCanonicalCycleManifest",
        "NonCanonicalCyclePath",
        "DuplicateCycleEvidence",
        "UnlistedCycleEvidence",
        "CycleDigestMismatch",
        "InsufficientHardwareCycles",
        "SpoofedCycleSummary",
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
        "ZIGOS:STORAGE:CHECKPOINT:FINAL",
        "enabled=true",
        "dirty=false",
        "generation=",
        "error=none",
        "ZIGOS:TASK:SESSION_READY",
        "MarkerOrder",
        "EVIDENCE_SOURCE:REAL_HARDWARE",
        "BOARD_SKU:RNUC15CRSU7",
        "activeMarkers",
        "for (try activeMarkers(ctx, try readEvidence(ctx, root, production_contract)))",
        "for (try activeMarkers(ctx, try readEvidence(ctx, root, verification_contract)))",
        "MarkerContractMismatch",
        "app.notes.daily",
        "userspace-notes-daily.elf",
        "ArtifactDigestMismatch",
        "stale_generation_rejected",
        "revoked_generation_rejected",
        "verifier_rejected_stale_attestation",
        "format=zigos-trusted-hardware-verifier-response-v1",
        "assertion=signed-response",
        "statement_sha256={s}",
        "nonce={s}",
        "production_role=verified",
        "verification_role=verified",
        "ExactVerifierResponseRequired",
        "follow_symlinks = false",
        "secureParent",
        "QEMU",
    };
    for (required_snippets) |snippet| {
        if (std.mem.indexOf(u8, source, snippet) == null) {
            try common.addError(errors, allocator, "RNUC15CRSU7 proof checker must enforce snippet: {s}", .{snippet});
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
    const signer_text_pool_snippets = [_][]const u8{
        "pub const HEAP_BACKED_SIGNER_TEXT_POOL_ON_FREESTANDING = true",
        "pub const SIGNER_TEXT_POOL_HANDLE_SIZE_CEILING_BYTES: usize = 8",
        "const SignerTextPoolBacking = if (heap_backed_signer_text_pool) ?*SignerTextPool else SignerTextPool",
        "const allocation = kernel_memory.kmalloc(@sizeOf(SignerTextPool)) orelse return error.NoSpaceLeft",
        "if (used != 0) @memset(pool[0..used], 0)",
        "kernel_memory.kfree(@ptrCast(pool))",
    };
    for (signer_text_pool_snippets) |snippet| {
        if (std.mem.indexOf(u8, source, snippet) == null) {
            try common.addError(errors, allocator, "Storage production track must keep on-demand signer text storage: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, source, "signer_text_pool: [SIGNER_TEXT_POOL_BYTES]u8") != null) {
        try common.addError(errors, allocator, "Storage production track must not restore the freestanding inline signer text pool", .{});
    }
    const production_attachment_snippets = [_][]const u8{
        "pub fn attachNvmePciBackend(self: *Volume, backend: Backend) bool",
        "pub fn hasProductionStorageBackend(self: *const Volume) bool",
        "self.attached_backend_kind == .nvme_pci",
        "pub fn attachmentBusy(self: *const Volume) bool",
        "if (!self.beginOperation()) return error.VolumeOperationBusy",
        "snapshot_current: bool",
        "dirty_snapshot.acknowledge(store, workspaces)",
        "try validateReplayLog(log, loaded.root)",
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
        "attachPublishedStorageBackend(publication, backend)",
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
        "const shares_root_volume = builtin.target.os.tag == .freestanding",
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
        "hasTestOnlyOperationalName(label)",
        "zigos.remote-attestation-context.v2",
        "request_context_digest",
        "attestation response cannot be relabeled for another verifier policy",
        "attestation rejects malformed bounded records before hashing or signing",
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
        "try self.hardware_provider.seal(&binding, raw, &blob)",
        "secret.hardware_provider_used = true",
        "secret.resident_material = !hardware_backed",
        "secret.material = .{ .sealed = blob }",
        "pub fn generateSigningKey",
        "try self.hardware_provider.generateSigningKey(&binding, &blob)",
        "pub fn restoreSealed",
        "try self.hardware_provider.open(&binding, blob, &scratch)",
        "secret.resident_material = false",
        "std.crypto.secureZero(u8, out)",
        "pub fn signDigest",
        "pub const IMPORTS_INTO_PREZEROED_SECRET_SLOTS = true",
        "const secret = &self.secrets[slot_index]",
        "secret imports reuse pre-zeroed inactive slots",
        "self.secret_count += 1",
        "secure secret store requires a hardware provider before hardware-backed imports",
    };
    for (store_snippets) |snippet| {
        if (std.mem.indexOf(u8, store_source, snippet) == null) {
            try common.addError(errors, allocator, "Secret vault hardware-backed boundary must keep store snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, store_source, "digestSecretMaterial") != null or
        std.mem.indexOf(u8, store_source, "defaultSeal") != null)
    {
        try common.addError(errors, allocator, "Secret vault hardware-backed boundary must not reintroduce software digest fallback for hardware-backed secrets", .{});
    }

    const adapter_source = try readRequiredSource(allocator, io, errors, "src/native/platform/tpm2_secret_provider.zig") orelse return;
    for ([_][]const u8{ "self.client.seal(", "self.client.unseal(", "authorization: *const tpm.Key", "std.crypto.secureZero(u8, &key)", "std.crypto.secureZero(u8, &seed)", "self.io.random(&seed)", "sealing.encrypt(", "envelope.open(" }) |snippet| {
        if (std.mem.indexOf(u8, adapter_source, snippet) == null) {
            try common.addError(errors, allocator, "Secret vault TPM adapter must retain operation: {s}", .{snippet});
        }
    }
    const sealing_source = try readRequiredSource(allocator, io, errors, "src/native/platform/secret_sealing.zig") orelse return;
    for ([_][]const u8{ "XChaCha20Poly1305", "operations: ?*const Operations", "seal: *const fn", "open: *const fn", "generateSigningKey: ?*const fn", "errdefer std.crypto.secureZero(u8, out)", "Aead.decrypt(" }) |snippet| {
        if (std.mem.indexOf(u8, sealing_source, snippet) == null) {
            try common.addError(errors, allocator, "Secret vault sealing boundary must retain operation: {s}", .{snippet});
        }
    }

    const service_path = "src/native/services/secret_vault_service.zig";
    const service_source = try readRequiredSource(allocator, io, errors, service_path) orelse return;
    const service_snippets = [_][]const u8{
        "pub const GenerateSigningKeyRequest",
        "self.store.generateSigningKey(request.owner, request.label)",
        ".operation = .generate_signing_key",
        "errdefer self.discardUnpublishedSecret(slot_index, previous_id)",
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
        "pub const VaultAuthority",
        "if (authority.holder.kind != .service) return error.InvalidIdentityAuthority",
        "authority.vault.signDigest",
        "authority.policies.credentialAssertionDecision",
        "secret.id != credential.secret_id",
        "crypto_hash.updateInt(&hasher, \"assertion-counter\", assertion.assertion_counter)",
        "const challenge = recoveryIntentDigest(credential, request.recovery_device, secret)",
        "trusted_device_count < credential.recovery_threshold",
    };
    for (identity_snippets) |snippet| {
        if (std.mem.indexOf(u8, identity_source, snippet) == null) {
            try common.addError(errors, allocator, "Secret vault hardware-backed boundary must keep identity provider test snippet: {s}", .{snippet});
        }
    }

    const identity_runtime_end = std.mem.indexOf(u8, identity_source, "const identity_keys =") orelse identity_source.len;
    const identity_runtime = identity_source[0..identity_runtime_end];
    for ([_][]const u8{ "request.credential_identity", "request.replacement_credential_identity", "request.tick", "request.threshold" }) |legacy_input| {
        if (std.mem.indexOf(u8, identity_runtime, legacy_input) != null) {
            try common.addError(errors, allocator, "Identity vault boundary must not trust request-supplied signing authority: {s}", .{legacy_input});
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
        "secret_store_context.store.attachHardwareProvider(@import(\"../../../tests/fixtures/secret_provider.zig\").provider())",
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
    const background_dispatch_path = "src/native/task/background_dispatch.zig";
    const platform_policy_signals_path = "src/native/platform/platform_policy_signals.zig";
    const benchmark_path = "src/kernel/boot/benchmark/suite.zig";
    const service_graph_builder_path = "src/native/session/service_graph_builder.zig";
    const supervisor_path = "src/native/session/supervisor.zig";
    const trust_boot_path = "src/native/session/trust_boot.zig";
    const session_manager_support_path = "src/native/session/session_manager_support.zig";
    const session_manager_boot_flow_path = "src/native/session/session_manager_boot_flow.zig";
    const session_demo_boot_path = "src/native/demo/session_demo_boot.zig";
    const booted_evidence_path = "src/native/session/booted_evidence.zig";
    const accelerator_source = try readRequiredSource(allocator, io, errors, accelerator_path) orelse return;
    const userspace_source = try readRequiredSource(allocator, io, errors, userspace_path) orelse return;
    const background_dispatch_source = try readRequiredSource(allocator, io, errors, background_dispatch_path) orelse return;
    const platform_policy_signals_source = try readRequiredSource(allocator, io, errors, platform_policy_signals_path) orelse return;
    const benchmark_source = try readRequiredSource(allocator, io, errors, benchmark_path) orelse return;
    const service_graph_builder_source = try readRequiredSource(allocator, io, errors, service_graph_builder_path) orelse return;
    const supervisor_source = try readRequiredSource(allocator, io, errors, supervisor_path) orelse return;
    const trust_boot_source = try readRequiredSource(allocator, io, errors, trust_boot_path) orelse return;
    const session_manager_support_source = try readRequiredSource(allocator, io, errors, session_manager_support_path) orelse return;
    const session_manager_boot_flow_source = try readRequiredSource(allocator, io, errors, session_manager_boot_flow_path) orelse return;
    const session_demo_boot_source = try readRequiredSource(allocator, io, errors, session_demo_boot_path) orelse return;
    const booted_evidence_source = try readRequiredSource(allocator, io, errors, booted_evidence_path) orelse return;

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

    const background_dispatch_storage_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = background_dispatch_path, .source = background_dispatch_source, .snippet = "pub fn initializeAllocated(self: *Controller) void" },
        .{ .path = service_graph_builder_path, .source = service_graph_builder_source, .snippet = "pub const HEAP_BACKED_BACKGROUND_DISPATCH_ON_FREESTANDING = true" },
        .{ .path = service_graph_builder_path, .source = service_graph_builder_source, .snippet = "const BackgroundDispatchBacking = if (heap_backed_background_dispatch) ?*background_dispatch.Controller else background_dispatch.Controller" },
        .{ .path = service_graph_builder_path, .source = service_graph_builder_source, .snippet = "const allocation = kernel_memory.kmalloc(@sizeOf(background_dispatch.Controller)) orelse return error.NoSpaceLeft" },
        .{ .path = service_graph_builder_path, .source = service_graph_builder_source, .snippet = "kernel_memory.kfree(@ptrCast(controller))" },
        .{ .path = session_manager_support_path, .source = session_manager_support_source, .snippet = "background_dispatcher: ?*background_dispatch.Controller" },
        .{ .path = session_manager_boot_flow_path, .source = session_manager_boot_flow_source, .snippet = "self.service_graph_builder.releaseBackgroundDispatch()" },
        .{ .path = session_demo_boot_path, .source = session_demo_boot_source, .snippet = "graph.env.background_dispatcher = manager.backgroundDispatchPtr() catch" },
        .{ .path = booted_evidence_path, .source = booted_evidence_source, .snippet = "evidence_env.background_dispatcher = manager.backgroundDispatchPtr() catch" },
    };
    for (background_dispatch_storage_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Background dispatch must retain on-demand freestanding storage in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    if (std.mem.indexOf(u8, service_graph_builder_source, "background_dispatcher: background_dispatch.Controller =") != null) {
        try common.addError(errors, allocator, "Background dispatch must not return to inline freestanding service-graph storage", .{});
    }

    const boot_service_binding_snippets = [_][]const u8{
        "pub const STACK_LOCAL_BOOT_SERVICE_BINDINGS = true",
        "var service_bindings = ServiceBindings.init()",
        "graph.service_bindings = service_bindings",
        ".uses_stack_workspace = STACK_LOCAL_BOOT_SERVICE_BINDINGS and !@hasField(Builder, \"service_bindings\")",
    };
    for (boot_service_binding_snippets) |snippet| {
        if (std.mem.indexOf(u8, service_graph_builder_source, snippet) == null) {
            try common.addError(errors, allocator, "Service graph boot must retain stack-local binding workspace: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, service_graph_builder_source, "    service_bindings: ServiceBindings = ServiceBindings.init(),") != null) {
        try common.addError(errors, allocator, "Service graph builders must not retain boot-only service-binding workspace", .{});
    }

    const supervisor_diagnostic_storage_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = supervisor_path, .source = supervisor_source, .snippet = "pub const ACTIONABLE_DIAGNOSTICS_ONLY = true" },
        .{ .path = supervisor_path, .source = supervisor_source, .snippet = "pub const HEAP_BACKED_ACTIONABLE_DIAGNOSTICS_ON_FREESTANDING = true" },
        .{ .path = supervisor_path, .source = supervisor_source, .snippet = "const DiagnosticBacking = if (heap_backed_actionable_diagnostics) ?*DiagnosticArray else DiagnosticArray" },
        .{ .path = supervisor_path, .source = supervisor_source, .snippet = "const allocation = kernel_memory.kmalloc(@sizeOf(DiagnosticArray)) orelse return null" },
        .{ .path = supervisor_path, .source = supervisor_source, .snippet = "@memset(std.mem.asBytes(diagnostics), 0)" },
        .{ .path = supervisor_path, .source = supervisor_source, .snippet = "kernel_memory.kfree(@ptrCast(diagnostics))" },
        .{ .path = session_manager_boot_flow_path, .source = session_manager_boot_flow_source, .snippet = "self.service_graph_builder.supervisor.deinit()" },
    };
    for (supervisor_diagnostic_storage_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Supervisor diagnostics must retain actionable on-demand freestanding storage in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    if (std.mem.indexOf(u8, supervisor_source, "diagnostics: [MAX_DIAGNOSTICS]DiagnosticEvent") != null) {
        try common.addError(errors, allocator, "Supervisor diagnostics must not return to inline freestanding ring storage", .{});
    }

    const supervisor_service_schema_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = supervisor_path, .source = supervisor_source, .snippet = "pub const SCHEMA_DERIVED_SERVICE_METADATA = true" },
        .{ .path = supervisor_path, .source = supervisor_source, .snippet = "pub const SERVICE_ID_IS_ISOLATION_DOMAIN = true" },
        .{ .path = supervisor_path, .source = supervisor_source, .snippet = "pub fn descriptor(self: *const ServiceRecord) contract.ServiceDescriptor" },
        .{ .path = supervisor_path, .source = supervisor_source, .snippet = "pub fn isolationDomainId(self: *const ServiceRecord) u64" },
        .{ .path = supervisor_path, .source = supervisor_source, .snippet = "if (!service.descriptor().restartable)" },
        .{ .path = trust_boot_path, .source = trust_boot_source, .snippet = "const descriptor = service.descriptor()" },
        .{ .path = trust_boot_path, .source = trust_boot_source, .snippet = "service.isolationDomainId()" },
    };
    for (supervisor_service_schema_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Supervisor service state must retain schema-derived metadata in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    const retired_supervisor_service_fields = [_][]const u8{
        "isolation_domain_id: u64",
        "boundary: contract.ServiceBoundary",
        "restartable: bool",
        "network_privilege: contract.NetworkPrivilege",
        "storage_privilege: contract.StoragePrivilege",
        "ui_privilege: contract.UiPrivilege",
        "driver_class: ?driver_service.DeviceClass",
    };
    for (retired_supervisor_service_fields) |field| {
        if (std.mem.indexOf(u8, supervisor_source, field) != null) {
            try common.addError(errors, allocator, "Supervisor service records must not duplicate schema metadata: {s}", .{field});
        }
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
    const request_header_path = "src/native/core/request_header.zig";
    const smp_probe_path = "src/arch/x86_64/high_half_smp_probe.zig";
    const native_kernel_path = "src/native/kernel_api/native_kernel.zig";
    const device_syscalls_path = "src/native/kernel_api/device_syscalls.zig";
    const endpoint_syscalls_path = "src/native/kernel_api/endpoint_syscalls.zig";
    const syscall_broker_path = "src/native/kernel_api/syscall_broker.zig";
    const paging_path = "src/kernel/memory/paging64.zig";
    const endpoint_path = "src/native/kernel_api/endpoint.zig";
    const syscall_dispatch_path = "src/native/kernel_api/syscall_dispatch.zig";
    const syscall_surface_path = "src/native/kernel_api/syscall_surface.zig";
    const compositor_session_path = "src/native/platform/compositor_session.zig";
    const native_ux_path = "src/native/platform/native_ux.zig";
    const session_manager_boot_flow_path = "src/native/session/session_manager_boot_flow.zig";
    const session_manager_contexts_path = "src/native/session/session_manager_contexts.zig";
    const booted_evidence_path = "src/native/session/booted_evidence.zig";
    const userspace_mailbox_path = "src/native/task/userspace_bootstrap_mailbox.zig";
    const userspace_executor_path = "src/native/task/userspace_executor.zig";
    const userspace_runtime_path = "src/userspace/runtime.zig";
    const userspace_ui_state_path = "src/userspace/ui_surface_state.zig";
    const native_smoke_markers_path = "src/native_smoke_markers.zig";
    const trust_boot_path = "src/native/session/trust_boot.zig";
    const bootstrap_driver_port_path = "src/native/drivers/bootstrap_driver_port.zig";
    const driver_service_path = "src/native/drivers/driver_service.zig";
    const driver_runtime_path = "src/native/drivers/driver_runtime.zig";
    const measured_boot_path = "src/native/platform/measured_boot.zig";
    const driver_spec_path = "src/tests/spec/drivers_storage_sync.zig";
    const backlog_gate_path = "src/tests/spec/backlog_gates.zig";
    const broker_source = try readRequiredSource(allocator, io, errors, broker_path) orelse return;
    const native_abi_source = try readRequiredSource(allocator, io, errors, native_abi_path) orelse return;
    const component_port_source = try readRequiredSource(allocator, io, errors, component_port_path) orelse return;
    const request_header_source = try readRequiredSource(allocator, io, errors, request_header_path) orelse return;
    const smp_probe_source = try readRequiredSource(allocator, io, errors, smp_probe_path) orelse return;
    const native_kernel_source = try readRequiredSource(allocator, io, errors, native_kernel_path) orelse return;
    const device_syscalls_source = try readRequiredSource(allocator, io, errors, device_syscalls_path) orelse return;
    const endpoint_syscalls_source = try readRequiredSource(allocator, io, errors, endpoint_syscalls_path) orelse return;
    const syscall_broker_source = try readRequiredSource(allocator, io, errors, syscall_broker_path) orelse return;
    const paging_source = try readRequiredSource(allocator, io, errors, paging_path) orelse return;
    const endpoint_source = try readRequiredSource(allocator, io, errors, endpoint_path) orelse return;
    const syscall_dispatch_source = try readRequiredSource(allocator, io, errors, syscall_dispatch_path) orelse return;
    const syscall_surface_source = try readRequiredSource(allocator, io, errors, syscall_surface_path) orelse return;
    const compositor_session_source = try readRequiredSource(allocator, io, errors, compositor_session_path) orelse return;
    const native_ux_source = try readRequiredSource(allocator, io, errors, native_ux_path) orelse return;
    const session_manager_boot_flow_source = try readRequiredSource(allocator, io, errors, session_manager_boot_flow_path) orelse return;
    const session_manager_contexts_source = try readRequiredSource(allocator, io, errors, session_manager_contexts_path) orelse return;
    const booted_evidence_source = try readRequiredSource(allocator, io, errors, booted_evidence_path) orelse return;
    const userspace_mailbox_source = try readRequiredSource(allocator, io, errors, userspace_mailbox_path) orelse return;
    const userspace_executor_source = try readRequiredSource(allocator, io, errors, userspace_executor_path) orelse return;
    const userspace_runtime_source = try readRequiredSource(allocator, io, errors, userspace_runtime_path) orelse return;
    const userspace_ui_state_source = try readRequiredSource(allocator, io, errors, userspace_ui_state_path) orelse return;
    const native_smoke_markers_source = try readRequiredSource(allocator, io, errors, native_smoke_markers_path) orelse return;
    const trust_boot_source = try readRequiredSource(allocator, io, errors, trust_boot_path) orelse return;
    const bootstrap_driver_port_source = try readRequiredSource(allocator, io, errors, bootstrap_driver_port_path) orelse return;
    const driver_service_source = try readRequiredSource(allocator, io, errors, driver_service_path) orelse return;
    const driver_runtime_source = try readRequiredSource(allocator, io, errors, driver_runtime_path) orelse return;
    const measured_boot_source = try readRequiredSource(allocator, io, errors, measured_boot_path) orelse return;
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
        "pub const ABI_VERSION: u16 = 23",
        "pub const DEVICE_DESCRIPTOR_RESERVED_BYTES: usize = 7",
        "pub const DeviceDescriptor = ex" ++ "tern struct",
        "mmio_window_count: u8",
    };
    for (device_abi_snippets) |snippet| {
        if (std.mem.indexOf(u8, native_abi_source, snippet) == null) {
            try common.addError(errors, allocator, "Userspace driver data path must keep the compact PCI/MMIO native ABI snippet: {s}", .{snippet});
        }
    }
    const focused_input_abi_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "pub const InputEventDescriptor = ex" ++ "tern struct" },
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "pub const InputRecvResponse = ex" ++ "tern struct" },
        .{ .path = component_port_path, .source = component_port_source, .snippet = "pub fn inputRecv(" },
        .{ .path = native_kernel_path, .source = native_kernel_source, .snippet = "pub fn bindFocusedInputReceiver" },
        .{ .path = native_kernel_path, .source = native_kernel_source, .snippet = "authorizeSubjectTaskOperation(.input_recv" },
        .{ .path = syscall_surface_path, .source = syscall_surface_source, .snippet = "syscall surface delivers focused input only through task-scoped authority" },
        .{ .path = session_manager_boot_flow_path, .source = session_manager_boot_flow_source, .snippet = "self.input_router.deinit()" },
    };
    for (focused_input_abi_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Userspace input ABI must retain snippet in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    const retired_authority_failure_counters = [_][]const u8{
        "input_authority_failures",
        "surface_authority_failures",
    };
    for (retired_authority_failure_counters) |counter| {
        if (std.mem.indexOf(u8, session_manager_boot_flow_source, counter) != null) {
            try common.addError(errors, allocator, "Session managers must not retain unobserved authority failure counter: {s}", .{counter});
        }
    }
    const compact_endpoint_receive_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "pub const EndpointRecvResponse = ex" ++ "tern struct" },
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "pub const EndpointRecvWireRequest = ex" ++ "tern struct" },
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "try std.testing.expectEqual(@as(usize, 56), @sizeOf(EndpointRecvWireRequest))" },
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "_reserved_generation: u32 = 0" },
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "_reserved_tail: u32 = 0" },
        .{ .path = component_port_path, .source = component_port_source, .snippet = "pub inline fn endpointRecvFromWireInto" },
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "try std.testing.expectEqual(@as(usize, 56), @sizeOf(EndpointRecvResponse))" },
        .{ .path = component_port_path, .source = component_port_source, .snippet = "payload_out: []u8" },
        .{ .path = component_port_path, .source = component_port_source, .snippet = "attached_capability_out: *abi.CapabilityDescriptor" },
        .{ .path = native_kernel_path, .source = native_kernel_source, .snippet = "self.endpoint_table.recvInto(" },
        .{ .path = syscall_surface_path, .source = syscall_surface_source, .snippet = "syscall surface validates compact endpoint receive outputs before dequeue" },
        .{ .path = endpoint_syscalls_path, .source = endpoint_syscalls_source, .snippet = "dispatch.readRequest(abi.EndpointRecvWireRequest, memory, request_addr)" },
        .{ .path = endpoint_syscalls_path, .source = endpoint_syscalls_source, .snippet = "wire.receiver_task_id != memory.caller_task_id" },
        .{ .path = endpoint_syscalls_path, .source = endpoint_syscalls_source, .snippet = "rangesOverlap(response_addr, response_len, payload_address, capacity)" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "wire.header.subject_task_id != caller or wire.receiver_task_id != caller" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "validOutputRange(response) or !validOutputRange(payload) or !validOutputRange(capability)" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "local_port.endpointRecv(request, now_ticks)" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "copy.write_outputs(copy.context, claim, outputs[0..count])" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "syscall broker receive output preparation and short payload preserve queue and permit exact retry" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "syscall broker receive STOP around staging and output never retries a consumed moved grant" },
        .{ .path = userspace_executor_path, .source = userspace_executor_source, .snippet = "resolveSyscallOutputInto(anchor, &resolved, claim" },
        .{ .path = userspace_executor_path, .source = userspace_executor_source, .snippet = "const final_enabled = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled()" },
        .{ .path = userspace_executor_path, .source = userspace_executor_source, .snippet = "final.executor != resolved.executor or final.mapping != resolved.mapping" },
        .{ .path = paging_path, .source = paging_source, .snippet = "permissions == null or !permissions.?.writable or count == segments.len" },
        .{ .path = paging_path, .source = paging_source, .snippet = "owned output resolution preflights late leaves and aliases before publishing any destination" },
    };
    for (compact_endpoint_receive_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Compact endpoint receive ABI must retain snippet in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    const endpoint_close_admission_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = request_header_path, .source = request_header_source, .snippet = "if (header.flags != 0) return error.InvalidRequestFlags" },
        .{ .path = component_port_path, .source = component_port_source, .snippet = "try request_header.validateHeader(request.header, abi.opcode(operation))" },
        .{ .path = syscall_dispatch_path, .source = syscall_dispatch_source, .snippet = "err == error.InvalidRequestFlags" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "try closeClaimInto(port, claim, copy, now_ticks, &reply)" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "request.header.subject_task_id != caller" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "local_port.endpointClose(request, now_ticks)" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "syscall broker close retires unread moves and exact target grants before waking surviving peers once" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "syscall broker close malformed staging and denied authority preserve complete queues and grants" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "syscall broker close cancellation and revoked sibling authority preserve queued gifts" },
        .{ .path = syscall_broker_path, .source = syscall_broker_source, .snippet = "syscall broker close STOP before commit preserves resources and wake termination pins them until ACK" },
        .{ .path = smp_probe_path, .source = smp_probe_source, .snippet = "proveBrokerCloses(runtime, kernel, &port" },
        .{ .path = smp_probe_path, .source = smp_probe_source, .snippet = "SMP broker close exact retirement" },
        .{ .path = smp_probe_path, .source = smp_probe_source, .snippet = "SMP broker close peer receive result" },
        .{ .path = smp_probe_path, .source = smp_probe_source, .snippet = "SMP broker duplicate close mutation" },
    };
    for (endpoint_close_admission_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Endpoint close and reserved header admission must retain snippet in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    const endpoint_table_storage_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = endpoint_path, .source = endpoint_source, .snippet = "pub fn initializeAllocated(self: *Table) void" },
        .{ .path = session_manager_contexts_path, .source = session_manager_contexts_source, .snippet = "pub const HEAP_BACKED_ENDPOINT_TABLE_ON_FREESTANDING = true" },
        .{ .path = session_manager_contexts_path, .source = session_manager_contexts_source, .snippet = "const EndpointTableBacking = if (heap_backed_endpoint_table) ?*endpoint_mod.Table else endpoint_mod.Table" },
        .{ .path = session_manager_contexts_path, .source = session_manager_contexts_source, .snippet = "const table = table_backing.alloc(endpoint_mod.Table) orelse return error.NoSpaceLeft" },
        .{ .path = session_manager_contexts_path, .source = session_manager_contexts_source, .snippet = "table_backing.free(endpoint_mod.Table, table)" },
        .{ .path = session_manager_boot_flow_path, .source = session_manager_boot_flow_source, .snippet = "self.kernel_context.ensureEndpointTable() catch" },
    };
    for (endpoint_table_storage_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Endpoint table must retain on-demand freestanding storage in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    if (std.mem.indexOf(u8, session_manager_contexts_source, "endpoint_table: endpoint_mod.Table =") != null) {
        try common.addError(errors, allocator, "Endpoint table must not return to inline freestanding session storage", .{});
    }
    const review_ux_controller_storage_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = native_ux_path, .source = native_ux_source, .snippet = "pub fn initializeAllocated(self: *Controller) void" },
        .{ .path = session_manager_contexts_path, .source = session_manager_contexts_source, .snippet = "pub const HEAP_BACKED_REVIEW_UX_CONTROLLER_ON_FREESTANDING = true" },
        .{ .path = session_manager_contexts_path, .source = session_manager_contexts_source, .snippet = "const ReviewUxControllerBacking = if (heap_backed_review_ux_controller) ?*native_ux.Controller else native_ux.Controller" },
        .{ .path = session_manager_contexts_path, .source = session_manager_contexts_source, .snippet = "const controller = table_backing.alloc(native_ux.Controller) orelse return error.NoSpaceLeft" },
        .{ .path = session_manager_contexts_path, .source = session_manager_contexts_source, .snippet = "table_backing.free(native_ux.Controller, controller)" },
        .{ .path = session_manager_boot_flow_path, .source = session_manager_boot_flow_source, .snippet = "self.recovery_context.releaseReviewUxController()" },
        .{ .path = booted_evidence_path, .source = booted_evidence_source, .snippet = "manager.reviewUxControllerPtr() catch" },
    };
    for (review_ux_controller_storage_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Review UX controller must retain on-demand freestanding storage in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    if (std.mem.indexOf(u8, session_manager_contexts_source, "review_ux_controller: native_ux.Controller =") != null) {
        try common.addError(errors, allocator, "Review UX controller must not return to inline freestanding session storage", .{});
    }
    const protected_endpoint_send_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = syscall_dispatch_path, .source = syscall_dispatch_source, .snippet = "pub fn copyUserSlice(" },
        .{ .path = syscall_dispatch_path, .source = syscall_dispatch_source, .snippet = "user slice copies enforce source and destination bounds" },
        .{ .path = endpoint_syscalls_path, .source = endpoint_syscalls_source, .snippet = "var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined" },
        .{ .path = endpoint_syscalls_path, .source = endpoint_syscalls_source, .snippet = "dispatch.readRequest(abi.EndpointSendWireRequest, memory, request_addr)" },
        .{ .path = endpoint_syscalls_path, .source = endpoint_syscalls_source, .snippet = "!wire.validEncoding() or wire.header.subject_task_id != memory.caller_task_id" },
        .{ .path = endpoint_syscalls_path, .source = endpoint_syscalls_source, .snippet = "staged = dispatch.copyUserSlice(memory, source[0..length], &payload)" },
        .{ .path = endpoint_syscalls_path, .source = endpoint_syscalls_source, .snippet = "component_port.endpointSendFromWireInto(wire, staged, &request)" },
        .{ .path = syscall_dispatch_path, .source = syscall_dispatch_source, .snippet = "user_memory.readUserMemory(memory.caller_task_id," },
        .{ .path = syscall_dispatch_path, .source = syscall_dispatch_source, .snippet = "user_memory.writeUserMemory(memory.caller_task_id," },
        .{ .path = endpoint_syscalls_path, .source = endpoint_syscalls_source, .snippet = "component_port.invokeGenerated(.endpoint_send, &local_port, request, now_ticks)" },
        .{ .path = endpoint_path, .source = endpoint_source, .snippet = "ipc_ring.pushPayload(peer.data_ring, header, payload)" },
        .{ .path = syscall_surface_path, .source = syscall_surface_source, .snippet = ".payload_address = 0x1000" },
    };
    for (protected_endpoint_send_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Safe endpoint copy path must retain snippet in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    if (std.mem.indexOf(u8, syscall_dispatch_source, "borrowImmediateUserSlice") != null or
        std.mem.indexOf(u8, endpoint_syscalls_source, "borrowImmediateUserSlice") != null)
    {
        try common.addError(errors, allocator, "Endpoint send must not retain a borrowed userspace payload beyond its scoped SMAP access window", .{});
    }
    const surface_presentation_abi_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "pub const SURFACE_PRESENT_IS_HANDLE_PLUS_FENCE = true" },
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "pub const SurfacePresentation = ex" ++ "tern struct" },
        .{ .path = component_port_path, .source = component_port_source, .snippet = "pub fn surfacePresent(" },
        .{ .path = native_kernel_path, .source = native_kernel_source, .snippet = "authorizeSubjectTaskOperation(.surface_present" },
        .{ .path = compositor_session_path, .source = compositor_session_source, .snippet = "pub fn presentSurface(" },
        .{ .path = session_manager_boot_flow_path, .source = session_manager_boot_flow_source, .snippet = "bindSurfacePresentationReceiver" },
        .{ .path = userspace_mailbox_path, .source = userspace_mailbox_source, .snippet = "pub const VERSION: u16 = 11" },
        .{ .path = userspace_mailbox_path, .source = userspace_mailbox_source, .snippet = "pub const ABI_SIZE_BYTES: usize = 256" },
        .{ .path = userspace_mailbox_path, .source = userspace_mailbox_source, .snippet = "heartbeat_increment: u32 = 1" },
        .{ .path = userspace_executor_path, .source = userspace_executor_source, .snippet = "granted.rights.has(.surface_present)" },
        .{ .path = userspace_executor_path, .source = userspace_executor_source, .snippet = ".heartbeat_increment = update.heartbeat_increment" },
        .{ .path = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "fn presentUiState(" },
        .{ .path = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "zigos_userspace_bootstrap.heartbeat_increment" },
        .{ .path = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "const input = drainFocusedInput(ui, saves_documents);" },
        .{ .path = userspace_ui_state_path, .source = userspace_ui_state_source, .snippet = "pub fn presentation(" },
        .{ .path = session_manager_boot_flow_path, .source = session_manager_boot_flow_source, .snippet = "provisionSurfacePresentationCapabilities" },
        .{ .path = session_manager_boot_flow_path, .source = session_manager_boot_flow_source, .snippet = "proveUserspaceSurfacePresentation" },
        .{ .path = native_smoke_markers_path, .source = native_smoke_markers_source, .snippet = "boot_markers.userspace_surface_presentation_ready" },
        .{ .path = syscall_surface_path, .source = syscall_surface_source, .snippet = "syscall surface copies bounded presentations through task-scoped authority" },
    };
    for (surface_presentation_abi_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Surface presentation ABI must retain snippet in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    const reproducible_policy_measurement_snippets = [_][]const u8{
        "capabilityTargetAffectsProductionPolicy",
        ".service, .device, .policy => true",
        ".task, .endpoint, .shared_memory, .object, .workspace, .network_policy => false",
        "test \"production policy measurement excludes runtime resource grants\"",
    };
    for (reproducible_policy_measurement_snippets) |snippet| {
        if (std.mem.indexOf(u8, trust_boot_source, snippet) == null) {
            try common.addError(errors, allocator, "Measured policy roots must exclude runtime resource grants: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, trust_boot_source, "capability-issued-at") != null) {
        try common.addError(errors, allocator, "Measured policy roots must not include runtime capability issuance timestamps", .{});
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

    const derived_dma_policy_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = driver_service_path, .source = driver_service_source, .snippet = "pub const DERIVES_DMA_WINDOWS_FROM_DEVICE_POLICY = true" },
        .{ .path = driver_service_path, .source = driver_service_source, .snippet = "pub fn dmaRangeCount(self: *const DriverRecord) usize" },
        .{ .path = driver_service_path, .source = driver_service_source, .snippet = "pub fn dmaRange(self: *const DriverRecord, index: usize) ?DmaRange" },
        .{ .path = measured_boot_path, .source = measured_boot_source, .snippet = "const dma_range_count = driver.dmaRangeCount()" },
        .{ .path = measured_boot_path, .source = measured_boot_source, .snippet = "const range = driver.dmaRange(range_index).?" },
    };
    for (derived_dma_policy_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Driver DMA policy must retain derived device-class windows in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    const retired_dma_storage_snippets = [_][]const u8{
        "dma_range_count: u8",
        "dma_ranges: [MAX_DMA_RANGES]DmaRange",
    };
    for (retired_dma_storage_snippets) |snippet| {
        if (std.mem.indexOf(u8, driver_service_source, snippet) != null) {
            try common.addError(errors, allocator, "Driver DMA policy must not restore mutable per-record range storage: {s}", .{snippet});
        }
    }

    const derived_activation_publisher_snippets = [_]struct {
        path: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .path = driver_runtime_path, .source = driver_runtime_source, .snippet = "pub const DERIVES_ACTIVATION_PUBLISHER_FROM_PUBLICATION = true" },
        .{ .path = driver_runtime_path, .source = driver_runtime_source, .snippet = "bootstrap_driver_port.activePublicationPublisher(" },
        .{ .path = bootstrap_driver_port_path, .source = bootstrap_driver_port_source, .snippet = "pub fn activePublicationPublisher(" },
        .{ .path = bootstrap_driver_port_path, .source = bootstrap_driver_port_source, .snippet = "publication.active_service_id != service_id" },
    };
    for (derived_activation_publisher_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Driver activation metadata must derive publishers from active publications in {s}: {s}", .{ required.path, required.snippet });
        }
    }
    const retired_activation_publisher_snippets = [_][]const u8{
        "publisher_len: u8",
        "publisher: [MAX_ACTIVATION_PUBLISHER_BYTES]u8",
    };
    for (retired_activation_publisher_snippets) |snippet| {
        if (std.mem.indexOf(u8, driver_runtime_source, snippet) != null) {
            try common.addError(errors, allocator, "Driver activation metadata must not restore duplicate publisher storage: {s}", .{snippet});
        }
    }

    const derived_activation_state_snippets = [_][]const u8{
        "pub const DERIVES_ACTIVATION_STATE_FLAGS = true",
        "pub fn iommuEnforced(self: *const ActivationRecord) bool",
        "pub fn hasExclusiveClaim(self: *const ActivationRecord) bool",
        "pub fn kernelBootstrap(self: *const ActivationRecord) bool",
    };
    for (derived_activation_state_snippets) |snippet| {
        if (std.mem.indexOf(u8, driver_runtime_source, snippet) == null) {
            try common.addError(errors, allocator, "Driver activation metadata must retain derived state invariant: {s}", .{snippet});
        }
    }
    const retired_activation_state_snippets = [_][]const u8{
        "iommu_enforced: bool",
        "exclusive_claim: bool",
        "kernel_bootstrap: bool",
    };
    for (retired_activation_state_snippets) |snippet| {
        if (std.mem.indexOf(u8, driver_runtime_source, snippet) != null) {
            try common.addError(errors, allocator, "Driver activation metadata must not restore duplicate state flags: {s}", .{snippet});
        }
    }

    const network_activation_snippets = [_][]const u8{
        "networkPublicationMatchesDetectedDevice",
        "device_inventory.requireProductionDriverDeviceId(.network_adapter)",
        "if (!networkPublicationMatchesDetectedDevice(device_id)) return false",
        "@import(\"../../kernel/drivers/network_hw.zig\").activate() catch return false",
        "try std.testing.expect(!activateNetworkDevice(i225_device_id, 9))",
    };
    for (network_activation_snippets) |snippet| {
        if (std.mem.indexOf(u8, bootstrap_driver_port_source, snippet) == null) {
            try common.addError(errors, allocator, "Userspace driver data path must validate the selected NIC before publication: {s}", .{snippet});
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
    const userspace_runtime_path = "src/userspace/runtime.zig";
    const userspace_entry_path = "src/userspace/service_entry.zig";
    const userspace_linker_path = "src/userspace/linker.ld";
    const archive_generator_path = "tools/generate_userspace_archive.zig";
    const userspace_build_path = "build_support/userspace.zig";

    const manifest_source = try readRequiredSource(allocator, io, errors, manifest_path) orelse return;
    const linter_source = try readRequiredSource(allocator, io, errors, linter_path) orelse return;
    const contract_source = try readRequiredSource(allocator, io, errors, contract_path) orelse return;
    const boot_registry_source = try readRequiredSource(allocator, io, errors, boot_registry_path) orelse return;
    const archive_index_source = try readRequiredSource(allocator, io, errors, archive_index_path) orelse return;
    const loader_source = try readRequiredSource(allocator, io, errors, loader_path) orelse return;
    const launch_source = try readRequiredSource(allocator, io, errors, launch_path) orelse return;
    const rendered_shell_launch_source = try readRequiredSource(allocator, io, errors, rendered_shell_launch_path) orelse return;
    const userspace_runtime_source = try readRequiredSource(allocator, io, errors, userspace_runtime_path) orelse return;
    const userspace_entry_source = try readRequiredSource(allocator, io, errors, userspace_entry_path) orelse return;
    const userspace_linker_source = try readRequiredSource(allocator, io, errors, userspace_linker_path) orelse return;
    const archive_generator_source = try readRequiredSource(allocator, io, errors, archive_generator_path) orelse return;
    const userspace_build_source = try readRequiredSource(allocator, io, errors, userspace_build_path) orelse return;

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
        "for (active_boot_image_specs, 0..) |spec, artifact_index|",
        "const artifact = archive_index.artifacts[artifact_index]",
        "validateGeneratedArtifact(artifact)",
        "bundle.signature = try userspace_manifest_signing.signBundle(bundle)",
        "catalog.registerBuildValidatedArtifact",
        "try std.testing.expect(catalog.findByBundleId(\"zigos.system.session\").?.embedsElf())",
    };
    for (required_boot_registry_snippets) |snippet| {
        if (std.mem.indexOf(u8, boot_registry_source, snippet) == null) {
            try common.addError(errors, allocator, "Native-only launch track must keep archive-backed boot registry snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, boot_registry_source, "spec.signed") != null) {
        try common.addError(errors, allocator, "Native-only boot userspace must not retain an unsigned registry policy path", .{});
    }
    const required_archive_index_snippets = [_][]const u8{
        "const archive = @import(\"userspace_archive\")",
        "role_registry.indexForRole(bundle_id)",
        "return archive.artifacts[artifact_index]",
        "test \"userspace archive index resolves every generated artifact bundle\"",
    };
    for (required_archive_index_snippets) |snippet| {
        if (std.mem.indexOf(u8, archive_index_source, snippet) == null) {
            try common.addError(errors, allocator, "Native-only launch track must keep indexed archive lookup snippet: {s}", .{snippet});
        }
    }
    const forbidden_archive_index_snippets = [_][]const u8{
        "@import(\"../core/id_index.zig\")",
        "const bundle_index = buildBundleIndex()",
        "fn bundleIndexKey(",
    };
    for (forbidden_archive_index_snippets) |snippet| {
        if (std.mem.indexOf(u8, archive_index_source, snippet) != null) {
            try common.addError(errors, allocator, "Native-only launch track must not duplicate the role registry index in the userspace archive: {s}", .{snippet});
        }
    }

    const required_runtime_snippets = [_][]const u8{
        "fn bootstrapDetail() mailbox.Detail",
        "zigos_userspace_bootstrap.heartbeat_increment",
        "if (detail != .proof)",
        "publishState(.runtime_ready, detail, 1)",
    };
    for (required_runtime_snippets) |snippet| {
        if (std.mem.indexOf(u8, userspace_runtime_source, snippet) == null) {
            try common.addError(errors, allocator, "Native-only userspace runtime must keep kernel-published launch metadata snippet: {s}", .{snippet});
        }
    }
    const required_role_identity_snippets = [_]struct {
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .source = userspace_entry_source, .snippet = "pub export const zigos_userspace_role_identity: [8]u8 align(1)" },
        .{ .source = userspace_entry_source, .snippet = "linksection(\".zigos_userspace_role_identity\")" },
        .{ .source = userspace_linker_source, .snippet = "KEEP(*(.zigos_userspace_role_identity))" },
    };
    for (required_role_identity_snippets) |requirement| {
        if (std.mem.indexOf(u8, requirement.source, requirement.snippet) == null) {
            try common.addError(errors, allocator, "Native-only userspace must keep its minimal static role identity: {s}", .{requirement.snippet});
        }
    }
    const forbidden_runtime_descriptor_snippets = [_][]const u8{
        "userspace_descriptor",
        "zigos_userspace_descriptor",
    };
    for (forbidden_runtime_descriptor_snippets) |snippet| {
        if (std.mem.indexOf(u8, userspace_runtime_source, snippet) != null or
            std.mem.indexOf(u8, userspace_linker_source, snippet) != null or
            std.mem.indexOf(u8, archive_generator_source, snippet) != null)
        {
            try common.addError(errors, allocator, "Native-only userspace must not restore runtime descriptor plumbing: {s}", .{snippet});
        }
    }
    const required_archive_generator_snippets = [_][]const u8{
        "const artifact_args = args[6..]",
        "const bundle_id = artifact_args[artifact_arg_index]",
        ".bundle_id = try arena.dupe(u8, bundle_id)",
    };
    for (required_archive_generator_snippets) |snippet| {
        if (std.mem.indexOf(u8, archive_generator_source, snippet) == null) {
            try common.addError(errors, allocator, "Userspace archive generation must keep registry-bound artifact arguments: {s}", .{snippet});
        }
    }
    const required_userspace_build_snippets = [_][]const u8{
        "production_archive_run.addArg(spec.image.bundleId())",
        "verification_archive_run.addArg(spec.image.bundleId())",
    };
    for (required_userspace_build_snippets) |snippet| {
        if (std.mem.indexOf(u8, userspace_build_source, snippet) == null) {
            try common.addError(errors, allocator, "Userspace builds must bind registry bundle ids to generated artifacts: {s}", .{snippet});
        }
    }

    const required_loader_snippets = [_][]const u8{
        "const executable_image = embedded orelse return error.EmbeddedArtifactRequired",
        "try validateBuildValidatedImage(request.elf_file, executable_image)",
        "const digest = elf_file.sha256()",
        "task_runtime_launch.validateUserspaceImage",
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
        "logLaunchFailure(bundle_id, failure_phase, error.EmbeddedArtifactRequired)",
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
        \\    "id": "asus-nuc15crsu7",
        \\    "vendor": "Intel",
        \\    "product": "NUC 15 Pro Mini PC",
        \\    "sku": "RNUC15CRSU7",
        \\    "status": "hardware_required",
        \\    "selection_reason": "self-test",
        \\    "boot_medium": "UEFI",
        \\    "serial_capture": "self-test",
        \\    "required_subsystems": ["uefi_boot"],
        \\    "reference_artifacts": [
        \\      "src/native/platform/hardware_target.zig",
        \\      "spec/hardware/nuc15crsu7-required-markers.txt",
        \\      "tools/host/hardware.zig"
        \\    ],
        \\    "qemu_preflight_commands": ["zig build iso"],
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

fn validateNativeSchedulerLoopSource(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    source: []const u8,
) !void {
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    var lexer = std.zig.Tokenizer.init(code);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "native scheduler loop must remain valid Zig source", .{});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    const required_one_shot_scheduler_snippets = [_][:0]const u8{
        "timer.synchronize()",
        "session_manager.bindHardwareInput",
        "pollHardwareKeyboardReport",
        "xhci_driver_task.pollKeyboardReport()",
        "hardwareInputProof",
        "xhci_driver_task.inputProof()",
        "session_manager.servicePendingInputWork(now_ticks)",
        "xhci_driver_task.lifecyclePending()",
        "userspaceSchedulerHasDispatchableTasks(timer.getTicks())",
        "timer.armSchedulerTick()",
        "timer.disarmSchedulerTick()",
        "x86.cli()",
        "x86.sti()",
        "smp.idle()",
    };
    for (required_one_shot_scheduler_snippets) |snippet| {
        if (!hasCodeTokens(code, tokens.items, snippet)) {
            try common.addError(errors, allocator, "native scheduler loop must retain one-shot idle deadline control: {s}", .{snippet});
        }
    }
    const run = topLevelFunctionBody(code, tokens.items, "run") orelse {
        try common.addError(errors, allocator, "native scheduler loop must retain its actual run function", .{});
        return;
    };
    const required_run_snippets = [_][:0]const u8{
        "session_manager.system().serviceAuthenticationClock(now_ticks); wakeBoundXhciTask(xhci_driver_task, session_manager, pending, now_ticks);",
        "if (xhci_driver_task.lifecyclePending()) { timer.armSchedulerTick(); } else if (session_manager.nextServiceWake()) |deadline| { timer.armWakeAt(deadline); } else { timer.disarmSchedulerTick();",
    };
    for (required_run_snippets) |snippet| {
        if (!hasCodeTokens(code, run, snippet)) {
            try common.addError(errors, allocator, "native scheduler run must retain bound xHCI wake, authority expiry and idle deadline control: {s}", .{snippet});
        }
    }
    const helper = topLevelFunctionBody(code, tokens.items, "wakeBoundXhciTask") orelse {
        try common.addError(errors, allocator, "native scheduler must retain its actual bound xHCI wake helper", .{});
        return;
    };
    // Compare the whole executable body: test calls, quoted snippets, comments
    // or an unreachable predicate must not replace the production wake guard.
    const required_helper_body =
        "if (pending.xhci or (pending.timer and driver.workPending())) { " ++
        "const bound_task_id = driver.boundTaskId(); " ++
        "if (bound_task_id != 0) _ = manager.wakeUserspaceTask(bound_task_id, now_ticks); }";
    const matching_tokens = codeTokenSequenceLength(code, helper, required_helper_body);
    if (matching_tokens == null or matching_tokens.? != helper.len) {
        try common.addError(errors, allocator, "native scheduler xHCI helper must wake on IRQ or pending timer work through the exact nonzero bound task", .{});
    }
}

fn validateX2apicIpiPublicationSource(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    source: []const u8,
) !void {
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    var lexer = std.zig.Tokenizer.init(code);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "x2APIC IPI publication must remain valid Zig source", .{});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    // Scope the complete executable bodies so comments, quoted calls and
    // unreachable writes cannot replace the actual native publication path.
    const send = topLevelFunctionBody(code, tokens.items, "sendIpi") orelse &.{};
    if (!timerCodeMatches(
        code,
        send,
        "if (builtin.target.os.tag == .freestanding) { " ++
            "asm volatile (\"mfence; lfence\" ::: .{ .memory = true }); } " ++
            "writeApicMsr(X2APIC_ICR_MSR, icrValue(command));",
        .exact,
    )) try common.addError(errors, allocator, "x2APIC IPI delivery must order native MFENCE/LFENCE publication before exactly one ICR write", .{});

    const adapter = topLevelFunctionBody(code, tokens.items, "writeApicMsr") orelse &.{};
    if (!timerCodeMatches(
        code,
        adapter,
        "if (comptime builtin.is_test and builtin.target.os.tag != .freestanding) { " ++
            "if (Testing.observer) |observe| { observe(msr, value); return; } } " ++
            "x86.writeMsr(msr, value);",
        .exact,
    )) try common.addError(errors, allocator, "x2APIC MSR adapter must retain the native WRMSR and isolate hosted test observation", .{});
    if (!hasTopLevelCodeTokens(
        code,
        tokens.items,
        "pub const Testing = if (builtin.is_test and builtin.target.os.tag != .freestanding) struct { " ++
            "pub const WriteObserver = *const fn (msr: u32, value: u64) void; " ++
            "pub const ICR_MSR = X2APIC_ICR_MSR; pub const EOI_MSR = X2APIC_EOI_MSR; " ++
            "var observer: ?WriteObserver = null; " ++
            "pub fn swapWriteObserver(next: ?WriteObserver) ?WriteObserver { " ++
            "const previous = observer; observer = next; return previous; } } else struct {};",
    )) try common.addError(errors, allocator, "x2APIC observer state must remain absent from native images", .{});
}

const PreparedDispatchSourceKind = enum { coordinator, executor, scheduler };

fn preparedDispatchOrdered(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8), code: []const u8, body: []const std.zig.Token, patterns: []const [:0]const u8) !void {
    var offset: usize = 0;
    for (patterns) |pattern| {
        var found = false;
        for (body[offset..], offset..) |_, index| {
            if (codeTokenSequenceLength(code, body[index..], pattern)) |length| {
                offset = index + length;
                found = true;
                break;
            }
        }
        if (!found) try common.addError(errors, allocator, "Prepared dispatch must retain scoped ordered execution step: {s}", .{pattern});
    }
}

fn preparedDispatchTokenCount(code: []const u8, body: []const std.zig.Token, pattern: [:0]const u8) usize {
    var count: usize = 0;
    for (body, 0..) |_, index| if (codeTokenSequenceLength(code, body[index..], pattern) != null) {
        count += 1;
    };
    return count;
}

fn preparedDispatchTailAfter(code: []const u8, body: []const std.zig.Token, pattern: [:0]const u8) ?[]const std.zig.Token {
    for (body, 0..) |_, index| {
        if (codeTokenSequenceLength(code, body[index..], pattern)) |length| return body[index + length ..];
    }
    return null;
}

fn validatePreparedDispatchSource(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8), source: []const u8, kind: PreparedDispatchSourceKind) !void {
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    var lexer = std.zig.Tokenizer.init(code);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "Prepared dispatch {s} must remain valid Zig source", .{@tagName(kind)});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    switch (kind) {
        .coordinator => {
            const container = topLevelContainerBody(code, tokens.items, "pub const Coordinator = struct {") orelse &.{};
            if (topLevelFunctionBody(code, container, "bind") != null or topLevelFunctionBody(code, container, "acknowledgeReturned") != null)
                try common.addError(errors, allocator, "Prepared dispatch must not restore implicit-purpose bind or return ACK APIs", .{});
            for ([_][:0]const u8{
                "const PREPARED: u64 = 16; const PHASE_MASK: u64 = 7; const EPOCH_SHIFT = 5;",
                "pub const Phase = enum(u3) { idle, reserved, ready, running, returned, collecting, returning, return_consumed };",
                "pub const ReturnRecord = extern struct { ui_revision: u64 = 0, fault_instruction_pointer: u64 = 0, fault_address: u64 = 0, fault_error_code: u32 = 0, outcome: Outcome = .unavailable, fault_vector: u8 = 0, reserved: u16 = 0, };",
            }) |pattern| if (!hasTopLevelCodeTokens(code, tokens.items, pattern)) {
                try common.addError(errors, allocator, "Prepared dispatch must retain explicit purpose and deterministic scalar receipt: {s}", .{pattern});
            };
            for ([_]struct { name: []const u8, expected: [:0]const u8 }{
                .{ .name = "bindOwnedRoot", .expected = "try self.bindForPurpose(ticket, mapping_handle, physical_root, false);" },
                .{ .name = "bindPrepared", .expected = "try self.bindForPurpose(ticket, mapping_handle, physical_root, true);" },
                .{ .name = "startPreparedInto", .expected = "try self.startForPurpose(ticket, out, true);" },
            }) |entry| {
                const body = topLevelFunctionBody(code, container, entry.name) orelse &.{};
                if (!timerCodeMatches(code, body, entry.expected, .exact))
                    try common.addError(errors, allocator, "Prepared dispatch must retain its explicit purpose boundary: {s}", .{entry.name});
            }
            const start = topLevelFunctionBody(code, container, "startForPurpose") orelse &.{};
            if (!timerCodeMatches(code, start, "try requireOwner(ticket); try self.checkTicket(ticket); const slot = &self.slots[ticket.cpu]; " ++
                "const control = @atomicLoad(u64, &slot.control, .acquire); try requireTicket(control, ticket); " ++
                "if (require_prepared and control & PREPARED == 0) return error.WrongPurpose; " ++
                "if (phaseOf(control) != .ready) return error.WrongPhase; if (control & STOP != 0) return error.StopRequested; try requireSyscallIdle(slot);", .prefix))
                try common.addError(errors, allocator, "Prepared dispatch must admit exact owner purpose and idle mailbox before its start CAS", .{});
            try preparedDispatchOrdered(allocator, errors, code, start, &.{ "@cmpxchgStrong(u64, &slot.control, control, controlWithPhase(control, .running), .acq_rel, .acquire)", "out.* = .{ .identity = slot.identity, .mapping_handle = slot.mapping_handle, .physical_root = slot.physical_root };" });
            const ack = topLevelFunctionBody(code, container, "ackPreparedReturn") orelse &.{};
            if (!timerCodeMatches(code, ack, "try requireOwner(ticket); try self.checkTicket(ticket); const slot = &self.slots[ticket.cpu]; " ++
                "var control = @atomicLoad(u64, &slot.control, .acquire); try requireTicket(control, ticket); " ++
                "if (control & PREPARED == 0) return error.WrongPurpose; if (phaseOf(control) != .running) return error.WrongPhase; " ++
                "try requireSyscallIdle(slot); if (record.reserved != 0) return error.InvalidReturnRecord; slot.return_record = record;", .prefix))
                try common.addError(errors, allocator, "Prepared dispatch ACK must authenticate owner purpose and drained mailbox before writing the receipt", .{});
            try preparedDispatchOrdered(allocator, errors, code, ack, &.{ "slot.return_record = record;", "@cmpxchgStrong(u64, &slot.control, control, controlWithPhase(control, .returned), .release, .acquire)" });
            const consume = topLevelFunctionBody(code, container, "consumePreparedReturnInto") orelse &.{};
            if (!timerCodeMatches(code, consume, "try requireBsp(); try self.checkTicket(ticket); const slot = &self.slots[ticket.cpu]; " ++
                "const control = @atomicLoad(u64, &slot.control, .acquire); try requireTicket(control, ticket); " ++
                "if (control & PREPARED == 0) return error.WrongPurpose; if (phaseOf(control) != .returned) return error.WrongPhase; " ++
                "try requireSyscallIdle(slot); const record = slot.return_record; " ++
                "if (@cmpxchgStrong(u64, &slot.control, control, controlWithPhase(control, .return_consumed), .acq_rel, .acquire) != null) return error.WrongPhase; out.* = record;", .exact))
                try common.addError(errors, allocator, "Prepared dispatch receipt must acquire-consume exactly once and preserve output on denial", .{});
            const cancel = topLevelFunctionBody(code, container, "cancelUnstarted") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, cancel, &.{
                "try requireSyscallIdle(slot); const prepared = control & PREPARED != 0; const cancelled = controlWithPhase(control, if (prepared) .returning else .returned);",
                "if (@cmpxchgStrong(u64, &slot.control, control, cancelled, .acq_rel, .acquire) != null) return error.WrongPhase;",
                "if (prepared) { slot.return_record = .{}; var publishing = cancelled;",
                "@cmpxchgStrong(u64, &slot.control, publishing, controlWithPhase(publishing, .returned), .release, .acquire)",
            });
            const collect = topLevelFunctionBody(code, container, "beginCollectInto") orelse &.{};
            if (!hasCodeTokens(code, collect, "const expected_phase: Phase = if (control & PREPARED != 0) .return_consumed else .returned; if (phaseOf(control) != expected_phase) return error.WrongPhase; try requireSyscallIdle(slot);"))
                try common.addError(errors, allocator, "Prepared dispatch collection requires a consumed prepared receipt or explicit owned-root return", .{});
        },
        .executor => {
            const container = topLevelContainerBody(code, tokens.items, "pub const Executor = struct {") orelse &.{};
            const backend = topLevelContainerBody(code, tokens.items, "const NativePreparedDispatch = struct {") orelse &.{};
            if (!hasTopLevelCodeTokens(code, tokens.items, "const PreparedDispatch = dispatch_transport.Command;"))
                try common.addError(errors, allocator, "Prepared dispatch command must retain only its exact ticket and private trap stack scalar", .{});
            const native_owner = topLevelFunctionBody(code, backend, "ownerAvailable") orelse &.{};
            if (!timerCodeMatches(code, native_owner, "return smp.isRuntimeOwner() and continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();", .exact))
                try common.addError(errors, allocator, "Prepared dispatch native entry must retain the BSP owner admission guard", .{});
            const prepare = topLevelFunctionBody(code, container, "prepareTaskDispatchInto") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, prepare, &.{
                "if (!bspMappingTransaction() or !backend.preparationReady()) return false;",
                "if (!self.userAddressSpacePreparationReady(space) or mapping.owned_xstate == null) return false;",
                "if (!publishMailboxForDispatch(mapping, mailbox_update, backend)) return false;",
                "if (!mapping.resume_valid) mapping.user_context64 = .{ .instruction_pointer = mapping.dispatch_metadata.initial_instruction_pointer, .stack_pointer = mapping.dispatch_metadata.initial_stack_pointer, };",
                "const candidate: PreparedDispatch = .{ .ticket = ticket, .trap_stack_top = trap_stack_top };",
                "runtime.execution.bindPrepared(ticket, mapping_handle.value, physical_root) catch return false; out.* = candidate; return true;",
            });
            const admission = topLevelFunctionBody(code, container, "userAddressSpacePreparationReady") orelse &.{};
            if (!timerCodeMatches(code, admission, "return runtime.execution.rootAvailable(physical_root);", .suffix))
                try common.addError(errors, allocator, "Prepared dispatch must exclude an already leased root before context or mailbox edits", .{});
            if (preparedDispatchTokenCount(code, prepare, "runtime.execution.bindPrepared(") != 1 or preparedDispatchTokenCount(code, prepare, "return true;") != 1)
                try common.addError(errors, allocator, "Prepared dispatch preparation must publish its binding once before its only successful return", .{});
            const run = topLevelFunctionBody(code, container, "runPreparedTaskSlice") orelse &.{};
            if (!timerCodeMatches(code, run, "const ticket = prepared.ticket; const coordinator = @constCast(ticket.issuer); " ++
                "const restore_interrupts = backend.mask(); defer backend.restore(restore_interrupts); if (!backend.ownerAvailable()) return false; " ++
                "var bound: dispatch_ownership.BoundIdentity = undefined; coordinator.startPreparedInto(ticket, &bound) catch return false;", .prefix))
                try common.addError(errors, allocator, "Prepared dispatch must claim exact prepared owner before reading Executor or entry payload", .{});
            try preparedDispatchOrdered(allocator, errors, code, run, &.{
                "coordinator.startPreparedInto(ticket, &bound) catch return false;",
                "const authenticated_mapping: ?*MappingEntry = blk: {",
                "if (self.bound_runtime == null or &self.bound_runtime.?.execution != coordinator or",
                "const selected = self.findMappingByHandle(.{ .value = bound.mapping_handle }, bound.identity.address_space_id) orelse break :blk null;",
                "if (selected.dispatch_metadata.owner_task_id != bound.identity.task_id or mappingPhysicalRoot(selected) != bound.physical_root or selected.owned_xstate == null) break :blk null;",
                "var returned: ReturnRecord = .{}; if (authenticated_mapping) |mapping| {",
                "self.active_mapping = mapping; self.active_mapping_handle = .{ .value = bound.mapping_handle };",
                "backend.activate(mapping); backend.enter(self); requireIdleSyscallReturn(); backend.switchToKernel();",
                "self.active_task_id = 0; self.dispatch_quantum = .{}; self.active_mapping = null; self.active_mapping_handle = .{};",
                "returned.outcome = if (!self.handoff_completed) .unavailable else if (user_faulted) .faulted else switch (self.last_yield_disposition) { .runnable => .yielded, .wait_for_event => .wait_for_event, };",
                "returned.ui_revision = self.last_yield_ui_revision;",
                "returned.fault_instruction_pointer = fault.instruction_pointer; returned.fault_address = fault.fault_address;",
                "if (!continuationCleared(native_entry.current()) or !backend.kernelActive())",
                "self.active_dispatch_lease = null; } coordinator.ackPreparedReturn(ticket, returned)",
            });
            if (preparedDispatchTokenCount(code, run, "coordinator.ackPreparedReturn(") != 1)
                try common.addError(errors, allocator, "Prepared dispatch must publish exactly one terminal execution ACK", .{});
            if (!timerCodeMatches(code, run, "coordinator.ackPreparedReturn(ticket, returned) catch " ++
                "@call(.never_inline, executorInvariantFailure, .{.native_dispatch_acknowledges_its_exact_execution_lease}); return true;", .suffix))
                try common.addError(errors, allocator, "Prepared dispatch ACK must end owner backing access after the scalar snapshot and continuation clear", .{});
            const entry = topLevelFunctionBody(code, tokens.items, "enterUserspaceWithClock") orelse &.{};
            if (!timerCodeMatches(code, entry, "const mapping = executor.active_mapping orelse @call(.never_inline, executorInvariantFailure, .{.userspace_entry_requires_the_active_mapping_owner}); " ++
                "const storage = mapping.owned_xstate orelse @call(.never_inline, executorInvariantFailure, .{.userspace_entry_requires_private_extended_state}); " ++
                "clock.armSchedulerTick(); executor.dispatch_quantum = DispatchQuantum.begin(executor.active_task_id, clock.getTicks()); " ++
                "return entry.enter(&mapping.user_context64, storage.state());", .exact) or
                hasCodeTokens(code, container, "pending_user_context64"))
                try common.addError(errors, allocator, "Userspace entry must borrow the authenticated active mapping context and private state without an Executor context copy", .{});
            const fault = topLevelFunctionBody(code, tokens.items, "handleUserspacePageFaultWith") orelse &.{};
            if (!hasCodeTokens(code, fault, "const runtime_owner = smp.isRuntimeOwner();") or
                !hasCodeTokens(code, fault, "if (runtime_owner) { if (mapping.address_space) |*space| { if (hardware.resolve(space, faulting_address, error_code)) return; } }") or
                !hasCodeTokens(code, fault, "if (runtime_owner and hardware.recover(executor, mapping, frame, faulting_address, error_code))"))
                try common.addError(errors, allocator, "Prepared remote page faults must not mutate BSP demand paging or run its NX recovery", .{});
        },
        .scheduler => {
            const container = topLevelContainerBody(code, tokens.items, "pub const Scheduler = struct {") orelse &.{};
            const run = topLevelFunctionBody(code, container, "runNextWithDispatch") orelse &.{};
            if (!hasCodeTokens(code, run, "const record = dispatcher.executePreparedTask(task, &slot.mapping_handle, now_ticks); const outcome = record.outcome; const yielded = outcome.handedOff();") or
                !hasCodeTokens(code, run, "const ui_revision = record.ui_revision;") or
                !hasCodeTokens(code, run, "self.containUserException(runtime, task, now_ticks, &record);"))
                try common.addError(errors, allocator, "Prepared scheduler accounting must use the consumed receipt outcome UI revision and fault", .{});
            const direct = topLevelFunctionBody(code, container, "executeTaskWithDispatch") orelse &.{};
            if (!hasCodeTokens(code, direct, "const record = dispatcher.executePreparedTask(task, mapping_handle, now_ticks); if (record.outcome == .faulted) self.containUserException(runtime, task, now_ticks, &record); return record;"))
                try common.addError(errors, allocator, "Prepared direct scheduler dispatch must return its consumed scalar receipt", .{});
            for ([_][]const std.zig.Token{ run, direct }) |body| for ([_][:0]const u8{ "self.executor.last_yield_ui_revision", "self.executor.last_user_exception", "self.executor.last_yield_disposition" }) |retired| {
                if (hasCodeTokens(code, body, retired)) try common.addError(errors, allocator, "Prepared scheduler must not read an anchor Executor result: {s}", .{retired});
            };
            const fault = topLevelFunctionBody(code, container, "containUserException") orelse &.{};
            if (!hasCodeTokens(code, fault, "const exception = userspace_executor.UserException{ .vector = record.fault_vector, .error_code = record.fault_error_code, .instruction_pointer = record.fault_instruction_pointer, .fault_address = record.fault_address, };"))
                try common.addError(errors, allocator, "Prepared scheduler containment must derive every fault scalar from its execution receipt", .{});
            const finish = topLevelFunctionBody(code, container, "finishTaskDispatch") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, finish, &.{ "runtime.execution.consumePreparedReturnInto(ticket, &canceled)", "runtime.collectExecution(ticket)" });
        },
    }
}

test "prepared dispatch source gate accepts actual owner receipt paths and ignores quoted retired APIs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { path: []const u8, kind: PreparedDispatchSourceKind }{
        .{ .path = "src/native/task/dispatch_ownership.zig", .kind = .coordinator },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor },
        .{ .path = "src/native/task/userspace_scheduler.zig", .kind = .scheduler },
    }) |item| {
        const source = try common.readFileAlloc(allocator, std.testing.io, item.path, common.source_file_max_bytes);
        const annotated = try std.fmt.allocPrint(allocator, "{s}\n// pub fn bind() void {{}}\nconst quoted_old_ack = \"pub fn acknowledgeReturned() void {{}} self.executor.last_user_exception\";\n", .{source});
        var errors = std.ArrayList([]const u8).empty;
        try validatePreparedDispatchSource(allocator, &errors, annotated, item.kind);
        if (errors.items.len != 0) common.printErrors(errors.items);
        try std.testing.expectEqual(@as(usize, 0), errors.items.len);
    }
}

test "prepared dispatch source gate rejects missing purpose early ACK duplicate consume and racing cancellation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source = try common.readFileAlloc(allocator, std.testing.io, "src/native/task/dispatch_ownership.zig", common.source_file_max_bytes);
    for ([_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "pub fn bindOwnedRoot(", .replacement = "pub fn bind(" },
        .{ .needle = "pub fn acknowledgeOwnedRootReturn(", .replacement = "pub fn acknowledgeReturned(" },
        .{ .needle = "const EPOCH_SHIFT = 5;", .replacement = "const EPOCH_SHIFT = 4;" },
        .{ .needle = "try self.bindForPurpose(ticket, mapping_handle, physical_root, true);", .replacement = "try self.bindForPurpose(ticket, mapping_handle, physical_root, false);" },
        .{ .needle = "if (require_prepared and control & PREPARED == 0) return error.WrongPurpose;", .replacement = "// if (require_prepared and control & PREPARED == 0) return error.WrongPurpose;" },
        .{ .needle = "if (record.reserved != 0) return error.InvalidReturnRecord;", .replacement = "// if (record.reserved != 0) return error.InvalidReturnRecord;" },
        .{ .needle = "slot.return_record = record;", .replacement = "// slot.return_record = record;\nconst quoted = \"slot.return_record = record;\";" },
        .{ .needle = "controlWithPhase(control, .return_consumed)", .replacement = "controlWithPhase(control, .returned)" },
        .{ .needle = "if (prepared) .returning else .returned", .replacement = ".returned" },
        .{ .needle = "if (control & PREPARED != 0) .return_consumed else .returned", .replacement = ".returned" },
    }) |mutation| {
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        const altered = try std.mem.replaceOwned(u8, allocator, source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validatePreparedDispatchSource(allocator, &errors, altered, .coordinator);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "prepared dispatch source gate rejects premature publication backing reads and anchor result routing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { path: []const u8, kind: PreparedDispatchSourceKind, needle: []const u8, replacement: []const u8 }{
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "return smp.isRuntimeOwner() and continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();", .replacement = "return true;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "if (!publishMailboxForDispatch(mapping, mailbox_update, backend)) return false;", .replacement = "return true; // if (!publishMailboxForDispatch(mapping, mailbox_update, backend)) return false;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "out.* = candidate;", .replacement = "// out.* = candidate;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "if (!mapping.resume_valid) mapping.user_context64 =", .replacement = "if (true) mapping.user_context64 =" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "!self.userAddressSpacePreparationReady(space)", .replacement = "false" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "self.bound_runtime == null or &self.bound_runtime.?.execution != coordinator", .replacement = "false" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "self.findMappingByHandle(.{ .value = bound.mapping_handle }, bound.identity.address_space_id)", .replacement = "self.findMappingByHandle(.{ .value = 1 }, bound.identity.address_space_id)" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "return entry.enter(&mapping.user_context64, storage.state());", .replacement = "const entry_context = mapping.user_context64; return entry.enter(&entry_context, storage.state());" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "return entry.enter(&mapping.user_context64, storage.state());", .replacement = "return entry.enter(&UserContext64{}, storage.state());" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "pub const Executor = struct {", .replacement = "pub const Executor = struct { pending_user_context64: UserContext64 = .{}," },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "coordinator.startPreparedInto(ticket, &bound) catch return false;", .replacement = "_ = self.initialized; coordinator.startPreparedInto(ticket, &bound) catch return false;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "backend.switchToKernel();", .replacement = "// backend.switchToKernel();" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "coordinator.ackPreparedReturn(ticket, returned) catch", .replacement = "coordinator.ackPreparedReturn(ticket, .{}) catch" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "var returned: ReturnRecord = .{};", .replacement = "var returned: ReturnRecord = .{ .outcome = .faulted };" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "returned.outcome = if (!self.handoff_completed)", .replacement = "returned.outcome = if (true)" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "returned.ui_revision = self.last_yield_ui_revision;", .replacement = "returned.ui_revision = 0;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "coordinator.ackPreparedReturn(ticket, returned) catch", .replacement = "try coordinator.ackPreparedReturn(ticket, returned); coordinator.ackPreparedReturn(ticket, returned) catch" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "coordinator.ackPreparedReturn(ticket, returned) catch\n            @call(.never_inline, executorInvariantFailure, .{.native_dispatch_acknowledges_its_exact_execution_lease});\n        return true;", .replacement = "coordinator.ackPreparedReturn(ticket, returned) catch\n            @call(.never_inline, executorInvariantFailure, .{.native_dispatch_acknowledges_its_exact_execution_lease});\n        _ = self.initialized; return true;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "self.active_dispatch_lease = null;", .replacement = "// self.active_dispatch_lease = null;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "const runtime_owner = smp.isRuntimeOwner();", .replacement = "const runtime_owner = true;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "if (runtime_owner) {", .replacement = "if (true) {" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "if (runtime_owner and hardware.recover(", .replacement = "if (hardware.recover(" },
        .{ .path = "src/native/task/userspace_scheduler.zig", .kind = .scheduler, .needle = "const ui_revision = record.ui_revision;", .replacement = "const ui_revision = self.executor.last_yield_ui_revision;" },
        .{ .path = "src/native/task/userspace_scheduler.zig", .kind = .scheduler, .needle = ".fault_address = record.fault_address,", .replacement = ".fault_address = 0," },
        .{ .path = "src/native/task/userspace_scheduler.zig", .kind = .scheduler, .needle = "runtime.execution.consumePreparedReturnInto(ticket, &canceled)", .replacement = "runtime.execution.consumePreparedReturnInto(ticket, &ignored)" },
    }) |mutation| {
        const source = try common.readFileAlloc(allocator, std.testing.io, mutation.path, common.source_file_max_bytes);
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        const altered = try std.mem.replaceOwned(u8, allocator, source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validatePreparedDispatchSource(allocator, &errors, altered, mutation.kind);
        try std.testing.expect(errors.items.len != 0);
    }
}

const PreparedArchitectureProofSourceKind = enum { executor, probe, harness, proof_root, native_root };

fn validatePreparedArchitectureProofSource(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    source: []const u8,
    kind: PreparedArchitectureProofSourceKind,
) !void {
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    var lexer = std.zig.Tokenizer.init(code);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "Prepared architecture proof must remain valid Zig source", .{});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    switch (kind) {
        .executor => {
            for ([_][:0]const u8{
                "const architecture_smp_proof = @hasDecl(root, \"ARCHITECTURE_SMP_PROOF\") and root.ARCHITECTURE_SMP_PROOF;",
                "pub const ArchitecturePreparedCommand = if (architecture_smp_proof) PreparedDispatch else void;",
                "const ArchitecturePreparedBackend = if (architecture_smp_proof) struct {",
                "const ArchitecturePreparedFault = if (architecture_smp_proof) struct {",
            }) |pattern| if (!hasTopLevelCodeTokens(code, tokens.items, pattern)) {
                try common.addError(errors, allocator, "Prepared architecture bridge must remain isolated at compile time: {s}", .{pattern});
            };
            const executor = topLevelContainerBody(code, tokens.items, "pub const Executor = struct {") orelse &.{};
            for ([_]struct { name: []const u8, guard: [:0]const u8 }{
                .{ .name = "installPreparedExecutionMappingForArchitectureProof", .guard = "if (comptime !architecture_smp_proof) @compileError(\"prepared execution fixtures require an isolated proof root\");" },
                .{ .name = "bindPreparedExecutionForArchitectureProof", .guard = "if (comptime !architecture_smp_proof) @compileError(\"prepared execution binding requires an isolated proof root\");" },
                .{ .name = "runPreparedExecutionForArchitectureProof", .guard = "if (comptime !architecture_smp_proof) @compileError(\"prepared execution owner requires an isolated proof root\");" },
            }) |check| {
                const body = topLevelFunctionBody(code, executor, check.name) orelse &.{};
                try preparedDispatchOrdered(allocator, errors, code, body, &.{ "if (comptime builtin.target.os.tag != .freestanding) return false;", check.guard });
            }
            const install = topLevelFunctionBody(code, executor, "installPreparedExecutionMappingForArchitectureProof") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, install, &.{
                "if (!bspMappingTransaction() or !freestanding.paging.kernelAddressSpaceActive() or",
                "const storage = table_backing.alloc(xstate.Storage) orelse return false; storage.initialize();",
                "if (!self.installPreparedMappingForArchitectureProof(task, space, &handle)) { storage.erase(); table_backing.free(xstate.Storage, storage); return false; }",
                "mapping.owned_xstate = storage; mapping.user_context64 = context;",
                "out.* = handle; return true;",
            });
            const bind = topLevelFunctionBody(code, executor, "bindPreparedExecutionForArchitectureProof") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, bind, &.{
                "if (!bspMappingTransaction() or !freestanding.paging.kernelAddressSpaceActive() or",
                "if (cpu == 0 or ticket.cpu != cpu or registeredDomainExecutor(cpu, owner, runtime) != self or",
                "runtime.execution.identityInto(ticket, &identity) catch return false;",
                "identity.process_generation != task.process_generation or identity.address_space_id != task.address_space_id",
                "!self.userAddressSpacePreparationReady(space)",
                "const candidate: PreparedDispatch = .{ .ticket = ticket, .trap_stack_top = top };",
                "runtime.execution.bindPrepared(ticket, handle.value, physical_root) catch return false; out.* = candidate; return true;",
            });
            const run = topLevelFunctionBody(code, executor, "runPreparedExecutionForArchitectureProof") orelse &.{};
            if (!timerCodeMatches(code, run, "if (comptime builtin.target.os.tag != .freestanding) return false; " ++
                "if (comptime !architecture_smp_proof) @compileError(\"prepared execution owner requires an isolated proof root\"); " ++
                "return self.runPreparedTaskSlice(command, ArchitecturePreparedBackend{ .callback = callback, .callback_context = callback_context, });", .exact))
                try common.addError(errors, allocator, "Prepared architecture owner must reuse exactly one actual prepared runner without a separate lifecycle", .{});
            const backend = topLevelContainerBody(code, tokens.items, "const ArchitecturePreparedBackend = if (architecture_smp_proof) struct {") orelse &.{};
            for ([_]struct { name: []const u8, body: [:0]const u8 }{
                .{ .name = "ownerAvailable", .body = "return !smp.isRuntimeOwner() and native_entry.current().native_entry_modes == 0 and continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();" },
                .{ .name = "entryReady", .body = "return top != 0 and preparedKernelStackForCpu(cpu_identity.currentIndex()) == top and native_entry.current().kernel_stack_top == top and native_entry.current().native_entry_modes == 0 and continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();" },
                .{ .name = "mask", .body = "const enabled = x86.interruptsEnabled(); x86.cli(); return enabled;" },
                .{ .name = "restore", .body = "if (enabled) x86.sti();" },
                .{ .name = "activate", .body = "freestanding.paging.activateUserDomain(&mapping.address_space.?, mapping.dispatch_metadata.protectionKey());" },
                .{ .name = "enter", .body = "_ = enterUserspaceWithClock(executor, timer, Entry{ .backend = self, .executor = executor }); native_entry.clearContinuation();" },
                .{ .name = "switchToKernel", .body = "freestanding.paging.switchToKernelAddressSpace();" },
                .{ .name = "kernelActive", .body = "return freestanding.paging.kernelAddressSpaceActive();" },
            }) |check| {
                const body = topLevelFunctionBody(code, backend, check.name) orelse &.{};
                if (!timerCodeMatches(code, body, check.body, .exact))
                    try common.addError(errors, allocator, "Prepared architecture backend must retain real privileged {s} behavior", .{check.name});
            }
            const entry_container = topLevelContainerBody(code, backend, "const Entry = struct {") orelse &.{};
            const entry = topLevelFunctionBody(code, entry_container, "enter") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, entry, &.{
                "const entry: ArchitecturePreparedEntry = .{",
                ".physical_root = x86.readCr3() & x86.CR3_ADDRESS_MASK,",
                ".user_context = context, .xstate_address = @intFromPtr(state), .dispatch_quantum = self.executor.dispatch_quantum,",
                "const record = self.backend.callback(self.backend.callback_context, &entry);",
                "if (record.reserved != 0) @panic(\"isolated prepared callback returned reserved bits\");",
                "handleUserspaceYield(self.executor, &frame);",
                "handleUserspacePageFaultWith(&frame, ArchitecturePreparedFault{ .address = record.fault_address });",
                "return 1;",
            });
            if (preparedDispatchTokenCount(code, entry, "self.backend.callback(") != 1 or
                preparedDispatchTokenCount(code, backend, "enterUserspaceWithClock(") != 1)
                try common.addError(errors, allocator, "Prepared architecture proof may replace only one user entry callback", .{});
            const fault = topLevelContainerBody(code, tokens.items, "const ArchitecturePreparedFault = if (architecture_smp_proof) struct {") orelse &.{};
            for ([_]struct { name: []const u8, body: [:0]const u8 }{
                .{ .name = "resolve", .body = "@panic(\"AP prepared fault entered BSP demand mutation\");" },
                .{ .name = "recover", .body = "@panic(\"AP prepared fault entered BSP NX recovery\");" },
                .{ .name = "restoreKernel", .body = "freestanding.paging.switchToKernelAddressSpace();" },
            }) |check| {
                const body = topLevelFunctionBody(code, fault, check.name) orelse &.{};
                if (!timerCodeMatches(code, body, check.body, .exact))
                    try common.addError(errors, allocator, "Prepared architecture faults must retain the AP-local {s} boundary", .{check.name});
            }
        },
        .probe => {
            for ([_][:0]const u8{
                "var prepared_command: native_executor.ArchitecturePreparedCommand = undefined;",
                "var prepared_stale_command: native_executor.ArchitecturePreparedCommand = undefined;",
                "var prepared_owner_expectation: PreparedOwnerExpectation = .{};",
                "var prepared_phase: u32 = 0; var prepared_completed: u32 = 0;",
            }) |pattern| if (!hasTopLevelCodeTokens(code, tokens.items, pattern)) {
                try common.addError(errors, allocator, "Prepared AP evidence must retain static command callback and completion backing: {s}", .{pattern});
            };
            const prove = topLevelFunctionBody(code, tokens.items, "provePreparedOwner") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, prove, &.{
                "if (cpu_identity.currentIndex() != 0 or x86.interruptsEnabled() or !paging.kernelAddressSpaceActive() or runtime.execution.hasLeases() or preparedBorrowCount(runtime) != 0)",
                "if (!source.installPreparedExecutionMappingForArchitectureProof(task, space, context, &handle))",
                "if (snapshot.native_entry_modes != 0)",
                "const first = runtime.reserveExecution(task, PREPARED_OWNER_CPU)",
                "!source.bindPreparedExecutionForArchitectureProof(task, handle, first, &prepared_command)",
                "prepared_stale_command = prepared_command; @atomicStore(u32, &prepared_phase, 1, .release); waitForPreparedOwner(1); verifyPreparedOwnerReturn(runtime, source, first, admitted);",
                "runtime.execution.consumePreparedReturnInto(first, &returned)",
                "if (!std.meta.eql(returned, prepared_owner_expectation.receipt))",
                "rejectRepeatedPreparedConsume(runtime, first); runtime.collectExecution(first)",
                "prepared_owner_expectation.user_context.instruction_pointer += 4;",
                ".outcome = .faulted, .fault_vector = 14, .fault_error_code = 0x8000_0017, .fault_instruction_pointer = 0x4000_1234, .fault_address = 0x4000_5678,",
                "const second = runtime.reserveExecution(task, PREPARED_OWNER_CPU)",
                "second.epoch <= first.epoch",
                "!source.bindPreparedExecutionForArchitectureProof(task, handle, second, &prepared_command)",
                "@atomicStore(u32, &prepared_phase, 2, .release); waitForPreparedOwner(2); verifyPreparedOwnerReturn(runtime, source, second, admitted);",
                "runtime.terminateTask(task_id, 900)",
                "if (runtime.collectExecution(second)) |_|",
                "runtime.execution.consumePreparedReturnInto(second, &returned)",
                "if (!std.meta.eql(returned, prepared_owner_expectation.receipt))",
                "rejectRepeatedPreparedConsume(runtime, second); runtime.collectExecution(second)",
                "if (!native_executor.collectRegisteredRetiredMappings(scheduler, runtime) or",
                "paging.frameStats().allocated != admitted - 1",
                "const replacement_ticket = runtime.reserveExecution(replacement, PREPARED_OWNER_CPU)",
                "@atomicStore(u32, &prepared_phase, 3, .release); waitForPreparedOwner(3);",
                "if (prepared_owner_ran or @atomicLoad(u32, &prepared_callback_count, .acquire) != 2 or",
                "!= .reserved or",
                "preparedBorrowCount(runtime) != 1",
                "runtime.cancelUnstartedExecution(replacement_ticket)",
                "runtime.collectExecution(replacement_ticket)",
                "scheduler.deinit();",
                "prepared_owner_source = null;",
                "@atomicStore(u32, &prepared_phase, PREPARED_OWNER_DONE, .release); proof.pass(\"SMP_AP_PREPARED\");",
            });
            if (preparedDispatchTokenCount(code, prove, "prepared_command =") != 0 or
                preparedDispatchTokenCount(code, prove, "prepared_stale_command =") != 1)
                try common.addError(errors, allocator, "Prepared AP command storage must be published only through its checked binding and retained through completion", .{});
            const wait = topLevelFunctionBody(code, tokens.items, "waitForPreparedOwner") orelse &.{};
            if (!hasCodeTokens(code, wait, "while (@atomicLoad(u32, &prepared_completed, .acquire) != phase)") or
                !hasCodeTokens(code, wait, "deadline.expired()"))
                try common.addError(errors, allocator, "Prepared AP completion must acquire actual owner return under a bounded deadline", .{});
            const verify = topLevelFunctionBody(code, tokens.items, "verifyPreparedOwnerReturn") orelse &.{};
            for ([_][:0]const u8{
                "preparedBorrowCount(runtime) != 1",
                "!= .returned",
                "if (source.active_task_id != 0)",
                "if (source.active_mapping != null)",
                "if (source.active_dispatch_lease != null)",
                "if (!paging.kernelAddressSpaceActive())",
                "if (x86.interruptsEnabled())",
                "if (runtime.collectExecution(ticket)) |_|",
                "verifyPreparedNeighbors();",
            }) |pattern| if (!hasCodeTokens(code, verify, pattern)) {
                try common.addError(errors, allocator, "Prepared AP return evidence must retain pinned quiescent receipt checks: {s}", .{pattern});
            };
            const duplicate = topLevelFunctionBody(code, tokens.items, "rejectRepeatedPreparedConsume") orelse &.{};
            if (!hasCodeTokens(code, duplicate, "runtime.execution.consumePreparedReturnInto(ticket, &unchanged)") or
                !hasCodeTokens(code, duplicate, "err != error.WrongPhase") or
                !hasCodeTokens(code, duplicate, "if (!std.meta.eql(unchanged, canary))"))
                try common.addError(errors, allocator, "Prepared AP receipt evidence must reject duplicate consume without changing its output", .{});
            const owner = topLevelFunctionBody(code, tokens.items, "holdPreparedOwner") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, owner, &.{
                "if (index != PREPARED_OWNER_CPU) return; const saved_entry = native_entry.current().*;",
                "saved_entry.native_entry_modes != 0 or x86.interruptsEnabled()",
                "while (@atomicLoad(u32, &prepared_phase, .acquire) != phase)",
                "_ = native_entry.initializeCpu(index, assigned_top);",
                "prepared_owner_ran = source.runPreparedExecutionForArchitectureProof(if (phase == 3) &prepared_stale_command else &prepared_command, preparedOwnerCallback, &prepared_owner_expectation, );",
                "native_entry.current().* = saved_entry;",
                "if (!paging.kernelAddressSpaceActive() or x86.readCr3() & x86.CR3_ADDRESS_MASK != physical_cr3 or x86.interruptsEnabled() or gsEntryModes() != 0) reject(index);",
                "@atomicStore(u32, &prepared_completed, @intCast(phase), .release);",
            });
            if (preparedDispatchTokenCount(code, owner, "runPreparedExecutionForArchitectureProof(") != 1 or
                !timerCodeMatches(code, owner, "native_entry.current().* = saved_entry; " ++
                    "if (!paging.kernelAddressSpaceActive() or x86.readCr3() & x86.CR3_ADDRESS_MASK != physical_cr3 or " ++
                    "x86.interruptsEnabled() or gsEntryModes() != 0) reject(index); " ++
                    "@atomicStore(u32, &prepared_completed, @intCast(phase), .release); } " ++
                    "while (@atomicLoad(u32, &prepared_phase, .acquire) != PREPARED_OWNER_DONE) asm volatile (\"pause\");", .suffix))
                try common.addError(errors, allocator, "Prepared AP holder must publish completion after one real runner and retain backing without post-ACK domain access", .{});
            const after_runner = preparedDispatchTailAfter(code, owner, "prepared_owner_ran = source.runPreparedExecutionForArchitectureProof(if (phase == 3) &prepared_stale_command else &prepared_command, preparedOwnerCallback, &prepared_owner_expectation, );") orelse &.{};
            for ([_][:0]const u8{ "source", "runtime", "coordinator", "ticket", "issuer", "prepared_owner_source", "prepared_owner_expectation", "prepared_command", "prepared_stale_command" }) |borrowed| {
                if (hasCodeTokens(code, after_runner, borrowed))
                    try common.addError(errors, allocator, "Prepared AP holder must not access retired domain or command backing after owner ACK: {s}", .{borrowed});
            }
            const callback = topLevelFunctionBody(code, tokens.items, "preparedOwnerCallback") orelse &.{};
            for ([_][:0]const u8{
                "cpu_identity.currentIndex() != PREPARED_OWNER_CPU",
                "x86.interruptsEnabled() or paging.kernelAddressSpaceActive()",
                "x86.readCr3() & x86.CR3_ADDRESS_MASK != prepared_owner_expectation.physical_root",
                "gsWord(\"active_task_id\") != entry.task_id or gsEntryModes() != 0",
                "!std.meta.eql(entry.user_context.*, prepared_owner_expectation.user_context)",
                "!std.meta.eql(entry.dispatch_quantum, native_executor.DispatchQuantum.begin(entry.task_id, cpus[PREPARED_OWNER_CPU].observation.timer.cached_ticks))",
                "entry.xstate_address == 0 or entry.xstate_address % xstate.alignment != 0",
                "const rsp = asm volatile (\"mov %%rsp, %[value]\"",
                "rsp <= cpus[PREPARED_OWNER_CPU].stack_guard + PAGE_BYTES or rsp >= cpus[PREPARED_OWNER_CPU].stack_top",
                "state.pkru != 0 or state.reserved != 0",
                "prepared_xstate_address != entry.xstate_address",
                "@atomicRmw(u32, &prepared_callback_count, .Add, 1, .monotonic)",
            }) |pattern| if (!hasCodeTokens(code, callback, pattern)) {
                try common.addError(errors, allocator, "Prepared CPL0 callback must check actual root context stack and private storage evidence: {s}", .{pattern});
            };
            if (!timerCodeMatches(code, callback, "return prepared_owner_expectation.receipt;", .suffix))
                try common.addError(errors, allocator, "Prepared CPL0 callback must return only its retained scalar expectation", .{});
            const neighbors = topLevelFunctionBody(code, tokens.items, "verifyPreparedNeighbors") orelse &.{};
            if (!hasCodeTokens(code, neighbors, "!std.mem.eql(u8, std.mem.asBytes(&actual), std.mem.asBytes(expected)) or actual.native_entry_modes != 0") or
                !hasCodeTokens(code, neighbors, "trapStackWord(cpus[cpu].trap_stack_top, last).* != trapStackCanary(@intCast(cpu), last, true)"))
                try common.addError(errors, allocator, "Prepared AP proof must preserve all dormant GS and trap-backing neighbors", .{});
        },
        .harness => {
            const markers = topLevelContainerBody(code, tokens.items, "const high_half_proofs = [_][]const u8{") orelse &.{};
            if (!hasCodeTokens(code, markers, "\"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_16_BROKER:PASS\", \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_PREPARED:PASS\", \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRANSPORT:PASS\", \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRANSPORT_IPI:PASS\", \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRAP_STACK:PASS\", \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_LOW_RETIRED:PASS\",") or
                preparedDispatchTokenCount(code, markers, "\"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_PREPARED:PASS\"") != 1)
                try common.addError(errors, allocator, "Prepared AP proof must remain one ordered required guest marker", .{});
            const smoke = topLevelFunctionBody(code, tokens.items, "highHalfSmoke") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, smoke, &.{ "try healthy(h.ctx, bytes, \"FAIL\");", "log.exactOrdered(bytes, &high_half_proofs)" });
        },
        .proof_root => {
            if (!hasTopLevelCodeTokens(code, tokens.items, "pub const ARCHITECTURE_SMP_PROOF = true;"))
                try common.addError(errors, allocator, "Prepared architecture bridge must be admitted only by its dedicated proof root", .{});
            const publish = topLevelFunctionBody(code, tokens.items, "publishUserspaceActiveTaskId") orelse &.{};
            if (!timerCodeMatches(code, publish, "@import(\"arch/x86_64/native_entry_state.zig\").current().active_task_id = task_id;", .exact))
                try common.addError(errors, allocator, "Prepared architecture root must publish its selected native GS task identity", .{});
        },
        .native_root => {
            if (hasCodeTokens(code, tokens.items, "ARCHITECTURE_SMP_PROOF"))
                try common.addError(errors, allocator, "Production roots must not enable isolated prepared owner callbacks", .{});
        },
    }
}

test "prepared architecture proof gate accepts actual isolated bridge and ignores decoys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { path: []const u8, kind: PreparedArchitectureProofSourceKind }{
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe },
        .{ .path = "tools/host/qemu.zig", .kind = .harness },
        .{ .path = "src/high_half_entry.zig", .kind = .proof_root },
        .{ .path = "src/main.zig", .kind = .native_root },
        .{ .path = "src/efi_entry.zig", .kind = .native_root },
    }) |item| {
        const source = try common.readFileAlloc(allocator, std.testing.io, item.path, common.source_file_max_bytes);
        const annotated = try std.fmt.allocPrint(allocator, "{s}\n// return self.runPreparedTaskSlice(command, ArchitecturePreparedBackend{{}});\nconst proof_decoy = \"native_entry.clearContinuation(); ARCHITECTURE_SMP_PROOF\";\n", .{source});
        var errors = std.ArrayList([]const u8).empty;
        try validatePreparedArchitectureProofSource(allocator, &errors, annotated, item.kind);
        if (errors.items.len != 0) common.printErrors(errors.items);
        try std.testing.expectEqual(@as(usize, 0), errors.items.len);
    }
}

test "prepared architecture proof gate rejects production exposure duplicate lifecycle and fake privileged cleanup" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source = try common.readFileAlloc(allocator, std.testing.io, "src/native/task/userspace_executor.zig", common.source_file_max_bytes);
    for ([_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "const architecture_smp_proof = @hasDecl(root, \"ARCHITECTURE_SMP_PROOF\") and root.ARCHITECTURE_SMP_PROOF;", .replacement = "const architecture_smp_proof = true;" },
        .{ .needle = "pub const ArchitecturePreparedCommand = if (architecture_smp_proof) PreparedDispatch else void;", .replacement = "pub const ArchitecturePreparedCommand = PreparedDispatch;" },
        .{ .needle = "if (comptime !architecture_smp_proof) @compileError(\"prepared execution fixtures require an isolated proof root\");", .replacement = "// isolated fixtures compile guard removed" },
        .{ .needle = "if (comptime !architecture_smp_proof) @compileError(\"prepared execution binding requires an isolated proof root\");", .replacement = "// isolated binding compile guard removed" },
        .{ .needle = "if (comptime !architecture_smp_proof) @compileError(\"prepared execution owner requires an isolated proof root\");", .replacement = "// isolated owner compile guard removed" },
        .{ .needle = "return self.runPreparedTaskSlice(command, ArchitecturePreparedBackend{", .replacement = "try command.ticket.issuer.startPreparedInto(command.ticket, &bound); return self.runPreparedTaskSlice(command, ArchitecturePreparedBackend{" },
        .{ .needle = "const ArchitecturePreparedBackend = if (architecture_smp_proof) struct {", .replacement = "const ArchitecturePreparedBackend = struct {" },
        .{ .needle = "native_entry.current().native_entry_modes == 0", .replacement = "true" },
        .{ .needle = "const enabled = x86.interruptsEnabled();\n        x86.cli();\n        return enabled;", .replacement = "return false;" },
        .{ .needle = "if (enabled) x86.sti();", .replacement = "_ = enabled;" },
        .{ .needle = "freestanding.paging.activateUserDomain(&mapping.address_space.?, mapping.dispatch_metadata.protectionKey());", .replacement = "_ = mapping;" },
        .{ .needle = "_ = enterUserspaceWithClock(executor, timer, Entry{ .backend = self, .executor = executor });", .replacement = "_ = self.callback(self.callback_context, &entry);" },
        .{ .needle = "native_entry.clearContinuation();", .replacement = "// native_entry.clearContinuation();" },
        .{ .needle = "freestanding.paging.switchToKernelAddressSpace();", .replacement = "// freestanding.paging.switchToKernelAddressSpace();" },
        .{ .needle = "const record = self.backend.callback(self.backend.callback_context, &entry);", .replacement = "const record = ReturnRecord{};" },
        .{ .needle = "handleUserspaceYield(self.executor, &frame);", .replacement = "self.handoff_completed = true;" },
        .{ .needle = "handleUserspacePageFaultWith(&frame, ArchitecturePreparedFault{ .address = record.fault_address });", .replacement = "self.last_user_exception = null;" },
        .{ .needle = "@panic(\"AP prepared fault entered BSP demand mutation\");", .replacement = "return true;" },
        .{ .needle = "@panic(\"AP prepared fault entered BSP NX recovery\");", .replacement = "return true;" },
    }) |mutation| {
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        const altered = try std.mem.replaceOwned(u8, allocator, source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validatePreparedArchitectureProofSource(allocator, &errors, altered, .executor);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "prepared architecture proof gate rejects premature completion fabricated evidence and unordered marker" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { path: []const u8, kind: PreparedArchitectureProofSourceKind, needle: []const u8, replacement: []const u8 }{
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "var prepared_command: native_executor.ArchitecturePreparedCommand = undefined;", .replacement = "// static command removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "var prepared_stale_command: native_executor.ArchitecturePreparedCommand = undefined;", .replacement = "// static stale command removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "@atomicLoad(u32, &prepared_completed, .acquire)", .replacement = "@atomicLoad(u32, &prepared_completed, .monotonic)" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "@atomicStore(u32, &prepared_phase, 1, .release);", .replacement = "@atomicStore(u32, &prepared_phase, 1, .monotonic);" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "waitForPreparedOwner(1);", .replacement = "// owner wait removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "waitForPreparedOwner(1);", .replacement = "prepared_command = undefined; waitForPreparedOwner(1);" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "runtime.execution.consumePreparedReturnInto(first, &returned)", .replacement = "runtime.execution.identityInto(first, &returned)" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "rejectRepeatedPreparedConsume(runtime, second);", .replacement = "// duplicate receipt assertion removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "second.epoch <= first.epoch", .replacement = "false" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "preparedBorrowCount(runtime) != 1", .replacement = "false" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "prepared_owner_ran = source.runPreparedExecutionForArchitectureProof(", .replacement = "@atomicStore(u32, &prepared_completed, @intCast(phase), .release); prepared_owner_ran = true; if (false) _ = source.runPreparedExecutionForArchitectureProof(" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "native_entry.current().* = saved_entry;", .replacement = "// dormant GS restoration removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "native_entry.current().* = saved_entry;", .replacement = "_ = source.materializedCount(); native_entry.current().* = saved_entry;" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "native_entry.current().* = saved_entry;", .replacement = "_ = prepared_command.ticket.issuer; native_entry.current().* = saved_entry;" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "native_entry.current().* = saved_entry;", .replacement = "_ = prepared_owner_expectation.task_id; native_entry.current().* = saved_entry;" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "gsEntryModes() != 0", .replacement = "false" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "x86.readCr3() & x86.CR3_ADDRESS_MASK != prepared_owner_expectation.physical_root", .replacement = "false" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "!std.meta.eql(entry.user_context.*, prepared_owner_expectation.user_context)", .replacement = "false" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "rsp <= cpus[PREPARED_OWNER_CPU].stack_guard + PAGE_BYTES or rsp >= cpus[PREPARED_OWNER_CPU].stack_top", .replacement = "false" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "prepared_xstate_address != entry.xstate_address", .replacement = "false" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "@atomicStore(u32, &prepared_completed, @intCast(phase), .release);", .replacement = "@atomicStore(u32, &prepared_completed, @intCast(phase), .monotonic);" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "    \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_PREPARED:PASS\",", .replacement = "// prepared marker removed" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "log.exactOrdered(bytes, &high_half_proofs)", .replacement = "log.ordered(bytes, &high_half_proofs)" },
        .{ .path = "src/high_half_entry.zig", .kind = .proof_root, .needle = "pub const ARCHITECTURE_SMP_PROOF = true;", .replacement = "pub const ARCHITECTURE_SMP_PROOF = false;" },
        .{ .path = "src/high_half_entry.zig", .kind = .proof_root, .needle = "@import(\"arch/x86_64/native_entry_state.zig\").current().active_task_id = task_id;", .replacement = "_ = task_id;" },
    }) |mutation| {
        const source = try common.readFileAlloc(allocator, std.testing.io, mutation.path, common.source_file_max_bytes);
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        const altered = try std.mem.replaceOwned(u8, allocator, source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validatePreparedArchitectureProofSource(allocator, &errors, altered, mutation.kind);
        try std.testing.expect(errors.items.len != 0);
    }
    for ([_][]const u8{ "src/main.zig", "src/efi_entry.zig" }) |path| {
        const source = try common.readFileAlloc(allocator, std.testing.io, path, common.source_file_max_bytes);
        const altered = try std.fmt.allocPrint(allocator, "{s}\npub const ARCHITECTURE_SMP_PROOF = true;\n", .{source});
        var errors = std.ArrayList([]const u8).empty;
        try validatePreparedArchitectureProofSource(allocator, &errors, altered, .native_root);
        try std.testing.expect(errors.items.len != 0);
    }
}

const MappingXstateSourceKind = enum { proof_root, probe, model, assembly, base_probe, smp_probe, build, build_graph, harness };

fn mappingXstateBlock(code: []const u8, tokens: []const std.zig.Token, prefix: [:0]const u8) ?[]const std.zig.Token {
    for (tokens, 0..) |_, index| {
        const length = codeTokenSequenceLength(code, tokens[index..], prefix) orelse continue;
        if (length == 0 or tokens[index + length - 1].tag != .l_brace) return null;
        var depth: usize = 1;
        const start = index + length;
        for (tokens[start..], start..) |token, end| {
            if (token.tag == .l_brace) depth += 1;
            if (token.tag == .r_brace) depth -= 1;
            if (depth == 0) return tokens[start..end];
        }
    }
    return null;
}

fn mappingXstateDirectStatement(code: []const u8, tokens: []const std.zig.Token, statement: [:0]const u8) bool {
    var depth: usize = 0;
    for (tokens, 0..) |token, index| {
        if (depth == 0 and (index == 0 or tokens[index - 1].tag == .semicolon or tokens[index - 1].tag == .r_brace) and
            codeTokenSequenceLength(code, tokens[index..], statement) != null) return true;
        if (token.tag == .l_brace) depth += 1;
        if (token.tag == .r_brace) depth -= 1;
    }
    return false;
}

fn mappingXstateBody(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8), code: []const u8, tokens: []const std.zig.Token, name: []const u8, pattern: [:0]const u8, position: TimerCodePosition) !void {
    const body = topLevelFunctionBody(code, tokens, name) orelse &.{};
    if (!timerCodeMatches(code, body, pattern, position))
        try common.addError(errors, allocator, "Mapping compacted-state proof must retain actual scoped {s} control/lifetime oracle", .{name});
}

fn mappingXstateAssemblyExact(source: []const u8, expected: []const []const u8) bool {
    var lines = std.mem.splitScalar(u8, source, '\n');
    var matched: usize = 0;
    while (lines.next()) |raw| {
        const end = std.mem.indexOf(u8, raw, "//") orelse raw.len;
        const line = std.mem.trim(u8, raw[0..end], " \t\r");
        if (line.len == 0) continue;
        if (matched == expected.len or !std.mem.eql(u8, line, expected[matched])) return false;
        matched += 1;
    }
    return matched == expected.len;
}

fn mappingXstateAssemblyPolicy(source: []const u8) bool {
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw| {
        const end = std.mem.indexOf(u8, raw, "//") orelse raw.len;
        const line = std.mem.trim(u8, raw[0..end], " \t\r");
        if (std.mem.startsWith(u8, line, "#") and !std.mem.eql(u8, line, "#include \"../xstate64.inc\"")) return false;
        if (std.mem.startsWith(u8, line, ".if") or std.mem.startsWith(u8, line, ".else")) return false;
        if (std.mem.startsWith(u8, line, ".macro") and !std.mem.eql(u8, line, ".macro MAPPING_STANDARD_READBACK pointer")) return false;
    }
    return true;
}

fn validateMappingXstateSource(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8), source: []const u8, kind: MappingXstateSourceKind) !void {
    if (kind == .assembly) {
        // Authenticate the executable leaf and separate standard readback, not
        // an instruction name in a comment or a host substitute definition.
        if (!mappingXstateAssemblyPolicy(source) or !hasAssemblyLines(source, &.{"#include \"../xstate64.inc\""}) or
            std.mem.indexOf(u8, source, "#define ZIGOS_XSTATE_HOST_TEST") != null or
            std.mem.indexOf(u8, source, "prepared=") != null)
            try common.addError(errors, allocator, "Mapping oracle must use unchanged generic production compact macros without host or READY substitutes", .{});
        const standard = assemblySpan(source, ".macro MAPPING_STANDARD_READBACK pointer", ".endm");
        if (!mappingXstateAssemblyExact(standard, &.{ ".macro MAPPING_STANDARD_READBACK pointer", "leaq 512(\\pointer), %rdi", "xorl %eax, %eax", "movl $8, %ecx", "rep stosq", "movl $7, %eax", "xorl %edx, %edx", "xsave64 (\\pointer)", ".endm" }))
            try common.addError(errors, allocator, "Mapping independent oracle must clear its own standard header and execute XSAVE directly", .{});
        const leaf = assemblySpan(source, "zigos_mapping_xstate_roundtrip:", ".size zigos_mapping_xstate_roundtrip,.-zigos_mapping_xstate_roundtrip");
        if (!mappingXstateAssemblyExact(leaf, &.{
            "zigos_mapping_xstate_roundtrip:",  "pushq %rbp",                     "pushq %rbx",             "pushq %r12",       "pushq %r13",                                                            "pushq %r14",       "pushq %r15",                     "subq $16, %rsp",
            "movq %rcx, (%rsp)",                "movl %r8d, 8(%rsp)",             "movq %rsp, %rbx",        "movq %rdi, %r12",  "movq %rsi, %r14",                                                       "movq %rdx, %r15",  "subq $XSTATE_STACK_BYTES, %rsp", "andq $-64, %rsp",
            "movq %rsp, %rbp",                  "cld",                            "XSAVE_FULL_STATE %rbp",  "movq %r12, %r13",  "XRSTOR_STATE %r13",                                                     "cmpl $2, 8(%rbx)", "jae .Lmapping_resume",           "movq (%rbx), %r13",
            "MAPPING_STANDARD_READBACK %r13",   "jmp .Lmapping_seed",             ".Lmapping_resume:",      "cmpl $3, 8(%rbx)", "jne .Lmapping_save",                                                    ".Lmapping_seed:",  "movq %r14, %r13",                "XRSTOR_FULL_STATE %r13",
            ".Lmapping_save:",                  "movq %r12, %r13",                "XSAVE_STATE %r13",       "movq %r15, %r13",  "XRSTOR_FULL_STATE %r13",                                                "movq %r12, %r13",  "XRSTOR_STATE %r13",              "movq (%rbx), %r13",
            "addq $XSTATE_ALIGNED_BYTES, %r13", "MAPPING_STANDARD_READBACK %r13", "XRSTOR_FULL_STATE %rbp", "movq %rbx, %rsp",  "addq $16, %rsp",                                                        "popq %r15",        "popq %r14",                      "popq %r13",
            "popq %r12",                        "popq %rbx",                      "popq %rbp",              "ret",              ".size zigos_mapping_xstate_roundtrip,.-zigos_mapping_xstate_roundtrip",
        }))
            try common.addError(errors, allocator, "Mapping leaf must alternate real owned compact images and poison/live standard state before independent readback and caller restore", .{});
        return;
    }
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    var lexer = std.zig.Tokenizer.init(code);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "Mapping compacted-state proof requires valid actual Zig source", .{});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    switch (kind) {
        .proof_root => {
            if (!hasTopLevelCodeTokens(code, tokens.items, "pub const ARCHITECTURE_SMP_PROOF = true;") or
                !hasTopLevelCodeTokens(code, tokens.items, "pub const MAPPING_XSTATE_PROOF = true;"))
                try common.addError(errors, allocator, "Separate Mapping image must explicitly root only its architecture and compact proof", .{});
            try mappingXstateBody(allocator, errors, code, tokens.items, "publishUserspaceActiveTaskId", "@import(\"arch/x86_64/native_entry_state.zig\").current().active_task_id = task_id;", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "syscall_handler", "@import(\"arch/x86_64/high_half_probe.zig\").fail(\"unexpected Mapping-state native syscall entry\");", .exact);
        },
        .base_probe => try mappingXstateBody(allocator, errors, code, tokens.items, "kernel_main", "@import(\"../../kernel/utils/console.zig\").init(); if (comptime @import(\"mapping_xstate_probe.zig\").enabled) @import(\"mapping_xstate_probe.zig\").preflightBsp(); " ++
            "@import(\"../cpu_features.zig\").initializeNativeCachePolicy() catch fail(\"cache policy admission\");", .prefix),
        .smp_probe => {
            const run = topLevelFunctionBody(code, tokens.items, "proveCurrentRoots") orelse &.{};
            // These calls belong to the existing serial lease waves; they must
            // finish before Runtime reset and before the AP's final IPI loop.
            if (!hasCodeTokens(code, run, "proveGuardedTrapStack(runtime); if (comptime @import(\"mapping_xstate_probe.zig\").enabled) @import(\"mapping_xstate_probe.zig\").run(runtime, cpus[PREPARED_OWNER_CPU].trap_stack_top, physical_cr3); runtime.reset();"))
                try common.addError(errors, allocator, "Mapping orchestration must run before the original Runtime is reset", .{});
            const ap = topLevelFunctionBody(code, tokens.items, "apEntry") orelse &.{};
            if (!hasCodeTokens(code, ap, "holdGuardedTrapStack(index); if (comptime @import(\"mapping_xstate_probe.zig\").enabled) @import(\"mapping_xstate_probe.zig\").hold(index, cpus[index].trap_stack_top, cpus[index].stack_guard + PAGE_BYTES, cpus[index].stack_top); serviceIpis(index);"))
                try common.addError(errors, allocator, "Selected AP Mapping holder must retain actual guarded stack bounds and finish before permanent IPI service", .{});
        },
        .model => {
            const caps = topLevelContainerBody(code, tokens.items, "pub const Capabilities = struct {") orelse &.{};
            try mappingXstateBody(allocator, errors, code, caps, "unsupported", "if (self.maximum_leaf < 0xD) return .CPUID; " ++
                "if (self.leaf1_ecx & (1 << 26) == 0) return .XSAVE; if (self.leaf1_ecx & (1 << 28) == 0) return .AVX; " ++
                "if (self.state_features & (1 << 3) == 0) return .XSAVES; " ++
                "if (self.state_mask & 7 != 7 or self.ymm_bytes != 256 or self.ymm_offset != 576 or self.ymm_flags & 1 != 0) return .YMM_LAYOUT; return null;", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "guardsIntact", "if (image.state.pkru != 0 or image.state.reserved != 0) return false; " ++
                "for (std.mem.asBytes(image)[@sizeOf(xstate.State)..]) |byte| if (byte != 0xa5) return false; " ++
                "for (image.state.image[528..576]) |byte| if (byte != 0) return false; return true;", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "initialIntact", "const bytes = &image.state.image; " ++
                "for (bytes[160..416]) |byte| if (byte != 0) return false; for (bytes[576..832]) |byte| if (byte != 0) return false; " ++
                "return guardsIntact(image) and std.mem.readInt(u16, bytes[0..2], .little) == 0x037f and std.mem.readInt(u16, bytes[2..4], .little) == 0 and bytes[4] == 0 and " ++
                "std.mem.readInt(u32, bytes[24..28], .little) == 0x1f80 and std.mem.readInt(u64, bytes[512..520], .little) & ~@as(u64, 7) == 0 and std.mem.readInt(u64, bytes[520..528], .little) == 0;", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "restoredIntact", "const before = &expected.state.image; const after = &actual.state.image; " ++
                "if (!guardsIntact(actual) or !std.mem.eql(u8, before[0..5], after[0..5]) or !std.mem.eql(u8, before[24..28], after[24..28]) or " ++
                "!std.mem.eql(u8, before[160..416], after[160..416]) or !std.mem.eql(u8, before[576..832], after[576..832]) or " ++
                "std.mem.readInt(u64, after[512..520], .little) != 7 or std.mem.readInt(u64, after[520..528], .little) != 0) return false; " ++
                "for (0..8) |register| { const offset = 32 + register * 16; if (!std.mem.eql(u8, before[offset..][0..10], after[offset..][0..10])) return false; } return true;", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "compactedIntact", "if (state.pkru != 0 or state.reserved != 0 or " ++
                "std.mem.readInt(u64, state.image[512..520], .little) != 7 or std.mem.readInt(u64, state.image[520..528], .little) != (@as(u64, 1) << 63 | 7)) return false; " ++
                "for (state.image[528..576]) |byte| if (byte != 0) return false; return true;", .exact);
        },
        .probe => {
            for ([_][:0]const u8{
                "pub const enabled = @hasDecl(root, \"MAPPING_XSTATE_PROOF\") and root.MAPPING_XSTATE_PROOF;", "const OWNER: u8 = 1;",                          "const EPOCHS = 4;",                                  "const DONE: u32 = EPOCHS + 1;",
                "var phase: u32 = 0;",                                                                         "var owner_ready: u32 = 0;",                     "var returned_phase: u32 = 0;",                       "var completed_phase: u32 = 0;",
                "var release_phase: u32 = 0;",                                                                 "var owner_phase: u32 = 0;",                     "var callback_count: u32 = 0;",                       "var states: [2]*align(64) xstate.State = undefined;",
                "var storages: [2]*xstate.Storage = undefined;",                                               "var neighbor_state: xstate.State = undefined;", "var neighbors: [16]native_entry.State = undefined;", "var stack_hashes: [16]u64 = undefined;",
            }) |pattern| if (!hasTopLevelCodeTokens(code, tokens.items, pattern))
                try common.addError(errors, allocator, "Mapping compact proof must retain permanent isolated owner/completion backing: {s}", .{pattern});
            try mappingXstateBody(allocator, errors, code, tokens.items, "cpuid", "var eax: u32 = undefined; var ebx: u32 = undefined; var ecx: u32 = undefined; var edx: u32 = undefined; " ++
                "asm volatile (\"cpuid\" : [eax] \"={eax}\" (eax), [ebx] \"={ebx}\" (ebx), [ecx] \"={ecx}\" (ecx), [edx] \"={edx}\" (edx), : [leaf] \"{eax}\" (leaf), [subleaf] \"{ecx}\" (subleaf), ); " ++
                "return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "rawCapabilities", "const maximum = cpuid(0, 0).eax; " ++
                "var caps: model.Capabilities = .{ .maximum_leaf = maximum, .leaf1_ecx = 0, .state_mask = 0, .state_features = 0, .ymm_bytes = 0, .ymm_offset = 0, .ymm_flags = 0 }; " ++
                "if (maximum >= 1) caps.leaf1_ecx = cpuid(1, 0).ecx; if (maximum >= 0xD) { caps.state_mask = cpuid(0xD, 0).eax; caps.state_features = cpuid(0xD, 1).eax; " ++
                "const ymm = cpuid(0xD, 2); caps.ymm_bytes = ymm.eax; caps.ymm_offset = ymm.ebx; caps.ymm_flags = ymm.ecx; } return caps;", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "preflightBsp", "if (rawCapabilities().unsupported()) |reason| { " ++
                "console.print(\"ZIGOS:ARCH:X86_64:MAPPING_XSTATE:UNSUPPORTED:\"); console.print(@tagName(reason)); console.print(\"\\n\"); " ++
                "x86.outl(0xF4, 0x12); while (true) asm volatile (\"cli; hlt\"); } pass(\"BSP_ADMISSION\");", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "wait", "const deadline = clock.afterMilliseconds(2000); while (@atomicLoad(u32, word, .acquire) != wanted) { " ++
                "if (deadline.expired()) proof.fail(\"Mapping xstate phase timeout\"); asm volatile (\"pause\"); }", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "imageAuthority", "const start = @intFromPtr(state); " ++
                "const physical = address.directMappedPhysicalAddress(start, address.direct_map_capacity) orelse return false; " ++
                "if (paging.mappedRamSpan(physical, @sizeOf(xstate.State)) != start) return false; var page = start & ~@as(usize, 4095); " ++
                "while (page < start + @sizeOf(xstate.State)) : (page += 4096) { const permissions = paging.currentPagePermissions(page) orelse return false; " ++
                "if (!permissions.writable or permissions.executable or permissions.user) return false; } return true;", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "storageIntact", "const begin = @intFromPtr(storage.state()) - @intFromPtr(&storage.bytes); " ++
                "for (storage.bytes[0..begin]) |byte| if (byte != 0xa5) return false; for (storage.bytes[begin + @sizeOf(xstate.State) ..]) |byte| if (byte != 0xa5) return false; " ++
                "return storage.state().pkru == 0 and storage.state().reserved == 0;", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "verifyNeighbors", "for (&neighbors, 0..) |*expected, cpu| { " ++
                "const actual = native_entry.stateForCpu(@intCast(cpu)).*; const top = executor.preparedKernelStackForCpu(@intCast(cpu)) orelse proof.fail(\"Mapping xstate neighbor trap\"); " ++
                "if (!std.mem.eql(u8, std.mem.asBytes(expected), std.mem.asBytes(&actual)) or actual.native_entry_modes != 0 or stackHash(top) != stack_hashes[cpu]) " ++
                "proof.fail(\"Mapping xstate neighbor mutation\"); }", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "callback", "if (context != @as(*anyopaque, @ptrCast(&owner_phase)) or owner_phase == 0 or owner_phase > EPOCHS) proof.fail(\"Mapping xstate callback phase\"); " ++
                "const index = owner_phase - 1; const selected = index % 2; const other = selected ^ 1; " ++
                "if (cpu_identity.currentIndex() != OWNER or x86.interruptsEnabled() or paging.kernelAddressSpaceActive() or " ++
                "entry.task_id != task_ids[selected] or entry.physical_root != roots[selected] or x86.readCr3() & x86.CR3_ADDRESS_MASK != roots[selected] or " ++
                "native_entry.current().native_entry_modes != 0 or native_entry.current().kernel_stack_top != entry.trap_stack_top or entry.xstate_address != @intFromPtr(states[selected]) or " ++
                "!std.meta.eql(entry.user_context.*, contexts[selected]) or !imageAuthority(states[selected]) or !std.mem.eql(u8, std.mem.asBytes(&neighbor_state), std.mem.asBytes(states[other]))) " ++
                "proof.fail(\"Mapping xstate actual owner receipt\"); const seed = if (index == 3) &seeds[2] else &seeds[selected]; " ++
                "zigos_mapping_xstate_roundtrip(states[selected], seed, &poison, &results[index], index); " ++
                "if (!model.restoredIntact(seed, &results[index].restored) or (index < 2 and !model.initialIntact(&results[index].initial)) or " ++
                "!model.compactedIntact(states[selected]) or !storageIntact(storages[0]) or !storageIntact(storages[1]) or " ++
                "!std.mem.eql(u8, std.mem.asBytes(&neighbor_state), std.mem.asBytes(states[other]))) proof.fail(\"Mapping xstate hardware roundtrip oracle\"); " ++
                "_ = @atomicRmw(u32, &callback_count, .Add, 1, .monotonic); return .{ .outcome = .yielded, .ui_revision = owner_phase };", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "afterReturn", "if (context != @as(*anyopaque, @ptrCast(&owner_phase))) proof.fail(\"Mapping xstate completion hook\"); " ++
                "owner_ran = ran; const current_phase = owner_phase; @atomicStore(u32, &returned_phase, current_phase, .release); wait(&release_phase, current_phase);", .exact);
            try mappingXstateBody(allocator, errors, code, tokens.items, "hold", "if (index != OWNER) return; if (rawCapabilities().unsupported() != null) proof.fail(\"Mapping xstate selected capability mismatch\"); " ++
                "const saved_entry = native_entry.current().*; const saved_cr0 = x86.readCr0(); const saved_cr4 = x86.readCr4(); const saved_cr3 = x86.readCr3(); " ++
                "if (cpu_identity.currentIndex() != OWNER or x86.interruptsEnabled() or !paging.kernelAddressSpaceActive() or saved_entry.native_entry_modes != 0 or " ++
                "saved_cr4 & (x86.CR4_OSXSAVE | x86.CR4_PKE | x86.CR4_FRED) != x86.CR4_OSXSAVE or saved_cr0 & (x86.CR0_EM | x86.CR0_TS) != 0 or " ++
                "x86.readXcr0() != 7 or executor.preparedKernelStackForCpu(OWNER) != trap_top) proof.fail(\"Mapping xstate selected controls\"); " ++
                "const saved_xss = x86.readMsr(x86.IA32_XSS_MSR); x86.writeMsr(x86.IA32_XSS_MSR, 0); " ++
                "if (x86.readMsr(x86.IA32_XSS_MSR) != 0 or cpuid(0xD, 0).ebx != xstate.image_bytes or cpuid(0xD, 1).ebx != xstate.image_bytes) proof.fail(\"Mapping xstate enabled layout\"); " ++
                "@atomicStore(u32, &owner_ready, 1, .release); for (1..DONE) |current_phase| { wait(&phase, @intCast(current_phase)); owner_phase = @intCast(current_phase); " ++
                "const rsp = x86.stackPointer(); if (rsp <= ordinary_bottom or rsp >= ordinary_top) proof.fail(\"Mapping xstate ordinary stack\"); " ++
                "_ = native_entry.initializeCpu(OWNER, trap_top); " ++
                "if (!executor.runQueuedPreparedExecutionForArchitectureProof(callback, &owner_phase, &saved_entry, null, afterReturn, &owner_phase)) proof.fail(\"Mapping xstate owner command rejected\"); " ++
                "const restored_entry = native_entry.current().*; if (x86.readCr0() != saved_cr0 or x86.readCr4() != saved_cr4 or x86.readCr3() != saved_cr3 or " ++
                "x86.readXcr0() != 7 or x86.readMsr(x86.IA32_XSS_MSR) != 0 or x86.interruptsEnabled() or " ++
                "!std.mem.eql(u8, std.mem.asBytes(&restored_entry), std.mem.asBytes(&saved_entry))) proof.fail(\"Mapping xstate caller controls restore\"); " ++
                "@atomicStore(u32, &completed_phase, @intCast(current_phase), .release); } " ++
                "x86.writeMsr(x86.IA32_XSS_MSR, saved_xss); if (x86.readMsr(x86.IA32_XSS_MSR) != saved_xss) proof.fail(\"Mapping xstate XSS restore\"); " ++
                "@atomicStore(u32, &owner_ready, 2, .release); wait(&phase, DONE);", .exact);
            const run = topLevelFunctionBody(code, tokens.items, "run") orelse &.{};
            if (!timerCodeMatches(code, run, "if (cpu_identity.currentIndex() != 0 or x86.interruptsEnabled() or !paging.kernelAddressSpaceActive() or " ++
                "runtime.execution.hasLeases() or borrowCount(runtime) != 0 or transport.global.hasOutstandingForIssuer(&runtime.execution)) proof.fail(\"Mapping xstate BSP ownership\"); " ++
                "wait(&owner_ready, 1); const bsp_cr3 = x86.readCr3();", .prefix))
                try common.addError(errors, allocator, "Mapping BSP must admit kernel root/quiescent domain and acquire actual selected controls first", .{});
            try durableTransportRequired(allocator, errors, code, run, &.{
                "!scheduler_module.ArchitectureProof.bindDomain(scheduler, runtime) or !source.claimRuntimeBinding(scheduler, runtime) or !source.claimMappingRegistration(OWNER, scheduler, runtime)",
                "!source.installPreparedExecutionMappingForArchitectureProof(task, space, contexts[index], &handles[index])",
                "states[index] = storages[index].state();",
                "if (!imageAuthority(states[index]))",
                "paintStorage(storages[index]);",
                "roots[0] == roots[1]",
                "@intFromPtr(states[0]) < @intFromPtr(states[1]) + @sizeOf(xstate.State) and @intFromPtr(states[1]) < @intFromPtr(states[0]) + @sizeOf(xstate.State)",
                "model.initialize(&poison, 3);",
                "model.initializeResult(result);",
                "snapshot.native_entry_modes != 0",
            });
            const epoch = mappingXstateBlock(code, run, "for (0..EPOCHS) |index| {") orelse &.{};
            if (!timerCodeMatches(code, epoch, "const selected = index % 2; const other = selected ^ 1; neighbor_state = states[other].*; " ++
                "const ticket = runtime.reserveExecution(tasks[selected], OWNER) catch proof.fail(\"Mapping xstate lease reservation\"); " ++
                "if (ticket.epoch <= previous_epoch) proof.fail(\"Mapping xstate epoch reuse\"); previous_epoch = ticket.epoch; " ++
                "var command: executor.ArchitecturePreparedCommand = undefined; var key: transport.Key = undefined; " ++
                "if (!source.bindPreparedExecutionForArchitectureProof(tasks[selected], handles[selected], ticket, &command) or !source.publishPreparedExecutionForArchitectureProof(&command, &key)) " ++
                "proof.fail(\"Mapping xstate queue publication\"); @atomicStore(u32, &phase, @intCast(index + 1), .release); wait(&returned_phase, @intCast(index + 1)); " ++
                "if (!owner_ran or @atomicLoad(u32, &callback_count, .acquire) != index + 1 or (runtime.execution.phase(ticket) catch proof.fail(\"Mapping xstate returned phase\")) != .returned or " ++
                "source.active_task_id != 0 or source.active_mapping != null or source.active_dispatch_lease != null or borrowCount(runtime) != 1 or source.materializedCount() != 2 or paging.frameStats().allocated != admitted) " ++
                "proof.fail(\"Mapping xstate returned pin\"); var receipt: ownership.ReturnRecord = undefined; " ++
                "runtime.execution.consumePreparedReturnInto(ticket, &receipt) catch proof.fail(\"Mapping xstate acquired receipt\"); " ++
                "if (!std.meta.eql(receipt, ownership.ReturnRecord{ .outcome = .yielded, .ui_revision = index + 1 })) proof.fail(\"Mapping xstate exact return scalar\"); " ++
                "if (index == 2) { if (runtime.collectExecution(ticket)) |_| proof.fail(\"Mapping xstate collected before completion\") else |err| { " ++
                "if (err != error.Busy) proof.fail(\"Mapping xstate retained collection error\"); } " ++
                "if (executor.releaseRegisteredDomain(scheduler, runtime) or source.materializedCount() != 2 or borrowCount(runtime) != 1 or paging.frameStats().allocated != admitted) " ++
                "proof.fail(\"Mapping xstate retained domain backing\"); } " ++
                "@atomicStore(u32, &release_phase, @intCast(index + 1), .release); wait(&completed_phase, @intCast(index + 1)); " ++
                "var completion: transport.Completion = undefined; transport.global.completionInto(key, &completion) catch proof.fail(\"Mapping xstate static completion\"); " ++
                "if (completion != .owner_returned) proof.fail(\"Mapping xstate unstarted completion\"); runtime.collectExecution(ticket) catch proof.fail(\"Mapping xstate acknowledged collection\"); " ++
                "if (borrowCount(runtime) != 0 or runtime.execution.hasLeases() or transport.global.hasOutstandingForIssuer(&runtime.execution) or source.materializedCount() != 2 or paging.frameStats().allocated != admitted or " ++
                "!storageIntact(storages[0]) or !storageIntact(storages[1]) or !model.compactedIntact(states[selected]) or !std.mem.eql(u8, std.mem.asBytes(&neighbor_state), std.mem.asBytes(states[other]))) " ++
                "proof.fail(\"Mapping xstate persistent owner backing\"); contexts[selected].rax = 1; contexts[selected].rdx = index + 1; contexts[selected].rsi = 0; contexts[selected].instruction_pointer += 4; " ++
                "verifyNeighbors(); switch (index) { 0 => pass(\"MAPPING_A_SEED\"), 1 => pass(\"MAPPING_B_SEED\"), 2 => pass(\"MAPPING_A_RESTORE\"), 3 => pass(\"MAPPING_B_UPDATE\"), else => unreachable, }", .exact))
                try common.addError(errors, allocator, "Mapping A-B-A-B epochs must acquire returned receipt, reject early collection, then acquire independent completion before collection/reuse", .{});
            try preparedDispatchOrdered(allocator, errors, code, run, &.{
                "wait(&owner_ready, 2);",                                                             "verifyNeighbors();",                                             "pass(\"OWNERSHIP\");",                                                             "for (tasks) |task|",                                                                                                         "runtime.terminateTask(task.id, 920)",
                "runtime.findAddressSpaceConst(asid) != null or task.execution_component_count != 0", "!executor.collectRegisteredRetiredMappings(scheduler, runtime)", "source.materializedCount() != 0 or paging.frameStats().allocated != admitted - 2", "scheduler.deinit();",                                                                                                        "value.registration_cpu != null or value.bound_runtime != null or value.binding_owner != null or value.materializedCount() != 0",
                "table_backing.free(executor.Executor, value);",                                      "table_backing.free(scheduler_module.Scheduler, scheduler);",     "verifyNeighbors();",                                                               "borrowCount(runtime) != 0 or runtime.execution.hasLeases() or transport.global.hasOutstandingForIssuer(&runtime.execution)", "paging.frameStats().allocated != admitted - 2 or !paging.kernelAddressSpaceActive() or x86.readCr3() != bsp_cr3",
                "pass(\"RETIREMENT\");",                                                              "@atomicStore(u32, &phase, DONE, .release);",                     "console.print(\"ZIGOS:ARCH:X86_64:MAPPING_XSTATE:PASS\\n\");",
            });
        },
        .build => {
            try validateUpperHalfEntryBuild(allocator, errors, code, tokens.items);
            try mappingXstateBody(allocator, errors, code, tokens.items, "addMappingXstateProof", "const image = addUpperHalfProbeImage(b, optimize, .mapping_xstate); " ++
                "const artifact_step = b.step(\"mapping-xstate-proof-image\", \"Build the isolated fixed-topology Mapping-owned compacted-state probe without running it\"); " ++
                "artifact_step.dependOn(&b.addInstallFile(image.elf, \"bin/mapping-xstate-probe.elf\").step); artifact_step.dependOn(&b.addInstallFile(image.efi, \"bin/mapping-xstate-probe.efi\").step); " ++
                "artifact_step.dependOn(&b.addInstallFile(image.iso, \"mapping-xstate.iso\").step); " ++
                "const positive = host_tools.addRun(b, \"run-mapping-xstate-smoke\"); positive.addFileArg(image.iso); positive.addArg(\"build/mapping-xstate.log\"); positive.addArg(\"positive\"); " ++
                "const step = b.step(\"mapping-xstate-proof-check\", \"Require actual Mapping-owned XSAVES/XRSTORS, independent register readback and acknowledged lifetime; reject unsupported targets\"); step.dependOn(&positive.step); " ++
                "const unsupported = host_tools.addRun(b, \"run-mapping-xstate-smoke\"); unsupported.addFileArg(image.iso); unsupported.addArg(\"build/mapping-xstate-unsupported.log\"); unsupported.addArg(\"unsupported\"); " ++
                "const unsupported_step = b.step(\"mapping-xstate-unsupported-check\", \"Require explicit unsupported compacted-state admission before any privileged state operation\"); unsupported_step.dependOn(&unsupported.step); return step;", .exact);
        },
        .build_graph => {
            const body = topLevelFunctionBody(code, tokens.items, "build") orelse &.{};
            if (!mappingXstateDirectStatement(code, body, "const mapping_xstate_proof_check = kernel_build.addMappingXstateProof(b, optimize);") or
                !mappingXstateDirectStatement(code, body, "verify_step.dependOn(mapping_xstate_proof_check);"))
                try common.addError(errors, allocator, "Verify must unconditionally require the strict positive Mapping proof rather than the expected-unsupported diagnostic", .{});
        },
        .harness => {
            if (!hasTopLevelCodeTokens(code, tokens.items, "const MappingXstateMode = enum { positive, unsupported };") or
                !hasTopLevelCodeTokens(code, tokens.items, "const mapping_xstate_namespace = \"ZIGOS:ARCH:X86_64:MAPPING_XSTATE:\";"))
                try common.addError(errors, allocator, "Mapping validator must retain separate positive and unsupported protocols", .{});
            // The validator must authenticate bytes from a freshly launched
            // child, not merely exist beside a marker-only or fabricated path.
            try mappingXstateBody(allocator, errors, code, tokens.items, "run", "failure_exit_code = 1; const signals = process.Signals.install(); defer signals.restore(); " ++
                "var args = input; var harness: Harness = .{ .ctx = ctx, .boot_iso = ctx.env(\"QEMU_BOOT_ISO\") }; " ++
                "if (args.len >= 2 and std.mem.eql(u8, args[0], \"--boot-iso\")) { harness.boot_iso = args[1]; args = args[2..]; } " ++
                "if (std.mem.eql(u8, command, \"run-with-qemu-boot-iso\")) { try require(args, 2); const wrapped = try ctx.allocator.alloc([]const u8, args.len); " ++
                "wrapped[0] = \"--boot-iso\"; wrapped[1] = args[0]; @memcpy(wrapped[2..], args[2..]); const basename = std.fs.path.basename(args[1]); " ++
                "const name = if (std.mem.endsWith(u8, basename, \".sh\")) basename[0 .. basename.len - 3] else basename; return run(ctx, name, wrapped); } " ++
                "if (std.mem.eql(u8, command, \"qemu-harness\")) return runHarness(harness, args); " ++
                "if (std.mem.eql(u8, command, \"run-headless-qemu\")) { try require(args, 1); " ++
                "const argv = try harness.kernel(arg(args, 1, harness.profileMemory()), arg(args, 2, env(ctx, \"QEMU_SERIAL_TARGET\", \"stdio\")), true, false); " ++
                "const status = try process.run(ctx, argv.items, null); if (status != 0 and status != success_exit) { failure_exit_code = @intCast(@min(status, 255)); return error.QemuFailed; } return; } " ++
                "if (std.mem.eql(u8, command, \"run-uefi-boot-test\")) return uefiBoot(harness, args); " ++
                "if (std.mem.eql(u8, command, \"run-long-mode-entry-smoke\")) return entrySmoke(harness, args, true); " ++
                "if (std.mem.eql(u8, command, \"run-native-crypto-smoke\")) return nativeCryptoSmoke(harness, args); " ++
                "if (std.mem.eql(u8, command, \"run-high-half-smoke\")) return highHalfSmoke(harness, args); " ++
                "if (std.mem.eql(u8, command, \"run-mapping-xstate-smoke\")) return mappingXstateSmoke(harness, args);", .prefix);
            try mappingXstateBody(allocator, errors, code, tokens.items, "mappingXstateSmoke", "if (args.len != 3) return error.InvalidArguments; " ++
                "const mode = std.meta.stringToEnum(MappingXstateMode, args[2]) orelse return error.InvalidArguments; const ctx = h.ctx; const path = args[1]; " ++
                "try ctx.mkdir(std.fs.path.dirname(path) orelse \".\"); try remove(ctx, path); const status_path = try fmt(ctx, \"{s}.qemu-status\", .{stem(path)}); try remove(ctx, status_path); " ++
                "var command = try h.build(args[0], \"192M\", try fmt(ctx, \"file:{s}\", .{path}), true, false); " ++
                "try command.appendSlice(ctx.allocator, &.{ \"-smp\", \"cpus=16,sockets=1,cores=16,threads=1\" }); const qemu_log = try fmt(ctx, \"{s}.qemu.log\", .{stem(path)}); " ++
                "const status = try process.timed(ctx, command.items, qemu_log, try process.seconds(ctx, \"ZIGOS_MAPPING_XSTATE_SECONDS\", \"30\")); " ++
                "try ctx.write(status_path, try fmt(ctx, \"{d}\\n\", .{status})); const bytes = try readOptional(ctx, path); " ++
                "validateMappingXstateResult(status, mode, bytes) catch |err| { dump(ctx, bytes); dump(ctx, try readOptional(ctx, qemu_log)); " ++
                "ctx.warn(\"Mapping xstate {s} evidence rejected: QEMU exit {d}. Log: {s}\\n\", .{ @tagName(mode), status, path }) catch {}; return err; }; " ++
                "try ctx.warn(\"Mapping xstate {s} evidence validated with QEMU exit {d}. Log: {s}\\n\", .{ @tagName(mode), status, path });", .exact);
            const markers = topLevelContainerBody(code, tokens.items, "const mapping_xstate_proofs = [_][]const u8{") orelse &.{};
            if (!timerCodeMatches(code, markers, "mapping_xstate_namespace ++ \"BSP_ADMISSION:PASS\", mapping_xstate_namespace ++ \"MAPPING_A_SEED:PASS\", mapping_xstate_namespace ++ \"MAPPING_B_SEED:PASS\", " ++
                "mapping_xstate_namespace ++ \"MAPPING_A_RESTORE:PASS\", mapping_xstate_namespace ++ \"MAPPING_B_UPDATE:PASS\", mapping_xstate_namespace ++ \"OWNERSHIP:PASS\", " ++
                "mapping_xstate_namespace ++ \"RETIREMENT:PASS\", mapping_xstate_namespace ++ \"PASS\",", .exact))
                try common.addError(errors, allocator, "Mapping hardware proof must require all eight actual ordered records", .{});
            try mappingXstateBody(allocator, errors, code, tokens.items, "validateMappingXstateResult", "if (status != (if (mode == .positive) @as(u32, success_exit) else 37)) return error.UnexpectedMappingXstateExit; " ++
                "if (!log.healthy(bytes, \"FAIL\")) return error.UnhealthyMappingXstateEvidence; switch (mode) { .positive => { " ++
                "if (log.contains(bytes, \"UNSUPPORTED\")) return error.UnsupportedCpuTarget; if (!std.mem.endsWith(u8, bytes, \"\\n\")) return error.IncompleteMappingXstateEvidence; " ++
                "if (log.countContaining(bytes, mapping_xstate_namespace) != mapping_xstate_proofs.len or log.countContaining(bytes, \"ZIGOS:ARCH:X86_64:HIGH_HALF:\") != high_half_proofs.len or " ++
                "log.countContaining(bytes, \"ZIGOS:ARCH:X86_64:\") != mapping_xstate_proofs.len + high_half_proofs.len) return error.UnexpectedMappingXstateEvidence; " ++
                "try log.exactOrdered(bytes, &mapping_xstate_proofs); try log.exactOrdered(bytes, &high_half_proofs); " ++
                "try log.ordered(bytes, &.{ mapping_xstate_proofs[0], high_half_proofs[0] }); try log.ordered(bytes, &.{ mapping_xstate_proofs[mapping_xstate_proofs.len - 1], high_half_proofs[high_half_proofs.len - 1] }); }, " ++
                ".unsupported => { const prefix = mapping_xstate_namespace ++ \"UNSUPPORTED:\"; " ++
                "if (log.countContaining(bytes, mapping_xstate_namespace) != 1 or log.countContaining(bytes, \"ZIGOS:\") != 1 or log.contains(bytes, \":PASS\") or " ++
                "log.contains(bytes, \"AP:ONLINE\") or log.contains(bytes, \"AP_HIGH_ENTRY\")) return error.UnexpectedMappingXstateEvidence; " ++
                "inline for (.{ \"CPUID\", \"XSAVE\", \"AVX\", \"XSAVES\", \"YMM_LAYOUT\" }) |reason| { if (log.exact(bytes, prefix ++ reason) and std.mem.endsWith(u8, bytes, \"\\n\")) return; } " ++
                "return error.InvalidMappingXstateUnsupportedReason; }, }", .exact);
        },
        .assembly => unreachable,
    }
}

const mapping_xstate_gate_sources = [_]struct { path: []const u8, kind: MappingXstateSourceKind }{
    .{ .path = "src/mapping_xstate_entry.zig", .kind = .proof_root },
    .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe },
    .{ .path = "src/arch/x86_64/mapping_xstate_probe_model.zig", .kind = .model },
    .{ .path = "src/arch/x86_64/mapping_xstate_probe.S", .kind = .assembly },
    .{ .path = "src/arch/x86_64/high_half_probe.zig", .kind = .base_probe },
    .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .smp_probe },
    .{ .path = "build_support/kernel.zig", .kind = .build },
    .{ .path = "build.zig", .kind = .build_graph },
    .{ .path = "tools/host/qemu.zig", .kind = .harness },
};

test "Mapping compact source gate accepts actual isolated production macros and completion protocol" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for (mapping_xstate_gate_sources) |item| {
        const source = try common.readFileAlloc(allocator, std.testing.io, item.path, common.source_file_max_bytes);
        const annotated = try std.fmt.allocPrint(allocator, "{s}\n// XSAVES XCR0 READY and collectExecution decoys do not authenticate a scope\n", .{source});
        var errors = std.ArrayList([]const u8).empty;
        try validateMappingXstateSource(allocator, &errors, annotated, item.kind);
        for (errors.items) |message| std.debug.print("{s}: {s}\n", .{ item.path, message });
        try std.testing.expectEqual(@as(usize, 0), errors.items.len);
    }
}

const MappingXstateMutation = struct { path: []const u8, kind: MappingXstateSourceKind, needle: []const u8, replacement: []const u8 };

fn rejectMappingXstateMutations(mutations: []const MappingXstateMutation) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for (mutations) |mutation| {
        const source = try common.readFileAlloc(allocator, std.testing.io, mutation.path, common.source_file_max_bytes);
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        const altered = try std.mem.replaceOwned(u8, allocator, source, mutation.needle, mutation.replacement);
        const comment = try std.mem.replaceOwned(u8, allocator, mutation.needle, "\n", "\n// ");
        const with_decoys = if (mutation.kind == .assembly)
            try std.fmt.allocPrint(allocator, "{s}\n// {s}\n", .{ altered, comment })
        else
            try std.fmt.allocPrint(allocator, "{s}\n// {s}\nconst mapping_gate_quoted_decoy = {s};\n", .{ altered, comment, try std.json.Stringify.valueAlloc(allocator, mutation.needle, .{}) });
        var errors = std.ArrayList([]const u8).empty;
        try validateMappingXstateSource(allocator, &errors, with_decoys, mutation.kind);
        if (errors.items.len == 0) std.debug.print("Mapping gate accepted hostile {s}: {s}\n", .{ mutation.path, mutation.needle });
        try std.testing.expect(errors.items.len != 0);
    }
}

test "Mapping compact source gate rejects fabricated owner admission and premature backing collection" {
    try rejectMappingXstateMutations(&.{
        .{ .path = "src/mapping_xstate_entry.zig", .kind = .proof_root, .needle = "pub const MAPPING_XSTATE_PROOF = true;", .replacement = "pub const MAPPING_XSTATE_PROOF = false;" },
        .{ .path = "src/mapping_xstate_entry.zig", .kind = .proof_root, .needle = ".current().active_task_id = task_id;", .replacement = ".current().active_task_id = 0;" },
        .{ .path = "src/arch/x86_64/high_half_probe.zig", .kind = .base_probe, .needle = "if (comptime @import(\"mapping_xstate_probe.zig\").enabled)", .replacement = "if (false)" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .smp_probe, .needle = "@import(\"mapping_xstate_probe.zig\").run(runtime, cpus[PREPARED_OWNER_CPU].trap_stack_top, physical_cr3);", .replacement = "runtime.reset();" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .smp_probe, .needle = "@import(\"mapping_xstate_probe.zig\").hold(index, cpus[index].trap_stack_top, cpus[index].stack_guard + PAGE_BYTES, cpus[index].stack_top);", .replacement = "@import(\"mapping_xstate_probe.zig\").hold(index, cpus[index].stack_top, 0, cpus[index].stack_top);" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "var completed_phase: u32 = 0;", .replacement = "var completed_phase: u32 = 4;" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "asm volatile (\"cpuid\"", .replacement = "asm volatile (\"nop\"" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "caps.state_features = cpuid(0xD, 1).eax;", .replacement = "caps.state_features = 8;" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "x86.outl(0xF4, 0x12);", .replacement = "x86.outl(0xF4, 0x10);" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "@atomicLoad(u32, word, .acquire)", .replacement = "@atomicLoad(u32, word, .monotonic)" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "paging.mappedRamSpan(physical, @sizeOf(xstate.State)) != start", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "!permissions.writable or permissions.executable or permissions.user", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "storage.bytes[begin + @sizeOf(xstate.State) ..]", .replacement = "storage.bytes[storage.bytes.len..]" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "actual.native_entry_modes != 0", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "entry.task_id != task_ids[selected]", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "entry.xstate_address != @intFromPtr(states[selected])", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "native_entry.current().native_entry_modes != 0", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "zigos_mapping_xstate_roundtrip(states[selected], seed, &poison, &results[index], index);", .replacement = "if (false) zigos_mapping_xstate_roundtrip(states[selected], seed, &poison, &results[index], index);" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "!model.restoredIntact(seed, &results[index].restored)", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "owner_ran = ran;", .replacement = "owner_ran = ran; _ = states[0].image[0];" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "rawCapabilities().unsupported() != null", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "saved_cr4 & (x86.CR4_OSXSAVE | x86.CR4_PKE | x86.CR4_FRED) != x86.CR4_OSXSAVE", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "saved_cr0 & (x86.CR0_EM | x86.CR0_TS) != 0", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "x86.readXcr0() != 7", .replacement = "x86.readXcr0() & 7 != 7" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "x86.readMsr(x86.IA32_XSS_MSR) != 0", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "cpuid(0xD, 1).ebx != xstate.image_bytes", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "rsp <= ordinary_bottom or rsp >= ordinary_top", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "const restored_entry = native_entry.current().*;", .replacement = "_ = states[0].pkru; const restored_entry = native_entry.current().*;" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "x86.writeMsr(x86.IA32_XSS_MSR, saved_xss);", .replacement = "// lost original XSS" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "ticket.epoch <= previous_epoch", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "@atomicStore(u32, &phase, @intCast(index + 1), .release);", .replacement = "@atomicStore(u32, &phase, @intCast(index + 1), .monotonic);" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "wait(&returned_phase, @intCast(index + 1));", .replacement = "// early domain reads" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "borrowCount(runtime) != 1", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "runtime.execution.consumePreparedReturnInto(ticket, &receipt)", .replacement = "runtime.execution.identityInto(ticket, &receipt)" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "err != error.Busy", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "executor.releaseRegisteredDomain(scheduler, runtime)", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "wait(&completed_phase, @intCast(index + 1));", .replacement = "// collect at execution ACK only" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "completion != .owner_returned", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.zig", .kind = .probe, .needle = "paging.frameStats().allocated != admitted - 2", .replacement = "false" },
    });
}

test "Mapping compact source gate rejects substituted compact instructions and incomplete register oracles" {
    try rejectMappingXstateMutations(&.{
        .{ .path = "src/arch/x86_64/mapping_xstate_probe_model.zig", .kind = .model, .needle = "self.state_features & (1 << 3) == 0", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe_model.zig", .kind = .model, .needle = "self.ymm_offset != 576", .replacement = "false" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe_model.zig", .kind = .model, .needle = "image.state.image[528..576]", .replacement = "image.state.image[576..576]" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe_model.zig", .kind = .model, .needle = "for (bytes[160..416])", .replacement = "for (bytes[160..160])" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe_model.zig", .kind = .model, .needle = "for (bytes[576..832])", .replacement = "for (bytes[576..576])" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe_model.zig", .kind = .model, .needle = "& ~@as(u64, 7) == 0", .replacement = "== 7" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe_model.zig", .kind = .model, .needle = "before[offset..][0..10]", .replacement = "before[offset..][0..8]" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe_model.zig", .kind = .model, .needle = "before[576..832]", .replacement = "before[576..576]" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe_model.zig", .kind = .model, .needle = "!= (@as(u64, 1) << 63 | 7)", .replacement = "!= 7" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.S", .kind = .assembly, .needle = ".text\n.code64", .replacement = ".if 0\n.text\n.code64" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.S", .kind = .assembly, .needle = "#include \"../xstate64.inc\"", .replacement = "#define ZIGOS_XSTATE_HOST_TEST 1\n#include \"../xstate64.inc\"" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.S", .kind = .assembly, .needle = "    xsave64 (\\pointer)", .replacement = "    XSAVE_STATE \\pointer" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.S", .kind = .assembly, .needle = "    XRSTOR_STATE %r13", .replacement = "    XRSTOR_FULL_STATE %r13" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.S", .kind = .assembly, .needle = "    XSAVE_STATE %r13", .replacement = "    XSAVE_FULL_STATE %r13" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.S", .kind = .assembly, .needle = "    XSAVE_STATE %r13", .replacement = "    XSAVE_STATE %r13, prepared=1" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.S", .kind = .assembly, .needle = "    cmpl $3, 8(%rbx)", .replacement = "    cmpl $2, 8(%rbx)" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.S", .kind = .assembly, .needle = "    movq %r15, %r13", .replacement = "    movq %r14, %r13" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.S", .kind = .assembly, .needle = "    MAPPING_STANDARD_READBACK %r13", .replacement = "    call compiler_helper\n    MAPPING_STANDARD_READBACK %r13" },
        .{ .path = "src/arch/x86_64/mapping_xstate_probe.S", .kind = .assembly, .needle = "    XRSTOR_FULL_STATE %rbp", .replacement = "    // original caller state lost" },
    });
}

test "Mapping compact source gate rejects positive evidence downgrade redirected image and missing verify dependency" {
    try rejectMappingXstateMutations(&.{
        .{ .path = "build_support/kernel.zig", .kind = .build, .needle = "const image = addUpperHalfProbeImage(b, optimize, .mapping_xstate);", .replacement = "const image = addUpperHalfProbeImage(b, optimize, .entry);" },
        .{ .path = "build_support/kernel.zig", .kind = .build, .needle = "positive.addArg(\"positive\");", .replacement = "positive.addArg(\"unsupported\");" },
        .{ .path = "build_support/kernel.zig", .kind = .build, .needle = "step.dependOn(&positive.step);", .replacement = "if (false) step.dependOn(&positive.step);" },
        .{ .path = "build_support/kernel.zig", .kind = .build, .needle = "return step;\n}\n\nconst UpperHalfProbeKind", .replacement = "return unsupported_step;\n}\n\nconst UpperHalfProbeKind" },
        .{ .path = "build.zig", .kind = .build_graph, .needle = "verify_step.dependOn(mapping_xstate_proof_check);", .replacement = "if (false) verify_step.dependOn(mapping_xstate_proof_check);" },
        .{ .path = "build.zig", .kind = .build_graph, .needle = "verify_step.dependOn(mapping_xstate_proof_check);", .replacement = "if (false) { verify_step.dependOn(mapping_xstate_proof_check); }" },
        .{ .path = "build.zig", .kind = .build_graph, .needle = "const mapping_xstate_proof_check = kernel_build.addMappingXstateProof(b, optimize);", .replacement = "const mapping_xstate_proof_check = kernel_build.addHighHalfEntryCheck(b, optimize);" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "const MappingXstateMode = enum { positive, unsupported };", .replacement = "const MappingXstateMode = enum { unsupported };" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "if (mode == .positive) @as(u32, success_exit) else 37", .replacement = "if (mode == .positive) @as(u32, 37) else 37" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "if (log.contains(bytes, \"UNSUPPORTED\")) return error.UnsupportedCpuTarget;", .replacement = "if (log.contains(bytes, \"UNSUPPORTED\")) return;" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "try log.exactOrdered(bytes, &mapping_xstate_proofs);", .replacement = "try log.ordered(bytes, &mapping_xstate_proofs);" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "log.countContaining(bytes, \"ZIGOS:\") != 1", .replacement = "false" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "log.contains(bytes, \":PASS\")", .replacement = "false" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "\"XSAVES\", \"YMM_LAYOUT\"", .replacement = "\"XSAVES\", \"YMM_LAYOUT\", \"UNKNOWN\"" },
    });
}

test "Mapping compact source gate rejects fake subprocess evidence dead routes and test server stdout" {
    try rejectMappingXstateMutations(&.{
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "return mappingXstateSmoke(harness, args);", .replacement = "return highHalfSmoke(harness, args);" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "if (std.mem.eql(u8, command, \"run-mapping-xstate-smoke\"))", .replacement = "if (false)" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "if (std.mem.eql(u8, command, \"run-mapping-xstate-smoke\"))", .replacement = "if (false) if (std.mem.eql(u8, command, \"run-mapping-xstate-smoke\"))" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "failure_exit_code = 1;\n    const signals", .replacement = "return; failure_exit_code = 1;\n    const signals" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "if (args.len != 3) return error.InvalidArguments;", .replacement = "return; if (args.len != 3) return error.InvalidArguments;" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "try remove(ctx, path);\n    const status_path", .replacement = "// stale serial retained\n    const status_path" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "try remove(ctx, status_path);", .replacement = "// stale status retained" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "var command = try h.build(args[0], \"192M\",", .replacement = "var command = try h.kernel(\"192M\"," },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "\"cpus=16,sockets=1,cores=16,threads=1\"", .replacement = "\"cpus=1,sockets=1,cores=1,threads=1\"" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "const status = try process.timed(ctx, command.items, qemu_log, try process.seconds(ctx, \"ZIGOS_MAPPING_XSTATE_SECONDS\", \"30\"));", .replacement = "const status = 33; _ = try process.timed(ctx, command.items, qemu_log, try process.seconds(ctx, \"ZIGOS_MAPPING_XSTATE_SECONDS\", \"30\"));" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "const status = try process.timed(ctx, command.items, qemu_log, try process.seconds(ctx, \"ZIGOS_MAPPING_XSTATE_SECONDS\", \"30\"));", .replacement = "const status = try process.until(ctx, command.items, path, qemu_log, try process.seconds(ctx, \"ZIGOS_MAPPING_XSTATE_SECONDS\", \"30\"), .{ .line = mapping_xstate_proofs[7] });" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "try ctx.write(status_path, try fmt(ctx, \"{d}\\n\", .{status}));", .replacement = "try ctx.write(status_path, \"33\\n\");" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "const bytes = try readOptional(ctx, path);\n    validateMappingXstateResult", .replacement = "const bytes = mapping_xstate_namespace ++ \"PASS\\n\";\n    validateMappingXstateResult" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "const bytes = try readOptional(ctx, path);\n    validateMappingXstateResult", .replacement = "const bytes = try readOptional(ctx, qemu_log);\n    validateMappingXstateResult" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "validateMappingXstateResult(status, mode, bytes) catch |err|", .replacement = "validateMappingXstateResult(success_exit, mode, bytes) catch |err|" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "validateMappingXstateResult(status, mode, bytes) catch |err|", .replacement = "validateMappingXstateResult(status, .unsupported, bytes) catch |err|" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "validateMappingXstateResult(status, mode, bytes) catch |err|", .replacement = "validateMappingXstateResult(status, mode, mapping_xstate_proofs[7]) catch |err|" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "validateMappingXstateResult(status, mode, bytes) catch |err|", .replacement = "if (false) validateMappingXstateResult(status, mode, bytes) catch |err|" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "try ctx.warn(\"Mapping xstate {s} evidence validated", .replacement = "try ctx.print(\"Mapping xstate {s} evidence validated" },
    });
}

const TrapStackArchitectureSourceKind = enum { probe, window_assembly, entry_assembly, xstate_assembly, xstate_policy, build, harness };

fn validateUpperHalfEntryBuild(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8), code: []const u8, tokens: []const std.zig.Token) !void {
    if (!hasTopLevelCodeTokens(code, tokens, "const UpperHalfProbeKind = enum { entry, mapping_xstate };"))
        try common.addError(errors, allocator, "Upper-half proofs must retain separate entry and compacted-state image kinds", .{});
    const wrapper = topLevelFunctionBody(code, tokens, "addHighHalfEntryCheck") orelse &.{};
    if (!timerCodeMatches(code, wrapper, "const image = addUpperHalfProbeImage(b, optimize, .entry); " ++
        "const run = host_tools.addRun(b, \"run-high-half-smoke\"); " ++
        "run.addFileArg(image.iso); run.addArg(\"build/high-half-entry.log\"); " ++
        "const step = b.step(\"high-half-entry-check\", \"Boot isolated 16-CPU entry/SIPI, copied syscall broker, descriptor, SMAP, standard-xstate IPI and global-TLB proof in QEMU\"); " ++
        "step.dependOn(&run.step); return step;", .exact))
        try common.addError(errors, allocator, "The ordinary upper-half wrapper must run the actual entry image before its exact marker validator", .{});
    const helper = topLevelFunctionBody(code, tokens, "addUpperHalfProbeImage") orelse &.{};
    // Authenticate the unconditional module setup, not assembly names found in
    // a dead branch, quoted decoy, unrelated wrapper or the other image kind.
    if (!timerCodeMatches(code, helper, "const name = switch (kind) { .entry => \"high-half-entry\", .mapping_xstate => \"mapping-xstate\", }; " ++
        "const target = b.resolveTargetQuery(codegen_target.query()); " ++
        "const module = b.createModule(.{ " ++
        ".root_source_file = b.path(switch (kind) { .entry => \"src/high_half_entry.zig\", .mapping_xstate => \"src/mapping_xstate_entry.zig\", }), " ++
        ".target = target, .optimize = optimize, .strip = true, .red_zone = false, .code_model = .kernel, }); " ++
        "const options = b.addOptions(); " ++
        "options.addOption(shared.BootProfile, \"boot_profile\", .zigos_native); " ++
        "options.addOption(shared.KernelRole, \"kernel_role\", .production); " ++
        "options.addOption(shared.SmokeFaultMode, \"smoke_fault_mode\", .none); " ++
        "module.addOptions(\"build_options\", options); configureKernelModuleGraph(module); " ++
        "module.addAssemblyFile(b.path(\"src/boot/boot_x86_64.S\")); " ++
        "module.addAssemblyFile(b.path(\"src/arch/x86/invpcid.S\")); " ++
        "module.addAssemblyFile(b.path(\"src/arch/x86/xsaves.S\")); " ++
        "module.addAssemblyFile(b.path(\"src/arch/x86/user_access.S\")); " ++
        "module.addAssemblyFile(b.path(\"src/kernel/interrupts/gdt_flush64.S\")); " ++
        "module.addAssemblyFile(b.path(\"src/kernel/smp/ap_trampoline.S\")); " ++
        "module.addAssemblyFile(b.path(\"src/arch/x86_64/high_half_ipi_probe.S\")); " ++
        "module.addAssemblyFile(b.path(\"src/kernel/interrupts/interrupt64.S\")); " ++
        "module.addAssemblyFile(b.path(\"src/kernel/interrupts/fred64.S\")); " ++
        "module.addAssemblyFile(b.path(\"src/native/task/userspace_entry64.S\")); " ++
        "if (kind == .mapping_xstate) module.addAssemblyFile(b.path(\"src/arch/x86_64/mapping_xstate_probe.S\"));", .prefix))
        try common.addError(errors, allocator, "The shared upper-half builder must retain exact image routing and real unconditional entry/state/descriptor linkage", .{});
    try preparedDispatchOrdered(allocator, errors, code, helper, &.{
        "link.addFileArg(b.path(\"src/arch/x86_64/linker.ld\"));",
        "link.addFileArg(probe.getEmittedBin());",
        "const efi_stub = addEfiImage(b, optimize, linked_probe, b.path(\"src/boot/cmdline-qemu.txt\"));",
        "const validate_image = host_tools.addRun(b, \"check-efi-image\");",
        "validate_image.addFileArg(efi_stub.getEmittedBin());",
        "const iso = host_tools.addRun(b, \"build-efi-iso\");",
        "iso.addFileArg(efi_stub.getEmittedBin());",
        "iso.step.dependOn(&validate_image.step);",
        "return .{ .elf = linked_probe, .efi = efi_stub.getEmittedBin(), .iso = iso_path };",
    });
}

fn assemblySpan(source: []const u8, first: []const u8, last: []const u8) []const u8 {
    const start = std.mem.indexOf(u8, source, first) orelse return "";
    const end = std.mem.indexOf(u8, source[start..], last) orelse return "";
    return source[start .. start + end + last.len];
}

test "upper half build gates reject redirected wrappers conditional linkage and quoted decoys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source = try common.readFileAlloc(allocator, std.testing.io, "build_support/kernel.zig", common.source_file_max_bytes);
    for ([_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "const image = addUpperHalfProbeImage(b, optimize, .entry);", .replacement = "const image = addUpperHalfProbeImage(b, optimize, .mapping_xstate);" },
        .{ .needle = "const image = addUpperHalfProbeImage(b, optimize, .entry);", .replacement = "const image = otherUpperHalfProbeImage(b, optimize, .entry);" },
        .{ .needle = "const run = host_tools.addRun(b, \"run-high-half-smoke\");", .replacement = "const run = host_tools.addRun(b, \"run-mapping-xstate-smoke\");" },
        .{ .needle = ".entry => \"src/high_half_entry.zig\",", .replacement = ".entry => \"src/mapping_xstate_entry.zig\"," },
        .{ .needle = ".mapping_xstate => \"src/mapping_xstate_entry.zig\",", .replacement = ".mapping_xstate => \"src/high_half_entry.zig\"," },
        .{ .needle = "const name = switch (kind) {", .replacement = "return undefined; const name = switch (kind) {" },
        .{ .needle = "module.addAssemblyFile(b.path(\"src/kernel/interrupts/interrupt64.S\"));", .replacement = "if (false) module.addAssemblyFile(b.path(\"src/kernel/interrupts/interrupt64.S\"));" },
        .{ .needle = "module.addAssemblyFile(b.path(\"src/kernel/interrupts/fred64.S\"));", .replacement = "if (kind == .mapping_xstate) module.addAssemblyFile(b.path(\"src/kernel/interrupts/fred64.S\"));" },
        .{ .needle = "module.addAssemblyFile(b.path(\"src/arch/x86/xsaves.S\"));", .replacement = "// module.addAssemblyFile(b.path(\"src/arch/x86/xsaves.S\"));" },
        .{ .needle = "if (kind == .mapping_xstate)", .replacement = "if (false)" },
        .{ .needle = "const efi_stub = addEfiImage(b, optimize, linked_probe, b.path(\"src/boot/cmdline-qemu.txt\"));", .replacement = "const efi_stub = addEfiProofImage(b, optimize, linked_probe, b.path(\"src/boot/cmdline-qemu.txt\"));" },
    }) |mutation| {
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        const altered = try std.mem.replaceOwned(u8, allocator, source, mutation.needle, mutation.replacement);
        const comment = try std.mem.replaceOwned(u8, allocator, mutation.needle, "\n", "\n// ");
        const quoted = try std.json.Stringify.valueAlloc(allocator, mutation.needle, .{});
        const with_decoys = try std.fmt.allocPrint(allocator, "// {s}\nconst upper_half_build_quoted_decoy = {s};\n{s}", .{ comment, quoted, altered });
        var guarded_errors = std.ArrayList([]const u8).empty;
        try validateTrapStackArchitectureSource(allocator, &guarded_errors, with_decoys, .build);
        try std.testing.expect(guarded_errors.items.len != 0);
        var cold_errors = std.ArrayList([]const u8).empty;
        try validateEntryStackSource(allocator, &cold_errors, with_decoys, .build);
        try std.testing.expect(cold_errors.items.len != 0);
    }
}

fn validateTrapStackArchitectureSource(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8), source: []const u8, kind: TrapStackArchitectureSourceKind) !void {
    if (kind == .window_assembly) {
        const window = assemblySpan(source, ".macro PROOF_IPI_WAIT ", ".endm");
        if (!hasAssemblyLines(source, &.{"PROOF_IPI_WAIT zigos_arch_smp_poll_trap_stack, 1, 0, 1"}) or
            !hasAssemblyOrderedLines(window, &.{
                "movq %rsp, %rax",                     ".if \\trap_stack",                    "movq %rcx, %rsp",        "subq $64, %rsp",         ".endif",
                "subq $1024, %rsp",                    "andq $-64, %rsp",                     "movq %rax, 896(%rsp)",   "movq $16384, 936(%rsp)", "XSAVE_FULL_STATE %r13",
                "XRSTOR_FULL_STATE %r13",              "std",                                 "stac",                   "sti",                    "movl $1, zigos_arch_smp_trap_ipi_window(%rip)",
                "pause",                               "decq 936(%rsp)",                      "jnz .Lpoll_ipi\\@",      "cli",                    "movl $0, zigos_arch_smp_trap_ipi_window(%rip)",
                "CHECK_GP %rax, -0x1101, .Lbad_gp\\@", "CHECK_GP %r15, -0x110f, .Lbad_gp\\@", "pushfq",                 "popq %rax",              "cld",
                "clac",                                "XSAVE_FULL_STATE %r13",               "XRSTOR_FULL_STATE %r13", "movq 896(%rsp), %rsp",   "popq %r15",
                "popq %rbx",                           "ret",
            })) try common.addError(errors, allocator, "Guarded stack helper must switch RSP within its selected range, bound the live window and restore ordinary RSP/state before compiler code", .{});
        return;
    }
    if (kind == .entry_assembly) {
        const stub = assemblySpan(source, ".macro ISR_NOERRCODE num", ".endm");
        if (!hasAssemblyOrderedLines(stub, &.{ "isr\\num:", "endbr64", "pushq $0", "pushq $\\num", "jmp isr_common_stub" }) or
            !hasAssemblyLines(source, &.{"ISR_NOERRCODE 116"}))
            try common.addError(errors, allocator, "Trap stack proof requires the actual ISR116 stub and shared common-entry jump", .{});
        const common_entry = assemblySpan(source, "\nisr_common_stub:", "\n.userspace_resume:");
        if (!hasAssemblyOrderedLines(common_entry, &.{
            "clac",                                                                "SAVE_REGISTERS",                   "movq %rsp, %r12",                                                                           "cmpq $USER_CODE_SELECTOR, FRAME_CS(%r12)",
            "jne .isr_kernel_gs_ready",                                            "swapgs",                           ".isr_kernel_gs_ready:",                                                                     "ENTER_KERNEL_XSTATE FRAME_CS",
            "movq %r12, %rdi",                                                     "call isrHandler",                  "ZIGOS_IDT_VALIDATE_RETURN_PREFIX %r12, .invalid_interrupt_return, .validate_common_return", ".validate_common_return:",
            "ZIGOS_IDT_VALIDATE_RETURN_RIP_FLAGS %r12, .invalid_interrupt_return", ".restore_interrupted_xstate:",     "LEAVE_KERNEL_XSTATE FRAME_CS",                                                              ".interrupt_return:",
            "cmpq $USER_CODE_SELECTOR, FRAME_CS(%rsp)",                            "jne .interrupt_restore_registers", "swapgs",                                                                                    ".interrupt_restore_registers:",
            "RESTORE_REGISTERS",                                                   "addq $16, %rsp",                   "iretq",
        })) try common.addError(errors, allocator, "Trap stack evidence must retain the production kernel CS, state, admission and IRET path", .{});
        return;
    }
    if (kind == .xstate_assembly) {
        if (!hasAssemblyLines(source, &.{".equ XSTATE_MASK, 7"}))
            try common.addError(errors, allocator, "Guarded standard-state admission requires the exact shared x87/SSE/YMM assembly mask", .{});
        const enter = assemblySpan(source, ".macro ENTER_KERNEL_XSTATE frame_cs", ".endm");
        if (!hasAssemblyOrderedLines(enter, &.{
            "cli",                          "subq $XSTATE_STACK_BYTES, %rsp",               "andq $-64, %rsp",              "movq %rsp, %r13",
            "cmpq $0x23, \\frame_cs(%r12)", "jne .Lsave_kernel_xstate\\@",                  ".Lsave_kernel_xstate\\@:",     "movq %cr4, %rax",
            "testq $(1 << 18), %rax",       "jz .Lkernel_xstate_ready\\@",                  "xgetbv",                       "cmpl $XSTATE_MASK, %eax",
            "jne .Lkernel_xstate_ready\\@", "testl %edx, %edx",                             "jne .Lkernel_xstate_ready\\@", "movq $1, XSTATE_BYTES(%rsp)",
            "XSAVE_FULL_STATE %r13",        "leaq zigos_initial_kernel_xstate(%rip), %r13", "XRSTOR_FULL_STATE %r13",       ".Lkernel_xstate_ready\\@:",
            "cld",
        })) try common.addError(errors, allocator, "Actual kernel interrupt stack state must use admitted standard full images and initialized kernel controls", .{});
        const leave = assemblySpan(source, ".macro LEAVE_KERNEL_XSTATE frame_cs", ".endm");
        if (!hasAssemblyOrderedLines(leave, &.{
            "movq %rsp, %r13",                   "cmpq $0x23, \\frame_cs(%r12)",  "jne .Lrestore_saved_kernel_xstate\\@",
            ".Lrestore_saved_kernel_xstate\\@:", "cmpq $(0), XSTATE_BYTES(%rsp)", "je .Lleave_xstate_done\\@",
            "XRSTOR_FULL_STATE %r13",            ".Lleave_xstate_done\\@:",       "movq %r12, %rsp",
        })) try common.addError(errors, allocator, "Actual kernel interrupt return must restore the saved standard image before frame restoration", .{});
        return;
    }
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    var lexer = std.zig.Tokenizer.init(code);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "Trap stack proof gate requires valid actual Zig source", .{});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    switch (kind) {
        .xstate_policy => {
            if (!hasTopLevelCodeTokens(code, tokens.items, "pub const enabled_mask: u64 = 7;"))
                try common.addError(errors, allocator, "Guarded standard-state oracle must compare the exact x87/SSE/YMM mask", .{});
        },
        .build => {
            try validateUpperHalfEntryBuild(allocator, errors, code, tokens.items);
        },
        .harness => {
            const markers = topLevelContainerBody(code, tokens.items, "const high_half_proofs = [_][]const u8{") orelse &.{};
            if (!hasCodeTokens(code, markers, "\"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRANSPORT_IPI:PASS\", \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRAP_STACK:PASS\", \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_LOW_RETIRED:PASS\",") or
                preparedDispatchTokenCount(code, markers, "\"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRAP_STACK:PASS\"") != 1)
                try common.addError(errors, allocator, "The actual guarded production ISR stack proof must retain one ordered required marker", .{});
            try preparedDispatchOrdered(allocator, errors, code, topLevelFunctionBody(code, tokens.items, "highHalfSmoke") orelse &.{}, &.{ "try healthy(h.ctx, bytes, \"FAIL\");", "log.exactOrdered(bytes, &high_half_proofs)" });
        },
        .probe => {
            for ([_][:0]const u8{
                "const TRAP_STACK_DONE: u32 = 4;",                         "const TRAP_STACK_TOP_RESERVED: usize = 64;",
                "var trap_stack_phase: u32 = 0;",                          "var trap_stack_quiescent: [PROOF_CPU_COUNT]u8 = @splat(0);",
                "var trap_stack_checked: u32 = 0;",                        "var trap_stack_returned: u32 = 0;",
                "var trap_stack_released: u32 = 0;",                       "var trap_stack_completed: u32 = 0;",
                "var trap_stack_baseline_low: usize = 0;",                 "var trap_stack_interrupt_low: usize = 0;",
                "var trap_stack_key: dispatch_transport.Key = undefined;", "pub export var zigos_arch_smp_trap_ipi_window: u32 = 0;",
                "extern fn isr116() callconv(.c) void;",
            }) |pattern| if (!hasTopLevelCodeTokens(code, tokens.items, pattern)) {
                try common.addError(errors, allocator, "Guarded stack proof needs permanent independent receipts and actual production stub: {s}", .{pattern});
            };
            const proof = topLevelFunctionBody(code, tokens.items, "proveGuardedTrapStack") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, proof, &.{
                "cpu_identity.currentIndex() != 0 or x86.interruptsEnabled() or !paging.kernelAddressSpaceActive()",
                "@atomicStore(u8, &trap_stack_quiescent[0], 1, .release);",
                "for (trap_stack_quiescent[1..], 1..)",
                "@atomicLoad(u8, quiet, .acquire) != 1",
                "source.publishPreparedExecutionForArchitectureProof(&command, &trap_stack_key)",
                "verifyGuardedTrapAuthority(PREPARED_OWNER_CPU);",
                "verifyGuardedStackNeighbors();",
                "const saved_gate = idt.idt[smp.PREPARED_EXECUTION_IPI_VECTOR];",
                "idt.setGate(smp.PREPARED_EXECUTION_IPI_VECTOR, &isr116, gdt.KERNEL_CODE_SEG, 0x8e);",
                "verifyGuardedStackGate();",
                "asm volatile (\"mfence\" ::: .{ .memory = true });",
                "@atomicStore(u32, &trap_stack_phase, 1, .release);",
                "waitForTransportWord(&trap_stack_checked, 1);",
                "trap_stack_baseline_low == 0",
                "smp.notifyPreparedExecution(PREPARED_OWNER_CPU)",
                "@atomicStore(u32, &trap_stack_phase, 2, .release);",
                "waitForTransportWord(&trap_stack_checked, 2);",
                "trap_stack_interrupt_low < cpus[PREPARED_OWNER_CPU].trap_stack_top - native_executor.TRAP_STACK_USABLE_BYTES + PAGE_BYTES",
                "trap_stack_interrupt_low >= trap_stack_baseline_low",
                "trap_stack_baseline_low - trap_stack_interrupt_low < xstate.image_bytes",
                "verifyGuardedTrapAuthority(PREPARED_OWNER_CPU);",
                "verifyPreparedNeighbors();",
                "verifyGuardedStackNeighbors();",
                "verifyGuardedStackGate();",
                "idt.idt[smp.PREPARED_EXECUTION_IPI_VECTOR] = saved_gate;",
                "asm volatile (\"mfence\" ::: .{ .memory = true });",
                "@as(u128, @bitCast(idt.idt[smp.PREPARED_EXECUTION_IPI_VECTOR])) != @as(u128, @bitCast(saved_gate))",
                "@atomicStore(u32, &trap_stack_phase, 3, .release);",
                "waitForTransportWord(&trap_stack_returned, 1);",
                "runtime.execution.consumePreparedReturnInto(ticket, &returned)",
                "runtime.terminateTask(task_id, 922)",
                "rejectTransportCollection(runtime, scheduler, source, ticket, address_space_id, admitted);",
                "@atomicStore(u32, &trap_stack_released, 1, .release);",
                "waitForTransportWord(&trap_stack_completed, 1);",
                "dispatch_transport.global.completionInto(trap_stack_key, &completion)",
                "runtime.collectExecution(ticket)",
                "native_executor.collectRegisteredRetiredMappings(scheduler, runtime)",
                "paging.frameStats().allocated != admitted - 1",
                "scheduler.deinit();",
                "verifyPreparedNeighbors();",
                "verifyGuardedStackNeighbors();",
                "@atomicStore(u32, &trap_stack_phase, TRAP_STACK_DONE, .release);",
                "proof.pass(\"SMP_AP_TRAP_STACK\");",
            });
            try durableTransportRequired(allocator, errors, code, proof, &.{
                "runtime.execution.hasLeases() or preparedBorrowCount(runtime) != 0",
                "dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution)",
                "quiet_deadline.expired()",
                "snapshot.native_entry_modes != 0",
                "source.active_mapping != null",
                "task.state != .terminated or task.execution_component_count != 1",
                "completion != .owner_returned",
                "runtime.findAddressSpaceConst(address_space_id) != null",
                "err != error.StaleTicket",
            });
            const gate = topLevelFunctionBody(code, tokens.items, "verifyGuardedStackGate") orelse &.{};
            try durableTransportRequired(allocator, errors, code, gate, &.{
                "gate.offset_low",                                                                                                                          "gate.offset_middle", "gate.offset_high",
                "handler != @intFromPtr(&isr116) or gate.selector != gdt.KERNEL_CODE_SEG or gate.ist != 0 or gate.type_attr != 0x8e or gate.reserved != 0",
            });
            const authority = topLevelFunctionBody(code, tokens.items, "verifyGuardedTrapAuthority") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, authority, &.{
                "native_executor.preparedKernelStackForCpu(index) != top",                                                                                                                                     "paging.currentPagePermissions(top - native_executor.TRAP_STACK_TOTAL_BYTES) != null",
                "var page = top - native_executor.TRAP_STACK_USABLE_BYTES;",                                                                                                                                   "while (page < top) : (page += PAGE_BYTES)",
                "table.PML4_SHIFT, table.PDPT_SHIFT, table.PAGE_DIRECTORY_SHIFT",                                                                                                                              "entry & (table.PRESENT | table.WRITABLE | table.USER | table.WRITE_THROUGH | table.CACHE_DISABLE | table.LARGE_PAGE) != table.PRESENT | table.WRITABLE",
                "cache_policy.requireAdmittedWriteBack(physical, PAGE_BYTES)",                                                                                                                                 "paging.mappedRamSpan(physical, PAGE_BYTES)",
                "leaf & (table.PRESENT | table.WRITABLE | table.USER | table.WRITE_THROUGH | table.CACHE_DISABLE | table.LARGE_PAGE | table.NO_EXECUTE) != table.PRESENT | table.WRITABLE | table.NO_EXECUTE", "cache_policy.requireAdmittedWriteBack(physical, PAGE_BYTES)",
                "paging.mappedRamSpan(physical, PAGE_BYTES) == null",
            });
            const neighbors = topLevelFunctionBody(code, tokens.items, "verifyGuardedStackNeighbors") orelse &.{};
            try durableTransportRequired(allocator, errors, code, neighbors, &.{
                "for (&cpus, 0..)",                                                                                                                 "trapStackWord(top, last).* != trapStackCanary(@intCast(index), last, true)",
                "if (index == PREPARED_OWNER_CPU) top - TRAP_STACK_TOP_RESERVED else top - native_executor.TRAP_STACK_USABLE_BYTES + @sizeOf(u64)", "const word: *const volatile u32 = @ptrFromInt(cursor);",
                "if (word.* != TRAP_PAINT_WORD)",
            });
            const low = topLevelFunctionBody(code, tokens.items, "guardedStackLowWater") orelse &.{};
            try durableTransportRequired(allocator, errors, code, low, &.{
                "top - native_executor.TRAP_STACK_USABLE_BYTES + @sizeOf(u64)", "const usable_top = top - TRAP_STACK_TOP_RESERVED;",
                "while (cursor < usable_top) : (cursor += @sizeOf(u32))",       "const word: *const volatile u32 = @ptrFromInt(cursor);",
                "if (word.* != TRAP_PAINT_WORD) return cursor;",
            });
            const window = topLevelFunctionBody(code, tokens.items, "guardedStackWindow") orelse &.{};
            if (!timerCodeMatches(code, window, "const entry_cr4 = x86.readCr4(); if (cpu_identity.currentIndex() != index or x86.interruptsEnabled() or entry_cr4 & (x86.CR4_OSXSAVE | x86.CR4_FRED) != x86.CR4_OSXSAVE or x86.readXcr0() != xstate.enabled_mask or gsEntryModes() != 0) reject(index);", .prefix))
                try common.addError(errors, allocator, "Guarded window must admit current CR4.OSXSAVE and exact XCR0 before any standard-state instruction", .{});
            try preparedDispatchOrdered(allocator, errors, code, window, &.{
                "model.initialize(&cpu.seed, index % 3);",                                                       "model.initializeCanary(&cpu.restored);",
                "zigos_arch_smp_poll_trap_stack(&cpu.seed, &cpu.restored, &restored_flags, cpu.trap_stack_top)", "const observed = native_entry.current().*;",
                "gp_match != 1 or restored_flags & (FLAG_DF | FLAG_AC) != FLAG_DF | FLAG_AC",                    "!verifyRestoredState(&cpu.seed, &cpu.restored) or x86.interruptsEnabled() or interrupt_context.active()",
                "x86.readCr4() != entry_cr4 or x86.readXcr0() != xstate.enabled_mask",                           "!paging.kernelAddressSpaceActive() or x86.readCr3() & x86.CR3_ADDRESS_MASK != physical_cr3",
                "!std.mem.eql(u8, std.mem.asBytes(&observed), std.mem.asBytes(saved_entry))",
            });
            const after = topLevelFunctionBody(code, tokens.items, "guardedStackAfterReturn") orelse &.{};
            if (!timerCodeMatches(code, after, "trap_stack_owner_ran = ran; @atomicStore(u32, &trap_stack_returned, 1, .release); waitForTransportWord(&trap_stack_released, 1);", .exact))
                try common.addError(errors, allocator, "Guarded stack post-ACK hook may access only permanent proof words and captured return scalar", .{});
            const hold = topLevelFunctionBody(code, tokens.items, "holdGuardedTrapStack") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, hold, &.{
                "x86.interruptsEnabled() or cpu_identity.currentIndex() != index or !paging.kernelAddressSpaceActive()",
                "@atomicStore(u8, &trap_stack_quiescent[index], 1, .release);",
                "if (index != PREPARED_OWNER_CPU)",
                "waitForTransportWord(&trap_stack_phase, TRAP_STACK_DONE);",
                "assigned_top != cpus[index].trap_stack_top or saved_entry.native_entry_modes != 0",
                "waitForTransportWord(&trap_stack_phase, 1);",
                "verifyGuardedStackGate();",
                "verifyGuardedTrapAuthority(index);",
                "dispatch_transport.global.takePrompt(index)",
                "guardedStackWindow(index, &saved_entry);",
                "trap_stack_baseline_low = guardedStackLowWater();",
                "rejectPromptedEmpty(index, &saved_entry);",
                "@atomicStore(u32, &trap_stack_checked, 1, .release);",
                "waitForTransportWord(&trap_stack_phase, 2);",
                "guardedStackWindow(index, &saved_entry);",
                "trap_stack_interrupt_low = guardedStackLowWater();",
                "trap_stack_baseline_low - trap_stack_interrupt_low < xstate.image_bytes",
                "@atomicStore(u32, &trap_stack_checked, 2, .release);",
                "waitForTransportWord(&trap_stack_phase, 3);",
                "native_entry.initializeCpu(index, assigned_top)",
                "native_executor.runPromptedPreparedExecutionForArchitectureProof( preparedOwnerCallback, &prepared_owner_expectation, &saved_entry, null, guardedStackAfterReturn, &trap_stack_returned, )",
                "@atomicStore(u32, &trap_stack_completed, 1, .release);",
            });
            const tail = preparedDispatchTailAfter(code, hold, "if (!native_executor.runPromptedPreparedExecutionForArchitectureProof( preparedOwnerCallback, &prepared_owner_expectation, &saved_entry, null, guardedStackAfterReturn, &trap_stack_returned, )) reject(index);") orelse &.{};
            if (!timerCodeMatches(code, tail, "@atomicStore(u32, &trap_stack_completed, 1, .release); waitForTransportWord(&trap_stack_phase, TRAP_STACK_DONE);", .exact))
                try common.addError(errors, allocator, "Guarded stack owner suffix must end all borrowed domain access at ACK", .{});
            for ([_][]const std.zig.Token{ proof, hold, window }) |body| {
                if (hasCodeTokens(code, body, "notePrompt") or hasCodeTokens(code, body, "idt.setIstGate"))
                    try common.addError(errors, allocator, "Trap proof cannot synthesize its acquired prompt or claim an IST stack transition", .{});
            }
        },
        .window_assembly => unreachable,
        .entry_assembly, .xstate_assembly => unreachable,
    }
}

test "guarded trap stack source gate accepts actual shared kernel ISR and ignores decoys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { path: []const u8, kind: TrapStackArchitectureSourceKind }{
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .window_assembly },
        .{ .path = "src/kernel/interrupts/interrupt64.S", .kind = .entry_assembly },
        .{ .path = "src/arch/xstate64.inc", .kind = .xstate_assembly },
        .{ .path = "src/arch/xstate.zig", .kind = .xstate_policy },
        .{ .path = "build_support/kernel.zig", .kind = .build },
        .{ .path = "tools/host/qemu.zig", .kind = .harness },
    }) |item| {
        const source = try common.readFileAlloc(allocator, std.testing.io, item.path, common.source_file_max_bytes);
        const annotated = try std.fmt.allocPrint(allocator, "{s}\n// call isrHandler; XRSTOR_FULL_STATE; actual gate and lifetime stay scoped\n", .{source});
        var errors = std.ArrayList([]const u8).empty;
        try validateTrapStackArchitectureSource(allocator, &errors, annotated, item.kind);
        for (errors.items) |message| std.debug.print("{s}: {s}\n", .{ item.path, message });
        try std.testing.expectEqual(@as(usize, 0), errors.items.len);
    }
}

test "guarded trap stack source gate rejects false stack evidence early restore and post ACK reads" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "entry_cr4 & (x86.CR4_OSXSAVE | x86.CR4_FRED) != x86.CR4_OSXSAVE", .replacement = "false" },
        .{ .needle = "x86.readXcr0() != xstate.enabled_mask", .replacement = "x86.readXcr0() != 3" },
        .{ .needle = "x86.readXcr0() != xstate.enabled_mask", .replacement = "x86.readXcr0() & xstate.enabled_mask != xstate.enabled_mask" },
        .{ .needle = "x86.readCr4() != entry_cr4 or x86.readXcr0() != xstate.enabled_mask or", .replacement = "x86.readXcr0() != xstate.enabled_mask or" },
        .{ .needle = "x86.readCr4() != entry_cr4 or x86.readXcr0() != xstate.enabled_mask or", .replacement = "x86.readCr4() != entry_cr4 or" },
        .{ .needle = "var trap_stack_quiescent: [PROOF_CPU_COUNT]u8 = @splat(0);", .replacement = "var trap_stack_quiescent: [PROOF_CPU_COUNT]u8 = @splat(1);" },
        .{ .needle = "@atomicLoad(u8, quiet, .acquire) != 1", .replacement = "@atomicLoad(u8, quiet, .monotonic) != 1" },
        .{ .needle = "@atomicStore(u8, &trap_stack_quiescent[index], 1, .release);", .replacement = "@atomicStore(u8, &trap_stack_quiescent[index], 1, .monotonic);" },
        .{ .needle = "const saved_gate = idt.idt[smp.PREPARED_EXECUTION_IPI_VECTOR];", .replacement = "const saved_gate = idt.IdtEntry{};" },
        .{ .needle = "idt.setGate(smp.PREPARED_EXECUTION_IPI_VECTOR, &isr116, gdt.KERNEL_CODE_SEG, 0x8e);", .replacement = "idt.setGate(smp.PREPARED_EXECUTION_IPI_VECTOR, &zigos_arch_smp_prepared_execution_ipi, gdt.KERNEL_CODE_SEG, 0x8e);" },
        .{ .needle = "waitForTransportWord(&trap_stack_checked, 2);", .replacement = "// AP return quiescence omitted" },
        .{ .needle = "idt.idt[smp.PREPARED_EXECUTION_IPI_VECTOR] = saved_gate;", .replacement = "idt.idt[smp.PREPARED_EXECUTION_IPI_VECTOR].offset_low = saved_gate.offset_low;" },
        .{ .needle = "@as(u128, @bitCast(idt.idt[smp.PREPARED_EXECUTION_IPI_VECTOR])) != @as(u128, @bitCast(saved_gate))", .replacement = "false" },
        .{ .needle = "handler != @intFromPtr(&isr116)", .replacement = "handler != @intFromPtr(&zigos_arch_smp_prepared_execution_ipi)" },
        .{ .needle = "gate.ist != 0", .replacement = "gate.ist != 1" },
        .{ .needle = "gate.type_attr != 0x8e or gate.reserved != 0", .replacement = "false" },
        .{ .needle = "paging.currentPagePermissions(top - native_executor.TRAP_STACK_TOTAL_BYTES) != null", .replacement = "false" },
        .{ .needle = "table.PRESENT | table.WRITABLE | table.USER | table.WRITE_THROUGH | table.CACHE_DISABLE | table.LARGE_PAGE)", .replacement = "table.PRESENT | table.WRITABLE | table.USER | table.LARGE_PAGE)" },
        .{ .needle = "table.CACHE_DISABLE | table.LARGE_PAGE | table.NO_EXECUTE)", .replacement = "table.CACHE_DISABLE | table.LARGE_PAGE)" },
        .{ .needle = "cache_policy.requireAdmittedWriteBack(physical, PAGE_BYTES) catch proof.fail(\"SMP guarded stack leaf cache authority\");", .replacement = "// leaf cache admission omitted" },
        .{ .needle = "if (paging.mappedRamSpan(physical, PAGE_BYTES) == null) proof.fail(\"SMP guarded stack backing RAM authority\");", .replacement = "// backing authority omitted" },
        .{ .needle = "if (word.* != TRAP_PAINT_WORD) proof.fail(\"SMP guarded stack complete neighbor paint\");", .replacement = "// neighbor paint observation omitted" },
        .{ .needle = "if (word.* != TRAP_PAINT_WORD) return cursor;", .replacement = "return usable_top - 1024;" },
        .{ .needle = "trap_stack_baseline_low = guardedStackLowWater();", .replacement = "trap_stack_baseline_low = cpus[index].trap_stack_top - 1024;" },
        .{ .needle = "trap_stack_interrupt_low = guardedStackLowWater();", .replacement = "trap_stack_interrupt_low = trap_stack_baseline_low - xstate.image_bytes;" },
        .{ .needle = "trap_stack_interrupt_low < cpus[PREPARED_OWNER_CPU].trap_stack_top - native_executor.TRAP_STACK_USABLE_BYTES + PAGE_BYTES", .replacement = "false" },
        .{ .needle = "trap_stack_baseline_low - trap_stack_interrupt_low < xstate.image_bytes", .replacement = "false" },
        .{ .needle = "zigos_arch_smp_poll_trap_stack(&cpu.seed, &cpu.restored, &restored_flags, cpu.trap_stack_top)", .replacement = "zigos_arch_smp_poll_prepared_ipi(&cpu.seed, &cpu.restored, &restored_flags)" },
        .{ .needle = "gp_match != 1 or restored_flags & (FLAG_DF | FLAG_AC) != FLAG_DF | FLAG_AC", .replacement = "false" },
        .{ .needle = "!verifyRestoredState(&cpu.seed, &cpu.restored) or x86.interruptsEnabled() or interrupt_context.active()", .replacement = "false" },
        .{ .needle = "waitForTransportWord(&trap_stack_phase, 3);", .replacement = "// complete gate restoration release omitted" },
        .{ .needle = "    _ = dispatch_transport.global.takePrompt(index) catch reject(index);", .replacement = "    dispatch_transport.global.notePrompt() catch reject(index);" },
        .{ .needle = "trap_stack_owner_ran = ran;", .replacement = "trap_stack_owner_ran = ran; _ = source.materializedCount();" },
        .{ .needle = "waitForTransportWord(&trap_stack_released, 1);", .replacement = "// post-ACK static resource hold omitted" },
        .{ .needle = "@atomicStore(u32, &trap_stack_completed, 1, .release);", .replacement = "_ = command.ticket.issuer; @atomicStore(u32, &trap_stack_completed, 1, .release);" },
        .{ .needle = "waitForTransportWord(&trap_stack_completed, 1);", .replacement = "// durable completion wait omitted" },
        .{ .needle = "proof.pass(\"SMP_AP_TRAP_STACK\");", .replacement = "proof.pass(\"SMP_AP_TRAP_STACK_DISABLED\");" },
    }) |mutation| {
        const source = try common.readFileAlloc(allocator, std.testing.io, "src/arch/x86_64/high_half_smp_probe.zig", common.source_file_max_bytes);
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        const altered = try std.mem.replaceOwned(u8, allocator, source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateTrapStackArchitectureSource(allocator, &errors, altered, .probe);
        if (errors.items.len == 0) std.debug.print("Trap stack gate accepted hostile mutation: {s}\n", .{mutation.needle});
        try std.testing.expect(errors.items.len != 0);
    }
}

test "guarded trap stack source gate rejects replaced entry state and build linkage" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { path: []const u8, kind: TrapStackArchitectureSourceKind, needle: []const u8, replacement: []const u8 }{
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .window_assembly, .needle = "PROOF_IPI_WAIT zigos_arch_smp_poll_trap_stack, 1, 0, 1", .replacement = "PROOF_IPI_WAIT zigos_arch_smp_poll_trap_stack, 1, 0, 0" },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .window_assembly, .needle = "    movq %rcx, %rsp", .replacement = "    // selected stack switch omitted" },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .window_assembly, .needle = "    subq $64, %rsp", .replacement = "    subq $0, %rsp" },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .window_assembly, .needle = "    movq %rax, 896(%rsp)", .replacement = "    // ordinary stack lifetime omitted" },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .window_assembly, .needle = "    movq $16384, 936(%rsp)", .replacement = "    movq $0, 936(%rsp)" },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .window_assembly, .needle = "    sti", .replacement = "    cli" },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .window_assembly, .needle = "    movl $1, zigos_arch_smp_trap_ipi_window(%rip)", .replacement = "    // post-STI witness omitted" },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .window_assembly, .needle = "    decq 936(%rsp)", .replacement = "    // finite loop bound omitted" },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .window_assembly, .needle = "    movl $0, zigos_arch_smp_trap_ipi_window(%rip)", .replacement = "    // masked window exit omitted" },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .window_assembly, .needle = "    movq 896(%rsp), %rsp", .replacement = "    movq %rax, %rsp" },
        .{ .path = "src/kernel/interrupts/interrupt64.S", .kind = .entry_assembly, .needle = "ISR_NOERRCODE 116", .replacement = "// ISR_NOERRCODE 116" },
        .{ .path = "src/kernel/interrupts/interrupt64.S", .kind = .entry_assembly, .needle = "    jmp isr_common_stub", .replacement = "    jmp zigos_arch_smp_prepared_execution_ipi" },
        .{ .path = "src/kernel/interrupts/interrupt64.S", .kind = .entry_assembly, .needle = "    call isrHandler", .replacement = "    call zigos_arch_smp_handle_prepared_execution_ipi" },
        .{ .path = "src/kernel/interrupts/interrupt64.S", .kind = .entry_assembly, .needle = "    ENTER_KERNEL_XSTATE FRAME_CS", .replacement = "    // ENTER_KERNEL_XSTATE FRAME_CS" },
        .{ .path = "src/kernel/interrupts/interrupt64.S", .kind = .entry_assembly, .needle = "    ZIGOS_IDT_VALIDATE_RETURN_RIP_FLAGS %r12, .invalid_interrupt_return", .replacement = "    // ZIGOS_IDT_VALIDATE_RETURN_RIP_FLAGS %r12, .invalid_interrupt_return" },
        .{ .path = "src/kernel/interrupts/interrupt64.S", .kind = .entry_assembly, .needle = "    LEAVE_KERNEL_XSTATE FRAME_CS", .replacement = "    // LEAVE_KERNEL_XSTATE FRAME_CS" },
        .{ .path = "src/kernel/interrupts/interrupt64.S", .kind = .entry_assembly, .needle = "    iretq", .replacement = "    ret" },
        .{ .path = "src/arch/xstate.zig", .kind = .xstate_policy, .needle = "pub const enabled_mask: u64 = 7;", .replacement = "pub const enabled_mask: u64 = 3;" },
        .{ .path = "src/arch/xstate64.inc", .kind = .xstate_assembly, .needle = ".equ XSTATE_MASK, 7", .replacement = ".equ XSTATE_MASK, 3" },
        .{ .path = "src/arch/xstate64.inc", .kind = .xstate_assembly, .needle = "    XSAVE_FULL_STATE %r13", .replacement = "    XSAVE_STATE %r13" },
        .{ .path = "src/arch/xstate64.inc", .kind = .xstate_assembly, .needle = "    leaq zigos_initial_kernel_xstate(%rip), %r13", .replacement = "    leaq foreign_xstate(%rip), %r13" },
        .{ .path = "src/arch/xstate64.inc", .kind = .xstate_assembly, .needle = "    XRSTOR_FULL_STATE %r13", .replacement = "    XRSTOR_STATE %r13" },
        .{ .path = "src/arch/xstate64.inc", .kind = .xstate_assembly, .needle = "    movq %r12, %rsp", .replacement = "    movq %r13, %rsp" },
        .{ .path = "build_support/kernel.zig", .kind = .build, .needle = "    module.addAssemblyFile(b.path(\"src/kernel/interrupts/interrupt64.S\"));", .replacement = "    // actual entry object omitted" },
        .{ .path = "build_support/kernel.zig", .kind = .build, .needle = "    module.addAssemblyFile(b.path(\"src/native/task/userspace_entry64.S\"));", .replacement = "    // real initial kernel state omitted" },
        .{ .path = "build_support/kernel.zig", .kind = .build, .needle = "    module.addAssemblyFile(b.path(\"src/arch/x86/xsaves.S\"));", .replacement = "    // real XCR0 reader object omitted" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "    \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRAP_STACK:PASS\",", .replacement = "    // guarded stack marker omitted" },
    }) |item| {
        const source = try common.readFileAlloc(allocator, std.testing.io, item.path, common.source_file_max_bytes);
        try std.testing.expect(std.mem.indexOf(u8, source, item.needle) != null);
        const altered = try std.mem.replaceOwned(u8, allocator, source, item.needle, item.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateTrapStackArchitectureSource(allocator, &errors, altered, item.kind);
        try std.testing.expect(errors.items.len != 0);
    }
}

const DurableTransportSourceKind = enum { core, coordinator, runtime, session, executor, probe, prompt_probe, smp, isr, entry_assembly, prompt_assembly, harness };

fn durableTransportRequired(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8), code: []const u8, body: []const std.zig.Token, patterns: []const [:0]const u8) !void {
    for (patterns) |pattern| if (!hasCodeTokens(code, body, pattern)) {
        try common.addError(errors, allocator, "Durable dispatch transport must retain scoped step: {s}", .{pattern});
    };
}

fn validateDurableTransportSource(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8), source: []const u8, kind: DurableTransportSourceKind) !void {
    if (kind == .prompt_assembly) {
        const macro_start = std.mem.indexOf(u8, source, ".macro PROOF_IPI_WAIT ") orelse source.len;
        const macro_end = std.mem.indexOf(u8, source[macro_start..], ".endm") orelse 0;
        const wait_macro = source[macro_start .. macro_start + macro_end];
        if (!hasAssemblyOrderedLines(wait_macro, &.{ "sti", "movl $1, zigos_arch_smp_prepared_ipi_window(%rip)", "pause", "cli", "movl $0, zigos_arch_smp_prepared_ipi_window(%rip)" }))
            try common.addError(errors, allocator, "Prompt guest window witness must follow STI and clear only after bounded wait and CLI", .{});
        for ([_][]const u8{
            "PROOF_IPI_ENTRY zigos_arch_smp_prepared_execution_ipi, zigos_arch_smp_handle_prepared_execution_ipi",
            "PROOF_IPI_WAIT zigos_arch_smp_poll_prepared_ipi, 1, 1",
            "sti",
            "movl $1, zigos_arch_smp_prepared_ipi_window(%rip)",
            "pause",
            "decq 936(%rsp)",
            "cli",
            "movl $0, zigos_arch_smp_prepared_ipi_window(%rip)",
        }) |line| if (!hasAssemblyLines(source, &.{line})) {
            try common.addError(errors, allocator, "Prepared prompt guest must retain its real fixed IPI and finite interrupt window: {s}", .{line});
        };
        return;
    }
    if (kind == .entry_assembly) {
        if (!hasAssemblyLines(source, &.{"ISR_NOERRCODE 116"}))
            try common.addError(errors, allocator, "Prepared execution prompt needs the real shared vector 0x74 ISR stub", .{});
        return;
    }
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    var lexer = std.zig.Tokenizer.init(code);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "Durable dispatch transport must remain valid Zig source", .{});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    switch (kind) {
        .core => {
            for ([_][:0]const u8{
                "pub const Command = struct { ticket: ownership.Ticket, trap_stack_top: usize };",
                "pub const Key = struct { pool: *const Pool, cpu: u8, sequence: u64 };",
                "pub const ClaimedCommand = struct { key: Key, command: Command };",
                "const Phase = enum(u3) { idle, publishing, pending, claimed, completed, collecting };",
                "const MAX_SEQUENCE = std.math.maxInt(u64) >> SEQUENCE_SHIFT;",
                "pub var global: Pool = .{};",
            }) |pattern| if (!hasTopLevelCodeTokens(code, tokens.items, pattern)) {
                try common.addError(errors, allocator, "Durable transport must retain fixed command and static channel geometry: {s}", .{pattern});
            };
            const geometry = topLevelContainerBody(code, tokens.items, "comptime {") orelse &.{};
            try durableTransportRequired(allocator, errors, code, geometry, &.{
                "if (@sizeOf(Command) != 32 or @sizeOf(Key) != 24 or @sizeOf(ClaimedCommand) != 56)",
                "if (@alignOf(Channel) != 64 or @sizeOf(Channel) != 64 or @sizeOf(Pool) != CAPACITY * 64 or @alignOf(Pool) != 64)",
            });
            const channel = topLevelContainerBody(code, tokens.items, "const Channel = struct {") orelse &.{};
            try durableTransportRequired(allocator, errors, code, channel, &.{ "control: u64 align(64) = 0,", "ticket: ownership.Ticket = undefined,", "trap_stack_top: usize = 0,", "prompt: u8 = 0,", "padding: [23]u8 = @splat(0)," });
            const pool = topLevelContainerBody(code, tokens.items, "pub const Pool = struct {") orelse &.{};
            try durableTransportRequired(allocator, errors, code, pool, &.{"channels: [CAPACITY]Channel = @splat(.{}),"});
            if (topLevelFunctionBody(code, pool, "reset") != null or hasCodeTokens(code, pool, "self.* =") or hasCodeTokens(code, pool, "@memset") or hasCodeTokens(code, tokens.items, "global ="))
                try common.addError(errors, allocator, "Durable transport sequence cursors cannot be reset during pool lifetime", .{});
            if (!timerCodeMatches(code, topLevelFunctionBody(code, pool, "notePrompt") orelse &.{}, "const cpu = cpu_identity.currentIndex(); if (cpu >= CAPACITY) return error.InvalidCpu; try requireInterruptsMasked(); @atomicStore(u8, &self.channels[cpu].prompt, 1, .release);", .exact))
                try common.addError(errors, allocator, "Interrupt prompt recording must touch only the bounded current CPU hint after native IF admission", .{});
            if (!timerCodeMatches(code, topLevelFunctionBody(code, pool, "takePrompt") orelse &.{}, "try requireOwner(cpu); return @atomicRmw(u8, &self.channels[cpu].prompt, .Xchg, 0, .acquire) != 0;", .exact))
                try common.addError(errors, allocator, "Only the selected masked owner may acquire and consume its coalesced hint", .{});
            for ([_][]const u8{ "publishInto", "claimInto", "claimKeyInto", "withdraw", "complete", "beginCollectionInto", "endCollection", "hasOutstandingForIssuer" }) |name| {
                const operation = topLevelFunctionBody(code, pool, name) orelse &.{};
                if (hasCodeTokens(code, operation, ".prompt"))
                    try common.addError(errors, allocator, "Transport authority and collection must neither clear nor depend on prompt state: {s}", .{name});
            }
            const publish = topLevelFunctionBody(code, pool, "publishInto") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, publish, &.{
                "try requireBsp();",
                "try command.ticket.issuer.preparedReady(command.ticket);",
                "const previous = @atomicLoad(u64, &channel.control, .acquire); if (phaseOf(previous) != .idle) return error.Busy;",
                "if (old_sequence == MAX_SEQUENCE) return error.SequenceExhausted; const sequence = old_sequence + 1;",
                "if (@cmpxchgStrong(u64, &channel.control, previous, publishing, .acq_rel, .acquire) != null) return error.Busy;",
                "channel.ticket = command.ticket; channel.trap_stack_top = command.trap_stack_top;",
                "@atomicStore(u64, &channel.control, pack(sequence, .pending, .owner_returned), .release);",
                "out.* = .{ .pool = self, .cpu = command.ticket.cpu, .sequence = sequence };",
            });
            const claim = topLevelFunctionBody(code, pool, "claimKeyInto") orelse &.{};
            if (!timerCodeMatches(code, claim, "try requireOwner(key.cpu); try self.checkKey(key); const channel = &self.channels[key.cpu]; const control = @atomicLoad(u64, &channel.control, .acquire); try requireKey(control, key); if (phaseOf(control) != .pending) return error.NoCommand; if (@cmpxchgStrong(u64, &channel.control, control, withPhase(control, .claimed), .acq_rel, .acquire) != null) return error.NoCommand; out.* = .{ .key = key, .command = .{ .ticket = channel.ticket, .trap_stack_top = channel.trap_stack_top } };", .exact))
                try common.addError(errors, allocator, "Durable owner claim must acquire and win the pending CAS before copying the immutable shell", .{});
            const withdraw = topLevelFunctionBody(code, pool, "withdraw") orelse &.{};
            if (!timerCodeMatches(code, withdraw, "try requireBsp(); try self.checkKey(key); const channel = &self.channels[key.cpu]; const control = @atomicLoad(u64, &channel.control, .acquire); try requireKey(control, key); if (phaseOf(control) != .pending) return error.WrongPhase; if (@cmpxchgStrong(u64, &channel.control, control, pack(key.sequence, .completed, .unstarted), .release, .acquire) != null) return error.WrongPhase;", .exact))
                try common.addError(errors, allocator, "Durable withdrawal must race owner claim on the same pending control and retain unstarted completion", .{});
            const complete = topLevelFunctionBody(code, pool, "complete") orelse &.{};
            if (!timerCodeMatches(code, complete, "try requireOwner(key.cpu); try self.checkKey(key); const channel = &self.channels[key.cpu]; const control = @atomicLoad(u64, &channel.control, .acquire); try requireKey(control, key); if (phaseOf(control) != .claimed) return error.WrongPhase; if (@cmpxchgStrong(u64, &channel.control, control, pack(key.sequence, .completed, completion), .release, .acquire) != null) return error.WrongPhase;", .exact))
                try common.addError(errors, allocator, "Durable post-ACK completion may access only captured key scalars and independent static control", .{});
            if (topLevelFunctionBody(code, pool, "beginCollection") != null)
                try common.addError(errors, allocator, "Transport collection has one caller-owned success-output boundary", .{});
            const begin = topLevelFunctionBody(code, pool, "beginCollectionInto") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, begin, &.{
                "try requireBsp();",
                "if (ticket.cpu >= CAPACITY) return error.InvalidCpu; const channel = &self.channels[ticket.cpu];",
                "const control = @atomicLoad(u64, &channel.control, .acquire);",
                "if (phase == .idle) return false; if (phase == .publishing) return error.Busy;",
                "if (!sameTicket(channel.ticket, ticket)) return false; if (phase != .completed) return error.Busy;",
                "if (@cmpxchgStrong(u64, &channel.control, control, withPhase(control, .collecting), .acq_rel, .acquire) != null) return error.Busy;",
                "out.* = .{ .pool = self, .cpu = ticket.cpu, .sequence = sequenceOf(control) }; return true;",
            });
            const end = topLevelFunctionBody(code, pool, "endCollection") orelse &.{};
            try durableTransportRequired(allocator, errors, code, end, &.{ "try requireBsp(); try self.checkKey(key);", "try requireKey(control, key); if (phaseOf(control) != .collecting) return error.WrongPhase;", "const replacement = if (finished) pack(key.sequence, .idle, .owner_returned) else withPhase(control, .completed);", "@cmpxchgStrong(u64, &channel.control, control, replacement, .release, .acquire)" });
            for ([_]struct { name: []const u8, pattern: [:0]const u8 }{
                .{ .name = "abortCollection", .pattern = "try self.endCollection(key, false);" },
                .{ .name = "finishCollection", .pattern = "try self.endCollection(key, true);" },
                .{ .name = "checkKey", .pattern = "if (key.pool != self) return error.WrongCoordinator; if (key.cpu >= CAPACITY) return error.InvalidCpu; if (key.sequence == 0 or key.sequence > MAX_SEQUENCE) return error.StaleKey;" },
                .{ .name = "hasOutstandingForIssuer", .pattern = "if (cpu_identity.currentIndex() != 0) return true;" },
            }) |entry| try durableTransportRequired(allocator, errors, code, topLevelFunctionBody(code, pool, entry.name) orelse &.{}, &.{entry.pattern});
            const outstanding = topLevelFunctionBody(code, pool, "hasOutstandingForIssuer") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, outstanding, &.{ "const phase = phaseOf(@atomicLoad(u64, &channel.control, .acquire));", "if (phase == .idle) continue;", "if (phase == .publishing or channel.ticket.issuer == issuer) return true;" });
            for ([_]struct { name: []const u8, expected: [:0]const u8 }{
                .{ .name = "sameTicket", .expected = "return a.issuer == b.issuer and a.cpu == b.cpu and a.epoch == b.epoch;" },
                .{ .name = "requireKey", .expected = "if (phaseOf(control) == .idle or sequenceOf(control) != key.sequence) return error.StaleKey;" },
                .{ .name = "requireOwner", .expected = "if (cpu >= CAPACITY) return error.InvalidCpu; if (cpu_identity.currentIndex() != cpu) return error.WrongCpu; try requireInterruptsMasked();" },
                .{ .name = "requireBsp", .expected = "if (cpu_identity.currentIndex() != 0) return error.WrongCpu; try requireInterruptsMasked();" },
            }) |entry| if (!timerCodeMatches(code, topLevelFunctionBody(code, tokens.items, entry.name) orelse &.{}, entry.expected, .exact)) {
                try common.addError(errors, allocator, "Durable transport must retain exact ticket key and owner admission: {s}", .{entry.name});
            };
            try durableTransportRequired(allocator, errors, code, topLevelFunctionBody(code, tokens.items, "requireInterruptsMasked") orelse &.{}, &.{"if (@import(\"../../arch/x86.zig\").interruptsEnabled()) return error.InterruptsEnabled;"});
        },
        .coordinator => {
            const coordinator = topLevelContainerBody(code, tokens.items, "pub const Coordinator = struct {") orelse &.{};
            const ready = topLevelFunctionBody(code, coordinator, "preparedReady") orelse &.{};
            if (!timerCodeMatches(code, ready, "try requireBsp(); try self.checkTicket(ticket); const slot = &self.slots[ticket.cpu]; const control = @atomicLoad(u64, &slot.control, .acquire); try requireTicket(control, ticket); if (control & PREPARED == 0) return error.WrongPurpose; if (phaseOf(control) != .ready) return error.WrongPhase; if (control & STOP != 0) return error.StopRequested; try requireSyscallIdle(slot);", .exact))
                try common.addError(errors, allocator, "Queued publication requires the exact nonstopped ready prepared lease and idle syscall mailbox", .{});
            const slot = topLevelContainerBody(code, tokens.items, "const Slot = struct {") orelse &.{};
            try durableTransportRequired(allocator, errors, code, slot, &.{"padding: [56]u8 = @splat(0),"});
            if (!hasCodeTokens(code, tokens.items, "@sizeOf(Slot) != 192") or !hasCodeTokens(code, tokens.items, "@sizeOf(Coordinator) != 3080"))
                try common.addError(errors, allocator, "Queued transport must preserve 136 active bytes and 192/3080 Coordinator geometry", .{});
        },
        .runtime => {
            const runtime = topLevelContainerBody(code, tokens.items, "pub const Runtime = struct {") orelse &.{};
            const collect = topLevelFunctionBody(code, runtime, "collectExecution") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, collect, &.{
                "if (cpu_identity.currentIndex() != 0) return error.WrongCpu;",
                "if (comptime builtin.target.os.tag == .freestanding) x86.cli();",
                "try self.execution.identityInto(ticket, &identity);",
                "const borrow = self.execution_borrows[ticket.cpu] orelse return error.StaleTicket;",
                "var channel: dispatch_transport.Key = undefined; const channel_held = try dispatch_transport.global.beginCollectionInto(ticket, &channel);",
                "errdefer if (channel_held) dispatch_transport.global.abortCollection(channel)",
                "try self.execution.beginCollectInto(ticket, &identity);",
                "if (task.state == .terminated) self.finalizeTerminatedTask(task, self.execution_retirement_ticks[ticket.cpu]);",
                "self.execution_borrows[ticket.cpu].?.release(); self.execution_borrows[ticket.cpu] = null;",
                "self.execution.finishCollect(ticket)",
                "if (channel_held) dispatch_transport.global.finishCollection(channel)",
            });
            try durableTransportRequired(allocator, errors, code, collect, &.{ "identity.task_handle != borrow.handle.value or identity.task_id != borrow.task_id", "identity.process_generation != task.process_generation or identity.address_space_id != task.address_space_id", "if (restore_interrupts) x86.sti();" });
            const quiet = topLevelFunctionBody(code, runtime, "requireExecutionQuiescent") orelse &.{};
            try durableTransportRequired(allocator, errors, code, quiet, &.{ "if (cpu_identity.currentIndex() != 0) return error.WrongCpu;", "self.hasTaskBorrows() or self.lifecycle_transition_active or self.execution.hasLeases() or dispatch_transport.global.hasOutstandingForIssuer(&self.execution)" });
            for ([_][]const u8{ "restoreFromSnapshot", "rebuildIndexes" }) |name| {
                if (!timerCodeMatches(code, topLevelFunctionBody(code, runtime, name) orelse &.{}, "self.requireExecutionQuiescent() catch return error.TaskRuntimeBorrowed;", .prefix))
                    try common.addError(errors, allocator, "Runtime {s} must reject retained transport before mutation", .{name});
            }
            for ([_][]const u8{ "unbindAddressSpaceRetirementSink", "unbindTaskRetirementSink", "unbindExecutionStopSink" }) |name| {
                const unbind = topLevelFunctionBody(code, runtime, name) orelse &.{};
                try preparedDispatchOrdered(allocator, errors, code, unbind, &.{ "dispatch_transport.global.hasOutstandingForIssuer(&self.execution)", "if (!current.eql(expected)) return false;" });
            }
            const reset = topLevelFunctionBody(code, runtime, "reset") orelse &.{};
            if (!timerCodeMatches(code, reset, "self.requireExecutionQuiescent() catch", .prefix))
                try common.addError(errors, allocator, "Runtime reset must reject a queued owner before any resource or backing mutation", .{});
            if (hasCodeTokens(code, runtime, "dispatch_transport.global ="))
                try common.addError(errors, allocator, "Runtime lifecycle cannot reset the image-static transport", .{});
        },
        .session => {
            const session = topLevelContainerBody(code, tokens.items, "pub const SessionManager = struct {") orelse &.{};
            const preflight = topLevelFunctionBody(code, session, "requireResetExecutionQuiescent") orelse &.{};
            if (!timerCodeMatches(code, preflight, "if (self.runtime_context.taskRuntime()) |runtime| try runtime.requireExecutionQuiescent();", .exact))
                try common.addError(errors, allocator, "Session reset preflight must inspect existing Runtime without constructing or allocating state", .{});
            const reset = topLevelFunctionBody(code, session, "reset") orelse &.{};
            if (!timerCodeMatches(code, reset, "self.requireResetExecutionQuiescent() catch", .prefix))
                try common.addError(errors, allocator, "Session reset must reject pending transport before touching owned services", .{});
        },
        .executor => {
            const executor = topLevelContainerBody(code, tokens.items, "pub const Executor = struct {") orelse &.{};
            if (!timerCodeMatches(code, topLevelFunctionBody(code, tokens.items, "executionOwnershipOutstanding") orelse &.{}, "return runtime.execution.hasLeases() or dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution);", .exact))
                try common.addError(errors, allocator, "Executor teardown must retain the issuer and every source until independent static completion is collected", .{});
            for ([_][]const u8{ "claimRuntimeBinding", "claimMappingRegistration", "releaseMappingRegistration", "bindMappedObjectLifetime", "unbindMappedObjectLifetime", "releaseRuntimeBinding", "resetChecked" }) |name| {
                try durableTransportRequired(allocator, errors, code, topLevelFunctionBody(code, executor, name) orelse &.{}, &.{"executionOwnershipOutstanding(runtime)"});
            }
            for ([_][]const u8{ "claimCurrentExecutor", "releaseCurrentExecutor", "releaseRegisteredDomain" }) |name| {
                try durableTransportRequired(allocator, errors, code, topLevelFunctionBody(code, tokens.items, name) orelse &.{}, &.{"executionOwnershipOutstanding(runtime)"});
            }
            const publish = topLevelFunctionBody(code, executor, "publishPreparedCommandInto") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, publish, &.{
                "if (!bspMappingTransaction() or !freestanding.paging.kernelAddressSpaceActive() or !self.initialized or",
                "const runtime = self.bound_runtime orelse return false; const owner = self.binding_owner orelse return false; const ticket = command.ticket;",
                "if (ticket.issuer != &runtime.execution or self.registration_cpu != ticket.cpu or registeredDomainExecutor(ticket.cpu, owner, runtime) != self or preparedKernelStackForCpu(ticket.cpu) != command.trap_stack_top) return false;",
                "runtime.execution.preparedReady(ticket) catch return false;",
                "runtime.execution.identityInto(ticket, &identity) catch return false;",
                "const mapping = self.findMapping(identity.address_space_id) orelse return false;",
                "dispatch_transport.global.publishInto(command.*, out) catch return false; return true;",
            });
            try durableTransportRequired(allocator, errors, code, publish, &.{ "self.active_task_id != 0 or self.active_mapping != null or self.active_dispatch_lease != null", "mapping.dispatch_metadata.owner_task_id != identity.task_id or mapping.owned_xstate == null or mappingPhysicalRoot(mapping) == 0" });
            const prepare = topLevelFunctionBody(code, executor, "prepareQueuedTaskInto") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, prepare, &.{ "if (!smp.isRuntimeOwner()) return false;", "x86.cli();", "self.prepareTaskDispatchInto(", "return self.publishPreparedCommandInto(&command, out);" });
            const native = topLevelContainerBody(code, tokens.items, "const NativePreparedDispatch = struct {") orelse &.{};
            if (!timerCodeMatches(code, topLevelFunctionBody(code, native, "ownerAvailable") orelse &.{}, "return smp.isRuntimeOwner() and continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();", .exact))
                try common.addError(errors, allocator, "Queued transport cannot enable production AP native user admission", .{});
            if (!hasTopLevelCodeTokens(code, tokens.items, "fn runQueuedPreparedTaskSlice(comptime require_prompt: bool,"))
                try common.addError(errors, allocator, "Production and isolated polled paths must select prompt admission explicitly at compile time", .{});
            const run = topLevelFunctionBody(code, tokens.items, "runQueuedPreparedTaskSlice") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, run, &.{
                "const restore_interrupts = backend.mask(); defer backend.restore(restore_interrupts);",
                "if (require_prompt) { if (interrupt_context.active()) return false; if (!(dispatch_transport.global.takePrompt(cpu_identity.currentIndex()) catch return false)) return false; }",
                "dispatch_transport.global.claimInto(cpu_identity.currentIndex(), &claimed) catch return false; const key = claimed.key;",
                "const source = currentRegisteredExecutor();",
                "const ran = if (source) |executor| executor.runPreparedTaskSlice(&claimed.command, backend) else false;",
                "dispatch_transport.global.complete(key, if (ran) .owner_returned else .unstarted)",
            });
            const tail = preparedDispatchTailAfter(code, run, "const ran = if (source) |executor| executor.runPreparedTaskSlice(&claimed.command, backend) else false;") orelse &.{};
            for (tail) |token| if (token.tag == .identifier) {
                const identifier = code[token.loc.start..token.loc.end];
                for ([_][]const u8{ "source", "executor", "claimed", "command", "issuer", "ticket", "coordinator", "runtime", "mapping" }) |forbidden| {
                    if (std.mem.eql(u8, identifier, forbidden)) try common.addError(errors, allocator, "Queued owner cannot access borrowed backing after execution ACK: {s}", .{identifier});
                }
            };
            if (preparedDispatchTokenCount(code, run, "runPreparedTaskSlice(") != 1 or preparedDispatchTokenCount(code, run, "dispatch_transport.global.complete(") != 1)
                try common.addError(errors, allocator, "Queued owner must reuse one real lifecycle and publish exactly one independent completion", .{});
            for ([_]struct { container: []const std.zig.Token, name: []const u8, guard: [:0]const u8 }{
                .{ .container = executor, .name = "publishPreparedExecutionForArchitectureProof", .guard = "if (comptime !architecture_smp_proof) @compileError(\"queued execution fixtures require an isolated proof root\");" },
                .{ .container = tokens.items, .name = "runQueuedPreparedExecutionForArchitectureProof", .guard = "if (comptime !architecture_smp_proof) @compileError(\"queued owner fixtures require an isolated proof root\");" },
                .{ .container = tokens.items, .name = "runPromptedPreparedExecutionForArchitectureProof", .guard = "if (comptime !architecture_smp_proof) @compileError(\"prompted owner fixtures require an isolated proof root\");" },
            }) |entry| try preparedDispatchOrdered(allocator, errors, code, topLevelFunctionBody(code, entry.container, entry.name) orelse &.{}, &.{ "if (comptime builtin.target.os.tag != .freestanding) return false;", entry.guard });
            for ([_]struct { name: []const u8, call: [:0]const u8 }{
                .{ .name = "runQueuedPreparedExecutionForArchitectureProof", .call = "return runQueuedPreparedTaskSlice(false, ArchitecturePreparedBackend{" },
                .{ .name = "runPromptedPreparedExecutionForArchitectureProof", .call = "return runQueuedPreparedTaskSlice(true, ArchitecturePreparedBackend{" },
            }) |wrapper| {
                const body = topLevelFunctionBody(code, tokens.items, wrapper.name) orelse &.{};
                try durableTransportRequired(allocator, errors, code, body, &.{wrapper.call});
                if (preparedDispatchTokenCount(code, body, "runQueuedPreparedTaskSlice(") != 1)
                    try common.addError(errors, allocator, "Each isolated queued wrapper must reuse the actual owner lifecycle once", .{});
            }
            if (!timerCodeMatches(code, topLevelFunctionBody(code, tokens.items, "runQueuedPreparedTask") orelse &.{}, "if (comptime builtin.target.os.tag != .freestanding) return false; return runQueuedPreparedTaskSlice(true, NativePreparedDispatch{}, null, null, null, null);", .exact))
                try common.addError(errors, allocator, "Production queued entry must use only the guarded native backend with no proof callback", .{});
        },
        .probe => {
            for ([_][:0]const u8{
                "var transport_phase: u32 = 0;",                                              "var transport_claimed: u32 = 0;",
                "var transport_returned: u32 = 0;",                                           "var transport_released: u32 = 0;",
                "var transport_completed: u32 = 0;",                                          "var transport_owner_phase: u32 = 0;",
                "var transport_key: dispatch_transport.Key = undefined;",                     "var transport_stale_key: dispatch_transport.Key = undefined;",
                "var transport_claim_canary: dispatch_transport.ClaimedCommand = undefined;",
            }) |pattern| if (!hasTopLevelCodeTokens(code, tokens.items, pattern)) {
                try common.addError(errors, allocator, "Queued guest requires image-static command keys and independent completion storage: {s}", .{pattern});
            };
            const publish = topLevelFunctionBody(code, tokens.items, "publishTransportEpoch") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, publish, &.{
                "const ticket = runtime.reserveExecution(task, PREPARED_OWNER_CPU)",
                "source.bindPreparedExecutionForArchitectureProof(task, handle, ticket, command)",
                "source.publishPreparedExecutionForArchitectureProof(command, &transport_key)",
                "return ticket;",
            });
            const proof = topLevelFunctionBody(code, tokens.items, "provePreparedTransport") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, proof, &.{
                "const first = publishTransportEpoch(",
                "waitForTransportWord(&transport_returned, 1);",
                "runtime.execution.consumePreparedReturnInto(first, &returned)",
                "rejectTransportCollection(runtime, scheduler, source, first, address_space_id, admitted);",
                "@atomicStore(u32, &transport_released, 1, .release);",
                "verifyTransportCompletion(1, .owner_returned);",
                "runtime.collectExecution(first)",
                "dispatch_transport.global.withdraw(withdrawn_key)",
                "runtime.cancelUnstartedExecution(withdrawn)",
                "runtime.requestExecutionStop(stopped)",
                "verifyTransportCompletion(2, .unstarted);",
                "waitForTransportWord(&transport_claimed, 3);",
                "runtime.cancelUnstartedExecution(canceled)",
                "rejectTransportCollection(runtime, scheduler, source, canceled, address_space_id, admitted);",
                "verifyTransportCompletion(3, .unstarted);",
                "const faulted = publishTransportEpoch(",
                "runtime.terminateTask(task_id, 910)",
                "runtime.execution.consumePreparedReturnInto(faulted, &returned)",
                "rejectTransportCollection(runtime, scheduler, source, faulted, address_space_id, admitted);",
                "verifyTransportCompletion(4, .owner_returned);",
                "runtime.collectExecution(faulted)",
                "native_executor.collectRegisteredRetiredMappings(scheduler, runtime)",
                "const replacement_ticket = runtime.reserveExecution(replacement, PREPARED_OWNER_CPU)",
                "waitForTransportWord(&transport_completed, 5);",
                "runtime.cancelUnstartedExecution(replacement_ticket)",
                "runtime.collectExecution(replacement_ticket)",
                "scheduler.deinit();",
                "proof.pass(\"SMP_AP_TRANSPORT\");",
            });
            try durableTransportRequired(allocator, errors, code, proof, &.{
                "snapshot.native_entry_modes != 0",                                      "completion != .unstarted",
                "err != error.StaleKey or completion != .owner_returned",                "task.state != .terminated or task.execution_component_count != 1",
                "paging.frameStats().allocated != admitted - 1",                         "err != error.StaleTicket or paging.frameStats().allocated != admitted - 1",
                "dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution)",
            });
            const reject_collection = topLevelFunctionBody(code, tokens.items, "rejectTransportCollection") orelse &.{};
            try durableTransportRequired(allocator, errors, code, reject_collection, &.{
                "runtime.collectExecution(ticket)",                            "err != error.Busy",
                "native_executor.releaseRegisteredDomain(scheduler, runtime)", "preparedBorrowCount(runtime) != 1",
                "source.materializedCount() != 1",                             "runtime.findAddressSpaceConst(address_space_id) == null",
                "paging.frameStats().allocated != admitted",
            });
            const complete = topLevelFunctionBody(code, tokens.items, "verifyTransportCompletion") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, complete, &.{
                "waitForTransportWord(&transport_completed, phase);",
                "dispatch_transport.global.completionInto(transport_key, &completion)",
                "if (completion != expected)",
                "verifyPreparedNeighbors();",
            });
            const after = topLevelFunctionBody(code, tokens.items, "transportAfterReturn") orelse &.{};
            if (!timerCodeMatches(code, after, "if (context != @as(*anyopaque, @ptrCast(&transport_owner_phase))) proof.fail(\"SMP transport return hook context\"); const phase = transport_owner_phase; transport_owner_ran = ran; @atomicStore(u32, &transport_returned, phase, .release); if (phase == 1 or phase == 4) waitForTransportWord(&transport_released, phase);", .exact))
                try common.addError(errors, allocator, "Post-ACK proof hook must access only permanent phase words and captured scalar state", .{});
            const hold = topLevelFunctionBody(code, tokens.items, "holdPreparedTransport") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, hold, &.{
                "if (index != PREPARED_OWNER_CPU) return;",                              "const saved_entry = native_entry.current().*;",
                "saved_entry.native_entry_modes != 0 or x86.interruptsEnabled()",        "waitForTransportWord(&transport_phase, @intCast(phase));",
                "dispatch_transport.global.claimKeyInto(transport_stale_key, &claimed)", "err != error.StaleKey",
                "!std.meta.eql(claimed, transport_claim_canary)",                        "native_executor.runQueuedPreparedExecutionForArchitectureProof( preparedOwnerCallback, &prepared_owner_expectation, &saved_entry, transportBeforeRun, transportAfterReturn, &transport_owner_phase, )",
                "@atomicStore(u32, &transport_completed, @intCast(phase), .release);",
            });
            const tail = preparedDispatchTailAfter(code, hold, "if (!native_executor.runQueuedPreparedExecutionForArchitectureProof( preparedOwnerCallback, &prepared_owner_expectation, &saved_entry, transportBeforeRun, transportAfterReturn, &transport_owner_phase, )) reject(index);") orelse &.{};
            if (!timerCodeMatches(code, tail, "} @atomicStore(u32, &transport_completed, @intCast(phase), .release); } waitForTransportWord(&transport_phase, PREPARED_TRANSPORT_DONE);", .exact))
                try common.addError(errors, allocator, "Queued guest owner cannot read domain, issuer or command backing after its real runner returns", .{});
        },
        .prompt_probe => {
            for ([_][:0]const u8{
                "var prompted_phase: u32 = 0;",                                "var prompted_checked: u32 = 0;",
                "var prompted_returned: u32 = 0;",                             "var prompted_released: u32 = 0;",
                "var prompted_completed: u32 = 0;",                            "var prompted_owner_phase: u32 = 0;",
                "var prompted_ipi_count: u32 = 0;",                            "var prompted_key: dispatch_transport.Key = undefined;",
                "pub export var zigos_arch_smp_prepared_ipi_window: u32 = 0;",
            }) |pattern| if (!hasTopLevelCodeTokens(code, tokens.items, pattern)) {
                try common.addError(errors, allocator, "Prompted guest requires permanent independent phase and post-IRET evidence: {s}", .{pattern});
            };
            const proof = topLevelFunctionBody(code, tokens.items, "provePromptedPreparedTransport") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, proof, &.{
                "const first = publishPromptedEpoch(",                                                                 "waitForTransportWord(&prompted_checked, 1);",
                "@atomicLoad(u32, &prompted_ipi_count, .acquire) != 0",                                                "smp.notifyPreparedExecution(PREPARED_OWNER_CPU)",
                "waitForTransportWord(&prompted_returned, 2);",                                                        "verifyPromptedReturn(runtime, source, first, admitted, 1);",
                "runtime.execution.consumePreparedReturnInto(first, &returned)",                                       "rejectTransportCollection(runtime, scheduler, source, first, address_space_id, admitted);",
                "verifyPromptedCompletion(2);",                                                                        "runtime.collectExecution(first)",
                "smp.notifyPreparedExecution(PREPARED_OWNER_CPU) or !smp.notifyPreparedExecution(PREPARED_OWNER_CPU)", "waitForTransportWord(&prompted_completed, 3);",
                "const second = publishPromptedEpoch(",                                                                "waitForTransportWord(&zigos_arch_smp_prepared_ipi_window, 1);",
                "smp.notifyPreparedExecution(PREPARED_OWNER_CPU)",                                                     "waitForTransportWord(&prompted_returned, 4);",
                "verifyPromptedReturn(runtime, source, second, admitted, 2);",                                         "runtime.terminateTask(task_id, 920)",
                "runtime.execution.consumePreparedReturnInto(second, &returned)",                                      "rejectTransportCollection(runtime, scheduler, source, second, address_space_id, admitted);",
                "verifyPromptedCompletion(4);",                                                                        "runtime.collectExecution(second)",
                "native_executor.collectRegisteredRetiredMappings(scheduler, runtime)",                                "const replacement_ticket = runtime.reserveExecution(replacement, PREPARED_OWNER_CPU)",
                "smp.notifyPreparedExecution(PREPARED_OWNER_CPU)",                                                     "waitForTransportWord(&prompted_completed, 5);",
                "runtime.cancelUnstartedExecution(replacement_ticket)",                                                "runtime.collectExecution(replacement_ticket)",
                "scheduler.deinit();",                                                                                 "proof.pass(\"SMP_AP_TRANSPORT_IPI\");",
            });
            try durableTransportRequired(allocator, errors, code, proof, &.{
                "snapshot.native_entry_modes != 0",                                           "err != error.WrongPhase or completion != .unstarted",
                "second.epoch <= first.epoch or prompted_key.sequence <= first_key.sequence", "err != error.StaleKey or completion != .owner_returned",
                "task.state != .terminated or task.execution_component_count != 1",           "paging.frameStats().allocated != admitted - 1",
                "deliveries < 4 or deliveries > 5",
            });
            const handler = topLevelFunctionBody(code, tokens.items, "zigos_arch_smp_handle_prepared_execution_ipi") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, handler, &.{
                "isr.acknowledgePreparedExecutionInterrupt();",            "const index = cpu_identity.currentIndex();",
                "@atomicRmw(u32, &prompted_ipi_count, .Add, 1, .release)",
            });
            try durableTransportRequired(allocator, errors, code, handler, &.{
                "index != PREPARED_OWNER_CPU or !brokerInterruptEnvironment() or gsEntryModes() != 0",
                "@atomicLoad(u32, &zigos_arch_smp_prepared_ipi_window, .acquire) != 1",
            });
            const wait = topLevelFunctionBody(code, tokens.items, "waitForPreparedPrompt") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, wait, &.{
                "const deadline = tsc_clock.afterMilliseconds(2000);",
                "zigos_arch_smp_poll_prepared_ipi(&cpu.seed, &cpu.restored, &restored_flags)",
                "!verifyRestoredState(&cpu.seed, &cpu.restored) or x86.interruptsEnabled()",
                "const delivered = @atomicLoad(u32, &prompted_ipi_count, .acquire);",
                "if (delivered > previous) return delivered;",
                "deadline.expired()",
            });
            try durableTransportRequired(allocator, errors, code, wait, &.{
                "restored_flags & (FLAG_DF | FLAG_AC) != FLAG_DF | FLAG_AC",
                "x86.readCr3() & x86.CR3_ADDRESS_MASK != physical_cr3",
                "!std.mem.eql(u8, std.mem.asBytes(&observed), std.mem.asBytes(saved_entry))",
            });
            const after = topLevelFunctionBody(code, tokens.items, "promptedAfterReturn") orelse &.{};
            if (!timerCodeMatches(code, after, "if (context != @as(*anyopaque, @ptrCast(&prompted_owner_phase))) proof.fail(\"SMP prompted hook context\"); const phase = prompted_owner_phase; prompted_owner_ran = ran; @atomicStore(u32, &prompted_returned, phase, .release); waitForTransportWord(&prompted_released, phase);", .exact))
                try common.addError(errors, allocator, "Prompted post-ACK hook may access only permanent phase words and captured scalars", .{});
            const empty = topLevelFunctionBody(code, tokens.items, "rejectPromptedEmpty") orelse &.{};
            if (!timerCodeMatches(code, empty, "if (native_executor.runPromptedPreparedExecutionForArchitectureProof( preparedOwnerCallback, &prepared_owner_expectation, saved_entry, null, null, &prompted_owner_phase, )) reject(index); const observed = native_entry.current().*; if (!std.mem.eql(u8, std.mem.asBytes(&observed), std.mem.asBytes(saved_entry)) or !paging.kernelAddressSpaceActive() or x86.interruptsEnabled()) reject(index);", .exact))
                try common.addError(errors, allocator, "No-hint and empty-channel denials must invoke the real prompted body and preserve dormant GS/kernel state", .{});
            const hold = topLevelFunctionBody(code, tokens.items, "holdPromptedPreparedTransport") orelse &.{};
            try preparedDispatchOrdered(allocator, errors, code, hold, &.{
                "if (index != PREPARED_OWNER_CPU) return;",                           "saved_entry.native_entry_modes != 0 or x86.interruptsEnabled()",
                "waitForTransportWord(&prompted_phase, 1);",                          "rejectPromptedEmpty(index, &saved_entry); rejectPromptedEmpty(index, &saved_entry);",
                "waitForPreparedPrompt(index, delivered, &saved_entry)",              "native_executor.runPromptedPreparedExecutionForArchitectureProof( preparedOwnerCallback, &prepared_owner_expectation, &saved_entry, null, promptedAfterReturn, &prompted_owner_phase, )",
                "@atomicStore(u32, &prompted_completed, @intCast(phase), .release);",
            });
            const tail = preparedDispatchTailAfter(code, hold, "if (!native_executor.runPromptedPreparedExecutionForArchitectureProof( preparedOwnerCallback, &prepared_owner_expectation, &saved_entry, null, promptedAfterReturn, &prompted_owner_phase, )) reject(index);") orelse &.{};
            if (!timerCodeMatches(code, tail, "} else { rejectPromptedEmpty(index, &saved_entry); rejectPromptedEmpty(index, &saved_entry); } @atomicStore(u32, &prompted_completed, @intCast(phase), .release); } waitForTransportWord(&prompted_phase, PREPARED_IPI_DONE);", .exact))
                try common.addError(errors, allocator, "Prompted owner suffix cannot read retired domain or command backing after ACK", .{});
        },
        .smp => {
            if (!hasTopLevelCodeTokens(code, tokens.items, "pub const PREPARED_EXECUTION_IPI_VECTOR: u8 = 0x74;"))
                try common.addError(errors, allocator, "Prepared dispatch prompt uses one dedicated fixed interrupt vector", .{});
            if (!timerCodeMatches(code, topLevelFunctionBody(code, tokens.items, "notifyPreparedExecution") orelse &.{}, "if (!initialized or !isRuntimeOwner() or cpu >= MAX_CPUS or cpu >= cpu_count or cpu == currentCpuIndex()) return false; if (!@atomicLoad(bool, &cpus[cpu].online, .acquire)) return false; x2apic.sendIpi(.{ .destination = cpus[cpu].apic_id, .vector = PREPARED_EXECUTION_IPI_VECTOR, .delivery = .fixed }); return true;", .exact))
                try common.addError(errors, allocator, "Only BSP prompts a real online remote CPU without claiming or acknowledging execution", .{});
        },
        .isr => {
            if (!timerCodeMatches(code, topLevelFunctionBody(code, tokens.items, "acknowledgePreparedExecutionInterrupt") orelse &.{}, "x2apic.acknowledge(); dispatch_transport.global.notePrompt() catch return;", .exact))
                try common.addError(errors, allocator, "The immutable prompt ISR must EOI once before recording only its guarded local hint", .{});
            if (!timerCodeMatches(code, topLevelFunctionBody(code, tokens.items, "preparedExecutionInterrupt") orelse &.{}, "acknowledgePreparedExecutionInterrupt();", .exact))
                try common.addError(errors, allocator, "Prompt interrupt dispatch cannot claim or execute work", .{});
            try preparedDispatchOrdered(allocator, errors, code, topLevelFunctionBody(code, tokens.items, "handlerForVector") orelse &.{}, &.{
                "if (vector == smp.PREPARED_EXECUTION_IPI_VECTOR) return preparedExecutionInterrupt;",
                "if (vector < exception_handlers.len) return exception_handlers[vector];",
                "const index = externalHandlerIndex(vector)",
            });
            try durableTransportRequired(allocator, errors, code, topLevelFunctionBody(code, tokens.items, "init") orelse &.{}, &.{"setKernelGate(smp.PREPARED_EXECUTION_IPI_VECTOR, &isr116);"});
            const mutable_vectors = topLevelContainerBody(code, tokens.items, "const external_handler_vectors = [_]u8{") orelse &.{};
            if (hasCodeTokens(code, mutable_vectors, "smp.PREPARED_EXECUTION_IPI_VECTOR") or hasCodeTokens(code, mutable_vectors, "0x74"))
                try common.addError(errors, allocator, "Prepared interrupt handler cannot become a mutable registration slot", .{});
        },
        .entry_assembly, .prompt_assembly => unreachable,
        .harness => {
            const markers = topLevelContainerBody(code, tokens.items, "const high_half_proofs = [_][]const u8{") orelse &.{};
            if (!hasCodeTokens(code, markers, "\"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_PREPARED:PASS\", \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRANSPORT:PASS\", \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRANSPORT_IPI:PASS\", \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRAP_STACK:PASS\", \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_LOW_RETIRED:PASS\",") or preparedDispatchTokenCount(code, markers, "\"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRANSPORT:PASS\"") != 1)
                try common.addError(errors, allocator, "Durable transport proof must retain its one ordered required guest marker", .{});
            if (preparedDispatchTokenCount(code, markers, "\"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRANSPORT_IPI:PASS\"") != 1)
                try common.addError(errors, allocator, "Prompted transport proof requires exactly one ordered marker", .{});
            try preparedDispatchOrdered(allocator, errors, code, topLevelFunctionBody(code, tokens.items, "highHalfSmoke") orelse &.{}, &.{ "try healthy(h.ctx, bytes, \"FAIL\");", "log.exactOrdered(bytes, &high_half_proofs)" });
        },
    }
}

test "durable transport source gate accepts actual lifetime boundary and ignores quoted decoys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { path: []const u8, kind: DurableTransportSourceKind }{
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core },
        .{ .path = "src/kernel/smp.zig", .kind = .smp },
        .{ .path = "src/kernel/interrupts/isr.zig", .kind = .isr },
        .{ .path = "src/kernel/interrupts/interrupt64.S", .kind = .entry_assembly },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .prompt_assembly },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .prompt_probe },
        .{ .path = "src/native/task/dispatch_ownership.zig", .kind = .coordinator },
        .{ .path = "src/native/task/task_runtime.zig", .kind = .runtime },
        .{ .path = "src/native/session/session_manager_boot_flow.zig", .kind = .session },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe },
        .{ .path = "tools/host/qemu.zig", .kind = .harness },
    }) |item| {
        const source = try common.readFileAlloc(allocator, std.testing.io, item.path, common.source_file_max_bytes);
        const annotated = try std.fmt.allocPrint(allocator, "{s}\n// self.* = .{{}}; dispatch_transport.global = .{{}}; source.materializedCount();\nconst quoted_transport = \"self.* = reset; source.materializedCount();\";\n", .{source});
        var errors = std.ArrayList([]const u8).empty;
        try validateDurableTransportSource(allocator, &errors, annotated, item.kind);
        for (errors.items) |message| std.debug.print("{s}: {s}\n", .{ item.path, message });
        try std.testing.expectEqual(@as(usize, 0), errors.items.len);
    }
}

test "durable transport source gate rejects replay early collection and missing static completion" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { path: []const u8, kind: DurableTransportSourceKind, needle: []const u8, replacement: []const u8 }{
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "padding: [23]u8 = @splat(0),", .replacement = "padding: [16]u8 = @splat(0)," },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "prompt: u8 = 0,", .replacement = "prompt: u16 = 0," },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "if (interrupt_context.active()) return false;", .replacement = "// after-IRET guard removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .prompt_probe, .needle = "proof.pass(\"SMP_AP_TRANSPORT_IPI\");", .replacement = "proof.pass(\"SMP_AP_TRANSPORT_IPI_DISABLED\");" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .prompt_probe, .needle = "waitForTransportWord(&zigos_arch_smp_prepared_ipi_window, 1);", .replacement = "// after-STI window witness removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .prompt_probe, .needle = "isr.acknowledgePreparedExecutionInterrupt();", .replacement = "dispatch_transport.global.notePrompt() catch return;" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .prompt_probe, .needle = "const delivered = @atomicLoad(u32, &prompted_ipi_count, .acquire);", .replacement = "const delivered = previous + 1;" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .prompt_probe, .needle = "verifyPromptedCompletion(2);", .replacement = "// static completion observation removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .prompt_probe, .needle = "rejectTransportCollection(runtime, scheduler, source, first, address_space_id, admitted);", .replacement = "// early collection denial removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .prompt_probe, .needle = "waitForTransportWord(&prompted_released, phase);", .replacement = "// after-ACK resource hold removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .prompt_probe, .needle = "const observed = native_entry.current().*;\n    if (!std.mem.eql(u8, std.mem.asBytes(&observed), std.mem.asBytes(saved_entry)) or", .replacement = "const observed = native_entry.current().*;\n    if (false or" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .prompt_probe, .needle = "prompted_owner_ran = ran;", .replacement = "prompted_owner_ran = ran;\n_ = command.ticket.issuer;" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .prompt_probe, .needle = "@atomicStore(u32, &prompted_completed, @intCast(phase), .release);", .replacement = "_ = source.materializedCount();\n@atomicStore(u32, &prompted_completed, @intCast(phase), .release);" },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .prompt_assembly, .needle = "PROOF_IPI_WAIT zigos_arch_smp_poll_prepared_ipi, 1, 1", .replacement = "PROOF_IPI_WAIT zigos_arch_smp_poll_prepared_ipi, 1, 0" },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .prompt_assembly, .needle = "PROOF_IPI_ENTRY zigos_arch_smp_prepared_execution_ipi, zigos_arch_smp_handle_prepared_execution_ipi", .replacement = "// PROOF_IPI_ENTRY zigos_arch_smp_prepared_execution_ipi, zigos_arch_smp_handle_prepared_execution_ipi" },
        .{ .path = "src/arch/x86_64/high_half_ipi_probe.S", .kind = .prompt_assembly, .needle = "    sti\n.if \\trap_stack", .replacement = "    cli\n.if \\trap_stack" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "try requireInterruptsMasked();\n        @atomicStore(u8, &self.channels[cpu].prompt, 1, .release);", .replacement = "@atomicStore(u8, &self.channels[cpu].prompt, 1, .release);" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "@atomicStore(u8, &self.channels[cpu].prompt, 1, .release);", .replacement = "@atomicStore(u8, &self.channels[0].prompt, 1, .release);" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "@atomicRmw(u8, &self.channels[cpu].prompt, .Xchg, 0, .acquire)", .replacement = "@atomicRmw(u8, &self.channels[cpu].prompt, .Xchg, 0, .monotonic)" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "const old_sequence = sequenceOf(previous);", .replacement = "self.channels[command.ticket.cpu].prompt = 0;\n        const old_sequence = sequenceOf(previous);" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "if (require_prompt) {", .replacement = "if (false) {" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "return runQueuedPreparedTaskSlice(true, NativePreparedDispatch{}, null, null, null, null);", .replacement = "return runQueuedPreparedTaskSlice(false, NativePreparedDispatch{}, null, null, null, null);" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "return runQueuedPreparedTaskSlice(false, ArchitecturePreparedBackend{", .replacement = "return runQueuedPreparedTaskSlice(true, ArchitecturePreparedBackend{" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "@compileError(\"prompted owner fixtures require an isolated proof root\");", .replacement = "{};" },
        .{ .path = "src/kernel/smp.zig", .kind = .smp, .needle = "pub const PREPARED_EXECUTION_IPI_VECTOR: u8 = 0x74;", .replacement = "pub const PREPARED_EXECUTION_IPI_VECTOR: u8 = 0x73;" },
        .{ .path = "src/kernel/smp.zig", .kind = .smp, .needle = "cpu >= cpu_count or cpu == currentCpuIndex()) return false;", .replacement = "cpu == currentCpuIndex()) return false;" },
        .{ .path = "src/kernel/smp.zig", .kind = .smp, .needle = ".vector = PREPARED_EXECUTION_IPI_VECTOR, .delivery = .fixed", .replacement = ".vector = PREPARED_EXECUTION_IPI_VECTOR, .delivery = .nmi" },
        .{ .path = "src/kernel/interrupts/isr.zig", .kind = .isr, .needle = "x2apic.acknowledge();\n    dispatch_transport.global.notePrompt() catch return;", .replacement = "dispatch_transport.global.notePrompt() catch return;\n    x2apic.acknowledge();" },
        .{ .path = "src/kernel/interrupts/isr.zig", .kind = .isr, .needle = "if (vector == smp.PREPARED_EXECUTION_IPI_VECTOR) return preparedExecutionInterrupt;", .replacement = "if (vector == smp.PREPARED_EXECUTION_IPI_VECTOR) return executionStopInterrupt;" },
        .{ .path = "src/kernel/interrupts/isr.zig", .kind = .isr, .needle = "setKernelGate(smp.PREPARED_EXECUTION_IPI_VECTOR, &isr116);", .replacement = "setKernelGate(smp.PREPARED_EXECUTION_IPI_VECTOR, &isr115);" },
        .{ .path = "src/kernel/interrupts/interrupt64.S", .kind = .entry_assembly, .needle = "ISR_NOERRCODE 116", .replacement = "// ISR_NOERRCODE 116" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "    \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRANSPORT_IPI:PASS\",\n", .replacement = "" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "if (ticket.cpu >= CAPACITY) return error.InvalidCpu;", .replacement = "// collection CPU guard removed" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "try command.ticket.issuer.preparedReady(command.ticket);", .replacement = "// admission removed" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "if (old_sequence == MAX_SEQUENCE) return error.SequenceExhausted;", .replacement = "// exhaustion removed" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "const sequence = old_sequence + 1;", .replacement = "const sequence = old_sequence +% 1;" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "pack(sequence, .pending, .owner_returned), .release", .replacement = "pack(sequence, .pending, .owner_returned), .monotonic" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "withPhase(control, .claimed), .acq_rel, .acquire", .replacement = "withPhase(control, .claimed), .monotonic, .monotonic" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "if (phaseOf(control) != .pending) return error.WrongPhase;", .replacement = "if (phaseOf(control) != .claimed) return error.WrongPhase;" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "pack(key.sequence, .completed, .unstarted), .release", .replacement = "pack(key.sequence, .completed, .owner_returned), .release" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "pack(key.sequence, .completed, completion), .release", .replacement = "pack(key.sequence, .completed, completion), .monotonic" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "if (phase == .publishing) return error.Busy;", .replacement = "if (phase == .publishing) return false;" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "if (!sameTicket(channel.ticket, ticket)) return false;", .replacement = "// ticket match removed" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "if (phase != .completed) return error.Busy;", .replacement = "if (phase != .claimed) return error.Busy;" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "pack(key.sequence, .idle, .owner_returned)", .replacement = "pack(0, .idle, .owner_returned)" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "else withPhase(control, .completed);", .replacement = "else withPhase(control, .idle);" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "if (key.pool != self) return error.WrongCoordinator;", .replacement = "// pool identity removed" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "a.issuer == b.issuer and a.cpu == b.cpu and a.epoch == b.epoch", .replacement = "a.cpu == b.cpu and a.epoch == b.epoch" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "sequenceOf(control) != key.sequence", .replacement = "sequenceOf(control) < key.sequence" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "if (phase == .publishing or channel.ticket.issuer == issuer) return true;", .replacement = "if (channel.ticket.issuer == issuer) return true;" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "try requireInterruptsMasked();", .replacement = "// IF guard removed" },
        .{ .path = "src/native/task/dispatch_ownership.zig", .kind = .coordinator, .needle = "if (control & PREPARED == 0) return error.WrongPurpose;", .replacement = "// purpose check removed" },
        .{ .path = "src/native/task/dispatch_ownership.zig", .kind = .coordinator, .needle = "if (control & STOP != 0) return error.StopRequested;", .replacement = "// STOP check removed" },
        .{ .path = "src/native/task/task_runtime.zig", .kind = .runtime, .needle = "const channel_held = try dispatch_transport.global.beginCollectionInto(ticket, &channel);", .replacement = "const channel_held = false;" },
        .{ .path = "src/native/task/task_runtime.zig", .kind = .runtime, .needle = "dispatch_transport.global.abortCollection(channel)", .replacement = "dispatch_transport.global.finishCollection(channel)" },
        .{ .path = "src/native/task/task_runtime.zig", .kind = .runtime, .needle = "if (channel_held) dispatch_transport.global.finishCollection(channel)", .replacement = "if (channel_held) dispatch_transport.global.abortCollection(channel)" },
        .{ .path = "src/native/task/task_runtime.zig", .kind = .runtime, .needle = "dispatch_transport.global.hasOutstandingForIssuer(&self.execution)", .replacement = "false" },
        .{ .path = "src/native/task/task_runtime.zig", .kind = .runtime, .needle = "self.requireExecutionQuiescent() catch", .replacement = "self.requireOtherQuiescent() catch" },
        .{ .path = "src/native/task/task_runtime.zig", .kind = .runtime, .needle = "self.requireExecutionQuiescent() catch return error.TaskRuntimeBorrowed;", .replacement = "// retained transport check removed" },
        .{ .path = "src/native/session/session_manager_boot_flow.zig", .kind = .session, .needle = "self.requireResetExecutionQuiescent() catch", .replacement = "self.requireOtherQuiescent() catch" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "return runtime.execution.hasLeases() or dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution);", .replacement = "return runtime.execution.hasLeases();" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "runtime.execution.preparedReady(ticket) catch return false;", .replacement = "// ready validation removed" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "registeredDomainExecutor(ticket.cpu, owner, runtime) != self", .replacement = "false" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "const key = claimed.key;", .replacement = "const key = undefined;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "const ran = if (source) |executor| executor.runPreparedTaskSlice(&claimed.command, backend) else false;", .replacement = "const ran = false;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "dispatch_transport.global.complete(key, if (ran) .owner_returned else .unstarted)", .replacement = "dispatch_transport.global.complete(key, .owner_returned)" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "@compileError(\"queued owner fixtures require an isolated proof root\");", .replacement = "{};" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "return smp.isRuntimeOwner() and continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();", .replacement = "return continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "proof.pass(\"SMP_AP_TRANSPORT\");", .replacement = "proof.pass(\"SMP_AP_TRANSPORT_DISABLED\");" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "verifyTransportCompletion(1, .owner_returned);", .replacement = "// completion observation removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "rejectTransportCollection(runtime, scheduler, source, first, address_space_id, admitted);", .replacement = "// early collection refusal removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "native_executor.releaseRegisteredDomain(scheduler, runtime) or preparedBorrowCount(runtime) != 1", .replacement = "false or preparedBorrowCount(runtime) != 1" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "waitForTransportWord(&transport_completed, phase);", .replacement = "// completion acquire removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "if (phase == 1 or phase == 4) waitForTransportWord(&transport_released, phase);", .replacement = "// post-ACK lifetime hold removed" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "dispatch_transport.global.claimKeyInto(transport_stale_key, &claimed)", .replacement = "dispatch_transport.global.claimKeyInto(transport_key, &claimed)" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "    \"ZIGOS:ARCH:X86_64:HIGH_HALF:SMP_AP_TRANSPORT:PASS\",\n", .replacement = "" },
    }) |mutation| {
        const source = try common.readFileAlloc(allocator, std.testing.io, mutation.path, common.source_file_max_bytes);
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        const altered = try std.mem.replaceOwned(u8, allocator, source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateDurableTransportSource(allocator, &errors, altered, mutation.kind);
        if (errors.items.len == 0) std.debug.print("accepted mutation in {s}: {s}\n", .{ mutation.path, mutation.needle });
        try std.testing.expect(errors.items.len != 0);
    }
}

test "durable transport source gate rejects post ACK backing reads and pool resets" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { path: []const u8, kind: DurableTransportSourceKind, needle: []const u8, replacement: []const u8 }{
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "channels: [CAPACITY]Channel = @splat(.{}),", .replacement = "channels: [CAPACITY]Channel = @splat(.{}),\nfn reset(self: *Pool) void { self.* = .{}; }" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "pub var global: Pool = .{};", .replacement = "pub var global: Pool = .{};\nfn resetGlobal() void { global = .{}; }" },
        .{ .path = "src/native/task/dispatch_transport.zig", .kind = .core, .needle = "pack(key.sequence, .completed, completion), .release", .replacement = "pack(channel.ticket.epoch, .completed, completion), .release" },
        .{ .path = "src/native/task/task_runtime.zig", .kind = .runtime, .needle = "pub const Runtime = struct {", .replacement = "pub const Runtime = struct {\nfn resetTransport() void { dispatch_transport.global = .{}; }" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "const ran = if (source) |executor| executor.runPreparedTaskSlice(&claimed.command, backend) else false;", .replacement = "const ran = if (source) |executor| executor.runPreparedTaskSlice(&claimed.command, backend) else false;\n_ = claimed.command.ticket.issuer;" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "transport_owner_ran = ran;", .replacement = "transport_owner_ran = ran;\n_ = transport_key.pool.channels[0].ticket.issuer;" },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe, .needle = "@atomicStore(u32, &transport_completed, @intCast(phase), .release);", .replacement = "_ = source.materializedCount();\n@atomicStore(u32, &transport_completed, @intCast(phase), .release);" },
    }) |mutation| {
        const source = try common.readFileAlloc(allocator, std.testing.io, mutation.path, common.source_file_max_bytes);
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        const altered = try std.mem.replaceOwned(u8, allocator, source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateDurableTransportSource(allocator, &errors, altered, mutation.kind);
        try std.testing.expect(errors.items.len != 0);
    }
}

const VoluntaryYieldSourceKind = enum { runtime, executor, metadata };

fn validateVoluntaryYieldSource(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8), source: []const u8, kind: VoluntaryYieldSourceKind) !void {
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    var lexer = std.zig.Tokenizer.init(code);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "Voluntary yield admission must remain valid Zig source", .{});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    const retired = switch (kind) {
        .runtime => hasCodeTokens(code, tokens.items, "WaitRequest") or hasCodeTokens(code, tokens.items, "parkUntilEvent") or hasCodeTokens(code, tokens.items, ".wait"),
        .executor => hasCodeTokens(code, tokens.items, "requestEventWait"),
        .metadata => hasCodeTokens(code, tokens.items, ".operation = .wait") or hasCodeTokens(code, tokens.items, ".request_type_name = \"WaitRequest\""),
    };
    if (retired) try common.addError(errors, allocator, "Voluntary yield must not restore a separate wait syscall or ambient Executor setter", .{});
    switch (kind) {
        .runtime => {
            const steady = topLevelFunctionBody(code, tokens.items, "runSteadyState") orelse &.{};
            const publish = topLevelFunctionBody(code, tokens.items, "publishStateWithDisposition") orelse &.{};
            const entry = topLevelFunctionBody(code, tokens.items, "yieldCounter") orelse &.{};
            var idle_branches: usize = 0;
            for (steady, 0..) |_, index| if (codeTokenSequenceLength(code, steady[index..], ".wait_for_event") != null) {
                idle_branches += 1;
            };
            if (idle_branches != 2 or
                !hasCodeTokens(code, steady, "const disposition: mailbox.YieldDisposition") or
                !hasCodeTokens(code, steady, "publishStateWithDisposition(.steady, detail, pulse, disposition);") or
                !hasCodeTokens(code, publish, "_ = yieldCounter(counter, disposition, zigos_userspace_bootstrap.ui_state_revision);") or
                !hasCodeTokens(code, entry, "return freestanding_syscall.syscall_yield_asm(value, disposition, ui_revision);"))
                try common.addError(errors, allocator, "Both idle paths must publish their explicit disposition through the single voluntary yield entry", .{});
        },
        .executor => {
            const handoff = topLevelFunctionBody(code, tokens.items, "handleUserspaceYield") orelse &.{};
            const interrupt = topLevelFunctionBody(code, tokens.items, "handoffInterruptedUser") orelse &.{};
            if (!hasCodeTokens(code, handoff, "if (executor.active_task_id == 0) return; if (executor.handoff_completed or native_entry.current().resume_requested != 0) return;") or
                !hasCodeTokens(code, handoff, "const counter = std.math.cast(u32, frame.eax) orelse return containMalformedYield(executor, frame.eip); " ++
                    "const disposition_raw = std.math.cast(u32, frame.esi) orelse return containMalformedYield(executor, frame.eip); " ++
                    "const disposition = userspace_bootstrap_mailbox.yieldDisposition(disposition_raw) orelse return containMalformedYield(executor, frame.eip); " ++
                    "const interrupted_before_yield = mapping.interrupted_before_yield; mapping.interrupted_before_yield = false; " ++
                    "if (disposition == .wait_for_event and interrupted_before_yield) return; const ui_revision: u64 = @intCast(frame.edx);") or
                !hasCodeTokens(code, handoff, "executor.last_yield_disposition = disposition;") or
                !hasCodeTokens(code, interrupt, "if (executor.handoff_completed or native_entry.current().resume_requested != 0) return; mapping.resume_valid = true; mapping.interrupted_before_yield = true;") or
                !hasCodeTokens(code, handoff, "freestanding.paging.switchToKernelAddressSpace();"))
                try common.addError(errors, allocator, "Voluntary yield must preserve prior handoffs, validate the owner frame and skip one stale IRQ wait in the same quantum before normal kernel-root handoff", .{});
        },
        .metadata => {},
    }
}

test "voluntary yield source gate accepts actual owner handoff and ignores quoted retired APIs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { path: []const u8, kind: VoluntaryYieldSourceKind }{
        .{ .path = "src/userspace/runtime.zig", .kind = .runtime },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor },
        .{ .path = "src/native/kernel_api/operation_metadata.zig", .kind = .metadata },
    }) |item| {
        const source = try common.readFileAlloc(allocator, std.testing.io, item.path, common.source_file_max_bytes);
        const annotated = try std.fmt.allocPrint(allocator, "{s}\n// parkUntilEvent requestEventWait .operation = .wait\nconst historical_api = \"WaitRequest parkUntilEvent requestEventWait .operation = .wait\";\n", .{source});
        var errors = std.ArrayList([]const u8).empty;
        try validateVoluntaryYieldSource(allocator, &errors, annotated, item.kind);
        try std.testing.expectEqual(@as(usize, 0), errors.items.len);
    }
}

test "voluntary yield source gate rejects lost owner disposition and restored wait paths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { path: []const u8, kind: VoluntaryYieldSourceKind, needle: []const u8, replacement: []const u8 }{
        .{ .path = "src/userspace/runtime.zig", .kind = .runtime, .needle = "publishStateWithDisposition(.steady, detail, pulse, disposition);", .replacement = "// publishStateWithDisposition(.steady, detail, pulse, disposition);\nconst ignored = \"publishStateWithDisposition(.steady, detail, pulse, disposition);\";" },
        .{ .path = "src/userspace/runtime.zig", .kind = .runtime, .needle = "yieldCounter(counter, disposition,", .replacement = "yieldCounter(counter, .runnable," },
        .{ .path = "src/userspace/runtime.zig", .kind = .runtime, .needle = "return freestanding_syscall.syscall_yield_asm(value, disposition, ui_revision);", .replacement = "// return freestanding_syscall.syscall_yield_asm(value, disposition, ui_revision);\nreturn value;" },
        .{ .path = "src/userspace/runtime.zig", .kind = .runtime, .needle = ".wait_for_event", .replacement = ".runnable" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "if (disposition == .wait_for_event and interrupted_before_yield) return;", .replacement = "// if (disposition == .wait_for_event and interrupted_before_yield) return;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "mapping.interrupted_before_yield = true;", .replacement = "mapping.interrupted_before_yield = false;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "mapping.interrupted_before_yield = false;", .replacement = "// mapping.interrupted_before_yield = false;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "if (executor.handoff_completed or native_entry.current().resume_requested != 0) return;", .replacement = "// if (executor.handoff_completed or native_entry.current().resume_requested != 0) return;" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .needle = "executor.last_yield_disposition = disposition;", .replacement = "executor.last_yield_disposition = .runnable;" },
    }) |mutation| {
        const source = try common.readFileAlloc(allocator, std.testing.io, mutation.path, common.source_file_max_bytes);
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        const altered = try std.mem.replaceOwned(u8, allocator, source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateVoluntaryYieldSource(allocator, &errors, altered, mutation.kind);
        try std.testing.expect(errors.items.len != 0);
    }
    for ([_]struct { path: []const u8, kind: VoluntaryYieldSourceKind, addition: []const u8 }{
        .{ .path = "src/userspace/runtime.zig", .kind = .runtime, .addition = "fn parkUntilEvent() void {}" },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor, .addition = "pub fn requestEventWait() void {}" },
        .{ .path = "src/native/kernel_api/operation_metadata.zig", .kind = .metadata, .addition = "const obsolete = .{ .operation = .wait };" },
    }) |mutation| {
        const source = try common.readFileAlloc(allocator, std.testing.io, mutation.path, common.source_file_max_bytes);
        const altered = try std.fmt.allocPrint(allocator, "{s}\n{s}\n", .{ source, mutation.addition });
        var errors = std.ArrayList([]const u8).empty;
        try validateVoluntaryYieldSource(allocator, &errors, altered, mutation.kind);
        try std.testing.expect(errors.items.len != 0);
    }
}

fn topLevelFunctionBody(source: []const u8, tokens: []const std.zig.Token, name: []const u8) ?[]const std.zig.Token {
    var depth: usize = 0;
    for (tokens, 0..) |token, index| {
        if (depth == 0 and token.tag == .keyword_fn and index + 1 < tokens.len and
            tokens[index + 1].tag == .identifier and std.mem.eql(u8, source[tokens[index + 1].loc.start..tokens[index + 1].loc.end], name))
        {
            var start = index + 2;
            while (start < tokens.len) : (start += 1) {
                if (tokens[start].tag == .semicolon) return null;
                if (tokens[start].tag != .l_brace) continue;
                // An explicit error set is part of the return type, not the
                // function body whose admission/ordering this gate inspects.
                if (start != 0 and tokens[start - 1].tag == .keyword_error) {
                    while (start < tokens.len and tokens[start].tag != .r_brace) : (start += 1) {}
                    continue;
                }
                break;
            }
            if (start == tokens.len) return null;
            var nested: usize = 1;
            var end = start + 1;
            while (end < tokens.len) : (end += 1) {
                if (tokens[end].tag == .l_brace) nested += 1;
                if (tokens[end].tag == .r_brace) nested -= 1;
                if (nested == 0) return tokens[start + 1 .. end];
            }
            return null;
        }
        if (token.tag == .l_brace) depth += 1;
        if (token.tag == .r_brace) {
            if (depth == 0) return null;
            depth -= 1;
        }
    }
    return null;
}

fn codeTokenSequenceLength(source: []const u8, tokens: []const std.zig.Token, pattern: [:0]const u8) ?usize {
    var lexer = std.zig.Tokenizer.init(pattern);
    var count: usize = 0;
    while (true) {
        const expected = lexer.next();
        if (expected.tag == .eof) return count;
        if (count == tokens.len) return null;
        const actual = tokens[count];
        if (actual.tag != expected.tag or
            !std.mem.eql(u8, source[actual.loc.start..actual.loc.end], pattern[expected.loc.start..expected.loc.end])) return null;
        count += 1;
    }
}

fn hasCodeTokens(source: []const u8, tokens: []const std.zig.Token, pattern: [:0]const u8) bool {
    for (tokens, 0..) |_, index| if (codeTokenSequenceLength(source, tokens[index..], pattern) != null) return true;
    return false;
}

const CpuTimerSourceKind = enum { timer, isr, ap };
const TimerCodePosition = enum { contains, prefix, suffix, exact };

fn timerCodeMatches(source: []const u8, tokens: []const std.zig.Token, pattern: [:0]const u8, position: TimerCodePosition) bool {
    switch (position) {
        .contains => return hasCodeTokens(source, tokens, pattern),
        .prefix => return codeTokenSequenceLength(source, tokens, pattern) != null,
        .exact => return (codeTokenSequenceLength(source, tokens, pattern) orelse return false) == tokens.len,
        .suffix => {
            for (tokens, 0..) |_, index| {
                const length = codeTokenSequenceLength(source, tokens[index..], pattern) orelse continue;
                if (index + length == tokens.len) return true;
            }
            return false;
        },
    }
}

fn topLevelContainerBody(source: []const u8, tokens: []const std.zig.Token, declaration: [:0]const u8) ?[]const std.zig.Token {
    var depth: usize = 0;
    for (tokens, 0..) |token, index| {
        if (depth == 0) {
            if (codeTokenSequenceLength(source, tokens[index..], declaration)) |length| {
                const start = index + length;
                if (length == 0 or tokens[start - 1].tag != .l_brace) return null;
                var nested: usize = 1;
                for (tokens[start..], start..) |next, end| {
                    if (next.tag == .l_brace) nested += 1;
                    if (next.tag == .r_brace) nested -= 1;
                    if (nested == 0) return tokens[start..end];
                }
                return null;
            }
        }
        if (token.tag == .l_brace) depth += 1;
        if (token.tag == .r_brace) {
            if (depth == 0) return null;
            depth -= 1;
        }
    }
    return null;
}

fn tokenInBody(token: std.zig.Token, body: []const std.zig.Token) bool {
    return body.len != 0 and token.loc.start >= body[0].loc.start and token.loc.end <= body[body.len - 1].loc.end;
}

fn hasTopLevelCodeTokens(source: []const u8, tokens: []const std.zig.Token, pattern: [:0]const u8) bool {
    var depth: usize = 0;
    for (tokens, 0..) |token, index| {
        if (depth == 0 and codeTokenSequenceLength(source, tokens[index..], pattern) != null) return true;
        if (token.tag == .l_brace) depth += 1;
        if (token.tag == .r_brace) depth -|= 1;
    }
    return false;
}

fn timerHardwareAdapterMatches(source: []const u8, body: []const std.zig.Token, prefix: [:0]const u8, native_tail: [:0]const u8) bool {
    // Only the compile-time test branch may be opaque. Match from the actual
    // method's first token through that branch's closing brace, then require
    // its entire production remainder. Early returns or conditional decoys
    // cannot leave a passing native suffix behind.
    const start = codeTokenSequenceLength(source, body, prefix) orelse return false;
    if (start == 0 or body[start - 1].tag != .l_brace) return false;
    var depth: usize = 1;
    for (body[start..], start..) |token, index| {
        if (token.tag == .l_brace) depth += 1;
        if (token.tag == .r_brace) depth -= 1;
        if (depth == 0) return timerCodeMatches(source, body[index + 1 ..], native_tail, .exact);
    }
    return false;
}

fn validateCpuTimerSource(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    source: []const u8,
    kind: CpuTimerSourceKind,
) !void {
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    var lexer = std.zig.Tokenizer.init(code);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "CPU timer {s} must remain valid Zig source", .{@tagName(kind)});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    if (kind == .isr) {
        const body = topLevelFunctionBody(code, tokens.items, "timerInterrupt") orelse &.{};
        const expected = "timer.handleInterrupt(); if (cpu_identity.currentIndex() == 0) { event_wake.raise(.timer); event_wake.raise(.scheduler); }";
        if (!timerCodeMatches(code, body, expected, .exact))
            try common.addError(errors, allocator, "CPU timer ISR must acknowledge its selected owner and publish service wakes only on BSP", .{});
        return;
    }
    if (kind == .ap) {
        const body = topLevelFunctionBody(code, tokens.items, "apEntry") orelse &.{};
        // The bounded admission body makes native setup unconditional on the
        // successful path. Ordered token hits alone would accept dead branches
        // around identity, GS/xstate or IDT setup before timer admission.
        const expected = "const index = @import(\"std\").math.cast(u8, cpu_index) orelse park(); " ++
            "if (index == 0 or index >= bringup_cpu_count.* or index >= smp.MAX_CPUS) park(); " ++
            "const detected_features = cpu_features.detect(); " ++
            "if (admission_policy.firstMissing(detected_features)) |missing| { " ++
            "@atomicStore(u8, &rejection_reasons[index], @backingInt(missing) + 1, .release); park(); } " ++
            "const features = admission_policy.resolveFeatures(detected_features); " ++
            "cpu_features.admitApplicationProcessorCache() catch |err| { " ++
            "@atomicStore(u8, &rejection_reasons[index], cpu_features.cache_policy.rejectionCode(err), .release); park(); }; " ++
            "cpu_identity.initialize(index); paging.initializeCurrentKernelRoot(); x86.invalidatePage(startup_page_physical); " ++
            "gdt.initCpu(index); gdt.setKernelStack(bringup_cpus[index].kernel_stack_top); " ++
            "cpu_features.enableModernFeatures(features, admission_policy.process_context_mode, admission_policy.cet_mode, admission_policy.featureMode(),); " ++
            "const syscall64 = @import(\"interrupts/syscall64.zig\"); " ++
            "syscall64.initApplicationProcessor(index, bringup_cpus[index].kernel_stack_top); idt.init(); " ++
            "if (features.lass) { x86.enableLass() catch { " ++
            "@atomicStore(u8, &rejection_reasons[index], ADDRESS_PARTITION_REJECTED, .release); park(); }; } " ++
            "x2apic.enable(); if (!timer.initApplicationProcessor(features)) { " ++
            "@atomicStore(u8, &rejection_reasons[index], TIMER_ADMISSION_REJECTED, .release); park(); } " ++
            "@atomicStore(bool, &bringup_cpus[index].online, true, .release); while (true) smp.idle();";
        if (!timerCodeMatches(code, body, expected, .exact))
            try common.addError(errors, allocator, "CPU timer AP must execute native setup and park admission failures before online publication", .{});
        return;
    }

    const required_declarations = [_][:0]const u8{
        "pub const TICKLESS_TSC_DEADLINE = true;",
        "pub const Mode = enum { tsc_deadline, calibrated_countdown, };",
        "const IA32_TSC_DEADLINE_MSR: u32 = 0x6E0;",
        "const X2APIC_TIMER_MODE_TSC_DEADLINE: u64 = 1 << 18;",
        "const X2APIC_TIMER_MASKED: u64 = 1 << 16;",
        "var clock_authority: ClockAuthority = .{};",
        "var clock_ready: bool = false;",
        "var cpu_states: [cpu_identity.MAX_CPUS]TimerState align(64) = @splat(.{});",
        "comptime { if (@sizeOf(TimerState) != 64) @compileError(",
        "pub const Testing = if (builtin.is_test) struct {",
    };
    for (required_declarations) |pattern| {
        if (!hasTopLevelCodeTokens(code, tokens.items, pattern))
            try common.addError(errors, allocator, "CPU timer must retain clock and bounded owner declaration: {s}", .{pattern});
    }
    const clock = topLevelContainerBody(code, tokens.items, "const ClockAuthority = struct {") orelse &.{};
    if (!timerCodeMatches(code, clock, "mode: Mode = .tsc_deadline, epoch: u64 = 0, frequency_hz: u64 = 0, per_tick: u64 = 0,", .exact))
        try common.addError(errors, allocator, "CPU timer immutable clock must retain exact mode epoch frequency and per-tick authority", .{});
    const state = topLevelContainerBody(code, tokens.items, "const TimerState = extern struct {") orelse &.{};
    if (!timerCodeMatches(code, state, "ticks: u64 = 0, initialized: bool = false, scheduler_tick_enabled: bool = false, lvt_unmasked: bool = false, padding: [53]u8 = @splat(0),", .exact))
        try common.addError(errors, allocator, "CPU timer must retain one cache-isolated state per owner", .{});

    const guard = "const guard = InterruptGuard.enter(); defer guard.leave(); ";
    const function_checks = [_]struct { name: []const u8, pattern: [:0]const u8, position: TimerCodePosition = .exact }{
        .{ .name = "currentState", .pattern = "return &cpu_states[cpu_identity.currentIndex()];" },
        .{ .name = "init", .pattern = "if (!initializeBsp(features, mode)) @panic(\"invalid BSP timer initialization\");" },
        .{ .name = "initializeBsp", .position = .prefix, .pattern = guard ++
            "if (cpu_identity.currentIndex() != 0 or !Hardware.available() or " ++
            "@atomicLoad(bool, &clock_ready, .acquire) or currentState().initialized or " ++
            "features.tsc_frequency_hz / TICKS_PER_SECOND == 0 or " ++
            "(mode == .tsc_deadline and (!features.tsc_deadline or !features.invariant_tsc))) return false;" },
        .{ .name = "initializeBsp", .position = .contains, .pattern = "Hardware.enableApic(); clock_authority = .{ .mode = mode, .epoch = Hardware.counter(), .frequency_hz = features.tsc_frequency_hz, .per_tick = features.tsc_frequency_hz / TICKS_PER_SECOND, }; switch (mode) { .tsc_deadline => { Hardware.write(X2APIC_TIMER_INITIAL_COUNT_MSR, 0); Hardware.write(IA32_TSC_DEADLINE_MSR, 0); Hardware.write(X2APIC_LVT_TIMER_MSR, X2APIC_TIMER_MODE_TSC_DEADLINE | INTERRUPT_VECTOR,); }, .calibrated_countdown => initCalibratedCountdownTimer(), }" },
        .{ .name = "initializeBsp", .position = .suffix, .pattern = "currentState().* = .{ .initialized = true, .lvt_unmasked = true }; @atomicStore(bool, &clock_ready, true, .release); return true;" },
        .{ .name = "initApplicationProcessor", .pattern = guard ++
            "if (cpu_identity.currentIndex() == 0 or !Hardware.available() or " ++
            "!@atomicLoad(bool, &clock_ready, .acquire) or currentState().initialized or " ++
            "features.tsc_frequency_hz != clock_authority.frequency_hz or " ++
            "(clock_authority.mode == .tsc_deadline and (!features.tsc_deadline or !features.invariant_tsc))) return false; " ++
            "Hardware.write(X2APIC_LVT_TIMER_MSR, X2APIC_TIMER_MASKED | INTERRUPT_VECTOR | " ++
            "(if (clock_authority.mode == .tsc_deadline) X2APIC_TIMER_MODE_TSC_DEADLINE else @as(u64, 0))); " ++
            "Hardware.write(X2APIC_TIMER_INITIAL_COUNT_MSR, 0); if (features.tsc_deadline) Hardware.write(IA32_TSC_DEADLINE_MSR, 0); " ++
            "currentState().* = .{ .initialized = true }; return true;" },
        .{ .name = "synchronizeTicks", .pattern = "@atomicStore(u64, &state.ticks, elapsedTicks(clock_authority.epoch, now, clock_authority.per_tick), .monotonic);" },
        .{ .name = "scheduleNextTick", .pattern = "Hardware.write(IA32_TSC_DEADLINE_MSR, nextTickDeadline(clock_authority.epoch, now, clock_authority.per_tick));" },
        .{ .name = "unmaskDeadlineTimer", .pattern = "if (state.lvt_unmasked) return; Hardware.write(X2APIC_LVT_TIMER_MSR, X2APIC_TIMER_MODE_TSC_DEADLINE | INTERRUPT_VECTOR); state.lvt_unmasked = true;" },
        .{ .name = "synchronize", .pattern = guard ++ "const state = currentState(); if (state.initialized) synchronizeTicks(state, Hardware.counter());" },
        .{ .name = "armSchedulerTick", .pattern = guard ++ "const state = currentState(); if (!state.initialized or clock_authority.mode != .tsc_deadline) return; const now = Hardware.counter(); synchronizeTicks(state, now); state.scheduler_tick_enabled = true; unmaskDeadlineTimer(state); scheduleNextTick(now);" },
        .{ .name = "disarmSchedulerTick", .pattern = guard ++ "const state = currentState(); if (!state.initialized or clock_authority.mode != .tsc_deadline) return; synchronizeTicks(state, Hardware.counter()); state.scheduler_tick_enabled = false; Hardware.write(IA32_TSC_DEADLINE_MSR, 0);" },
        .{ .name = "armWakeAt", .pattern = guard ++ "const state = currentState(); if (!state.initialized or clock_authority.mode != .tsc_deadline) return; const now = Hardware.counter(); synchronizeTicks(state, now); state.scheduler_tick_enabled = false; unmaskDeadlineTimer(state); Hardware.write(IA32_TSC_DEADLINE_MSR, wakeDeadline(clock_authority.epoch, now, clock_authority.per_tick, deadline_ticks));" },
        .{ .name = "handleInterrupt", .pattern = guard ++ "const state = currentState(); if (state.initialized) { const now = Hardware.counter(); synchronizeTicks(state, now); if (clock_authority.mode == .tsc_deadline and state.scheduler_tick_enabled) scheduleNextTick(now); } Hardware.acknowledge();" },
        .{ .name = "getTicks", .pattern = "return @atomicLoad(u64, &currentState().ticks, .monotonic);" },
        .{ .name = "initCalibratedCountdownTimer", .position = .contains, .pattern = "Hardware.write(X2APIC_LVT_TIMER_MSR, X2APIC_TIMER_MASKED | INTERRUPT_VECTOR,); Hardware.write(X2APIC_TIMER_DIVIDE_CONFIG_MSR, X2APIC_TIMER_DIVIDE_BY_16); Hardware.write(X2APIC_TIMER_INITIAL_COUNT_MSR, std.math.maxInt(u32));" },
        .{ .name = "initCalibratedCountdownTimer", .position = .suffix, .pattern = "Hardware.write(X2APIC_LVT_TIMER_MSR, X2APIC_TIMER_MODE_PERIODIC | INTERRUPT_VECTOR,); Hardware.write(X2APIC_TIMER_INITIAL_COUNT_MSR, initial_count);" },
    };
    for (function_checks) |check| {
        const body = topLevelFunctionBody(code, tokens.items, check.name) orelse &.{};
        if (!timerCodeMatches(code, body, check.pattern, check.position))
            try common.addError(errors, allocator, "CPU timer must retain actual {s} clock/owner/register contract", .{check.name});
    }
    const hardware = topLevelContainerBody(code, tokens.items, "const Hardware = struct {") orelse &.{};
    const hardware_checks = [_]struct { name: []const u8, tail: [:0]const u8, prefix: [:0]const u8 = "if (builtin.is_test) {" }{
        .{ .name = "write", .tail = "else if (builtin.target.os.tag == .freestanding) x86.writeMsr(msr, value);" },
        .{ .name = "counter", .tail = "return if (builtin.target.os.tag == .freestanding) x86.rdtsc() else 0;" },
        .{ .name = "interruptsEnabled", .tail = "return if (builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;" },
        .{ .name = "disableInterrupts", .tail = "else if (builtin.target.os.tag == .freestanding) x86.cli();" },
        .{ .name = "restoreInterrupts", .prefix = "if (!enabled) return; if (builtin.is_test) {", .tail = "else if (builtin.target.os.tag == .freestanding) x86.sti();" },
        .{ .name = "readCurrentCount", .tail = "return if (builtin.target.os.tag == .freestanding) x86.readMsr(X2APIC_TIMER_CURRENT_COUNT_MSR) else 0;" },
        .{ .name = "enableApic", .tail = "else if (builtin.target.os.tag == .freestanding) x2apic.enable();" },
    };
    for (hardware_checks) |check| {
        const body = topLevelFunctionBody(code, hardware, check.name) orelse &.{};
        if (!timerHardwareAdapterMatches(code, body, check.prefix, check.tail))
            try common.addError(errors, allocator, "CPU timer Hardware.{s} must retain its actual freestanding adapter", .{check.name});
    }
    for ([_]struct { name: []const u8, pattern: [:0]const u8 }{
        .{ .name = "available", .pattern = "return if (builtin.is_test) Testing.active_model != null else builtin.target.os.tag == .freestanding;" },
        .{ .name = "acknowledge", .pattern = "if (builtin.is_test) write(0x80B, 0) else if (builtin.target.os.tag == .freestanding) x2apic.acknowledge();" },
    }) |check| {
        const body = topLevelFunctionBody(code, hardware, check.name) orelse &.{};
        if (!timerCodeMatches(code, body, check.pattern, .exact))
            try common.addError(errors, allocator, "CPU timer Hardware.{s} must retain its complete production control flow", .{check.name});
    }
    const irq_guard = topLevelContainerBody(code, tokens.items, "const InterruptGuard = struct {") orelse &.{};
    for ([_]struct { name: []const u8, pattern: [:0]const u8 }{
        .{ .name = "enter", .pattern = "const enabled = Hardware.interruptsEnabled(); Hardware.disableInterrupts(); return .{ .enabled = enabled };" },
        .{ .name = "leave", .pattern = "Hardware.restoreInterrupts(self.enabled);" },
    }) |check| {
        const body = topLevelFunctionBody(code, irq_guard, check.name) orelse &.{};
        if (!timerCodeMatches(code, body, check.pattern, .exact))
            try common.addError(errors, allocator, "CPU timer interrupt guard must preserve caller IF in {s}", .{check.name});
    }

    const bsp = topLevelFunctionBody(code, tokens.items, "initializeBsp") orelse &.{};
    const testing = topLevelContainerBody(code, tokens.items, "const Testing = if (builtin.is_test) struct {") orelse &.{};
    for (tokens.items, 0..) |token, index| {
        if (tokenInBody(token, bsp) or tokenInBody(token, testing)) continue;
        const tail = tokens.items[index..];
        if (codeTokenSequenceLength(code, tail, "clock_authority =") != null or
            codeTokenSequenceLength(code, tail, "@atomicStore(bool, &clock_ready") != null)
            try common.addError(errors, allocator, "CPU timer clock may be written only by once-only BSP initialization", .{});
        if (token.tag == .identifier and std.mem.eql(u8, code[token.loc.start..token.loc.end], "clock_authority") and
            tail.len >= 4 and tail[1].tag == .period and tail[2].tag == .identifier and
            tail[3].tag == .equal)
            try common.addError(errors, allocator, "CPU timer clock fields must remain immutable after BSP publication", .{});
    }
}

fn validateBootArenaRetirementSource(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    source: []const u8,
) !void {
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var lexer = std.zig.Tokenizer.init(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "boot arena retirement must remain valid Zig source", .{});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    const body = topLevelFunctionBody(code, tokens.items, "init") orelse {
        try common.addError(errors, allocator, "boot arena retirement must remain in actual paging initialization", .{});
        return;
    };
    const admission = "const restore_interrupts = x86.interruptsEnabled(); x86.cli(); defer if (restore_interrupts) x86.sti(); if (bootstrap_root != null) haltPagingFailure(.invalid_native_boot_memory_ownership);";
    var offset = codeTokenSequenceLength(code, body, admission) orelse {
        try common.addError(errors, allocator, "boot arena retirement must mask interrupts and reject reentry before any initialization", .{});
        return;
    };
    for ([_][:0]const u8{
        "const final_used_pages = initializeKernelHierarchy(",
        "x86.writeCr4(previous_cr4 & ~x86.CR4_PGE)",
        "x86.writeCr3(kernel_pml4_physical)",
        "x86.writeCr4(previous_cr4)",
        "initializeCurrentKernelRoot()",
        "firmware_memory_map.reclaimBootPagingArenas(",
        "x86.readCr3() & x86.CR3_ADDRESS_MASK, @intCast(final_used_pages)",
        "physical_frames.sealReservations()",
        "validateHighMemoryDirectMap()",
    }) |snippet| {
        var found = false;
        for (body[offset..], offset..) |_, index| {
            if (codeTokenSequenceLength(code, body[index..], snippet)) |length| {
                offset = index + length;
                found = true;
                break;
            }
        }
        if (!found) try common.addError(errors, allocator, "boot arena retirement must retain ordered executable step: {s}", .{snippet});
    }
}

fn validateBootArenaRetirementPreflightSource(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    source: []const u8,
) !void {
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var lexer = std.zig.Tokenizer.init(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "boot arena retirement preflight must remain valid Zig source", .{});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    const body = topLevelFunctionBody(code, tokens.items, "reclaimBootPagingArenas") orelse {
        try common.addError(errors, allocator, "boot arena retirement must retain its actual ownership preflight", .{});
        return;
    };
    var offset: usize = 0;
    for ([_][:0]const u8{
        "if (retirement.used_pages != 0) return error.BootArenasAlreadyRetired",
        "if (allocator.allocated_count != 0) return error.FrameAllocated",
        "if (allocator.reservations_sealed) return error.ReservationsSealed",
        "page_size != 4096 or used_final_pages < 3 or used_final_pages > arenas.final_pages",
        "if (active_root != arenas.final_base) return error.InvalidHandoffRange",
        "try validateBootOwnedRanges(",
        "if (entry.firmware_type != 2 or (entry.kind != 1 and entry.kind != 2)) return error.RamNotAvailable",
        "try allocator.validateReservation(run)",
        "if (!allocator.isReserved(run.base + offset)) return error.FrameReserved",
        "if (tail.count != 0) try allocator.validateReservation(tail)",
        "allocator.makeAvailable(arena_runs[0]) catch unreachable",
        "if (tail.count != 0) allocator.makeAvailable(tail) catch unreachable",
        "retirement.* = .{",
    }) |snippet| {
        var found = false;
        for (body[offset..], offset..) |_, index| {
            if (codeTokenSequenceLength(code, body[index..], snippet)) |length| {
                offset = index + length;
                found = true;
                break;
            }
        }
        if (!found) try common.addError(errors, allocator, "boot arena retirement must retain ordered executable preflight: {s}", .{snippet});
    }
}

fn validateCountSizedEfiArenaSource(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    source: []const u8,
) !void {
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var lexer = std.zig.Tokenizer.init(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "count-sized EFI arenas must remain valid Zig source", .{});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    if (!hasCodeTokens(code, tokens.items, "const PAGING_SIZING_ATTEMPTS: usize = 8;"))
        try common.addError(errors, allocator, "EFI arena sizing must retain its bounded eight-attempt limit", .{});
    const loader_main = topLevelFunctionBody(code, tokens.items, "main") orelse {
        try common.addError(errors, allocator, "count-sized EFI arenas must remain in actual loader main", .{});
        return;
    };
    var offset: usize = 0;
    for ([_][:0]const u8{
        "const heap_pages = boot.allocatePages(",
        "var measurement = tcg2.capture(",
        "const handoff_pages = boot.allocatePages(",
        "var raw_map = allocateMapBuffer(",
        "var bootstrap_pages: ?[]align(4096) uefi.Page = null;",
        "var final_pages: ?[]align(4096) uefi.Page = null;",
        "for (0..PAGING_SIZING_ATTEMPTS)",
        "const map_slice = boot.getMemoryMap(raw_map)",
        "const mmap_count = captureMemoryMap(map_slice, &mmap_entries, paging_info, framebuffer_span)",
        "const needed = countPagingArenas(transition_mode, image, mmap_entries[0..mmap_count], cache_view, boot_image.heap_base, framebuffer_span)",
        "if (bootstrap_pages != null and final_pages != null and needed.fits(bootstrap_pages.?.len, final_pages.?.len))",
        "bootstrap_pages = allocatePagingArena(boot, needed.transition, cache_view, framebuffer_span)",
        "final_pages = allocatePagingArena(boot, needed.final, cache_view, framebuffer_span)",
        ".transition_pages = @intCast(bootstrap_pages.?.len)",
        ".final_pages = @intCast(final_pages.?.len)",
        "paging_info.?.validate()",
        "if (!sizing_ready) return bootFailure(\"paging-sizing-limit\", .out_of_resources)",
        "for (0..2)",
        "const map_slice = boot.getMemoryMap(raw_map)",
        "const needed = countPagingArenas(transition_mode, image, request.mmap, cache_view, boot_image.heap_base, framebuffer_span)",
        "if (!needed.fits(arenas.transition_pages, arenas.final_pages)) return bootFailure(\"paging-capacity-changed\", .out_of_resources)",
        "efi_paging.buildForMode(bootstrap_pages.?, bootstrap_physical, pre_exit_root",
        "firmware_console_available = false; boot.exitBootServices(",
        "const bootstrap_cr3 = efi_paging.buildForMode(bootstrap_pages.?, bootstrap_physical, active_root",
    }) |snippet| {
        var found = false;
        for (loader_main[offset..], offset..) |_, index| {
            if (codeTokenSequenceLength(code, loader_main[index..], snippet)) |length| {
                offset = index + length;
                found = true;
                break;
            }
        }
        if (!found) try common.addError(errors, allocator, "count-sized EFI arenas must retain ordered executable step: {s}", .{snippet});
    }
    for (loader_main, 0..) |_, index| {
        if (codeTokenSequenceLength(code, loader_main[index..], "for (0..2)")) |length| {
            for ([_][:0]const u8{ "allocatePagingArena(", "allocateMapBuffer(", "boot.allocatePages(", "boot.allocatePool(" }) |allocation| {
                if (hasCodeTokens(code, loader_main[index + length ..], allocation))
                    try common.addError(errors, allocator, "EFI exit retries must not allocate after sizing: {s}", .{allocation});
            }
            break;
        }
    }
    const checks = [_]struct { function: []const u8, pattern: [:0]const u8 }{
        .{ .function = "countPagingArenas", .pattern = "try efi_paging.countForModeInto(mode, image, entries, cache, heap_base, framebuffer_span, &transition)" },
        .{ .function = "countPagingArenas", .pattern = "if (mode != .native_high) try efi_paging.countForModeInto(.native_high, image, entries, cache, heap_base, framebuffer_span, &final)" },
        .{ .function = "countPagingArenas", .pattern = "transition.used_pages < 3 or transition.used_pages > efi_paging.MAX_PAGE_COUNT or final.used_pages < 3 or final.used_pages > efi_paging.MAX_PAGE_COUNT" },
        .{ .function = "allocatePagingArena", .pattern = "if (count < 3 or count > efi_paging.MAX_PAGE_COUNT) return error.InvalidArena" },
        .{ .function = "allocatePagingArena", .pattern = "const pages = try boot.allocatePages(.{ .max_address = @ptrFromInt(efi_paging.ALIAS_BYTES - efi_paging.PAGE_BYTES) }, .loader_data, count)" },
        .{ .function = "allocatePagingArena", .pattern = "errdefer boot.freePages(pages) catch {}" },
        .{ .function = "allocatePagingArena", .pattern = "try requireOutsideFramebuffer(framebuffer_span, @intFromPtr(pages.ptr), pages.len * 4096)" },
        .{ .function = "allocatePagingArena", .pattern = "try cache.requireWriteBack(@intFromPtr(pages.ptr), pages.len * 4096)" },
        .{ .function = "bootFailure", .pattern = "if (!firmware_console_available) return status" },
    };
    for (checks) |check| {
        const body = topLevelFunctionBody(code, tokens.items, check.function) orelse &.{};
        if (!hasCodeTokens(code, body, check.pattern))
            try common.addError(errors, allocator, "EFI arena helper {s} must retain executable contract: {s}", .{ check.function, check.pattern });
    }
}

fn validatePagingArenaCapacitySource(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    source: []const u8,
    kind: enum { metadata, transition, final },
) !void {
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var lexer = std.zig.Tokenizer.init(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof or (kind == .metadata and token.tag == .keyword_test)) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "variable EFI arena capacity must remain valid Zig source", .{});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    const patterns: []const [:0]const u8 = switch (kind) {
        .metadata => &.{
            "PAYLOAD_BYTES: usize = 48",                                                                                                          "MAX_ARENA_PAGES: u32 = 4096",
            "transition_pages: u32",                                                                                                              "final_pages: u32",
            "self.transition_pages < 3 or self.transition_pages > MAX_ARENA_PAGES or self.final_pages < 3 or self.final_pages > MAX_ARENA_PAGES", "return @as(u64, self.transition_pages) * 4096",
            "return @as(u64, self.final_pages) * 4096",                                                                                           "bytes.writeU32Le(out[0..4], 3)",
            "bytes.writeU32Le(out[4..8], self.transition_pages)",                                                                                 "bytes.writeU32Le(out[8..12], self.final_pages)",
            "bytes.writeU32Le(out[12..16], 0)",                                                                                                   "bytes.writeU64Le(out[16..24], self.transition_base)",
            "bytes.writeU64Le(out[24..32], self.final_base)",                                                                                     "bytes.writeU64Le(out[32..40], self.framebuffer_base)",
            "bytes.writeU64Le(out[40..48], self.framebuffer_bytes)",                                                                              "source.len != PAYLOAD_BYTES or bytes.readU32Le(source[0..4]) != 3 or bytes.readU32Le(source[12..16]) != 0",
            ".transition_pages = bytes.readU32Le(source[4..8])",                                                                                  ".final_pages = bytes.readU32Le(source[8..12])",
            "try result.validate()",
        },
        .transition => &.{
            "try paging_info.validate()",
            "arena.len < 3 or arena.len > MAX_PAGE_COUNT or physical_base != paging_info.transition_base or arena.len != paging_info.transition_pages",
            "try prepareInto(image, entries, heap_base, try paging_info.framebufferSpan(), &plan)",
            "try sparse.build(tables[0..arena.len], physical_base, active_root, plan.config(mode, cache), &result)",
        },
        .final => &.{ "sparse.build(tables[0..arenas.final_pages], arenas.final_base, null", "return result.used_pages" },
    };
    const body = switch (kind) {
        .metadata => tokens.items,
        .transition => topLevelFunctionBody(code, tokens.items, "buildForMode") orelse &.{},
        .final => topLevelFunctionBody(code, tokens.items, "initializeKernelHierarchy") orelse &.{},
    };
    for (patterns) |pattern| {
        if (!hasCodeTokens(code, body, pattern))
            try common.addError(errors, allocator, "variable EFI arena {s} must retain executable capacity contract: {s}", .{ @tagName(kind), pattern });
    }
}

const ApCacheProbeSourceKind = enum { enabled, rejection, support, harness, build };

fn validateApCacheProbeSource(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    source: []const u8,
    kind: ApCacheProbeSourceKind,
) !void {
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var lexer = std.zig.Tokenizer.init(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "AP cache evidence must remain valid Zig source", .{});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    const Contract = struct { function: []const u8, ordered: []const [:0]const u8 };
    const contracts: []const Contract = switch (kind) {
        .enabled => &.{
            .{ .function = "main", .ordered = &.{ "support.initializeBsp()", "cache.copyBootstrapMtrrSnapshot(&expected)", "support.publish(page); support.startAp(page, &result.status)", "support.waitForPhase(&result.status, 1)", "const first = observed.first", "if (!enabledControls(first, expected.default_type))", "support.pass(\"FIRST_ENABLED\")", "support.waitForPhase(&result.status, 2)", "const actual = observed.observed", "!snapshotMatches(&expected, &actual)", "support.pass(\"SMP_CACHE_ENABLED_MATCH\")" } },
            .{ .function = "enabledControls", .ordered = &.{ "record.cr0) & (cache.CACHE_CONTROL_MASK | x86.CR0_PG) == 0", "record.flags & (1 << 9) == 0", "record.pat == cache.BOOTSTRAP_PAT", "record.default_type == expected_default", "record.default_type & cache.MTRR_ENABLED != 0" } },
            .{ .function = "snapshotMatches", .ordered = &.{"return std.mem.eql(u8, std.mem.asBytes(expected), std.mem.asBytes(actual))"} },
        },
        .rejection => &.{
            .{ .function = "kernel_main", .ordered = &.{ "support.initializeBsp()", "support.prepareBridge(&unexpectedHighEntry)", "const snapshot = snapshotBytes(trampoline); injectFault(snapshot); publishPage(trampoline); support.prepareAp()", "support.serialWrite(\"ZIGOS:ARCH:X86_64:AP_CACHE:\" ++ CASE_LABEL ++ \":ARMED\\n\")", "support.launchPhysical(trampoline.physical)", "if (options.ap_cache_fault == .none) support.retainAndHalt()", "if (@atomicLoad(u32, sentinel, .acquire) != 0) support.fail(\"UNEXPECTED_HIGH_ENTRY\")" } },
            .{ .function = "unexpectedHighEntry", .ordered = &.{ "@atomicStore(u32, sentinel, 1, .release)", "if (cpu_index != 1)", "if (options.ap_cache_fault == .none)", "support.pass(\"CONTROL_HIGH_ENTRY\")", "support.finish()", "support.fail(\"UNEXPECTED_HIGH_ENTRY\")" } },
            .{ .function = "injectFault", .ordered = &.{ ".none => {}", ".version => std.mem.writeInt(u32, snapshot[version..][0..4], 0, .little)", ".default_reserved =>", "original | (1 << 12)", ".mask_reserved =>", "& 0xff == 0", "@offsetOf(cache_policy.VariableMtrr, \"mask\")", "original | 1" } },
            .{ .function = "publishPage", .ordered = &.{ "cpu_features.clflushLineBytes()", "while (offset < PAGE_BYTES) : (offset += line_bytes) x86.flushCacheLine(base + offset)", "asm volatile (\"mfence\"" } },
        },
        .support => &.{
            .{ .function = "prepareBridge", .ordered = &.{ "bridge.install()", "paging.mapKernelBorrowedPage(trampoline.physical, trampoline.physical", "bridge.allocateStack()", "bridge.patch(trampoline, 1, stack.top, entry)" } },
            .{ .function = "prepareAp", .ordered = &.{ "if (x86.interruptsEnabled())", "x2apic.sendInit(AP_ID); waitMilliseconds(10)" } },
            .{ .function = "startAp", .ordered = &.{ "prepareAp(); launchPhysical(page.physical)", "if (@atomicLoad(u32, status, .acquire) == 0) launchPhysical(page.physical)" } },
            .{ .function = "waitForPhase", .ordered = &.{ "clock.afterMilliseconds(2000)", "@atomicLoad(u32, status, .acquire)", "if (observed > 2)", "if (observed >= wanted) return", "if (deadline.expired())" } },
            .{ .function = "retainAndHalt", .ordered = &.{"x86.cli(); while (true) x86.hlt()"} },
        },
        .harness => &.{
            .{ .function = "apCacheFirst", .ordered = &.{ ".none => \"ZIGOS:ARCH:X86_64:AP_CACHE:CONTROL:ARMED\"", ".version => \"ZIGOS:ARCH:X86_64:AP_CACHE:VERSION:ARMED\"", ".default_reserved => \"ZIGOS:ARCH:X86_64:AP_CACHE:DEFAULT_RESERVED:ARMED\"", ".mask_reserved => \"ZIGOS:ARCH:X86_64:AP_CACHE:MASK_RESERVED:ARMED\"", ".enabled => \"ZIGOS:ARCH:X86_64:AP_CACHE:FIRST_ENABLED:PASS\"" } },
            .{ .function = "apCacheLast", .ordered = &.{ ".none => \"ZIGOS:ARCH:X86_64:AP_CACHE:CONTROL_HIGH_ENTRY:PASS\"", ".enabled => \"ZIGOS:ARCH:X86_64:AP_CACHE:SMP_CACHE_ENABLED_MATCH:PASS\"", "else => \"ZIGOS:BOOT:CACHE:AP:REJECT:5\"" } },
            .{ .function = "validateApCacheEvidence", .ordered = &.{ "if (!log.healthy(bytes, \"FAIL\")) return error.UnhealthyApCacheEvidence", "std.mem.splitScalar(u8, bytes, '\\n')", "!log.contains(line, \"HIGH_ENTRY\")", "!log.contains(line, \"AP:ONLINE\")", "if (observed >= 2 or !std.mem.eql(u8, line, if (observed == 0) apCacheFirst(case) else apCacheLast(case)))", "if (observed != 2) return error.MissingApCacheEvidence" } },
        },
        .build => &.{
            .{ .function = "addApCacheRejectionCheck", .ordered = &.{ "inline for (.{ ApCacheFault.none, ApCacheFault.version, ApCacheFault.default_reserved, ApCacheFault.mask_reserved })", "\"src/ap_cache_rejection_entry.zig\", \"src/kernel/smp/ap_trampoline.S\", fault", "host_tools.addRun(b, \"run-ap-cache-rejection-smoke\")" } },
            .{ .function = "addSmpCacheEnabledMatchCheck", .ordered = &.{ "\"src/smp_cache_enabled_entry.zig\", \"src/arch/x86_64/smp_cache_enabled_probe.S\", null", "host_tools.addRun(b, \"run-smp-cache-enabled-match-smoke\")" } },
        },
    };
    for (contracts) |contract| {
        const body = topLevelFunctionBody(code, tokens.items, contract.function) orelse &.{};
        var offset: usize = 0;
        for (contract.ordered) |pattern| {
            var found = false;
            for (body[offset..], offset..) |_, index| {
                if (codeTokenSequenceLength(code, body[index..], pattern)) |length| {
                    offset = index + length;
                    found = true;
                    break;
                }
            }
            if (!found) try common.addError(errors, allocator, "AP cache {s} evidence must retain actual {s} contract: {s}", .{ @tagName(kind), contract.function, pattern });
        }
    }
    if (kind == .rejection) {
        const callback = topLevelFunctionBody(code, tokens.items, "unexpectedHighEntry") orelse &.{};
        if (codeTokenSequenceLength(code, callback, "const sentinel: *volatile u32 = &high_entry; @atomicStore(u32, sentinel, 1, .release);") == null)
            try common.addError(errors, allocator, "AP rejection callback must publish high entry before any diagnostic or other check", .{});
    }
}

// Exact instruction lines ignore indentation and line comments. Quoted text,
// unrelated labels and comments cannot stand in for an executable sequence.
fn hasAssemblyOrderedLines(source: []const u8, expected: []const []const u8) bool {
    var lines = std.mem.splitScalar(u8, source, '\n');
    var matched: usize = 0;
    var block_comment = false;
    while (lines.next()) |raw_line| {
        var raw = raw_line;
        if (block_comment) {
            const end = std.mem.indexOf(u8, raw, "*/") orelse continue;
            block_comment = false;
            raw = raw[end + 2 ..];
        }
        if (std.mem.indexOf(u8, raw, "/*")) |start| {
            block_comment = std.mem.indexOf(u8, raw[start + 2 ..], "*/") == null;
            raw = raw[0..start];
        }
        const end = std.mem.indexOf(u8, raw, "//") orelse raw.len;
        const line = std.mem.trim(u8, raw[0..end], " \t\r");
        if (!std.mem.eql(u8, line, expected[matched])) continue;
        matched += 1;
        if (matched == expected.len) return true;
    }
    return false;
}

fn hasAssemblyLines(source: []const u8, expected: []const []const u8) bool {
    var lines = std.mem.splitScalar(u8, source, '\n');
    var matched: usize = 0;
    while (lines.next()) |raw| {
        const end = std.mem.indexOf(u8, raw, "//") orelse raw.len;
        const line = std.mem.trim(u8, raw[0..end], " \t\r");
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, expected[matched])) {
            matched += 1;
            if (matched == expected.len) return true;
        } else matched = @intFromBool(std.mem.eql(u8, line, expected[0]));
    }
    return false;
}

fn validateEnabledApCacheAssemblySource(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8), proof: []const u8, macro: []const u8) !void {
    const proof_sequences = [_][]const []const u8{
        &.{ "zigos_arch_smp_cache_first_call:", "call zigos_arch_smp_cache_initialize" },
        &.{ "call .Lproof_require_enabled", "mfence", "movl $1, (zigos_arch_smp_cache_result - zigos_arch_smp_cache_start + PROOF_STATUS_OFFSET)(%esi)", "zigos_arch_smp_cache_second_call:", "call zigos_arch_smp_cache_initialize" },
        &.{ "call .Lproof_capture_snapshot", "mfence", "movl $2, (zigos_arch_smp_cache_result - zigos_arch_smp_cache_start + PROOF_STATUS_OFFSET)(%esi)" },
        &.{ "zigos_arch_smp_cache_initialize:", "ZIGOS_INITIALIZE_AP_MTRRS .Lproof_rejected, (zigos_arch_smp_cache_snapshot - zigos_arch_smp_cache_start), zigos_arch_smp_cache_start", "ret" },
        &.{ "testl $ZIGOS_MTRR_ENABLE, %eax", "jz .Lproof_invalid_controls", "cmpl ZIGOS_MTRR_DEFAULT_OFFSET(%ebp), %eax" },
        &.{ "#define PROOF_STATUS_OFFSET 672", "#define PROOF_RESULT_BYTES 680" },
        &.{ ".org zigos_arch_smp_cache_start + 3968, 0", "zigos_arch_smp_cache_end:" },
    };
    for (proof_sequences) |sequence| {
        if (!hasAssemblyLines(proof, sequence)) try common.addError(errors, allocator, "enabled AP cache evidence must retain actual assembly sequence beginning {s}", .{sequence[0]});
    }
    if (hasAssemblyLines(proof, &.{"wrmsr"}))
        try common.addError(errors, allocator, "enabled AP cache fixture must not add an MTRR writer outside the shared macro", .{});
    const macro_sequences = [_][]const []const u8{
        &.{ "testl $ZIGOS_MTRR_ENABLE, %eax", "jz .Lmtrr_repair\\@" },
        &.{ "call .Lmtrr_compare\\@", "ZIGOS_ENABLE_AP_CACHES \\reject", "jmp .Lmtrr_done\\@" },
        &.{ ".Lmtrr_compare\\@:", "xorl %edi, %edi", ".Lmtrr_registers\\@:", "pushl %edi" },
        &.{ "cmpl $0, (%esp)", "je .Lmtrr_fixed_read\\@" },
        &.{ ".Lmtrr_fixed_read\\@:", "rdmsr" },
        &.{ "cmpl $0, (%esp)", "je .Lmtrr_variable_read\\@" },
        &.{ ".Lmtrr_variable_read\\@:", "rdmsr" },
        &.{ ".Lmtrr_registers_done\\@:", "addl $4, %esp", "ret" },
    };
    for (macro_sequences) |sequence| {
        if (!hasAssemblyLines(macro, sequence)) try common.addError(errors, allocator, "enabled AP cache macro must retain its read-only path beginning {s}", .{sequence[0]});
    }
}

fn validateProductionBootFlags(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    path: []const u8,
    source: []const u8,
) !void {
    for ([_][]const u8{ "model_inventory", "qemu_software_cpu_fallback", "qemu_tsc_frequency_hz" }) |flag| {
        if (std.mem.indexOf(u8, source, flag) != null) {
            try common.addError(errors, allocator, "production boot defaults must not enable modeled hardware or a fabricated clock ({s}): {s}", .{ path, flag });
        }
    }
}

fn isOneOf(value: []const u8, allowed: []const []const u8) bool {
    for (allowed) |candidate| {
        if (std.mem.eql(u8, value, candidate)) return true;
    }
    return false;
}

test "production boot defaults reject modeled hardware and fixed clock overrides" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    for ([_][]const u8{
        "model_inventory",
        "qemu_tsc_frequency_hz=2400000000",
        "qemu_software_cpu_fallback",
        "multiboot2 /boot/kernel.elf model_inventory qemu_tsc_frequency_hz=2400000000",
    }) |source| {
        var errors = std.ArrayList([]const u8).empty;
        try validateProductionBootFlags(allocator, &errors, "production boot fixture", source);
        try std.testing.expect(errors.items.len > 0);
    }
    for ([_][]const u8{ "", "\n", "multiboot2 /boot/kernel.elf\nboot\n" }) |source| {
        var errors = std.ArrayList([]const u8).empty;
        try validateProductionBootFlags(allocator, &errors, "production boot fixture", source);
        try std.testing.expectEqual(@as(usize, 0), errors.items.len);
    }
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

test "KVM baseline policy rejects loose regression allowances" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var errors = std.ArrayList([]const u8).empty;
    try validateKvmBaselineAllowances(
        arena_state.allocator(),
        &errors,
        "bench.tight 10.00 50\nbench.loose 10.00 51\n",
    );
    try std.testing.expectEqual(@as(usize, 1), errors.items.len);
    try std.testing.expect(std.mem.indexOf(u8, errors.items[0], "exceeds the 50 percent") != null);
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
        "# ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:UEFI_BOOT:PASS\n" ++
        "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ACPI_TABLES:PASS\n";

    try std.testing.expect(!markerFileHasActiveLine(source, "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:UEFI_BOOT:PASS"));
    try std.testing.expect(markerFileHasActiveLine(source, "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:ACPI_TABLES:PASS"));
}

test "hardware marker lookup requires a complete active line" {
    const source = "prefix ZIGOS:NATIVE:READY suffix\nZIGOS:NATIVE:READY_EXTRA\n";
    try std.testing.expect(!markerFileHasActiveLine(source, "ZIGOS:NATIVE:READY"));
}

test "native scheduler source gate accepts the actual bound wake helper and idle deadlines" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/boot/profiles/zigos_native.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var errors = std.ArrayList([]const u8).empty;
    try validateNativeSchedulerLoopSource(arena.allocator(), &errors, source);
    try std.testing.expectEqual(@as(usize, 0), errors.items.len);
}

test "x2APIC publication source gate accepts the actual native write and hosted observer" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/interrupts/x2apic.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var errors = std.ArrayList([]const u8).empty;
    try validateX2apicIpiPublicationSource(arena.allocator(), &errors, source);
    try std.testing.expectEqual(@as(usize, 0), errors.items.len);
}

test "x2APIC publication source gate rejects reordered writes bypasses and resident observers" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/interrupts/x2apic.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    const mutations = [_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "mfence; lfence", .replacement = "lfence" },
        .{ .needle = "pub fn sendIpi(command: Icr) void {", .replacement = "pub fn sendIpi(command: Icr) void {\n    writeApicMsr(X2APIC_ICR_MSR, icrValue(command));" },
        .{ .needle = "writeApicMsr(X2APIC_ICR_MSR, icrValue(command));", .replacement = "return; writeApicMsr(X2APIC_ICR_MSR, icrValue(command));" },
        .{ .needle = "x86.writeMsr(msr, value);", .replacement = "ignoreNativeWrite(msr, value);" },
        .{ .needle = "inline fn writeApicMsr(msr: u32, value: u64) void {", .replacement = "inline fn writeApicMsr(msr: u32, value: u64) void { return;" },
        .{ .needle = "if (comptime builtin.is_test and builtin.target.os.tag != .freestanding)", .replacement = "if (comptime builtin.is_test or builtin.target.os.tag == .freestanding)" },
        .{ .needle = "pub const Testing = if (builtin.is_test and builtin.target.os.tag != .freestanding)", .replacement = "pub const Testing = if (true)" },
        .{ .needle = "} else struct {};", .replacement = "} else struct { var observer: usize = 0; };" },
    };
    for (mutations) |mutation| {
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        const altered = try std.mem.replaceOwned(u8, allocator, source, mutation.needle, mutation.replacement);
        const comment = try std.mem.replaceOwned(u8, allocator, mutation.needle, "\n", "\n// ");
        const quoted = try std.json.Stringify.valueAlloc(allocator, mutation.needle, .{});
        const with_decoys = try std.fmt.allocPrint(allocator, "// {s}\nconst ipi_gate_quoted_decoy = {s};\n{s}", .{ comment, quoted, altered });
        var errors = std.ArrayList([]const u8).empty;
        try validateX2apicIpiPublicationSource(allocator, &errors, with_decoys);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "CPU timer source gate accepts actual timer register ownership ISR and AP ordering" {
    const paths = [_][]const u8{ "src/kernel/timer/timer.zig", "src/kernel/interrupts/isr.zig", "src/kernel/smp_bringup.zig" };
    for (paths, [_]CpuTimerSourceKind{ .timer, .isr, .ap }) |path, kind| {
        const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, path, common.source_file_max_bytes);
        defer std.testing.allocator.free(source);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var errors = std.ArrayList([]const u8).empty;
        try validateCpuTimerSource(arena.allocator(), &errors, source, kind);
        if (errors.items.len != 0) common.printErrors(errors.items);
        try std.testing.expectEqual(@as(usize, 0), errors.items.len);
    }
}

fn expectCpuTimerMutationRejected(source: []const u8, kind: CpuTimerSourceKind, needle: []const u8, replacement: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, source, needle) != null);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const altered = try std.mem.replaceOwned(u8, allocator, source, needle, replacement);
    // Keeping the original text both commented and quoted must not rescue a
    // missing production guard, writer or owner. Token locations stay scoped
    // to the actual production function/container rather than these decoys.
    const comment = try std.mem.replaceOwned(u8, allocator, needle, "\n", "\n// ");
    const quoted = try std.json.Stringify.valueAlloc(allocator, needle, .{});
    const with_decoys = try std.fmt.allocPrint(allocator, "// {s}\nconst timer_gate_quoted_decoy = {s};\n{s}", .{ comment, quoted, altered });
    var errors = std.ArrayList([]const u8).empty;
    try validateCpuTimerSource(allocator, &errors, with_decoys, kind);
    if (errors.items.len == 0) std.debug.print("timer mutation escaped: {s}\n", .{needle});
    try std.testing.expect(errors.items.len != 0);
}

test "CPU timer source gate rejects lost native writes clock admission and owner isolation" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/timer/timer.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    const mutations = [_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "x86.writeMsr(msr, value)", .replacement = "ignoreTimerWrite(msr, value)" },
        .{ .needle = "else if (builtin.target.os.tag == .freestanding) x86.writeMsr", .replacement = "else if (builtin.target.os.tag == .linux) x86.writeMsr" },
        .{ .needle = "features.tsc_frequency_hz != clock_authority.frequency_hz", .replacement = "features.tsc_frequency_hz / TICKS_PER_SECOND != clock_authority.per_tick" },
        .{ .needle = "!features.tsc_deadline or !features.invariant_tsc", .replacement = "!features.tsc_deadline" },
        .{ .needle = "!features.tsc_deadline or !features.invariant_tsc", .replacement = "!features.invariant_tsc" },
        .{ .needle = "features.tsc_frequency_hz / TICKS_PER_SECOND == 0", .replacement = "false" },
        .{ .needle = "currentState().initialized or", .replacement = "false or" },
        .{ .needle = "cpu_identity.currentIndex() != 0 or", .replacement = "false or" },
        .{ .needle = "cpu_identity.currentIndex() == 0 or", .replacement = "false or" },
        .{ .needle = "@atomicLoad(bool, &clock_ready, .acquire)", .replacement = "@atomicLoad(bool, &clock_ready, .monotonic)" },
        .{ .needle = "@atomicStore(bool, &clock_ready, true, .release)", .replacement = "@atomicStore(bool, &clock_ready, true, .monotonic)" },
        .{ .needle = "X2APIC_TIMER_MASKED | INTERRUPT_VECTOR |", .replacement = "INTERRUPT_VECTOR |" },
        .{ .needle = "Hardware.write(X2APIC_TIMER_INITIAL_COUNT_MSR, 0)", .replacement = "Hardware.write(X2APIC_TIMER_INITIAL_COUNT_MSR, 1)" },
        .{ .needle = "if (features.tsc_deadline) Hardware.write(IA32_TSC_DEADLINE_MSR, 0);", .replacement = "Hardware.write(IA32_TSC_DEADLINE_MSR, 0);" },
        .{ .needle = "return &cpu_states[cpu_identity.currentIndex()];", .replacement = "return &cpu_states[0];" },
        .{ .needle = "[cpu_identity.MAX_CPUS]TimerState align(64)", .replacement = "[1]TimerState align(64)" },
        .{ .needle = "TimerState align(64)", .replacement = "TimerState align(8)" },
        .{ .needle = "@sizeOf(TimerState) != 64", .replacement = "@sizeOf(TimerState) != 8" },
        .{ .needle = "pub const Testing = if (builtin.is_test) struct", .replacement = "pub const Testing = if (true) struct" },
        .{ .needle = "pub fn getTicks()", .replacement = "fn resetClock() void { clock_authority.epoch = 0; }\npub fn getTicks()" },
        .{ .needle = "pub fn getTicks()", .replacement = "fn resetClock() void { clock_authority = .{}; }\npub fn getTicks()" },
        .{ .needle = "pub fn getTicks()", .replacement = "fn reopenClock() void { @atomicStore(bool, &clock_ready, false, .release); }\npub fn getTicks()" },
    };
    for (mutations) |mutation| try expectCpuTimerMutationRejected(source, .timer, mutation.needle, mutation.replacement);
}

test "CPU timer source gate rejects IRQ races duplicate EOI and shared cached getters" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/timer/timer.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    const mutations = [_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "const guard = InterruptGuard.enter();", .replacement = "const guard = InterruptGuard{ .enabled = false };" },
        .{ .needle = "defer guard.leave();", .replacement = "// defer guard.leave();" },
        .{ .needle = "Hardware.disableInterrupts();", .replacement = "// Hardware.disableInterrupts();" },
        .{ .needle = "Hardware.restoreInterrupts(self.enabled);", .replacement = "Hardware.restoreInterrupts(true);" },
        .{ .needle = "x86.cli();", .replacement = "ignoreInterruptMask();" },
        .{ .needle = "x86.sti();", .replacement = "ignoreInterruptRestore();" },
        .{ .needle = "if (!enabled) return;", .replacement = "if (false) return;" },
        .{ .needle = "Hardware.acknowledge();", .replacement = "Hardware.acknowledge(); Hardware.acknowledge();" },
        .{ .needle = "x2apic.acknowledge();", .replacement = "ignoreEoi();" },
        .{ .needle = "state.scheduler_tick_enabled = false;", .replacement = "state.scheduler_tick_enabled = true;" },
        .{ .needle = "return @atomicLoad(u64, &currentState().ticks, .monotonic);", .replacement = "return currentState().ticks;" },
        .{ .needle = "return @atomicLoad(u64, &currentState().ticks, .monotonic);", .replacement = "return @atomicLoad(u64, &cpu_states[0].ticks, .monotonic);" },
        .{ .needle = "Hardware.write(IA32_TSC_DEADLINE_MSR, nextTickDeadline(clock_authority.epoch, now, clock_authority.per_tick));", .replacement = "return; Hardware.write(IA32_TSC_DEADLINE_MSR, nextTickDeadline(clock_authority.epoch, now, clock_authority.per_tick));" },
        .{ .needle = ".calibrated_countdown => initCalibratedCountdownTimer(),", .replacement = ".calibrated_countdown => {}," },
    };
    for (mutations) |mutation| try expectCpuTimerMutationRejected(source, .timer, mutation.needle, mutation.replacement);
}

test "CPU timer source gate rejects adapter early returns and bypasses outside the test branch" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/timer/timer.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    for ([_]struct { signature: []const u8, skipped_return: []const u8 }{
        .{ .signature = "inline fn available() bool {", .skipped_return = "false" },
        .{ .signature = "inline fn counter() u64 {", .skipped_return = "0" },
        .{ .signature = "inline fn interruptsEnabled() bool {", .skipped_return = "false" },
        .{ .signature = "inline fn disableInterrupts() void {", .skipped_return = "" },
        .{ .signature = "inline fn restoreInterrupts(enabled: bool) void {", .skipped_return = "" },
        .{ .signature = "inline fn write(msr: u32, value: u64) void {", .skipped_return = "" },
        .{ .signature = "inline fn readCurrentCount() u64 {", .skipped_return = "0" },
        .{ .signature = "inline fn enableApic() void {", .skipped_return = "" },
        .{ .signature = "inline fn acknowledge() void {", .skipped_return = "" },
    }) |mutation| {
        const replacement = try std.fmt.allocPrint(std.testing.allocator, "{s}\n        if (cpu_identity.currentIndex() == 0) return {s};", .{ mutation.signature, mutation.skipped_return });
        defer std.testing.allocator.free(replacement);
        try expectCpuTimerMutationRejected(source, .timer, mutation.signature, replacement);
    }
    for ([_]struct { needle: []const u8, replacement: []const u8 }{
        .{
            .needle = "return if (builtin.target.os.tag == .freestanding) x86.rdtsc() else 0;",
            .replacement = "if (cpu_identity.currentIndex() == 0) return 0; return if (builtin.target.os.tag == .freestanding) x86.rdtsc() else 0;",
        },
        .{
            .needle = "return if (builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;",
            .replacement = "if (cpu_identity.currentIndex() == 0) return false; return if (builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;",
        },
        .{
            .needle = "return if (builtin.target.os.tag == .freestanding) x86.readMsr(X2APIC_TIMER_CURRENT_COUNT_MSR) else 0;",
            .replacement = "if (cpu_identity.currentIndex() == 0) return 0; return if (builtin.target.os.tag == .freestanding) x86.readMsr(X2APIC_TIMER_CURRENT_COUNT_MSR) else 0;",
        },
        .{ .needle = "if (builtin.is_test) {", .replacement = "if (builtin.is_test or cpu_identity.currentIndex() == 0) {" },
    }) |mutation| try expectCpuTimerMutationRejected(source, .timer, mutation.needle, mutation.replacement);
}

test "CPU timer source gate rejects AP early publication and unguarded shared ISR wakes" {
    const ap = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/smp_bringup.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(ap);
    const ap_mutations = [_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "if (!timer.initApplicationProcessor(features))", .replacement = "if (false)" },
        .{ .needle = "TIMER_ADMISSION_REJECTED, .release);\n        park();", .replacement = "TIMER_ADMISSION_REJECTED, .release);\n        return;" },
        .{ .needle = "    x2apic.enable();", .replacement = "    @atomicStore(bool, &bringup_cpus[index].online, true, .release);\n    x2apic.enable();" },
        .{ .needle = "idt.init();", .replacement = "// idt.init();" },
        .{ .needle = "idt.init();", .replacement = "if (false) idt.init();" },
        .{ .needle = "idt.init();", .replacement = "if (false) { idt.init(); }" },
        .{ .needle = "syscall64.initApplicationProcessor(index, bringup_cpus[index].kernel_stack_top);", .replacement = "// syscall64.initApplicationProcessor(index, bringup_cpus[index].kernel_stack_top);" },
        .{ .needle = "syscall64.initApplicationProcessor(index, bringup_cpus[index].kernel_stack_top);", .replacement = "if (false) syscall64.initApplicationProcessor(index, bringup_cpus[index].kernel_stack_top);" },
        .{ .needle = "syscall64.initApplicationProcessor(index, bringup_cpus[index].kernel_stack_top);", .replacement = "if (false) { syscall64.initApplicationProcessor(index, bringup_cpus[index].kernel_stack_top); }" },
        .{ .needle = "cpu_identity.initialize(index);", .replacement = "if (false) cpu_identity.initialize(index);" },
        .{ .needle = "const detected_features = cpu_features.detect();", .replacement = "return; const detected_features = cpu_features.detect();" },
        .{ .needle = "@atomicStore(bool, &bringup_cpus[index].online, true, .release)", .replacement = "@atomicStore(bool, &bringup_cpus[index].online, true, .monotonic)" },
    };
    for (ap_mutations) |mutation| try expectCpuTimerMutationRejected(ap, .ap, mutation.needle, mutation.replacement);
    const isr = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/interrupts/isr.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(isr);
    for ([_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "if (cpu_identity.currentIndex() == 0)", .replacement = "if (true)" },
        .{ .needle = "if (cpu_identity.currentIndex() == 0)", .replacement = "if (cpu_identity.currentIndex() != 0)" },
        .{ .needle = "    timer.handleInterrupt();", .replacement = "    // timer.handleInterrupt();" },
        .{ .needle = "event_wake.raise(.timer);", .replacement = "{}" },
    }) |mutation| try expectCpuTimerMutationRejected(isr, .isr, mutation.needle, mutation.replacement);
}

test "boot arena retirement source gate accepts the actual verified boot sequence" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/memory/paging64.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var errors = std.ArrayList([]const u8).empty;
    try validateBootArenaRetirementSource(arena.allocator(), &errors, source);
    try std.testing.expectEqual(@as(usize, 0), errors.items.len);
}

test "boot arena retirement source gate accepts complete ownership preflight before mutations" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/memory/firmware_memory_map.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var errors = std.ArrayList([]const u8).empty;
    try validateBootArenaRetirementPreflightSource(arena.allocator(), &errors, source);
    try std.testing.expectEqual(@as(usize, 0), errors.items.len);
}

test "boot arena retirement source gate rejects weakened provenance prefix and reservation preflight" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/memory/firmware_memory_map.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    const mutations = [_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "entry.firmware_type != 2", .replacement = "entry.firmware_type != 7" },
        .{ .needle = "used_final_pages < 3", .replacement = "used_final_pages == 0" },
        .{ .needle = "used_final_pages > arenas.final_pages", .replacement = "used_final_pages > paging_info.MAX_ARENA_PAGES" },
        .{ .needle = "if (allocator.reservations_sealed) return error.ReservationsSealed;", .replacement = "// if (allocator.reservations_sealed) return error.ReservationsSealed;" },
        .{ .needle = "if (!allocator.isReserved(run.base + offset)) return error.FrameReserved;", .replacement = "if (false) return error.FrameReserved;" },
        .{ .needle = "if (tail.count != 0) try allocator.validateReservation(tail);", .replacement = "// if (tail.count != 0) try allocator.validateReservation(tail);" },
    };
    for (mutations) |mutation| {
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const altered = try std.mem.replaceOwned(u8, arena.allocator(), source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateBootArenaRetirementPreflightSource(arena.allocator(), &errors, altered);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "AP cache source gate accepts actual probes support harness build and shared read-only assembly" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var errors = std.ArrayList([]const u8).empty;
    for ([_]struct { path: []const u8, kind: ApCacheProbeSourceKind }{
        .{ .path = "src/arch/x86_64/smp_cache_enabled_probe.zig", .kind = .enabled },
        .{ .path = "src/arch/x86_64/ap_cache_rejection_probe.zig", .kind = .rejection },
        .{ .path = "src/arch/x86_64/ap_cache_probe_support.zig", .kind = .support },
        .{ .path = "tools/host/qemu.zig", .kind = .harness },
        .{ .path = "build_support/kernel.zig", .kind = .build },
    }) |contract| {
        const source = try common.readFileAlloc(arena.allocator(), std.testing.io, contract.path, common.source_file_max_bytes);
        try validateApCacheProbeSource(arena.allocator(), &errors, source, contract.kind);
    }
    const proof = try common.readFileAlloc(arena.allocator(), std.testing.io, "src/arch/x86_64/smp_cache_enabled_probe.S", common.source_file_max_bytes);
    const macro = try common.readFileAlloc(arena.allocator(), std.testing.io, "src/arch/x86_64/mtrr_bootstrap.inc", common.source_file_max_bytes);
    try validateEnabledApCacheAssemblySource(arena.allocator(), &errors, proof, macro);
    try std.testing.expectEqual(@as(usize, 0), errors.items.len);
}

test "AP cache source gate rejects missing independent enabled controls snapshot and publication" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/arch/x86_64/smp_cache_enabled_probe.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    for ([_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "support.waitForPhase(&result.status, 2);", .replacement = "// stale phase" },
        .{ .needle = "const actual = observed.observed;", .replacement = "const actual = expected;" },
        .{ .needle = "record.default_type & cache.MTRR_ENABLED != 0", .replacement = "true" },
        .{ .needle = "record.flags & (1 << 9) == 0", .replacement = "true" },
        .{ .needle = "std.mem.asBytes(actual)", .replacement = "std.mem.asBytes(expected)" },
        .{ .needle = "support.publish(page);", .replacement = "// stale code/payload" },
    }) |mutation| {
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const altered = try std.mem.replaceOwned(u8, arena.allocator(), source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateApCacheProbeSource(arena.allocator(), &errors, altered, .enabled);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "AP cache source gate rejects a late sentinel unobserved entry wrong faults and missing control" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/arch/x86_64/ap_cache_rejection_probe.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    for ([_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "@atomicStore(u32, sentinel, 1, .release);", .replacement = "support.pass(\"forged diagnostic\"); @atomicStore(u32, sentinel, 1, .release);" },
        .{ .needle = "@atomicLoad(u32, sentinel, .acquire)", .replacement = "0" },
        .{ .needle = "support.pass(\"CONTROL_HIGH_ENTRY\");", .replacement = "// missing uncorrupted control" },
        .{ .needle = "support.prepareBridge(&unexpectedHighEntry)", .replacement = "support.prepareBridge(&otherEntry)" },
        .{ .needle = "original | (1 << 12)", .replacement = "original | (1 << 11)" },
        .{ .needle = "original | 1", .replacement = "original" },
        .{ .needle = "publishPage(trampoline);", .replacement = "// mutation remains dirty" },
    }) |mutation| {
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const altered = try std.mem.replaceOwned(u8, arena.allocator(), source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateApCacheProbeSource(arena.allocator(), &errors, altered, .rejection);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "AP cache source gate rejects unbounded wait reset and weakened exact evidence validation" {
    for ([_]struct { path: []const u8, kind: ApCacheProbeSourceKind, needle: []const u8, replacement: []const u8 }{
        .{ .path = "src/arch/x86_64/ap_cache_probe_support.zig", .kind = .support, .needle = "clock.afterMilliseconds(2000)", .replacement = "clock.afterMilliseconds(0)" },
        .{ .path = "src/arch/x86_64/ap_cache_probe_support.zig", .kind = .support, .needle = "launchPhysical(page.physical);", .replacement = "prepareAp();" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "if (!log.healthy(bytes, \"FAIL\"))", .replacement = "if (false)" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "if (observed >= 2 or !std.mem.eql(u8, line, if (observed == 0) apCacheFirst(case) else apCacheLast(case)))", .replacement = "if (false)" },
        .{ .path = "tools/host/qemu.zig", .kind = .harness, .needle = "if (observed != 2) return error.MissingApCacheEvidence;", .replacement = "// accept absence" },
        .{ .path = "build_support/kernel.zig", .kind = .build, .needle = "ApCacheFault.none, ApCacheFault.version,", .replacement = "ApCacheFault.version," },
    }) |mutation| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const source = try common.readFileAlloc(arena.allocator(), std.testing.io, mutation.path, common.source_file_max_bytes);
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        const altered = try std.mem.replaceOwned(u8, arena.allocator(), source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateApCacheProbeSource(arena.allocator(), &errors, altered, mutation.kind);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "AP cache source gate rejects a second writer missing enabled precheck and broken read-only mode" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const proof = try common.readFileAlloc(arena.allocator(), std.testing.io, "src/arch/x86_64/smp_cache_enabled_probe.S", common.source_file_max_bytes);
    const macro = try common.readFileAlloc(arena.allocator(), std.testing.io, "src/arch/x86_64/mtrr_bootstrap.inc", common.source_file_max_bytes);
    for ([_]struct { in_macro: bool = false, needle: []const u8, replacement: []const u8 }{
        .{ .needle = "zigos_arch_smp_cache_second_call:\n    call zigos_arch_smp_cache_initialize", .replacement = "zigos_arch_smp_cache_second_call:\n    wrmsr\n    call zigos_arch_smp_cache_initialize" },
        .{ .needle = "    call .Lproof_require_enabled\n", .replacement = "    // quoted call .Lproof_require_enabled\n" },
        .{ .needle = "    call .Lproof_capture_snapshot\n", .replacement = "    // skip independent readback\n" },
        .{ .in_macro = true, .needle = ".Lmtrr_compare\\@:\n    xorl %edi, %edi", .replacement = ".Lmtrr_compare\\@:\n    movl $1, %edi" },
        .{ .in_macro = true, .needle = "    je .Lmtrr_fixed_read\\@", .replacement = "    jne .Lmtrr_fixed_read\\@" },
        .{ .in_macro = true, .needle = "    je .Lmtrr_variable_read\\@", .replacement = "    jne .Lmtrr_variable_read\\@" },
    }) |mutation| {
        const original = if (mutation.in_macro) macro else proof;
        try std.testing.expect(std.mem.indexOf(u8, original, mutation.needle) != null);
        const altered = try std.mem.replaceOwned(u8, arena.allocator(), original, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateEnabledApCacheAssemblySource(arena.allocator(), &errors, if (mutation.in_macro) proof else altered, if (mutation.in_macro) altered else macro);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "count-sized EFI arena source gate accepts actual sizing exit retry and helper paths" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/boot/efi_stub.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var errors = std.ArrayList([]const u8).empty;
    try validateCountSizedEfiArenaSource(arena.allocator(), &errors, source);
    try std.testing.expectEqual(@as(usize, 0), errors.items.len);
}

test "count-sized EFI arena source gate rejects fixed seeds stale retry count and post-exit allocation" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/boot/efi_stub.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    const mutations = [_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "PAGING_SIZING_ATTEMPTS: usize = 8", .replacement = "PAGING_SIZING_ATTEMPTS: usize = 80" },
        .{ .needle = "var bootstrap_pages: ?[]align(4096) uefi.Page = null;", .replacement = "var bootstrap_pages: ?[]align(4096) uefi.Page = allocatePagingArena(boot, efi_paging.MAX_PAGE_COUNT, cache_view, framebuffer_span) catch return .out_of_resources;" },
        .{ .needle = "captureMemoryMap(map_slice, &mmap_entries, paging_info, framebuffer_span)", .replacement = "captureMemoryMap(stale_map, &mmap_entries, paging_info, framebuffer_span)" },
        .{ .needle = "allocatePagingArena(boot, needed.final, cache_view, framebuffer_span)", .replacement = "allocatePagingArena(boot, needed.transition, cache_view, framebuffer_span)" },
        .{ .needle = ".transition_pages = @intCast(bootstrap_pages.?.len)", .replacement = ".transition_pages = efi_paging.MAX_PAGE_COUNT" },
        .{ .needle = "countPagingArenas(transition_mode, image, request.mmap, cache_view, boot_image.heap_base, framebuffer_span)", .replacement = "countPagingArenas(transition_mode, image, stale_entries, cache_view, boot_image.heap_base, framebuffer_span)" },
        .{ .needle = "if (!needed.fits(arenas.transition_pages, arenas.final_pages))", .replacement = "if (false)" },
        .{ .needle = "firmware_console_available = false;", .replacement = "// firmware_console_available = false;" },
        .{ .needle = "for (0..2) |attempt| {", .replacement = "for (0..2) |attempt| { _ = allocateMapBuffer(boot, cache_view, framebuffer_span);" },
        .{ .needle = "if (mode != .native_high) try efi_paging.countForModeInto(.native_high, image, entries, cache, heap_base, framebuffer_span, &final);", .replacement = "// omitted final native count" },
        .{ .needle = ".loader_data, count);", .replacement = ".loader_data, efi_paging.MAX_PAGE_COUNT);" },
        .{ .needle = "if (!firmware_console_available) return status;", .replacement = "// unconditional firmware console" },
    };
    for (mutations) |mutation| {
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const altered = try std.mem.replaceOwned(u8, arena.allocator(), source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateCountSizedEfiArenaSource(arena.allocator(), &errors, altered);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "count-sized EFI arena source gate accepts required v3 and actual capacity consumers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var errors = std.ArrayList([]const u8).empty;
    const metadata = try common.readFileAlloc(arena.allocator(), std.testing.io, "src/boot/paging_info.zig", common.source_file_max_bytes);
    const transition = try common.readFileAlloc(arena.allocator(), std.testing.io, "src/boot/efi_paging.zig", common.source_file_max_bytes);
    const final = try common.readFileAlloc(arena.allocator(), std.testing.io, "src/kernel/memory/paging64.zig", common.source_file_max_bytes);
    try validatePagingArenaCapacitySource(arena.allocator(), &errors, metadata, .metadata);
    try validatePagingArenaCapacitySource(arena.allocator(), &errors, transition, .transition);
    try validatePagingArenaCapacitySource(arena.allocator(), &errors, final, .final);
    try std.testing.expectEqual(@as(usize, 0), errors.items.len);
}

test "count-sized EFI arena source gate rejects weakened wire version counts and reserved fields" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/boot/paging_info.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    const mutations = [_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "PAYLOAD_BYTES: usize = 48", .replacement = "PAYLOAD_BYTES: usize = 40" },
        .{ .needle = "MAX_ARENA_PAGES: u32 = 4096", .replacement = "MAX_ARENA_PAGES: u32 = 8192" },
        .{ .needle = "self.transition_pages < 3", .replacement = "self.transition_pages == 0" },
        .{ .needle = "self.final_pages > MAX_ARENA_PAGES", .replacement = "false" },
        .{ .needle = "bytes.writeU32Le(out[8..12], self.final_pages)", .replacement = "bytes.writeU32Le(out[8..12], self.transition_pages)" },
        .{ .needle = "bytes.readU32Le(source[0..4]) != 3", .replacement = "bytes.readU32Le(source[0..4]) != 2" },
        .{ .needle = "bytes.readU32Le(source[12..16]) != 0", .replacement = "false" },
        .{ .needle = ".final_pages = bytes.readU32Le(source[8..12])", .replacement = ".final_pages = MAX_ARENA_PAGES" },
    };
    for (mutations) |mutation| {
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const altered = try std.mem.replaceOwned(u8, arena.allocator(), source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validatePagingArenaCapacitySource(arena.allocator(), &errors, altered, .metadata);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "count-sized EFI arena source gate rejects fixed or mismatched transition and final capacity" {
    const transition = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/boot/efi_paging.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(transition);
    const final = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/memory/paging64.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(final);
    for ([_][]const u8{
        "try paging_info.validate();",
        "arena.len != paging_info.transition_pages",
        "try sparse.build(tables[0..arena.len]",
    }) |needle| {
        try std.testing.expect(std.mem.indexOf(u8, transition, needle) != null);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const altered = try std.mem.replaceOwned(u8, arena.allocator(), transition, needle, "false");
        var errors = std.ArrayList([]const u8).empty;
        try validatePagingArenaCapacitySource(arena.allocator(), &errors, altered, .transition);
        try std.testing.expect(errors.items.len != 0);
    }
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const altered = try std.mem.replaceOwned(u8, arena.allocator(), final, "tables[0..arenas.final_pages]", "tables[0..efi_handoff.paging_info.MAX_ARENA_PAGES]");
    var errors = std.ArrayList([]const u8).empty;
    try validatePagingArenaCapacitySource(arena.allocator(), &errors, altered, .final);
    try std.testing.expect(errors.items.len != 0);
}

test "boot arena retirement source gate rejects missing global retirement readback and sealing order" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/memory/paging64.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    const mutations = [_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "x86.cli();\n    defer if (restore_interrupts) x86.sti();", .replacement = "defer if (restore_interrupts) x86.sti();" },
        .{ .needle = "if (bootstrap_root != null) haltPagingFailure(.invalid_native_boot_memory_ownership);", .replacement = "// if (bootstrap_root != null) haltPagingFailure(.invalid_native_boot_memory_ownership);" },
        .{ .needle = "x86.writeCr4(previous_cr4 & ~x86.CR4_PGE);", .replacement = "// x86.writeCr4(previous_cr4 & ~x86.CR4_PGE);" },
        .{ .needle = "initializeCurrentKernelRoot();", .replacement = "// initializeCurrentKernelRoot();" },
        .{ .needle = "firmware_memory_map.reclaimBootPagingArenas(", .replacement = "deferred_reclamation(" },
        .{ .needle = "physical_frames.sealReservations()", .replacement = "inherited_reservations()" },
    };
    for (mutations) |mutation| {
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const altered = try std.mem.replaceOwned(u8, arena.allocator(), source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateBootArenaRetirementSource(arena.allocator(), &errors, altered);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "boot arena retirement source gate rejects reclamation before readback or after sealing" {
    const source =
        "pub fn init() void { const restore_interrupts = x86.interruptsEnabled(); " ++
        "x86.cli(); defer if (restore_interrupts) x86.sti(); " ++
        "if (bootstrap_root != null) haltPagingFailure(.invalid_native_boot_memory_ownership); " ++
        "const final_used_pages = initializeKernelHierarchy(); " ++
        "x86.writeCr4(previous_cr4 & ~x86.CR4_PGE); " ++
        "x86.writeCr3(kernel_pml4_physical); x86.writeCr4(previous_cr4); " ++
        "initializeCurrentKernelRoot(); " ++
        "firmware_memory_map.reclaimBootPagingArenas(x86.readCr3() & x86.CR3_ADDRESS_MASK, @intCast(final_used_pages)); " ++
        "physical_frames.sealReservations(); validateHighMemoryDirectMap(); }";
    const mutations = [_]struct { needle: []const u8, replacement: []const u8 }{
        .{
            .needle = "initializeCurrentKernelRoot(); firmware_memory_map.reclaimBootPagingArenas(x86.readCr3() & x86.CR3_ADDRESS_MASK, @intCast(final_used_pages));",
            .replacement = "firmware_memory_map.reclaimBootPagingArenas(x86.readCr3() & x86.CR3_ADDRESS_MASK, @intCast(final_used_pages)); initializeCurrentKernelRoot();",
        },
        .{
            .needle = "firmware_memory_map.reclaimBootPagingArenas(x86.readCr3() & x86.CR3_ADDRESS_MASK, @intCast(final_used_pages)); physical_frames.sealReservations();",
            .replacement = "physical_frames.sealReservations(); firmware_memory_map.reclaimBootPagingArenas(x86.readCr3() & x86.CR3_ADDRESS_MASK, @intCast(final_used_pages));",
        },
        .{
            .needle = "physical_frames.sealReservations(); validateHighMemoryDirectMap();",
            .replacement = "validateHighMemoryDirectMap(); physical_frames.sealReservations();",
        },
    };
    var baseline = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer baseline.deinit();
    var baseline_errors = std.ArrayList([]const u8).empty;
    try validateBootArenaRetirementSource(baseline.allocator(), &baseline_errors, source);
    try std.testing.expectEqual(@as(usize, 0), baseline_errors.items.len);
    for (mutations) |mutation| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const altered = try std.mem.replaceOwned(u8, arena.allocator(), source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateBootArenaRetirementSource(arena.allocator(), &errors, altered);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "boot arena retirement source gate ignores test-only and quoted retirement calls" {
    const source =
        "pub fn init() void { const restore_interrupts = x86.interruptsEnabled(); " ++
        "x86.cli(); defer if (restore_interrupts) x86.sti(); " ++
        "if (bootstrap_root != null) haltPagingFailure(.invalid_native_boot_memory_ownership); " ++
        "const final_used_pages = initializeKernelHierarchy(); " ++
        "x86.writeCr4(previous_cr4 & ~x86.CR4_PGE); " ++
        "x86.writeCr3(kernel_pml4_physical); x86.writeCr4(previous_cr4); " ++
        "initializeCurrentKernelRoot(); " ++
        "const diagnostic = \"firmware_memory_map.reclaimBootPagingArenas(\"; " ++
        "physical_frames.sealReservations(); validateHighMemoryDirectMap(); } " ++
        "test \"unrelated retirement fixture\" { firmware_memory_map.reclaimBootPagingArenas(); }";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var errors = std.ArrayList([]const u8).empty;
    try validateBootArenaRetirementSource(arena.allocator(), &errors, source);
    try std.testing.expect(errors.items.len != 0);
    try std.testing.expect(std.mem.indexOf(u8, errors.items[0], "ordered executable step: firmware_memory_map.reclaimBootPagingArenas(") != null);
}

test "native scheduler source gate rejects broken driver binding pending predicate and idle deadlines" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/boot/profiles/zigos_native.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    const mutations = [_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "wakeBoundXhciTask(xhci_driver_task, session_manager, pending, now_ticks);", .replacement = "wakeBoundXhciTask(other_driver, session_manager, pending, now_ticks);" },
        .{ .needle = "pending.timer and driver.workPending()", .replacement = "pending.timer" },
        .{ .needle = "pending.xhci or (pending.timer", .replacement = "false or (pending.timer" },
        .{ .needle = "driver.boundTaskId()", .replacement = "unrelatedTaskId()" },
        .{ .needle = "if (bound_task_id != 0)", .replacement = "if (true)" },
        .{ .needle = "timer.armWakeAt(deadline);", .replacement = "timer.disarmSchedulerTick();" },
        .{ .needle = "session_manager.system().serviceAuthenticationClock(now_ticks);", .replacement = "{}" },
    };
    for (mutations) |mutation| {
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const altered = try std.mem.replaceOwned(u8, arena.allocator(), source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateNativeSchedulerLoopSource(arena.allocator(), &errors, altered);
        try std.testing.expect(errors.items.len != 0);
    }
}

test "native scheduler source gate ignores comments quoted calls and unreachable helper bodies" {
    const source = try common.readFileAlloc(std.testing.allocator, std.testing.io, "src/kernel/boot/profiles/zigos_native.zig", common.source_file_max_bytes);
    defer std.testing.allocator.free(source);
    const call = "wakeBoundXhciTask(xhci_driver_task, session_manager, pending, now_ticks);";
    const mutations = [_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = call, .replacement = "// " ++ call },
        .{ .needle = call, .replacement = "_ = \"" ++ call ++ "\";" },
        .{ .needle = call, .replacement = "{}" },
        .{ .needle = "if (pending.xhci or (pending.timer and driver.workPending()))", .replacement = "return; if (pending.xhci or (pending.timer and driver.workPending()))" },
        .{
            .needle = "    if (pending.xhci or (pending.timer and driver.workPending())) {\n" ++
                "        const bound_task_id = driver.boundTaskId();\n" ++
                "        if (bound_task_id != 0) _ = manager.wakeUserspaceTask(bound_task_id, now_ticks);\n" ++
                "    }",
            .replacement = "",
        },
    };
    for (mutations) |mutation| {
        try std.testing.expect(std.mem.indexOf(u8, source, mutation.needle) != null);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const altered = try std.mem.replaceOwned(u8, arena.allocator(), source, mutation.needle, mutation.replacement);
        var errors = std.ArrayList([]const u8).empty;
        try validateNativeSchedulerLoopSource(arena.allocator(), &errors, altered);
        try std.testing.expect(errors.items.len != 0);
    }
}

const EntryStackSourceKind = enum { x86, gdt, syscall, executor, benchmark, probe, build, proof_root };

fn entryStackMatch(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8), code: []const u8, body: []const std.zig.Token, name: []const u8, pattern: [:0]const u8, position: TimerCodePosition) !void {
    if (!timerCodeMatches(code, body, pattern, position))
        try common.addError(errors, allocator, "Cold entry stack must retain scoped {s} ownership and publication order", .{name});
}

fn validateEntryStackSource(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8), source: []const u8, kind: EntryStackSourceKind) !void {
    const code = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(code);
    var tokens = std.ArrayList(std.zig.Token).empty;
    defer tokens.deinit(allocator);
    var lexer = std.zig.Tokenizer.init(code);
    while (true) {
        const token = lexer.next();
        if (token.tag == .eof) break;
        if (token.tag == .invalid) {
            try common.addError(errors, allocator, "Cold entry stack {s} must remain valid Zig source", .{@tagName(kind)});
            return;
        }
        if (token.tag != .doc_comment and token.tag != .container_doc_comment) try tokens.append(allocator, token);
    }
    switch (kind) {
        .x86 => {
            if (topLevelFunctionBody(code, tokens.items, "updateFredStack") == null or
                topLevelFunctionBody(code, tokens.items, "setFredRsp0") != null)
                try common.addError(errors, allocator, "Cold entry stack must update every normal FRED level rather than RSP0 alone", .{});
            const checks = [_]struct { name: []const u8, body: [:0]const u8 }{
                .{ .name = "fredEntryAddress", .body = "return @intFromPtr(&zigos_fred_entry);" },
                .{ .name = "fredEnabled", .body = "return fredEnabledWith(kernel_stack_top, emergency_stack_top, fredEntryAddress(), struct { inline fn readCr4(_: @This()) usize { return @import(\"x86.zig\").readCr4(); } inline fn readMsr(_: @This(), msr: u32) u64 { return @import(\"x86.zig\").readMsr(msr); } }{});" },
                .{ .name = "fredEnabledWith", .body = "return validFredStackTop(kernel_stack_top) and validFredStackTop(emergency_stack_top) and fredControlMatchesWith(emergency_stack_top, entry, hardware) and hardware.readMsr(IA32_FRED_RSP0_MSR) == kernel_stack_top and hardware.readMsr(IA32_FRED_RSP1_MSR) == kernel_stack_top and hardware.readMsr(IA32_FRED_RSP2_MSR) == kernel_stack_top;" },
                .{ .name = "fredControlMatchesWith", .body = "return (hardware.readCr4() & CR4_FRED) != 0 and hardware.readMsr(IA32_FRED_CONFIG_MSR) == entry and hardware.readMsr(IA32_FRED_STKLVLS_MSR) == FRED_DOUBLE_FAULT_STACK_LEVELS and hardware.readMsr(IA32_FRED_RSP3_MSR) == emergency_stack_top;" },
                .{ .name = "updateFredStack", .body = "updateFredStackWith(kernel_stack_top, struct { inline fn writeMsr(_: @This(), msr: u32, value: u64) void { @import(\"x86.zig\").writeMsr(msr, value); } }{});" },
                .{ .name = "updateFredStackWith", .body = "if (!validFredStackTop(kernel_stack_top)) unreachable; hardware.writeMsr(IA32_FRED_RSP0_MSR, kernel_stack_top); hardware.writeMsr(IA32_FRED_RSP1_MSR, kernel_stack_top); hardware.writeMsr(IA32_FRED_RSP2_MSR, kernel_stack_top);" },
                .{ .name = "validFredStackTop", .body = "return stack_top >= 0xFFFF_8000_0000_0000 and stack_top % FRED_STACK_ALIGNMENT == 0;" },
            };
            for (checks) |check|
                try entryStackMatch(allocator, errors, code, topLevelFunctionBody(code, tokens.items, check.name) orelse &.{}, check.name, check.body, .exact);
            if (!hasTopLevelCodeTokens(code, tokens.items, "const FRED_DOUBLE_FAULT_STACK_LEVELS: u64 = @as(u64, 3) << (2 * 8);"))
                try common.addError(errors, allocator, "Cold entry stack must retain the exact double-fault emergency FRED level policy", .{});
        },
        .gdt => {
            const owner = topLevelFunctionBody(code, tokens.items, "kernelStackOwnerIsLoaded") orelse &.{};
            try entryStackMatch(allocator, errors, code, owner, "loaded GDTR/TR and selected busy TSS", "const state = currentTables(); const storage = double_fault_stacks orelse return false; " ++
                "const emergency_top = @intFromPtr(&storage[cpu_identity.currentIndex()]) + DOUBLE_FAULT_STACK_TOTAL_BYTES; " ++
                "const low: *volatile u64 = &state.gdt[TSS_DESCRIPTOR_LOW_INDEX]; const high: *volatile u64 = &state.gdt[TSS_DESCRIPTOR_HIGH_INDEX]; " ++
                "const descriptor = low.*; const base = ((descriptor >> 16) & 0xFF_FFFF) | ((descriptor >> 32) & 0xFF00_0000) | (high.* << 32); " ++
                "const limit = (descriptor & 0xFFFF) | ((descriptor >> 32) & 0xF0000); const ist1: *align(1) volatile u64 = &state.tss.ist1; " ++
                "return state.initialized and task_register == TSS_SEG and gdtr.base == @intFromPtr(&state.gdt) and gdtr.limit == @sizeOf(@TypeOf(state.gdt)) - 1 and " ++
                "state.gdt_ptr.base == gdtr.base and state.gdt_ptr.limit == gdtr.limit and base == @intFromPtr(&state.tss) and limit == @sizeOf(Tss) - 1 and " ++
                "((descriptor >> 40) & 0xFF) == PRESENT | AVAILABLE_TSS | 2 and ((descriptor >> 52) & 0xF) == 0 and high.* >> 32 == 0 and " ++
                "ist1.* == emergency_top and state.tss.iomap_base == @sizeOf(Tss);", .exact);
            try entryStackMatch(allocator, errors, code, topLevelFunctionBody(code, tokens.items, "kernelStackMatches") orelse &.{}, "TSS stack readback", "const state = currentTables(); const rsp0: *align(1) volatile u64 = &state.tss.rsp0; const ist1: *align(1) volatile u64 = &state.tss.ist1; return rsp0.* == stack and ist1.* == doubleFaultStackTop();", .exact);
            try entryStackMatch(allocator, errors, code, topLevelFunctionBody(code, tokens.items, "setKernelStack") orelse &.{}, "TSS stack write", "const rsp0: *align(1) volatile u64 = &currentTables().tss.rsp0; rsp0.* = stack;", .exact);
        },
        .syscall => {
            if (!hasTopLevelCodeTokens(code, tokens.items, "const StackBinding = enum { bound, rejected, failed };"))
                try common.addError(errors, allocator, "Cold entry stack must distinguish no-write rejection from committed failure", .{});
            const install = topLevelFunctionBody(code, tokens.items, "installKernelStack") orelse &.{};
            const preflight =
                "const interrupts_enabled = hardware.interruptsEnabled(); hardware.disableInterrupts(); var restore_interrupts = true; " ++
                "defer if (restore_interrupts and interrupts_enabled) hardware.enableInterrupts(); const state = native_entry.current(); const cr4 = hardware.readCr4(); " ++
                "if (!x86.validFredStackTop(stack_top_value) or !gdt.kernelStackOwnerIsLoaded(hardware.readGdt(), hardware.readTaskRegister()) or " ++
                "hardware.readMsr(x86.IA32_GS_BASE_MSR) != @intFromPtr(state) or state.userspace_xstate != 0 or state.kernel_xstate != 0 or " ++
                "state.resume_rsp != 0 or state.resume_rip != 0 or state.resume_requested != 0 or " ++
                "(publishedFredMode(state) != null and state.native_entry_modes != entryModesFromCr4(cr4))) return .rejected; " ++
                "const fred = (cr4 & x86.CR4_FRED) != 0; const emergency_top = gdt.doubleFaultStackTop(); " ++
                "if (!x86.validFredStackTop(emergency_top) or (fred and !x86.fredControlMatchesWith(emergency_top, hardware.fredEntryAddress(), hardware))) return .rejected;";
            const publication =
                "const previous_modes = state.native_entry_modes; state.native_entry_modes = previous_modes & ~ENTRY_READY; " ++
                "hardware.setTssKernelStack(stack_top_value); if (fred) hardware.updateFredStack(stack_top_value); " ++
                "if (!gdt.kernelStackOwnerIsLoaded(hardware.readGdt(), hardware.readTaskRegister()) or !hardware.kernelStackMatches(stack_top_value) or hardware.readCr4() != cr4 or " ++
                "hardware.readMsr(x86.IA32_GS_BASE_MSR) != @intFromPtr(state) or " ++
                "(fred and !x86.fredEnabledWith(stack_top_value, emergency_top, hardware.fredEntryAddress(), hardware))) { " ++
                "state.native_entry_modes &= ~ENTRY_READY; restore_interrupts = false; return .failed; } state.kernel_stack_top = stack_top_value; state.native_entry_modes = previous_modes; return .bound;";
            try entryStackMatch(allocator, errors, code, install, "complete saved-IF preflight update readback and GS-last transaction", preflight ++ publication, .exact);
            const checks = [_]struct { name: []const u8, body: [:0]const u8 }{
                .{ .name = "setKernelStack", .body = "return switch (installKernelStack(stack_top_value, Hardware{})) { .bound => true, .rejected => false, .failed => haltInvalidStack(), };" },
                .{ .name = "haltInvalidStack", .body = "x86.cli(); while (true) x86.hlt();" },
                .{ .name = "enabled", .body = "return enabledWith(Hardware{});" },
                .{ .name = "publishNativeEntryModes", .body = "if (!x86.xsavesEnabled() or x86.taskSwitched()) haltInvalidStack(); native_entry.stateForCpu(cpu_index).native_entry_modes = entryModesFromCr4(x86.readCr4());" },
                .{ .name = "entryModesFromCr4", .body = "return ENTRY_READY | (if ((cr4 & x86.CR4_PKE) != 0) ENTRY_PKU else @as(u8, 0)) | (if ((cr4 & x86.CR4_FRED) != 0) ENTRY_FRED else @as(u8, 0));" },
                .{ .name = "publishedFredMode", .body = "if ((state.native_entry_modes & ENTRY_READY) == 0) return null; return (state.native_entry_modes & ENTRY_FRED) != 0;" },
                .{ .name = "enableNativeEntry", .body = "x86.writeMsr(x86.IA32_STAR_MSR, SYSCALL_STAR_VALUE); x86.writeMsr(x86.EFER_MSR, x86.readMsr(x86.EFER_MSR) | x86.EFER_SCE); if (!syscallSelectorsEnabled()) haltInvalidStack(); const features = @import(\"../../arch/cpu_features.zig\").detect(); if (features.fred and features.lkgs) { x86.enableFred(kernel_stack_top, gdt.doubleFaultStackTop()); if (!x86.fredEnabled(kernel_stack_top, gdt.doubleFaultStackTop())) haltInvalidStack(); return; } enableSyscallMsrs(); if (!syscallMsrsEnabled()) haltInvalidStack();" },
                .{ .name = "bootstrapIdentityWith", .body = "if (!hardware.supportsRdpid() or (hardware.readMsr(IA32_APIC_BASE_MSR) & APIC_BASE_BSP) == 0) return false; hardware.initializeLogicalCpu(0); return true;" },
                .{ .name = "enabledWith", .body = "if ((hardware.readCr4() & x86.CR4_FRED) != 0) { return x86.fredEnabledWith(native_entry.current().kernel_stack_top, gdt.doubleFaultStackTop(), hardware.fredEntryAddress(), hardware) and selectorsEnabledWith(hardware); } return selectorsEnabledWith(hardware) and hardware.readMsr(x86.IA32_LSTAR_MSR) == hardware.syscallEntryAddress() and hardware.readMsr(x86.IA32_FMASK_MSR) == SYSCALL_RFLAGS_MASK;" },
                .{ .name = "init", .body = "const interrupts_enabled = x86.interruptsEnabled(); x86.cli(); if (!bootstrapIdentityWith(Hardware{})) haltInvalidStack(); bindCpu(0, @intFromPtr(&stack_top)); enableNativeEntry(@intFromPtr(&stack_top)); if (!setKernelStack(@intFromPtr(&stack_top)) or !enabled()) haltInvalidStack(); publishNativeEntryModes(0); if (interrupts_enabled) x86.sti();" },
                .{ .name = "initApplicationProcessor", .body = "const interrupts_enabled = x86.interruptsEnabled(); x86.cli(); bindCpu(cpu_index, stack_top_value); enableNativeEntry(stack_top_value); if (!setKernelStack(stack_top_value) or !enabled()) haltInvalidStack(); publishNativeEntryModes(cpu_index); if (interrupts_enabled) x86.sti();" },
            };
            for (checks) |check|
                try entryStackMatch(allocator, errors, code, topLevelFunctionBody(code, tokens.items, check.name) orelse &.{}, check.name, check.body, .exact);
            try entryStackMatch(allocator, errors, code, topLevelFunctionBody(code, tokens.items, "bindCpu") orelse &.{}, "CPU binding owner before state initialization", "if (!x86.validFredStackTop(stack_top_value) or cpu_index >= cpu_identity.MAX_CPUS or cpu_identity.currentIndex() != cpu_index or " ++
                "!gdt.kernelStackOwnerIsLoaded((Hardware{}).readGdt(), (Hardware{}).readTaskRegister())) haltInvalidStack(); " ++
                "const state = native_entry.current(); if (state.native_entry_modes != 0 or state.userspace_xstate != 0 or state.kernel_xstate != 0 or state.resume_rsp != 0 or state.resume_rip != 0 or state.resume_requested != 0) haltInvalidStack(); " ++
                "if (!@import(\"../../arch/cpu_features.zig\").detect().rdpid) @panic(\"RDPID is required for native CPU identity\"); const state_addr = @intFromPtr(native_entry.initializeCpu(cpu_index, 0)); " ++
                "x86.writeMsr(x86.IA32_GS_BASE_MSR, state_addr); x86.writeMsr(x86.IA32_KERNEL_GS_BASE_MSR, 0); cpu_identity.initialize(cpu_index);", .exact);
            const hardware = topLevelContainerBody(code, tokens.items, "const Hardware = struct {") orelse &.{};
            const adapters = [_]struct { name: []const u8, body: [:0]const u8 }{
                .{ .name = "supportsRdpid", .body = "return @import(\"../../arch/cpu_features.zig\").detect().rdpid;" },
                .{ .name = "initializeLogicalCpu", .body = "cpu_identity.initialize(index);" },
                .{ .name = "interruptsEnabled", .body = "return x86.interruptsEnabled();" },
                .{ .name = "disableInterrupts", .body = "x86.cli();" },
                .{ .name = "enableInterrupts", .body = "x86.sti();" },
                .{ .name = "readCr4", .body = "return x86.readCr4();" },
                .{ .name = "readMsr", .body = "return x86.readMsr(msr);" },
                .{ .name = "fredEntryAddress", .body = "return x86.fredEntryAddress();" },
                .{ .name = "readGdt", .body = "var gdtr: gdt.GdtPtr = undefined; asm volatile (\"sgdt (%[table])\" : : [table] \"r\" (&gdtr), : .{ .memory = true }); return gdtr;" },
                .{ .name = "readTaskRegister", .body = "return asm volatile (\"str %[selector]\" : [selector] \"=r\" (-> u16), );" },
                .{ .name = "setTssKernelStack", .body = "gdt.setKernelStack(top);" },
                .{ .name = "updateFredStack", .body = "x86.updateFredStack(top);" },
                .{ .name = "kernelStackMatches", .body = "return gdt.kernelStackMatches(top);" },
            };
            for (adapters) |adapter|
                try entryStackMatch(allocator, errors, code, topLevelFunctionBody(code, hardware, adapter.name) orelse &.{}, adapter.name, adapter.body, .exact);
            for ([_][:0]const u8{ "const IA32_APIC_BASE_MSR: u32 = 0x1B;", "const APIC_BASE_BSP: u64 = 1 << 8;" }) |pattern|
                if (!hasTopLevelCodeTokens(code, tokens.items, pattern))
                    try common.addError(errors, allocator, "Cold entry stack bootstrap identity must authenticate actual BSP before slot selection", .{});
        },
        .executor => {
            const container = topLevelContainerBody(code, tokens.items, "pub const Executor = struct {") orelse &.{};
            const init = topLevelFunctionBody(code, container, "init") orelse &.{};
            try entryStackMatch(allocator, errors, code, init, "Executor.init", "if (comptime builtin.target.os.tag == .freestanding) { if (!smp.isRuntimeOwner()) @call(.never_inline, executorInvariantFailure, .{.shared_executor_services_require_the_bsp_runtime_owner}); if (!claimCurrentExecutor(self)) @call(.never_inline, executorInvariantFailure, .{.selected_cpu_executor_registration_requires_its_exact_owner}); } if (builtin.target.os.tag != .freestanding) return; if (self.initialized) return;", .prefix);
            try entryStackMatch(allocator, errors, code, init, "Executor.init", "const trap_stack_top = prepareKernelStack(); if (!freestanding.syscall64.setKernelStack(trap_stack_top)) @call(.never_inline, executorInvariantFailure, .{.selected_cpu_trap_stack_must_be_provisioned_before_entry}); self.initialized = true;", .suffix);
            if (hasCodeTokens(code, init, "freestanding.gdt.setKernelStack("))
                try common.addError(errors, allocator, "Cold entry stack must not write TSS outside the checked publication transaction", .{});
            if (preparedDispatchTokenCount(code, init, "self.initialized = true;") != 1 or
                preparedDispatchTokenCount(code, init, "freestanding.syscall64.setKernelStack(") != 1)
                try common.addError(errors, allocator, "Cold entry stack must publish Executor readiness exactly once after its checked binding", .{});
            const native = topLevelContainerBody(code, tokens.items, "const NativePreparedDispatch = struct {") orelse &.{};
            try entryStackMatch(allocator, errors, code, topLevelFunctionBody(code, native, "ownerAvailable") orelse &.{}, "native owner admission", "return smp.isRuntimeOwner() and continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();", .exact);
            try entryStackMatch(allocator, errors, code, topLevelFunctionBody(code, native, "entryReady") orelse &.{}, "steady native entry", "return stack_top != 0 and preparedKernelStackForCpu(cpu_identity.currentIndex()) == stack_top and native_entry.current().kernel_stack_top == stack_top and continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();", .exact);
        },
        .benchmark => {
            const prepare = topLevelFunctionBody(code, tokens.items, "prepareSyscallBenchmarkFixture") orelse &.{};
            try entryStackMatch(allocator, errors, code, prepare, "benchmark cold preparation", "if (syscall_benchmark_context.prepared) return; if (!syscall64.setKernelStack(userspace_executor.prepareKernelStack())) benchmark_reporting.benchStepFailure(\"syscall benchmark entry stack\", error.InvalidState); var space = paging.createUserAddressSpace()", .prefix);
            try entryStackMatch(allocator, errors, code, prepare, "benchmark readiness", "syscall_benchmark_context.prepared = true;", .suffix);
            if (preparedDispatchTokenCount(code, prepare, "syscall64.setKernelStack(") != 1)
                try common.addError(errors, allocator, "Cold entry stack benchmark binding must occur exactly once before readiness", .{});
            const measured = topLevelFunctionBody(code, tokens.items, "benchmarkSyscallFastEntryRoundtrip") orelse &.{};
            for ([_][:0]const u8{ "prepareKernelStack(", "setKernelStack(", "updateFredStack(", "fredEnabled(", "readMsr(", "readCr4(", "kernelStackOwnerIsLoaded(", "kernelStackMatches(" }) |forbidden|
                if (hasCodeTokens(code, measured, forbidden))
                    try common.addError(errors, allocator, "Measured syscall loop must not repeat cold stack ownership/control checks: {s}", .{forbidden});
        },
        .probe => {
            const capture = topLevelFunctionBody(code, tokens.items, "captureColdStackHardware") orelse &.{};
            const prove = topLevelFunctionBody(code, tokens.items, "proveColdStackOwner") orelse &.{};
            try entryStackMatch(allocator, errors, code, capture, "independent privileged oracle admission", "if (cpu_identity.currentIndex() != index or x86.interruptsEnabled() or !paging.kernelAddressSpaceActive()) return false; " ++
                "const cr4 = x86.readCr4(); if (cr4 & (x86.CR4_OSXSAVE | x86.CR4_FRED) != x86.CR4_OSXSAVE) return false; " ++
                "const xcr0 = x86.readXcr0(); if (xcr0 != xstate.enabled_mask) return false;", .prefix);
            try preparedDispatchOrdered(allocator, errors, code, capture, &.{
                "asm volatile (\"sgdt (%[table])\" : : [table] \"r\" (&gdtr), : .{ .memory = true });",
                "const selector = asm volatile (\"str %[selector]\" : [selector] \"=r\" (-> u16), );",
                "if (selector != gdt.TSS_SEG or gdtr.limit != 55 or address.imagePhysicalAddress(gdtr.base) == null or address.imagePhysicalAddress(gdtr.base + gdtr.limit) == null) return false;",
                "const descriptors: *const volatile [7]u64 = @ptrFromInt(gdtr.base); const entries = descriptors.*;",
                "if ((low >> 40) & 0xFF != 0x8B or high >> 32 != 0 or (low & 0xFFFF) | ((low >> 32) & 0xF0000) != @sizeOf(gdt.Tss) - 1 or address.imagePhysicalAddress(tss_base) == null or address.imagePhysicalAddress(tss_base + @sizeOf(gdt.Tss) - 1) == null) return false;",
                "const tss: *const volatile gdt.Tss = @ptrFromInt(tss_base);",
                "if (state.native_entry_modes != 0 or tss.ist1 != gdt.doubleFaultStackTop() or tss.iomap_base != @sizeOf(gdt.Tss) or x86.readMsr(x86.IA32_GS_BASE_MSR) != @intFromPtr(native_entry.stateForCpu(index))) return false;",
                "out.* = .{ .gdtr = gdtr, .selector = selector, .descriptors = entries, .tss_base = tss_base, .tss = tss.*, .cr0 = x86.readCr0(), .cr3 = x86.readCr3(), .cr4 = cr4, .xcr0 = xcr0, .efer = x86.readMsr(x86.EFER_MSR), .gs_base = x86.readMsr(x86.IA32_GS_BASE_MSR), .kernel_gs_base = x86.readMsr(x86.IA32_KERNEL_GS_BASE_MSR), .tsc_aux = x86.readMsr(x86.IA32_TSC_AUX_MSR), .control_flags = flags & ((1 << 9) | FLAG_DF | FLAG_AC), };",
            });
            try entryStackMatch(allocator, errors, code, capture, "unchanged IF DF AC oracle", "return out.control_flags == 0;", .suffix);
            if (hasCodeTokens(code, capture, "return true;") or
                preparedDispatchTokenCount(code, prove, "return;") != 1 or
                preparedDispatchTokenCount(code, prove, "@atomicStore(u8, &cpus[index].cold_stack_checked,") != 1)
                try common.addError(errors, allocator, "Cold entry stack oracle must not bypass privileged checks or publish a premature receipt", .{});
            try entryStackMatch(allocator, errors, code, prove, "selected CPU1 cold proof", "if (index != PREPARED_OWNER_CPU) return; if (cpu_identity.currentIndex() != index or x86.interruptsEnabled()) reject(index);", .prefix);
            try preparedDispatchOrdered(allocator, errors, code, prove, &.{
                "if (!captureColdStackHardware(index, &hardware_before) or hardware_before.tss.rsp0 != ordinary_top) reject(index);",
                "for (&neighbors, &canaries, 0..)",
                "if (!syscall64.setKernelStack(guarded_top)) reject(index);",
                "if (!captureColdStackHardware(index, &hardware_guarded)) reject(index);",
                "expected_hardware.tss.rsp0 = guarded_top;",
                "expected_state.kernel_stack_top = guarded_top;",
                "if (!std.meta.eql(expected_hardware, hardware_guarded) or !std.mem.eql(u8, std.mem.asBytes(&expected_state), std.mem.asBytes(&guarded_state))) reject(index);",
                "if (!syscall64.setKernelStack(ordinary_top)) reject(index);",
                "if (!captureColdStackHardware(index, &hardware_restored) or !std.meta.eql(hardware_before, hardware_restored)) reject(index);",
                "for (&neighbors, &canaries, 0..)",
                "trapStackWord(cpus[cpu].trap_stack_top, false).* != ends[0] or trapStackWord(cpus[cpu].trap_stack_top, true).* != ends[1]",
                "while (cursor < cpus[cpu].trap_stack_top - @sizeOf(u64))",
                "if (word.* != TRAP_PAINT_WORD) reject(index);",
                "@atomicStore(u8, &cpus[index].cold_stack_checked, 1, .release);",
            });
            try entryStackMatch(allocator, errors, code, prove, "cold proof receipt publication", "@atomicStore(u8, &cpus[index].cold_stack_checked, 1, .release);", .suffix);
            try preparedDispatchOrdered(allocator, errors, code, topLevelFunctionBody(code, tokens.items, "apEntry") orelse &.{}, &.{
                "touchSelectedTrapStack(index); proveColdStackOwner(index); bindProofContinuation(index);",
            });
            try preparedDispatchOrdered(allocator, errors, code, topLevelFunctionBody(code, tokens.items, "run") orelse &.{}, &.{
                "if (@atomicLoad(u8, &cpus[PREPARED_OWNER_CPU].cold_stack_checked, .acquire) != 1) proof.fail(\"SMP cold stack ownership receipt\");",
                "proof.pass(\"SMP_16_DESCRIPTORS\");",
            });
        },
        .build => {
            try validateUpperHalfEntryBuild(allocator, errors, code, tokens.items);
        },
        .proof_root => {
            if (!hasTopLevelCodeTokens(code, tokens.items, "pub const ARCHITECTURE_SMP_PROOF = true;"))
                try common.addError(errors, allocator, "Cold entry stack privileged oracle must remain in the isolated architecture root", .{});
            try entryStackMatch(allocator, errors, code, topLevelFunctionBody(code, tokens.items, "syscall_handler") orelse &.{}, "unexpected isolated native syscall rejection", "@import(\"arch/x86_64/high_half_probe.zig\").fail(\"unexpected isolated native syscall entry\");", .exact);
        },
    }
}

fn expectEntryStackMutationRejected(path: []const u8, kind: EntryStackSourceKind, needle: []const u8, replacement: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const source = try common.readFileAlloc(allocator, std.testing.io, path, common.source_file_max_bytes);
    try std.testing.expect(std.mem.indexOf(u8, source, needle) != null);
    const altered = try std.mem.replaceOwned(u8, allocator, source, needle, replacement);
    const comment = try std.mem.replaceOwned(u8, allocator, needle, "\n", "\n// ");
    const quoted = try std.json.Stringify.valueAlloc(allocator, needle, .{});
    const with_decoys = try std.fmt.allocPrint(allocator, "// {s}\nconst entry_stack_quoted_decoy = {s};\n{s}", .{ comment, quoted, altered });
    var errors = std.ArrayList([]const u8).empty;
    try validateEntryStackSource(allocator, &errors, with_decoys, kind);
    if (errors.items.len == 0) std.debug.print("Accepted cold entry stack mutation: {s}: {s}\n", .{ path, needle });
    try std.testing.expect(errors.items.len != 0);
}

test "cold entry stack source gate accepts actual owner transaction and ignores decoys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_]struct { path: []const u8, kind: EntryStackSourceKind }{
        .{ .path = "src/arch/x86.zig", .kind = .x86 },
        .{ .path = "src/kernel/interrupts/gdt64.zig", .kind = .gdt },
        .{ .path = "src/kernel/interrupts/syscall64.zig", .kind = .syscall },
        .{ .path = "src/native/task/userspace_executor.zig", .kind = .executor },
        .{ .path = "src/kernel/boot/benchmark/suite.zig", .kind = .benchmark },
        .{ .path = "src/arch/x86_64/high_half_smp_probe.zig", .kind = .probe },
        .{ .path = "build_support/kernel.zig", .kind = .build },
        .{ .path = "src/high_half_entry.zig", .kind = .proof_root },
    }) |item| {
        const source = try common.readFileAlloc(allocator, std.testing.io, item.path, common.source_file_max_bytes);
        const annotated = try std.fmt.allocPrint(allocator, "{s}\n// setFredRsp0(top); state.kernel_stack_top = top;\nconst cold_entry_decoy = \"hardware.readMsr(IA32_FRED_RSP2_MSR) == kernel_stack_top\";\n", .{source});
        var errors = std.ArrayList([]const u8).empty;
        try validateEntryStackSource(allocator, &errors, annotated, item.kind);
        if (errors.items.len != 0) common.printErrors(errors.items);
        try std.testing.expectEqual(@as(usize, 0), errors.items.len);
    }
}

test "cold entry stack source gate rejects unsafe preflight commit and publication" {
    for ([_]struct { needle: []const u8, replacement: []const u8 }{
        .{ .needle = "const interrupts_enabled = hardware.interruptsEnabled();", .replacement = "const interrupts_enabled = false;" },
        .{ .needle = "hardware.disableInterrupts();", .replacement = "ignoreInterruptMask();" },
        .{ .needle = "defer if (restore_interrupts and interrupts_enabled) hardware.enableInterrupts();", .replacement = "defer hardware.enableInterrupts();" },
        .{ .needle = "!x86.validFredStackTop(stack_top_value)", .replacement = "false" },
        .{ .needle = "!gdt.kernelStackOwnerIsLoaded(hardware.readGdt(), hardware.readTaskRegister())", .replacement = "false" },
        .{ .needle = "hardware.readMsr(x86.IA32_GS_BASE_MSR) != @intFromPtr(state)", .replacement = "false" },
        .{ .needle = "state.userspace_xstate != 0", .replacement = "false" },
        .{ .needle = "state.kernel_xstate != 0", .replacement = "false" },
        .{ .needle = "state.resume_rsp != 0", .replacement = "false" },
        .{ .needle = "state.resume_rip != 0", .replacement = "false" },
        .{ .needle = "state.resume_requested != 0", .replacement = "false" },
        .{ .needle = "state.native_entry_modes != entryModesFromCr4(cr4)", .replacement = "false" },
        .{ .needle = "!x86.validFredStackTop(emergency_top)", .replacement = "false" },
        .{ .needle = "fred and !x86.fredControlMatchesWith", .replacement = "!x86.fredControlMatchesWith" },
        .{ .needle = "state.native_entry_modes = previous_modes & ~ENTRY_READY;", .replacement = "state.native_entry_modes = previous_modes;" },
        .{ .needle = "hardware.setTssKernelStack(stack_top_value);", .replacement = "state.kernel_stack_top = stack_top_value; hardware.setTssKernelStack(stack_top_value);" },
        .{ .needle = "if (fred) hardware.updateFredStack(stack_top_value);", .replacement = "hardware.updateFredStack(stack_top_value);" },
        .{ .needle = "!hardware.kernelStackMatches(stack_top_value)", .replacement = "false" },
        .{ .needle = "hardware.readCr4() != cr4", .replacement = "false" },
        .{ .needle = "fred and !x86.fredEnabledWith", .replacement = "!x86.fredEnabledWith" },
        .{ .needle = "state.native_entry_modes &= ~ENTRY_READY;", .replacement = "state.native_entry_modes = previous_modes;" },
        .{ .needle = "restore_interrupts = false;", .replacement = "restore_interrupts = true;" },
        .{ .needle = "return .failed;", .replacement = "return .rejected;" },
        .{ .needle = "state.kernel_stack_top = stack_top_value;\n    state.native_entry_modes = previous_modes;", .replacement = "state.native_entry_modes = previous_modes;\n    state.kernel_stack_top = stack_top_value;" },
        .{ .needle = ".failed => haltInvalidStack(),", .replacement = ".failed => false," },
        .{ .needle = "while (true) x86.hlt();", .replacement = "unreachable;" },
        .{ .needle = "if ((hardware.readCr4() & x86.CR4_FRED) != 0)", .replacement = "if (true)" },
        .{ .needle = "if (!setKernelStack(stack_top_value) or !enabled()) haltInvalidStack();", .replacement = "if (!enabled()) haltInvalidStack();" },
        .{ .needle = "publishNativeEntryModes(cpu_index);", .replacement = "publishNativeEntryModes(cpu_index); setKernelStack(stack_top_value);" },
        .{ .needle = "cpu_identity.currentIndex() != cpu_index", .replacement = "false" },
        .{ .needle = "native_entry.initializeCpu(cpu_index, 0)", .replacement = "native_entry.initializeCpu(cpu_index, stack_top_value)" },
        .{ .needle = "return x86.readMsr(msr);", .replacement = "return 0;" },
        .{ .needle = "return gdt.kernelStackMatches(top);", .replacement = "return true;" },
        .{ .needle = "\"sgdt (%[table])\"", .replacement = "\"nop\"" },
        .{ .needle = "\"str %[selector]\"", .replacement = "\"xor %[selector], %[selector]\"" },
        .{ .needle = "!hardware.supportsRdpid()", .replacement = "false" },
        .{ .needle = "(hardware.readMsr(IA32_APIC_BASE_MSR) & APIC_BASE_BSP) == 0", .replacement = "false" },
        .{ .needle = "hardware.initializeLogicalCpu(0);", .replacement = "hardware.initializeLogicalCpu(1);" },
        .{ .needle = "if (!bootstrapIdentityWith(Hardware{})) haltInvalidStack();", .replacement = "// inherited AUX is trusted" },
        .{ .needle = "cpu_identity.initialize(index);", .replacement = "ignoreLogicalCpu(index);" },
    }) |mutation| try expectEntryStackMutationRejected("src/kernel/interrupts/syscall64.zig", .syscall, mutation.needle, mutation.replacement);
}

test "cold entry stack source gate rejects weakened FRED and loaded TSS ownership" {
    for ([_]struct { kind: EntryStackSourceKind, path: []const u8, needle: []const u8, replacement: []const u8 }{
        .{ .kind = .x86, .path = "src/arch/x86.zig", .needle = "return validFredStackTop(kernel_stack_top) and validFredStackTop(emergency_stack_top) and", .replacement = "return" },
        .{ .kind = .x86, .path = "src/arch/x86.zig", .needle = "hardware.readMsr(IA32_FRED_RSP0_MSR) == kernel_stack_top", .replacement = "true" },
        .{ .kind = .x86, .path = "src/arch/x86.zig", .needle = "hardware.readMsr(IA32_FRED_RSP1_MSR) == kernel_stack_top", .replacement = "true" },
        .{ .kind = .x86, .path = "src/arch/x86.zig", .needle = "hardware.readMsr(IA32_FRED_RSP2_MSR) == kernel_stack_top", .replacement = "true" },
        .{ .kind = .x86, .path = "src/arch/x86.zig", .needle = "hardware.readMsr(IA32_FRED_RSP3_MSR) == emergency_stack_top", .replacement = "true" },
        .{ .kind = .x86, .path = "src/arch/x86.zig", .needle = "hardware.readMsr(IA32_FRED_CONFIG_MSR) == entry", .replacement = "true" },
        .{ .kind = .x86, .path = "src/arch/x86.zig", .needle = "hardware.readMsr(IA32_FRED_STKLVLS_MSR) == FRED_DOUBLE_FAULT_STACK_LEVELS", .replacement = "true" },
        .{ .kind = .x86, .path = "src/arch/x86.zig", .needle = "hardware.writeMsr(IA32_FRED_RSP1_MSR, kernel_stack_top);", .replacement = "// FRED level1 not updated" },
        .{ .kind = .x86, .path = "src/arch/x86.zig", .needle = "hardware.writeMsr(IA32_FRED_RSP2_MSR, kernel_stack_top);", .replacement = "// FRED level2 not updated" },
        .{ .kind = .x86, .path = "src/arch/x86.zig", .needle = "stack_top >= 0xFFFF_8000_0000_0000", .replacement = "stack_top != 0" },
        .{ .kind = .x86, .path = "src/arch/x86.zig", .needle = "return @import(\"x86.zig\").readMsr(msr);", .replacement = "return 0;" },
        .{ .kind = .gdt, .path = "src/kernel/interrupts/gdt64.zig", .needle = "state.initialized and task_register == TSS_SEG", .replacement = "true" },
        .{ .kind = .gdt, .path = "src/kernel/interrupts/gdt64.zig", .needle = "gdtr.base == @intFromPtr(&state.gdt)", .replacement = "true" },
        .{ .kind = .gdt, .path = "src/kernel/interrupts/gdt64.zig", .needle = "gdtr.limit == @sizeOf(@TypeOf(state.gdt)) - 1", .replacement = "true" },
        .{ .kind = .gdt, .path = "src/kernel/interrupts/gdt64.zig", .needle = "base == @intFromPtr(&state.tss)", .replacement = "true" },
        .{ .kind = .gdt, .path = "src/kernel/interrupts/gdt64.zig", .needle = "limit == @sizeOf(Tss) - 1", .replacement = "true" },
        .{ .kind = .gdt, .path = "src/kernel/interrupts/gdt64.zig", .needle = "PRESENT | AVAILABLE_TSS | 2", .replacement = "PRESENT | AVAILABLE_TSS" },
        .{ .kind = .gdt, .path = "src/kernel/interrupts/gdt64.zig", .needle = "((descriptor >> 52) & 0xF) == 0 and high.* >> 32 == 0", .replacement = "true" },
        .{ .kind = .gdt, .path = "src/kernel/interrupts/gdt64.zig", .needle = "ist1.* == emergency_top", .replacement = "true" },
        .{ .kind = .gdt, .path = "src/kernel/interrupts/gdt64.zig", .needle = "state.tss.iomap_base == @sizeOf(Tss)", .replacement = "true" },
        .{ .kind = .gdt, .path = "src/kernel/interrupts/gdt64.zig", .needle = "const rsp0: *align(1) volatile u64 =", .replacement = "const rsp0: *align(1) u64 =" },
        .{ .kind = .gdt, .path = "src/kernel/interrupts/gdt64.zig", .needle = "return rsp0.* == stack and ist1.* == doubleFaultStackTop();", .replacement = "return true;" },
    }) |mutation| try expectEntryStackMutationRejected(mutation.path, mutation.kind, mutation.needle, mutation.replacement);
}

test "cold entry stack source gate rejects steady checks premature readiness and fake privileged evidence" {
    for ([_]struct { kind: EntryStackSourceKind, path: []const u8, needle: []const u8, replacement: []const u8 }{
        .{ .kind = .executor, .path = "src/native/task/userspace_executor.zig", .needle = "if (!freestanding.syscall64.setKernelStack(trap_stack_top))", .replacement = "if (false)" },
        .{ .kind = .executor, .path = "src/native/task/userspace_executor.zig", .needle = "const trap_stack_top = prepareKernelStack();", .replacement = "self.initialized = true; const trap_stack_top = prepareKernelStack();" },
        .{ .kind = .executor, .path = "src/native/task/userspace_executor.zig", .needle = "return smp.isRuntimeOwner() and continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();", .replacement = "return continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();" },
        .{ .kind = .executor, .path = "src/native/task/userspace_executor.zig", .needle = "return stack_top != 0 and preparedKernelStackForCpu", .replacement = "return x86.fredEnabled(stack_top, freestanding.gdt.doubleFaultStackTop()) and stack_top != 0 and preparedKernelStackForCpu" },
        .{ .kind = .benchmark, .path = "src/kernel/boot/benchmark/suite.zig", .needle = "if (!syscall64.setKernelStack(userspace_executor.prepareKernelStack()))", .replacement = "if (false)" },
        .{ .kind = .benchmark, .path = "src/kernel/boot/benchmark/suite.zig", .needle = "fn benchmarkSyscallFastEntryRoundtrip(iteration: u32) u64 {", .replacement = "fn benchmarkSyscallFastEntryRoundtrip(iteration: u32) u64 { syscall64.setKernelStack(userspace_executor.prepareKernelStack());" },
        .{ .kind = .benchmark, .path = "src/kernel/boot/benchmark/suite.zig", .needle = "fn benchmarkSyscallFastEntryRoundtrip(iteration: u32) u64 {", .replacement = "fn benchmarkSyscallFastEntryRoundtrip(iteration: u32) u64 { _ = x86.readCr4(); _ = x86.readMsr(0x1cc);" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "proveColdStackOwner(index);", .replacement = "// cold ownership proof omitted" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "if (!syscall64.setKernelStack(guarded_top)) reject(index);", .replacement = "gdt.setKernelStack(guarded_top); native_entry.current().kernel_stack_top = guarded_top;" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "if (!syscall64.setKernelStack(ordinary_top)) reject(index);", .replacement = "// ordinary binding restore omitted" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "\"sgdt (%[table])\"", .replacement = "\"nop\"" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "(low >> 40) & 0xFF != 0x8B", .replacement = "false" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "address.imagePhysicalAddress(tss_base) == null", .replacement = "false" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "!std.meta.eql(expected_hardware, hardware_guarded)", .replacement = "false" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "!std.meta.eql(hardware_before, hardware_restored)", .replacement = "false" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "if (word.* != TRAP_PAINT_WORD) reject(index);", .replacement = "// neighboring interior paint omitted" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "@atomicStore(u8, &cpus[index].cold_stack_checked, 1, .release);", .replacement = "@atomicStore(u8, &cpus[index].cold_stack_checked, 1, .monotonic);" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "@atomicLoad(u8, &cpus[PREPARED_OWNER_CPU].cold_stack_checked, .acquire)", .replacement = "@atomicLoad(u8, &cpus[PREPARED_OWNER_CPU].cold_stack_checked, .monotonic)" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "fn captureColdStackHardware(index: u8, out: *ColdStackHardware) bool {", .replacement = "fn captureColdStackHardware(index: u8, out: *ColdStackHardware) bool { return true;" },
        .{ .kind = .probe, .path = "src/arch/x86_64/high_half_smp_probe.zig", .needle = "if (index != PREPARED_OWNER_CPU) return;", .replacement = "if (index != PREPARED_OWNER_CPU) return; return;" },
        .{ .kind = .build, .path = "build_support/kernel.zig", .needle = "module.addAssemblyFile(b.path(\"src/kernel/interrupts/fred64.S\"));", .replacement = "// real FRED entry linkage omitted" },
        .{ .kind = .proof_root, .path = "src/high_half_entry.zig", .needle = "pub const ARCHITECTURE_SMP_PROOF = true;", .replacement = "pub const ARCHITECTURE_SMP_PROOF = false;" },
        .{ .kind = .proof_root, .path = "src/high_half_entry.zig", .needle = "@import(\"arch/x86_64/high_half_probe.zig\").fail(\"unexpected isolated native syscall entry\");", .replacement = "return;" },
    }) |mutation| try expectEntryStackMutationRejected(mutation.path, mutation.kind, mutation.needle, mutation.replacement);
}
