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
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:UEFI_BOOT:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_TABLES:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:VT_D_DISCOVERY:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:VT_D_STORAGE_ISOLATION:ENFORCED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:VT_D_INTERRUPT_ISOLATION:ENFORCED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:VT_D_BLOCKED_DMA_FAULT:OBSERVED",
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
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_XSDT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_MADT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_FADT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_DMAR:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:VT_D_SEGMENT_ZERO:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:VT_D_BLOCKED_DMA_FAULT:OBSERVED",
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
    "ZIGOS:CPU:PGE:ENABLED",
    "ZIGOS:CPU:SYSCALL:ENABLED",
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
    "ZIGOS:CPU:SYSCALL:ENABLED",
    "ZIGOS:CPU:PCID:ENABLED",
    "BOOT:CORE_READY",
    "ZIGOS:KERNEL_NETWORK:DEFERRED",
    "ZIGOS:NATIVE:BOOTSTRAP",
    "ZIGOS:TCB:DEFINED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:EVIDENCE_SOURCE:REAL_HARDWARE",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:BOARD_SKU:NUC11TNKi5",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:SMBIOS_SKU:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:MULTIBOOT_MEMORY_MAP:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_XSDT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_MADT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_FADT:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_DMAR:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:VT_D_SEGMENT_ZERO:OBSERVED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_TABLES:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:VT_D_DISCOVERY:PASS",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:VT_D_STORAGE_ISOLATION:ENFORCED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:VT_D_INTERRUPT_ISOLATION:ENFORCED",
    "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:VT_D_BLOCKED_DMA_FAULT:OBSERVED",
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
    "src/kernel/platform/dmar.zig",
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
    try validateBenchmarkEnvironmentGate(allocator, io, &errors);
    try validateSyntheticUserspaceImageMarkers(allocator, io, &errors);
    try validateEventLedgerRollover(allocator, io, &errors);

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
    const capture_path = "scripts/capture-kernel-benchmark.sh";
    const capture_source = try readRequiredSource(allocator, io, errors, capture_path) orelse return;
    const capture_snippets = [_][]const u8{
        "qemu_harness_accelerator",
        "guest output must not declare its host accelerator",
        "BENCH:ENV:accelerator=%s",
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
    if (std.mem.indexOf(u8, workflow_source, "command: QEMU_ACCELERATOR=kvm ./scripts/zig.sh build -Doptimize=ReleaseFast benchmark") == null) {
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
    const userspace_syscall_path = "src/arch/x86/syscall_trap.S";
    const gdt_path = "src/kernel/interrupts/gdt64.zig";
    const runtime_init_path = "src/kernel/boot/init/runtime.zig";
    const native_profile_path = "src/kernel/boot/profiles/zigos_native.zig";
    const timer_path = "src/kernel/timer/timer.zig";
    const qemu_harness_path = "scripts/qemu-harness.sh";
    const kernel_build_path = "build_support/kernel.zig";
    const bootloader_path = "src/boot/boot_x86_64.S";
    const kernel_linker_path = "src/arch/x86_64/linker.ld";
    const qemu_grub_path = "src/boot/grub-x86_64-qemu.cfg";
    const production_grub_path = "src/boot/grub-x86_64-kernel.cfg";
    const ci_setup_path = ".github/actions/setup-zigos-ci/action.yml";
    const cpu_baseline_path = "src/arch/cpu_baseline.zig";
    const x86_path = "src/arch/x86.zig";
    const invpcid_path = "src/arch/x86/invpcid.S";
    const user_access_path = "src/arch/x86/user_access.S";
    const cpu_features_path = "src/arch/cpu_features.zig";
    const boot_entry_path = "src/kernel/boot/entry.zig";
    const paging_path = "src/kernel/memory/paging64.zig";
    const pcid_allocator_path = "src/kernel/memory/pcid_allocator.zig";
    const userspace_executor_path = "src/native/task/userspace_executor.zig";
    const userspace_scheduler_path = "src/native/task/userspace_scheduler.zig";
    const userspace_runtime_path = "src/userspace/runtime.zig";
    const userspace_ui_state_path = "src/userspace/ui_surface_state.zig";
    const permission_review_path = "src/native/policy/permission_review_service.zig";
    const input_driver_task_path = "src/native/drivers/input_driver_task.zig";
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
    if (!common.pathExists(io, acpi_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 ACPI parser is missing: {s}", .{acpi_path});
        return;
    }
    if (!common.pathExists(io, fadt_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 FADT suspend proof source is missing: {s}", .{fadt_path});
        return;
    }
    if (!common.pathExists(io, mcfg_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 PCIe firmware parser is missing: {s}", .{mcfg_path});
        return;
    }
    if (!common.pathExists(io, framebuffer_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 framebuffer proof source is missing: {s}", .{framebuffer_path});
        return;
    }
    if (!common.pathExists(io, handoff_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 boot handoff source is missing: {s}", .{handoff_path});
        return;
    }
    if (!common.pathExists(io, multiboot2_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 Multiboot2 parser is missing: {s}", .{multiboot2_path});
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
    if (!common.pathExists(io, isr_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 interrupt source is missing: {s}", .{isr_path});
        return;
    }
    if (!common.pathExists(io, interrupt_stubs_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 interrupt stubs are missing: {s}", .{interrupt_stubs_path});
        return;
    }
    if (!common.pathExists(io, runtime_init_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 runtime initialization source is missing: {s}", .{runtime_init_path});
        return;
    }
    if (!common.pathExists(io, native_profile_path)) {
        try common.addError(errors, allocator, "native scheduler loop source is missing: {s}", .{native_profile_path});
        return;
    }
    if (!common.pathExists(io, timer_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 timer source is missing: {s}", .{timer_path});
        return;
    }
    if (!common.pathExists(io, qemu_harness_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 QEMU harness is missing: {s}", .{qemu_harness_path});
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
    if (!common.pathExists(io, kernel_linker_path)) {
        try common.addError(errors, allocator, "x86-64 kernel linker source is missing: {s}", .{kernel_linker_path});
        return;
    }
    if (!common.pathExists(io, qemu_grub_path)) {
        try common.addError(errors, allocator, "QEMU boot configuration is missing: {s}", .{qemu_grub_path});
        return;
    }
    if (!common.pathExists(io, production_grub_path)) {
        try common.addError(errors, allocator, "production boot configuration is missing: {s}", .{production_grub_path});
        return;
    }
    if (!common.pathExists(io, ci_setup_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 CI setup action is missing: {s}", .{ci_setup_path});
        return;
    }
    if (!common.pathExists(io, cpu_baseline_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 CPU baseline source is missing: {s}", .{cpu_baseline_path});
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
        try common.addError(errors, allocator, "NUC11TNKi5 permission review source is missing: {s}", .{permission_review_path});
        return;
    }
    if (!common.pathExists(io, input_router_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 focused input router source is missing: {s}", .{input_router_path});
        return;
    }
    if (!common.pathExists(io, console_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 early console source is missing: {s}", .{console_path});
        return;
    }
    if (common.pathExists(io, legacy_vga_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 early console must not restore the legacy VGA text driver: {s}", .{legacy_vga_path});
    }
    if (!common.pathExists(io, nvme_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 NVMe proof source is missing: {s}", .{nvme_path});
        return;
    }
    if (!common.pathExists(io, xhci_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 xHCI proof source is missing: {s}", .{xhci_path});
        return;
    }
    if (!common.pathExists(io, xhci_hw_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 xHCI hardware probe source is missing: {s}", .{xhci_hw_path});
        return;
    }
    if (!common.pathExists(io, i225_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 I225 proof source is missing: {s}", .{i225_path});
        return;
    }
    if (!common.pathExists(io, pci_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 PCI inventory source is missing: {s}", .{pci_path});
        return;
    }
    if (!common.pathExists(io, mmio_windows_path)) {
        try common.addError(errors, allocator, "NUC11TNKi5 kernel MMIO layout source is missing: {s}", .{mmio_windows_path});
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
    const userspace_syscall_source = try common.readFileAlloc(allocator, io, userspace_syscall_path, common.source_file_max_bytes);
    const gdt_source = try common.readFileAlloc(allocator, io, gdt_path, common.source_file_max_bytes);
    const runtime_init_source = try common.readFileAlloc(allocator, io, runtime_init_path, common.source_file_max_bytes);
    const native_profile_source = try common.readFileAlloc(allocator, io, native_profile_path, common.source_file_max_bytes);
    const timer_source = try common.readFileAlloc(allocator, io, timer_path, common.source_file_max_bytes);
    const qemu_harness_source = try common.readFileAlloc(allocator, io, qemu_harness_path, common.source_file_max_bytes);
    const kernel_build_source = try common.readFileAlloc(allocator, io, kernel_build_path, common.source_file_max_bytes);
    const bootloader_source = try common.readFileAlloc(allocator, io, bootloader_path, common.source_file_max_bytes);
    const kernel_linker_source = try common.readFileAlloc(allocator, io, kernel_linker_path, common.source_file_max_bytes);
    const qemu_grub_source = try common.readFileAlloc(allocator, io, qemu_grub_path, common.source_file_max_bytes);
    const production_grub_source = try common.readFileAlloc(allocator, io, production_grub_path, common.source_file_max_bytes);
    const ci_setup_source = try common.readFileAlloc(allocator, io, ci_setup_path, common.source_file_max_bytes);
    const cpu_baseline_source = try common.readFileAlloc(allocator, io, cpu_baseline_path, common.source_file_max_bytes);
    const x86_source = try common.readFileAlloc(allocator, io, x86_path, common.source_file_max_bytes);
    const invpcid_source = try common.readFileAlloc(allocator, io, invpcid_path, common.source_file_max_bytes);
    const user_access_source = try common.readFileAlloc(allocator, io, user_access_path, common.source_file_max_bytes);
    const cpu_features_source = try common.readFileAlloc(allocator, io, cpu_features_path, common.source_file_max_bytes);
    const boot_entry_source = try common.readFileAlloc(allocator, io, boot_entry_path, common.source_file_max_bytes);
    const paging_source = try common.readFileAlloc(allocator, io, paging_path, common.source_file_max_bytes);
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
        "device inventory accepts only target xHCI input hardware",
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
        "ps2_bootstrap",
        ".ata_bootstrap",
        "AtaBrokerGrant",
    };
    for (retired_device_inventory_binding_snippets) |snippet| {
        if (std.mem.indexOf(u8, device_inventory_source, snippet) != null) {
            try common.addError(errors, allocator, "NUC11TNKi5 device inventory source must not bind production input through PS/2 bootstrap: {s}", .{snippet});
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
        "xhci_hw.probe(dev)",
        "device_inventory.registerDetected(.usb_controller, xhci_device_id, .xhci_inventory, false)",
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
    };
    for (required_boot_device_inventory_snippets) |snippet| {
        if (std.mem.indexOf(u8, devices_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 boot device inventory source must capture target-specific PCI snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, devices_source, "device_inventory.registerDetected(.input_device, xhci_device_id, .xhci_inventory, false)") != null) {
        try common.addError(errors, allocator, "NUC11TNKi5 PCI discovery must not publish input authority before keyboard enumeration and hardware event-ring evidence", .{});
    }
    const required_pci_inventory_snippets = [_][]const u8{
        "mcfg.Allocation",
        "pub const PCI_DEVICE_SIZE_CEILING_BYTES: usize = 20",
        "const PCI_INVENTORY_SIZE_CEILING_BYTES: usize = 5_120",
        "pub const HEAP_BACKED_PCI_INVENTORY_ON_FREESTANDING = true",
        "pub const PCI_INVENTORY_HANDLE_SIZE_CEILING_BYTES: usize = 8",
        "mmio_windows.pci_ecam.base",
        "paging.mapKernelBorrowedPage",
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
            try common.addError(errors, allocator, "NUC11TNKi5 PCI discovery must retain its cached topology-aware inventory: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, pci_source, "var boot_inventory: [PCI_INVENTORY_CAPACITY]PCIDevice") != null) {
        try common.addError(errors, allocator, "PCI inventory must remain heap-backed on freestanding kernels", .{});
    }
    if (std.mem.indexOf(u8, pci_source, "while (bus < PCI_MAX_BUS_COUNT)") != null) {
        try common.addError(errors, allocator, "NUC11TNKi5 PCI discovery must not restore repeated exhaustive 256-bus scans", .{});
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
            try common.addError(errors, allocator, "NUC11TNKi5 PCI discovery must not recache unused BAR words: {s}", .{snippet});
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
            try common.addError(errors, allocator, "NUC11TNKi5 kernel MMIO layout must retain bounded non-overlap enforcement: {s}", .{snippet});
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
            try common.addError(errors, allocator, "NUC11TNKi5 PCI discovery must not restore legacy configuration-port access: {s}", .{snippet});
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
            try common.addError(errors, allocator, "NUC11TNKi5 PCIe discovery must retain validated ACPI MCFG parsing: {s}", .{snippet});
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
                try common.addError(errors, allocator, "NUC11TNKi5 input path must not reintroduce legacy kernel keyboard snippet in {s}: {s}", .{ source_check.label, snippet });
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
            try common.addError(errors, allocator, "NUC11TNKi5 interrupt path must use x2APIC timer vectors with both legacy PICs masked: {s}", .{snippet});
        }
    }
    const required_compact_handler_dispatch_snippets = [_][]const u8{
        "exception_handlers: [EXCEPTION_VECTOR_COUNT]?InterruptHandler",
        "external_handlers: [external_handler_vectors.len]?InterruptHandler",
        "fn externalHandlerIndex(vector: usize) ?usize",
        "const HANDLER_STORAGE_SIZE_CEILING_BYTES: usize = 304",
    };
    for (required_compact_handler_dispatch_snippets) |snippet| {
        if (std.mem.indexOf(u8, isr_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 interrupt dispatch must retain compact handler storage: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, isr_source, "custom_handlers: [idt.IDT_ENTRIES]") != null) {
        try common.addError(errors, allocator, "NUC11TNKi5 interrupt dispatch must not restore a full-IDT function-pointer table", .{});
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
            try common.addError(errors, allocator, "NUC11TNKi5 interrupt path must not restore legacy PIC dispatch or IRQ stub surface: {s}", .{snippet});
        }
    }
    const required_x2apic_stubs = [_][]const u8{
        "ISR_NOERRCODE 64",
        "ISR_NOERRCODE 67",
        "ISR_NOERRCODE 255",
    };
    for (required_x2apic_stubs) |snippet| {
        if (std.mem.indexOf(u8, interrupt_stubs_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 interrupt assembly must expose the x2APIC timer surface: {s}", .{snippet});
        }
    }
    const required_interrupt_return_guard_snippets = [_][]const u8{
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
            try common.addError(errors, allocator, "NUC11TNKi5 interrupt assembly must not restore legacy PIC IRQ dispatch: {s}", .{snippet});
        }
    }
    const required_tsc_deadline_timer_snippets = [_][]const u8{
        "IA32_TSC_DEADLINE_MSR",
        "X2APIC_LVT_TIMER_MSR",
        "X2APIC_TIMER_MODE_TSC_DEADLINE",
        "x2apic.acknowledge()",
        "x86.writeMsr(IA32_TSC_DEADLINE_MSR, deadline)",
        "elapsedTicks",
        "nextTickDeadline",
        "synchronizeTicks",
        "scheduleNextTick",
        "scheduler_tick_enabled",
        "armSchedulerTick",
        "disarmSchedulerTick",
    };
    for (required_tsc_deadline_timer_snippets) |snippet| {
        if (std.mem.indexOf(u8, timer_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 timer must use invariant TSC-deadline delivery: {s}", .{snippet});
        }
    }
    const required_one_shot_scheduler_snippets = [_][]const u8{
        "timer.synchronize()",
        "xhci_hw.servicePendingEvents()",
        "session_manager.bindHardwareInput",
        "pollHardwareKeyboardReport",
        "xhci_hw.pollKeyboardReport()",
        "hardwareInputProof",
        "xhci_hw.inputProof()",
        "session_manager.servicePendingInputWork(now_ticks)",
        "xhci_hw.eventWorkPending()",
        "xhci_hw.lifecyclePending()",
        "userspaceSchedulerHasReadyTasks",
        "timer.armSchedulerTick()",
        "timer.disarmSchedulerTick()",
        "x86.cli()",
        "x86.sti()",
        "x86.hlt()",
    };
    for (required_one_shot_scheduler_snippets) |snippet| {
        if (std.mem.indexOf(u8, native_profile_source, snippet) == null) {
            try common.addError(errors, allocator, "native scheduler loop must retain one-shot idle deadline control: {s}", .{snippet});
        }
    }
    const required_emulator_countdown_timer_snippets = [_][]const u8{
        "X2APIC_TIMER_INITIAL_COUNT_MSR",
        "X2APIC_TIMER_CURRENT_COUNT_MSR",
        "X2APIC_TIMER_DIVIDE_CONFIG_MSR",
        "X2APIC_TIMER_MODE_PERIODIC",
        "initCalibratedCountdownTimer",
        "calibrated_countdown",
    };
    for (required_emulator_countdown_timer_snippets) |snippet| {
        if (std.mem.indexOf(u8, timer_source, snippet) == null) {
            try common.addError(errors, allocator, "QEMU software emulation must retain its isolated x2APIC countdown path: {s}", .{snippet});
        }
    }
    const required_accelerated_qemu_snippets = [_][]const u8{
        "qemu_harness_accelerator",
        "-c /dev/kvm",
        "QEMU_HARNESS_COMMAND+=(-accel",
        "printf '%s\\n' \"host\"",
        "max,+x2apic,tsc-frequency=2400000000",
    };
    for (required_accelerated_qemu_snippets) |snippet| {
        if (std.mem.indexOf(u8, qemu_harness_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 QEMU validation must use hardware-backed x2APIC when KVM is available: {s}", .{snippet});
        }
    }
    const required_compact_benchmark_boot_snippets = [_][]const u8{
        "boot_profile == .benchmark",
        "--strip-debug",
        "qemu_iso.addFileArg(boot_kernel)",
    };
    for (required_compact_benchmark_boot_snippets) |snippet| {
        if (std.mem.indexOf(u8, kernel_build_source, snippet) == null) {
            try common.addError(errors, allocator, "benchmark boot media must use the debug-stripped diagnostic-ELF derivative: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, qemu_grub_source, "qemu_software_cpu_fallback") == null) {
        try common.addError(errors, allocator, "QEMU boot configuration must explicitly request the software-emulator CPU fallback", .{});
    }
    if (std.mem.indexOf(u8, production_grub_source, "qemu_software_cpu_fallback") != null) {
        try common.addError(errors, allocator, "production boot configuration must not permit the software-emulator CPU fallback", .{});
    }
    const required_ci_kvm_snippets = [_][]const u8{
        "Enable KVM acceleration when available",
        "sudo chmod 0666 /dev/kvm",
        "test -w /dev/kvm",
    };
    for (required_ci_kvm_snippets) |snippet| {
        if (std.mem.indexOf(u8, ci_setup_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 CI setup must expose KVM to QEMU jobs when the runner supports it: {s}", .{snippet});
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
            try common.addError(errors, allocator, "NUC11TNKi5 timer must not restore PIT programming: {s}", .{snippet});
        }
    }
    const required_modern_cpu_baseline_snippets = [_][]const u8{
        "x2apic",
        "tsc_deadline",
        "invariant_tsc",
        "tsc_frequency_hz",
        "decodeTscFrequency",
        "pcid",
        "invpcid",
        "pge",
        "syscall",
        "smep",
        "smap",
        "umip",
    };
    for (required_modern_cpu_baseline_snippets) |snippet| {
        if (std.mem.indexOf(u8, cpu_baseline_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 CPU baseline must expose the modern timer and process-context contract: {s}", .{snippet});
        }
    }
    const required_x86_pcid_snippets = [_][]const u8{
        "CR4_PCIDE",
        "CR4_PGE",
        "CR3_NO_FLUSH",
        "pcidCr3Value",
        "writeCr3WithPcid",
        "invalidatePcid",
        "enableProcessContextIdentifiers",
        "processContextIdentifiersEnabled",
        "globalPagesEnabled",
        "CR4_SMEP",
        "CR4_SMAP",
        "CR4_UMIP",
        "supervisorAccessPreventionEnabled",
        "allowSupervisorUserMemory",
        "forbidSupervisorUserMemory",
        "EFER_SCE",
        "IA32_STAR_MSR",
        "IA32_LSTAR_MSR",
        "IA32_FMASK_MSR",
        "IA32_KERNEL_GS_BASE_MSR",
        "syscallExtensionEnabled",
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
    if (std.mem.indexOf(u8, interrupt_stubs_source, "isr_common_stub:\n    clac") == null) {
        try common.addError(errors, allocator, "x86 interrupt entry must clear AC before entering kernel handlers", .{});
    }
    const required_cpu_feature_pcid_snippets = [_][]const u8{
        "enableModernFeatures",
        "ProcessContextMode",
        "hardware_pcid",
        "software_flush",
        "CR4_PGE",
        "globalPagesEnabled",
        "CR4_SMEP",
        "CR4_SMAP",
        "CR4_UMIP",
        "supervisorAccessPreventionEnabled",
        "enableProcessContextIdentifiers",
        "processContextIdentifiersEnabled",
    };
    for (required_cpu_feature_pcid_snippets) |snippet| {
        if (std.mem.indexOf(u8, cpu_features_source, snippet) == null) {
            try common.addError(errors, allocator, "modern CPU feature enablement must retain snippet: {s}", .{snippet});
        }
    }
    const required_boot_process_context_snippets = [_][]const u8{
        "softwareCpuFallbackRequested",
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
    };
    for (required_boot_process_context_snippets) |snippet| {
        if (std.mem.indexOf(u8, boot_entry_source, snippet) == null) {
            try common.addError(errors, allocator, "CPU boot process-context gate must retain snippet: {s}", .{snippet});
        }
    }
    const required_boot_timer_snippets = [_][]const u8{
        "softwareCpuFallbackRequested",
        "qemu_software_cpu_fallback",
        "software_cpu_fallback",
        "hardware_tsc_timer",
        "software_timer_fallback",
        "required_features.tsc_deadline = true",
        "required_features.invariant_tsc = true",
        ".tsc_deadline else .calibrated_countdown",
    };
    for (required_boot_timer_snippets) |snippet| {
        if (std.mem.indexOf(u8, boot_entry_source, snippet) == null) {
            try common.addError(errors, allocator, "CPU boot timer gate must retain snippet: {s}", .{snippet});
        }
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
        "releaseProcessContext",
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
        "USER_STAR_BASE_SELECTOR",
        "SYSCALL_RFLAGS_MASK",
        "IA32_GS_BASE_MSR",
        "IA32_KERNEL_GS_BASE_MSR",
        "IA32_STAR_MSR",
        "IA32_LSTAR_MSR",
        "IA32_FMASK_MSR",
        "EFER_SCE",
        "setKernelStack",
        "syscallExtensionEnabled",
    };
    for (required_syscall_configuration_snippets) |snippet| {
        if (std.mem.indexOf(u8, syscall_source, snippet) == null) {
            try common.addError(errors, allocator, "native x86-64 syscall configuration must retain snippet: {s}", .{snippet});
        }
    }
    const required_syscall_entry_snippets = [_][]const u8{
        "zigos_syscall_entry",
        "swapgs",
        "CPU_KERNEL_STACK_TOP",
        "CPU_USER_STACK_POINTER",
        "fxsave64",
        "sysretq",
        "call syscall_handler",
        "call isrHandler",
    };
    for (required_syscall_entry_snippets) |snippet| {
        if (std.mem.indexOf(u8, syscall_entry_source, snippet) == null) {
            try common.addError(errors, allocator, "native x86-64 syscall entry must retain snippet: {s}", .{snippet});
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
            try common.addError(errors, allocator, "NUC11TNKi5 permission review must retain hardware xHCI input snippet: {s}", .{snippet});
        }
    }
    const required_input_router_snippets = [_][]const u8{
        "pub const MAX_KEYBOARDS",
        "pub const MAX_QUEUED_EVENTS",
        "pub const MAX_EVENTS_PER_INBOX",
        "KeyboardIdentity",
        "event_slots",
        "free_event_head",
        "report.sequence <= self.last_sequence",
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
            try common.addError(errors, allocator, "NUC11TNKi5 compositor input ownership must retain focused-router snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, input_router_source, "event_slots: [MAX_QUEUED_EVENTS]EventSlot =") != null) {
        try common.addError(errors, allocator, "NUC11TNKi5 input event slots must not return to inline freestanding router storage", .{});
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
            try common.addError(errors, allocator, "NUC11TNKi5 input router must not restore unobserved telemetry: {s}", .{snippet});
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
            try common.addError(errors, allocator, "NUC11TNKi5 input decoder must return bounded event batches: {s}", .{snippet});
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
            try common.addError(errors, allocator, "NUC11TNKi5 input decoder must not restore queued state or duplicate telemetry: {s}", .{snippet});
        }
    }
    const required_userspace_input_snippets = [_]struct {
        label: []const u8,
        source: []const u8,
        snippet: []const u8,
    }{
        .{ .label = userspace_executor_path, .source = userspace_executor_source, .snippet = "granted.rights.has(.input_recv)" },
        .{ .label = userspace_executor_path, .source = userspace_executor_source, .snippet = "mailbox_ptr.input_capability_id" },
        .{ .label = userspace_executor_path, .source = userspace_executor_source, .snippet = "last_yield_disposition" },
        .{ .label = userspace_executor_path, .source = userspace_executor_source, .snippet = "last_yield_ui_revision" },
        .{ .label = userspace_scheduler_path, .source = userspace_scheduler_source, .snippet = "outcome == .wait_for_event" },
        .{ .label = userspace_scheduler_path, .source = userspace_scheduler_source, .snippet = "executionRemainsReady(outcome)" },
        .{ .label = userspace_scheduler_path, .source = userspace_scheduler_source, .snippet = "ui_revision > slot.last_ui_state_revision" },
        .{ .label = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "const INPUT_EVENTS_PER_DISPATCH: usize = 8" },
        .{ .label = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "fn drainFocusedInput()" },
        .{ .label = userspace_runtime_path, .source = userspace_runtime_source, .snippet = ".wait_for_event" },
        .{ .label = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "recordInputEvent" },
        .{ .label = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "publishUiState" },
        .{ .label = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "mailbox.FLAG_OWNS_UI_SURFACE" },
        .{ .label = userspace_ui_state_path, .source = userspace_ui_state_source, .snippet = "pub const TEXT_CAPACITY: usize = abi.SURFACE_PRESENTATION_TEXT_BYTES" },
        .{ .label = userspace_ui_state_path, .source = userspace_ui_state_source, .snippet = "pub fn modelForBundle" },
        .{ .label = userspace_ui_state_path, .source = userspace_ui_state_source, .snippet = "test \"Notes UI state edits and commits document text\"" },
    };
    for (required_userspace_input_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 userspace input delivery must retain snippet in {s}: {s}", .{ required.label, required.snippet });
        }
    }
    const required_early_console_snippets = [_][]const u8{
        "const serial = @import(\"../drivers/serial.zig\")",
        "serial.init()",
        "serial.print(str)",
        "serial.putChar(c)",
    };
    for (required_early_console_snippets) |snippet| {
        if (std.mem.indexOf(u8, console_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 early console must remain serial-backed: {s}", .{snippet});
        }
    }
    const required_boot_handoff_snippets = [_][]const u8{
        "MULTIBOOT2_BOOTLOADER_MAGIC",
        "parseMultiboot2Info",
        "multiboot2MemoryMap",
        "capturedAcpi2Rsdp",
        "zigos_multiboot_magic != MULTIBOOT2_BOOTLOADER_MAGIC",
    };
    for (required_boot_handoff_snippets) |snippet| {
        if (std.mem.indexOf(u8, handoff_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 boot handoff must remain Multiboot2-only: {s}", .{snippet});
        }
    }
    const required_bootloader_load_contract_snippets = [_][]const u8{
        "MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS",
        ".long _start",
    };
    for (required_bootloader_load_contract_snippets) |snippet| {
        if (std.mem.indexOf(u8, bootloader_source, snippet) == null) {
            try common.addError(errors, allocator, "x86-64 bootloader must retain its explicit Multiboot2 entry contract: {s}", .{snippet});
        }
    }
    const required_kernel_load_contract_snippets = [_][]const u8{
        "PHDRS",
        "kernel PT_LOAD FLAGS(6);",
        "__kernel_start = .;",
        "__kernel_data_end = .;",
        "__kernel_end = .;",
    };
    for (required_kernel_load_contract_snippets) |snippet| {
        if (std.mem.indexOf(u8, kernel_linker_source, snippet) == null) {
            try common.addError(errors, allocator, "x86-64 linker must retain its single contiguous boot payload: {s}", .{snippet});
        }
    }
    if (std.mem.count(u8, kernel_linker_source, ":kernel") != 6) {
        try common.addError(errors, allocator, "x86-64 linker must bind all six runtime regions to one boot payload", .{});
    }
    const retired_bootloader_address_tag_snippets = [_][]const u8{
        "MULTIBOOT2_HEADER_TAG_ADDRESS",
        ".long multiboot2_header_start",
        ".long __kernel_data_end",
    };
    for (retired_bootloader_address_tag_snippets) |snippet| {
        if (std.mem.indexOf(u8, bootloader_source, snippet) != null) {
            try common.addError(errors, allocator, "x86-64 bootloader must not restore the size-sensitive address-tag relocator path: {s}", .{snippet});
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
            try common.addError(errors, allocator, "NUC11TNKi5 boot handoff must retain the ACPI RSDP tag path: {s}", .{snippet});
        }
    }
    const retired_multiboot2_acpi_snippets = [_][]const u8{
        "TAG_ACPI_OLD",
        "ACPI_RSDP_V1_BYTES",
        "seen_acpi_old",
    };
    for (retired_multiboot2_acpi_snippets) |snippet| {
        if (std.mem.indexOf(u8, multiboot2_source, snippet) != null) {
            try common.addError(errors, allocator, "NUC11TNKi5 boot handoff must not restore the ACPI 1 compatibility tag: {s}", .{snippet});
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
            try common.addError(errors, allocator, "NUC11TNKi5 ACPI parser must require ACPI 2+ with XSDT entries: {s}", .{snippet});
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
            try common.addError(errors, allocator, "NUC11TNKi5 ACPI parser must not restore RSDT or BIOS scanning compatibility: {s}", .{snippet});
        }
    }
    const required_mapped_acpi_snippets = [_][]const u8{
        "capturePlatformFirmwareEvidence",
        "capturedRsdp",
        "mappedPhysicalTableBytes",
        "paging.mapKernelBorrowedPage",
        "acpi.xsdtEntryCount",
        "mcfg.segmentZeroAllocation",
        ":ACPI_XSDT:OBSERVED",
    };
    for (required_mapped_acpi_snippets) |snippet| {
        if (std.mem.indexOf(u8, hardware_proof_source, snippet) == null) {
            try common.addError(errors, allocator, "NUC11TNKi5 firmware discovery must retain mapped ACPI table access: {s}", .{snippet});
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
            try common.addError(errors, allocator, "NUC11TNKi5 firmware discovery must not restore BIOS ACPI scanning or RSDT fallback: {s}", .{snippet});
        }
    }
    const retired_boot_handoff_snippets = [_][]const u8{
        "multiboot1",
        "MULTIBOOT_BOOTLOADER_MAGIC",
        "parseInfo(",
    };
    for (retired_boot_handoff_snippets) |snippet| {
        if (std.mem.indexOf(u8, handoff_source, snippet) != null) {
            try common.addError(errors, allocator, "NUC11TNKi5 boot handoff must not restore legacy Multiboot1 parsing: {s}", .{snippet});
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
        "SUPPORTED_PROTOCOLS_SIZE_CEILING_BYTES: usize = 770",
        "SupportedProtocolRange",
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
            try common.addError(errors, allocator, "NUC11TNKi5 xHCI proof source must enforce hardware-owned event-ring snippet: {s}", .{snippet});
        }
    }
    if (std.mem.indexOf(u8, xhci_source, "ports: [256]?PortProtocol") != null) {
        try common.addError(errors, allocator, "xHCI supported protocols must remain stored as capability ranges", .{});
    }
    const required_xhci_hw_snippets = [_][]const u8{
        "pci.memoryBar0(device_info)",
        "bar.address % PAGE_BYTES != 0",
        "mmio_windows.xhci.base",
        "paging.PAGE_PRESENT | paging.PAGE_CACHE_DISABLE",
        "readCapabilitySnapshot",
        "xhci.parseCapabilityRegisters(&snapshot)",
        "validateExtendedCapabilityRange",
        "ExtendedCapabilityReader",
        "probedLegacyOwnership",
        "OWNERSHIP_TIMEOUT_MILLISECONDS: u64 = 1_000",
        "writeOsOwnedByte",
        "paging.PAGE_WRITABLE",
        "tsc_clock.initialized",
        "tsc_clock.afterMilliseconds",
        "controllerReset",
        "enabledDeviceSlots",
        "writeReg32",
        "writeReg64",
        "InvariantClock",
        "BusMasteringNotRevoked",
        "controllerDmaFrameCount",
        "paging.alloc_frames(dma_frame_count)",
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
        "allocateControllerRuntimeState(capabilities.max_ports)",
        "controllerRuntimeStateFrameCountFor",
        "active_keyboard_reports = controller_runtime_state.keyboard_reports",
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
            try common.addError(errors, allocator, "NUC11TNKi5 xHCI hardware probe must retain read-only capability validation snippet: {s}", .{snippet});
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
        "if (hardware_backed and !exportable)",
        "secret.resident_material = false",
        "secret.value_len = 0",
        "pub const IMPORTS_INTO_PREZEROED_SECRET_SLOTS = true",
        "const secret = &self.secrets[slot_index]",
        "dense secret imports append into pre-zeroed slots",
        "self.secret_count += 1",
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
    const native_kernel_path = "src/native/kernel_api/native_kernel.zig";
    const device_syscalls_path = "src/native/kernel_api/device_syscalls.zig";
    const endpoint_syscalls_path = "src/native/kernel_api/endpoint_syscalls.zig";
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
    const native_kernel_source = try readRequiredSource(allocator, io, errors, native_kernel_path) orelse return;
    const device_syscalls_source = try readRequiredSource(allocator, io, errors, device_syscalls_path) orelse return;
    const endpoint_syscalls_source = try readRequiredSource(allocator, io, errors, endpoint_syscalls_path) orelse return;
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
        "pub const ABI_VERSION: u16 = 5",
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
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "try std.testing.expectEqual(@as(usize, 48), @sizeOf(EndpointRecvResponse))" },
        .{ .path = component_port_path, .source = component_port_source, .snippet = "payload_out: []u8" },
        .{ .path = component_port_path, .source = component_port_source, .snippet = "attached_capability_out: *abi.CapabilityDescriptor" },
        .{ .path = native_kernel_path, .source = native_kernel_source, .snippet = "self.endpoint_table.recvInto(" },
        .{ .path = syscall_surface_path, .source = syscall_surface_source, .snippet = "syscall surface validates compact endpoint receive outputs before dequeue" },
    };
    for (compact_endpoint_receive_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "Compact endpoint receive ABI must retain snippet in {s}: {s}", .{ required.path, required.snippet });
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
        .{ .path = session_manager_contexts_path, .source = session_manager_contexts_source, .snippet = "const allocation = kernel_memory.kmalloc(@sizeOf(endpoint_mod.Table)) orelse return error.NoSpaceLeft" },
        .{ .path = session_manager_contexts_path, .source = session_manager_contexts_source, .snippet = "kernel_memory.kfree(@ptrCast(table))" },
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
        .{ .path = session_manager_contexts_path, .source = session_manager_contexts_source, .snippet = "const allocation = kernel_memory.kmalloc(@sizeOf(native_ux.Controller)) orelse return error.NoSpaceLeft" },
        .{ .path = session_manager_contexts_path, .source = session_manager_contexts_source, .snippet = "kernel_memory.kfree(@ptrCast(controller))" },
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
        .{ .path = endpoint_syscalls_path, .source = endpoint_syscalls_source, .snippet = "var payload_buffer: [endpoint.MAX_MESSAGE_BYTES]u8" },
        .{ .path = endpoint_syscalls_path, .source = endpoint_syscalls_source, .snippet = "request.payload = dispatch.copyUserSlice(memory, request.payload, &payload_buffer)" },
        .{ .path = endpoint_syscalls_path, .source = endpoint_syscalls_source, .snippet = "component_port.invokeGeneratedFromValidatedSyscall(.endpoint_send, port, request, now_ticks)" },
        .{ .path = syscall_surface_path, .source = syscall_surface_source, .snippet = "invalid_payload_ptr[0..1]" },
    };
    for (protected_endpoint_send_snippets) |required| {
        if (std.mem.indexOf(u8, required.source, required.snippet) == null) {
            try common.addError(errors, allocator, "SMAP-safe endpoint send path must retain snippet in {s}: {s}", .{ required.path, required.snippet });
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
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "pub const SURFACE_PRESENTATION_TEXT_BYTES: usize = 512" },
        .{ .path = native_abi_path, .source = native_abi_source, .snippet = "pub const SurfacePresentation = ex" ++ "tern struct" },
        .{ .path = component_port_path, .source = component_port_source, .snippet = "pub fn surfacePresent(" },
        .{ .path = native_kernel_path, .source = native_kernel_source, .snippet = "authorizeSubjectTaskOperation(.surface_present" },
        .{ .path = compositor_session_path, .source = compositor_session_source, .snippet = "pub fn presentSurface(" },
        .{ .path = session_manager_boot_flow_path, .source = session_manager_boot_flow_source, .snippet = "bindSurfacePresentationReceiver" },
        .{ .path = userspace_mailbox_path, .source = userspace_mailbox_source, .snippet = "pub const VERSION: u16 = 5" },
        .{ .path = userspace_mailbox_path, .source = userspace_mailbox_source, .snippet = "pub const ABI_SIZE_BYTES: usize = 192" },
        .{ .path = userspace_mailbox_path, .source = userspace_mailbox_source, .snippet = "heartbeat_increment: u32 = 1" },
        .{ .path = userspace_executor_path, .source = userspace_executor_source, .snippet = "granted.rights.has(.surface_present)" },
        .{ .path = userspace_executor_path, .source = userspace_executor_source, .snippet = ".heartbeat_increment = update.heartbeat_increment" },
        .{ .path = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "fn presentUiState(" },
        .{ .path = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "zigos_userspace_bootstrap.heartbeat_increment" },
        .{ .path = userspace_runtime_path, .source = userspace_runtime_source, .snippet = "const input = drainFocusedInput();" },
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
        "try std.testing.expect(catalog.findByBundleId(\"zigos.system.session-manager\").?.embedsElf())",
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
        "# ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:UEFI_BOOT:PASS\n" ++
        "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_TABLES:PASS\n";

    try std.testing.expect(!markerFileHasActiveLine(source, "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:UEFI_BOOT:PASS"));
    try std.testing.expect(markerFileHasActiveLine(source, "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5:ACPI_TABLES:PASS"));
}

test "hardware marker lookup requires a complete active line" {
    const source = "prefix ZIGOS:NATIVE:READY suffix\nZIGOS:NATIVE:READY_EXTRA\n";
    try std.testing.expect(!markerFileHasActiveLine(source, "ZIGOS:NATIVE:READY"));
}
