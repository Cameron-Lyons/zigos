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
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:MEMORY_MAP:OBSERVED",
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
    "ZIGOS:HW_TARGET:ASUS_NUC15CRSU7:MEMORY_MAP:OBSERVED",
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
const RETIRED_TRACK_CLAIMS = [_][]const u8{ "demo-image migration", "migration inputs" };
const RETIRED_TRACK_CLAIM_FIELDS = [_][]const u8{ "current_evidence", "graduation_criteria", "next_actions" };
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

const PRODUCTION_CMDLINE_PATH = "src/boot/cmdline.txt";
/// Checked for the same production boot flags while it exists.
const PRODUCTION_GRUB_CONFIG_PATH = "src/boot/grub-x86_64-kernel.cfg";
const NATIVE_SCHEDULER_LOOP_PATH = "src/kernel/boot/profiles/zigos_native.zig";

const KERNEL_TCB_ROOT = "src/kernel";
const KERNEL_TCB_EXCLUDED_DIRS = [_][]const u8{"src/kernel/boot/benchmark"};
const KERNEL_TCB_EXCLUDED_FILES = [_][]const u8{
    "src/kernel/tcb.zig",
    "src/kernel/boot/recovery_suite.zig",
    "src/kernel/boot/profiles/recovery.zig",
    "src/kernel/boot/profiles/benchmark.zig",
};
const KERNEL_TCB_FORBIDDEN_IMPORT_PREFIXES = [_][]const u8{
    "native/storage/",
    "native/sync/",
    "native/policy/",
    "native/services/",
    "native/demo/",
    "native/platform/compositor",
    "native/platform/rendered_shell",
    "native/platform/os_contract",
};

/// Source text that must stay absent so retired legacy surfaces and
/// security regressions cannot quietly return. A path ending in '/' is a
/// directory tree of Zig sources that must exist, so security bans on it
/// survive file renames. A missing file satisfies its bans, so deleting code
/// never requires editing this table.
const SourceBan = struct {
    paths: []const []const u8,
    snippets: []const []const u8,
    reason: []const u8,
};

const RETIRED_PATHS = [_]struct { path: []const u8, reason: []const u8 }{
    .{ .path = "src/kernel/drivers/vga.zig", .reason = "the early console must not restore the legacy VGA text driver" },
};

const RETIRED_SOURCES = [_]SourceBan{
    .{
        .paths = &.{"src/kernel/boot/profiles/zigos_native.zig"},
        .snippets = &.{"_ = xhci_driver_task.dispatch();"},
        .reason = "the native idle loop must not service xHCI from the kernel",
    },
    .{
        .paths = &.{"src/native/drivers/device_inventory.zig"},
        .snippets = &.{
            "defaultRecord(.network_adapter, 100)",
            "defaultRecord(.storage_controller, 200)",
            "defaultRecord(.usb_controller, 300)",
            "defaultRecord(.input_device, 600)",
            "ps2_bootstrap",
            ".ata_bootstrap",
            "AtaBrokerGrant",
        },
        .reason = "device inventory must not restore synthetic fallback ids or PS/2 and ATA bootstrap bindings",
    },
    .{
        .paths = &.{"src/kernel/boot/init/devices.zig"},
        .snippets = &.{"device_inventory.registerDetected(.input_device, xhci_device_id, .xhci_inventory, false)"},
        .reason = "PCI discovery must not publish input authority before keyboard enumeration and hardware event-ring evidence",
    },
    .{
        .paths = &.{"src/kernel/drivers/"},
        .snippets = &.{ "CONFIG_ADDRESS", "CONFIG_DATA", "io.outl", "io.inl" },
        .reason = "PCI discovery must not restore legacy configuration-port access",
    },
    .{
        .paths = &.{"src/kernel/drivers/pci.zig"},
        .snippets = &.{ "../utils/io.zig", "var boot_inventory: [PCI_INVENTORY_CAPACITY]PCIDevice", "while (bus < PCI_MAX_BUS_COUNT)" },
        .reason = "PCI discovery must not restore port I/O, inline inventory storage or repeated exhaustive 256-bus scans",
    },
    .{
        .paths = &.{"src/kernel/drivers/pci.zig"},
        .snippets = &.{ "PCI_BAR2_OFFSET", "PCI_BAR3_OFFSET", "PCI_BAR4_OFFSET", "PCI_BAR5_OFFSET", "bar2: u32", "bar3: u32", "bar4: u32", "bar5: u32" },
        .reason = "PCI discovery must not recache unused BAR words",
    },
    .{
        .paths = &.{ "src/kernel/interrupts/isr.zig", "src/kernel/boot/init/runtime.zig", "src/native/policy/permission_review_service.zig" },
        .snippets = &.{ "keyboard.zig", "KEYBOARD_IRQ_VECTOR", "PIC_KEYBOARD_IRQ_BIT", "deferInputDataPlaneToUserspace", "keyboard.has_char()" },
        .reason = "input must not return to the legacy kernel keyboard path",
    },
    .{
        .paths = &.{"src/kernel/interrupts/isr.zig"},
        .snippets = &.{
            "PIC_EOI",               "PIC_ICW",          "PIC_TIMER_IRQ_BIT",                  "PIC_MASTER_NO_SLAVE",
            "IRQ_SLAVE_BASE_VECTOR", "irq_stubs",        "remapPIC",                           "irqHandler",
            "extern fn irq0",        "extern fn irq1()", "custom_handlers: [idt.IDT_ENTRIES]",
        },
        .reason = "interrupt dispatch must not restore legacy PIC dispatch, IRQ stubs or a full-IDT handler table",
    },
    .{
        .paths = &.{"src/kernel/interrupts/interrupt64.S"},
        .snippets = &.{ ".macro IRQ", "irq_common_stub", ".extern irqHandler", "IRQ 0, 32" },
        .reason = "interrupt assembly must not restore legacy PIC IRQ dispatch",
    },
    .{
        .paths = &.{"src/kernel/timer/timer.zig"},
        .snippets = &.{ "PIT_CHANNEL0", "PIT_COMMAND", "PIT_FREQUENCY", "io.outb" },
        .reason = "the timer must not restore PIT programming",
    },
    .{
        .paths = &.{
            "src/native/task/userspace_executor.zig",
            "src/arch/xstate64.inc",
            "src/kernel/interrupts/interrupt64.S",
            "src/kernel/interrupts/syscall64.S",
            "src/kernel/interrupts/fred64.S",
        },
        .snippets = &.{
            "zigos_userspace_resume_requested",
            "zigos_userspace_resume_esp",
            "zigos_userspace_resume_eip",
            "zigos_userspace_xstate",
            "zigos_kernel_xstate",
        },
        .reason = "native entry must not restore shared cross-CPU continuation state",
    },
    .{
        .paths = &.{"src/kernel/interrupts/syscall64.S"},
        .snippets = &.{"xorq %rdi"},
        .reason = "syscall entry must keep the userspace request pointer in %rdi",
    },
    .{
        .paths = &.{ "src/kernel/memory/paging64.zig", "src/native/task/userspace_executor.zig" },
        .snippets = &.{ "var current_page_directory:", "var registered_executor:", "var trap_stack:", "switchPageDirectory" },
        .reason = "the native runtime must not restore a shared CPU owner or the flush-on-every-switch API",
    },
    .{
        .paths = &.{"src/arch/cpu_features.zig"},
        .snippets = &.{"x86.enableLass("},
        .reason = "LASS activation must wait for native descriptor and entry initialization",
    },
    .{
        .paths = &.{ "src/kernel/smp/ap_trampoline.S", "src/kernel/smp/trampoline.zig" },
        .snippets = &.{"smp_trampoline_cr4"},
        .reason = "the AP trampoline must enter with minimal CR4 controls instead of copying BSP state",
    },
    .{
        .paths = &.{"src/arch/x86.zig"},
        .snippets = &.{"cet_programmed"},
        .reason = "CET enablement must use admitted per-CPU policy instead of shared programming state",
    },
    .{
        .paths = &.{"src/arch/x86.zig"},
        .snippets = &.{"fn setFredRsp0("},
        .reason = "entry-stack binding must update every normal FRED stack level instead of RSP0 alone",
    },
    .{
        .paths = &.{"src/native/task/userspace_scheduler.zig"},
        .snippets = &.{ "policy/manifest.zig", "session/service_catalog.zig", "xhci_driver_task.zig" },
        .reason = "the userspace scheduler must not import product policy, the service catalog or driver tasks",
    },
    .{
        .paths = &.{"src/native/task/userspace_scheduler.zig"},
        .snippets = &.{ "self.executor.last_yield_ui_revision", "self.executor.last_user_exception", "self.executor.last_yield_disposition" },
        .reason = "the scheduler must read dispatch results from its execution receipt instead of the anchor Executor",
    },
    .{
        .paths = &.{"src/native/task/userspace_executor.zig"},
        .snippets = &.{"pending_user_context64"},
        .reason = "userspace entry must borrow the active mapping context instead of an Executor context copy",
    },
    .{
        .paths = &.{ "src/userspace/runtime.zig", "src/native/task/userspace_executor.zig", "src/native/kernel_api/operation_metadata.zig" },
        .snippets = &.{ "WaitRequest", "parkUntilEvent", "requestEventWait", ".operation = .wait," },
        .reason = "voluntary yield must not restore a separate wait syscall or an ambient Executor setter",
    },
    .{
        .paths = &.{"src/native/task/dispatch_transport.zig"},
        .snippets = &.{"fn beginCollection("},
        .reason = "transport collection must keep one caller-owned success-output boundary",
    },
    .{
        .paths = &.{
            "src/kernel/interrupts/isr.zig",
            "src/kernel/interrupts/interrupt64.S",
            "src/arch/x86/syscall_trap.S",
            "src/native/task/userspace_executor.zig",
        },
        .snippets = &.{ "setUserGate", "ISR_NOERRCODE 128", "ISR_NOERRCODE 129", "int $0x80", "int $129" },
        .reason = "userspace entry must not restore the software-interrupt ABI",
    },
    .{
        .paths = &.{"src/native/platform/input_router.zig"},
        .snippets = &.{
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
        },
        .reason = "the input router must not restore unobserved telemetry",
    },
    .{
        .paths = &.{"src/native/drivers/input_driver_task.zig"},
        .snippets = &.{
            "EVENT_QUEUE_CAPACITY",
            "COMPACT_EVENT_QUEUE_METADATA",
            "QUEUE_ONLY_DECODER_STATE",
            "SINGLE_REPORT_EVENT_QUEUE",
            "EventQueueFull",
            "pub fn poll(",
            "pub fn pendingCount(",
            "reports_consumed: usize",
            "events_emitted: usize",
        },
        .reason = "the input decoder must not restore queued state or duplicate telemetry",
    },
    .{
        .paths = &.{
            "src/native/session/session_manager_contexts.zig",
            "src/native/session/service_graph_builder.zig",
            "src/native/session/supervisor.zig",
            "src/native/platform/input_router.zig",
            "src/native/storage/storage_volume.zig",
        },
        .snippets = &.{
            "endpoint_table: endpoint_mod.Table =",
            "review_ux_controller: native_ux.Controller =",
            "background_dispatcher: background_dispatch.Controller =",
            "service_bindings: ServiceBindings = ServiceBindings.init(),",
            "diagnostics: [MAX_DIAGNOSTICS]DiagnosticEvent",
            "event_slots: [MAX_QUEUED_EVENTS]EventSlot =",
            "signer_text_pool: [SIGNER_TEXT_POOL_BYTES]u8",
        },
        .reason = "session, router and storage tables must not move back into inline owner storage",
    },
    .{
        .paths = &.{"src/native/platform/event_ledger.zig"},
        .snippets = &.{ "for (&self.events.slots, 0..) |*slot, index|", "for (&backing.events.slots, 0..) |*slot, index|" },
        .reason = "event-ledger rollover must not restore the full-slot oldest-event scan",
    },
    .{
        .paths = &.{"src/boot/boot_x86_64.S"},
        .snippets = &.{
            "MULTIBOOT2_HEADER_TAG_ADDRESS",
            ".long multiboot2_header_start",
            ".long __kernel_data_end",
            "MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS",
            ".long _start",
            ".code32",
        },
        .reason = "the bootloader must not restore the retired protected-mode Multiboot entry",
    },
    .{
        .paths = &.{"src/kernel/boot/multiboot2.zig"},
        .snippets = &.{ "TAG_ACPI_OLD", "ACPI_RSDP_V1_BYTES", "seen_acpi_old" },
        .reason = "the boot handoff must not restore the ACPI 1 compatibility tag",
    },
    .{
        .paths = &.{"src/kernel/platform/acpi.zig"},
        .snippets = &.{ "RSDT_SIGNATURE", "rsdt_address", "findRsdp(", "rootEntrySize" },
        .reason = "the ACPI parser must not restore RSDT or BIOS scanning compatibility",
    },
    .{
        .paths = &.{"src/kernel/platform/hardware_proof.zig"},
        .snippets = &.{ "BIOS_RSDP_SCAN", "acpi.findRsdp", "rsdp.rsdt_address", "rootTableEntry", ":ACPI_RSDP:OBSERVED" },
        .reason = "firmware discovery must not restore BIOS ACPI scanning or RSDT fallback",
    },
    .{
        .paths = &.{"src/kernel/boot/handoff.zig"},
        .snippets = &.{ "multiboot1", "MULTIBOOT_BOOTLOADER_MAGIC", "parseInfo(" },
        .reason = "the boot handoff must not restore Multiboot1 parsing",
    },
    .{
        .paths = &.{"build_support/kernel.zig"},
        .snippets = &.{"const boot_kernel = if"},
        .reason = "debug stripping must apply to every kernel boot profile",
    },
    .{
        .paths = &.{"tools/host/images.zig"},
        .snippets = &.{"exitBootServices"},
        .reason = "the image builder must install the native EFI stub instead of driving firmware boot services itself",
    },
    .{
        .paths = &.{ "src/kernel/drivers/xhci.zig", "src/kernel/drivers/xhci_hw.zig" },
        .snippets = &.{ "ports: [256]?PortProtocol", "var ports: [256]PortRuntimeState" },
        .reason = "xHCI port state must remain sized to reported hardware capacity",
    },
    .{
        .paths = &.{ "src/native/storage/volume/backend.zig", "src/native/drivers/bootstrap_driver_port.zig" },
        .snippets = &.{ "ata_bootstrap_broker", "attachAtaBootstrap" },
        .reason = "storage must not reintroduce the retired ATA attachment bridge",
    },
    .{
        .paths = &.{"src/native/session/native_store_mount.zig"},
        .snippets = &.{
            "checkpoint_store.volume.attachBackendFns(",
            "checkpoint_store.volume.attachAtaBootstrapDevice(",
            "checkpoint_store.volume.attachAtaBootstrapBrokerBackendFns(",
        },
        .reason = "the native store must not adopt non-NVMe root storage",
    },
    .{
        .paths = &.{"src/native/storage/storage_volume.zig"},
        .snippets = &.{ "findWorkspaceSlotById", "findSnapshotSlotIndexById" },
        .reason = "storage replay must not reintroduce linear scan helpers",
    },
    .{
        .paths = &.{"src/native/"},
        .snippets = &.{ "digestSecretMaterial", "defaultSeal" },
        .reason = "hardware-backed secrets must not fall back to software digests",
    },
    .{
        .paths = &.{"src/native/"},
        .snippets = &.{ "request.credential_identity", "request.replacement_credential_identity" },
        .reason = "the identity vault must not trust request-supplied signing authority",
    },
    .{
        .paths = &.{"src/native/platform/os_identity.zig"},
        .snippets = &.{ "request.tick", "request.threshold" },
        .reason = "the identity vault must not trust request-supplied clocks or approval thresholds",
    },
    .{
        .paths = &.{"src/native/task/userspace_scheduler.zig"},
        .snippets = &.{"return self.resource_telemetry_source != .hardware or self.resource_hardware_evidence_complete"},
        .reason = "emulator or boot-provider telemetry must not wake hardware queues",
    },
    .{
        .paths = &.{
            "src/native/platform/platform_policy_signals.zig",
            "src/kernel/boot/benchmark/suite.zig",
            "src/native/drivers/bootstrap_driver_port.zig",
            "src/native/drivers/driver_runtime.zig",
            "src/tests/spec/backlog_gates.zig",
        },
        .snippets = &.{"syntheticUserspaceImage("},
        .reason = "hardware policy counters, benchmarks and driver data paths must use generated images instead of synthetic executable descriptors",
    },
    .{
        .paths = &.{"src/native/session/supervisor.zig"},
        .snippets = &.{
            "isolation_domain_id: u64",
            "boundary: contract.ServiceBoundary",
            "restartable: bool",
            "network_privilege: contract.NetworkPrivilege",
            "storage_privilege: contract.StoragePrivilege",
            "ui_privilege: contract.UiPrivilege",
            "driver_class: ?driver_service.DeviceClass",
        },
        .reason = "supervisor service records must not duplicate schema metadata",
    },
    .{
        .paths = &.{"src/native/kernel_api/device_broker.zig"},
        .snippets = &.{ "publishAtaController", "HostedAtaControllerState", "storage_driver_protocol" },
        .reason = "the device broker must not reintroduce the retired ATA broker",
    },
    .{
        .paths = &.{"src/native/"},
        .snippets = &.{ "x86.inb", "x86.outb", "device_port_read", "device_port_write", "DevicePortRead", "DevicePortWrite", "DevicePortWidth", "devicePortRead", "devicePortWrite" },
        .reason = "native drivers and the userspace driver ABI must not reintroduce port I/O",
    },
    .{
        .paths = &.{"src/native/session/session_manager_boot_flow.zig"},
        .snippets = &.{ "input_authority_failures", "surface_authority_failures" },
        .reason = "session managers must not retain unobserved authority failure counters",
    },
    .{
        .paths = &.{"src/native/"},
        .snippets = &.{"borrowImmediateUserSlice"},
        .reason = "endpoint send must not retain a borrowed userspace payload beyond its scoped SMAP access window",
    },
    .{
        .paths = &.{"src/native/"},
        .snippets = &.{"capability-issued-at"},
        .reason = "measured policy roots must not include runtime capability issuance timestamps",
    },
    .{
        .paths = &.{"src/native/drivers/driver_service.zig"},
        .snippets = &.{ "dma_range_count: u8", "dma_ranges: [MAX_DMA_RANGES]DmaRange" },
        .reason = "driver DMA windows must stay derived from device policy instead of mutable per-record storage",
    },
    .{
        .paths = &.{"src/native/drivers/driver_runtime.zig"},
        .snippets = &.{
            "publisher_len: u8",
            "publisher: [MAX_ACTIVATION_PUBLISHER_BYTES]u8",
            "iommu_enforced: bool",
            "exclusive_claim: bool",
            "kernel_bootstrap: bool",
        },
        .reason = "driver activation records must derive their publisher and state flags",
    },
    .{
        .paths = &.{"src/tests/spec/drivers_storage_sync.zig"},
        .snippets = &.{"e1000-userspace"},
        .reason = "driver specs must not use e1000 as a production network fixture",
    },
    .{
        .paths = &.{"src/native/task/userspace_boot_registry.zig"},
        .snippets = &.{"spec.signed"},
        .reason = "boot userspace must not retain an unsigned registry policy path",
    },
    .{
        .paths = &.{"src/native/task/userspace_archive_index.zig"},
        .snippets = &.{ "@import(\"../core/id_index.zig\")", "const bundle_index = buildBundleIndex()", "fn bundleIndexKey(" },
        .reason = "the userspace archive must not duplicate the role registry index",
    },
    .{
        .paths = &.{ "src/userspace/runtime.zig", "src/userspace/linker.ld", "tools/generate_userspace_archive.zig" },
        .snippets = &.{ "userspace_descriptor", "zigos_userspace_descriptor" },
        .reason = "userspace must not restore runtime descriptor plumbing",
    },
    .{
        .paths = &.{"src/native/task/userspace_loader.zig"},
        .snippets = &.{"syntheticExecutableImage"},
        .reason = "the catalog must not synthesize executable images from metadata-only requests",
    },
    .{
        .paths = &.{"src/native/platform/rendered_shell/task_launch.zig"},
        .snippets = &.{"const image = task_runtime.syntheticUserspaceImage(config.task_label, config.task_entry)"},
        .reason = "rendered-shell task launch must not synthesize descriptors unconditionally",
    },
    .{
        .paths = &.{ "src/main.zig", "src/efi_entry.zig" },
        .snippets = &.{"ARCHITECTURE_SMP_PROOF"},
        .reason = "production roots must not enable isolated architecture-proof callbacks",
    },
};

/// Security controls that refactors must not drop; moving one out of its
/// scopes means retargeting its entry. Every scope must yield at least one
/// source, and scopes follow the SourceBan path rules.
const SecurityControl = struct {
    scopes: []const []const u8,
    snippets: []const []const u8,
    reason: []const u8,
    match: Match = .any_scope,

    const Match = enum {
        /// Each snippet appears in at least one scope, so it may move between them.
        any_scope,
        /// Every scope contains every snippet.
        each_scope,
        /// Every scope contains the snippets in this order. The first anchors
        /// the rest, and the last, the step they guard, must not also appear
        /// between the anchor and those checks.
        ordered,
    };
};

const SECURITY_CONTROLS = [_]SecurityControl{
    .{
        .scopes = &.{"src/native/kernel_api/device_broker.zig"},
        .snippets = &.{
            "if (request.bus_master_dma_enabled and request.mode != .brokered_dma_buffers)",
            "try std.testing.expectError(error.UnsupportedBusMasterDma, programDmaIsolation",
            "try std.testing.expect(!status.bus_master_dma_enabled)",
        },
        .reason = "the device broker must confine bus-master DMA to brokered buffers",
    },
    .{
        .scopes = &.{"src/native/drivers/bootstrap_driver_port.zig"},
        .snippets = &.{
            "if (!programStorageDmaIsolation(publication.device_id, dma_domain_id)) return false",
            "device_broker.programBusMasterStorageDmaIsolation(",
        },
        .reason = "storage activation must program broker-confined controller DMA before publishing the controller session",
    },
    .{
        .scopes = &.{ "src/native/drivers/bootstrap_driver_port.zig", "src/tests/spec/drivers_storage_sync.zig" },
        .snippets = &.{
            "if (!networkPublicationMatchesDetectedDevice(device_id)) return false",
            "try std.testing.expect(!activateNetworkDevice(i225_device_id, 9))",
            "try std.testing.expect(!bootstrap_driver_port.activateNetworkDevice(i225_device_id, 800))",
        },
        .reason = "network activation must validate the detected NIC before publication",
    },
    .{
        .scopes = &.{ "src/native/task/userspace_boot_registry.zig", "src/native/task/userspace_launch.zig" },
        .snippets = &.{
            "try std.testing.expect(catalog.findByBundleId(\"zigos.system.session\").?.embedsElf())",
            "if (!image.embedsElf()) return error.EmbeddedArtifactRequired",
        },
        .reason = "boot userspace must launch only embedded, build-validated ELF artifacts",
    },
    .{
        .scopes = &.{ "src/native/storage/storage_volume.zig", "src/native/session/native_store_mount.zig" },
        .snippets = &.{
            "try validateReplayLog(log, loaded.root)",
            "if (!canAdoptProductionRootVolume(root_volume)) return false",
        },
        .reason = "storage must validate replay logs against the committed root and adopt only production NVMe root volumes",
    },
    .{
        .scopes = &.{"src/kernel/drivers/device_isolation.zig"},
        .snippets = &.{
            "if (!intel_vtd.requesterProtected(device)) return error.DmaIsolationBypassed;",
            "if (!intel_vtd.faultMonitoringEnabled()) return error.DmaFaultMonitoringUnavailable;",
            "if (!intel_vtd.interruptIsolationEnabled()) return error.InterruptIsolationUnavailable;",
            "intel_vtd.routeInterrupt(device, vector,",
            "errdefer intel_vtd.clearInterruptRoute(device)",
            "intel_vtd.pollFaultForDevice(device)",
        },
        .reason = "the shared isolation helper must require VT-d translation, fault recording and interrupt remapping, remap every message route and poll DMA faults",
    },
    .{
        .scopes = &.{"src/kernel/drivers/pci.zig"},
        .snippets = &.{"if (busMasteringEnabled(dev)) return error.BusMasteringNotRevoked;"},
        .reason = "BAR admission must refuse devices that still hold inherited bus mastering",
    },
    .{
        .scopes = &.{ "src/kernel/drivers/xhci_hw.zig", "src/kernel/drivers/intel_i225_hw.zig", "src/kernel/drivers/virtio_net_hw.zig" },
        .snippets = &.{ "BusMasteringNotRevoked", "device_isolation.requireIsolated(", "device_isolation.routeInterrupt(", ".pollFault" },
        .match = .each_scope,
        .reason = "DMA-capable drivers must refuse inherited bus mastering, require VT-d requester isolation, remap interrupts and poll DMA faults",
    },
    .{
        .scopes = &.{"src/kernel/drivers/nvme_hw.zig"},
        .snippets = &.{ "return error.BusMasteringNotRevoked", "!intel_vtd.requesterProtected(dev)) return error.DmaIsolationBypassed", "device_isolation.routeInterrupt(", "device_isolation.pollFault(" },
        .reason = "the NVMe driver must revoke inherited bus mastering, require VT-d requester isolation, remap its interrupt and poll DMA faults",
    },
    .{
        .scopes = &.{"src/kernel/drivers/xhci_hw.zig"},
        .snippets = &.{
            "dma_plan.frameCount() > dma_frame_count",
            "PORT_RESET_TIMEOUT_CONTAINED",
            "COMMAND_TIMEOUT_CONTAINED",
            "TRANSFER_TIMEOUT_CONTAINED",
        },
        .reason = "the xHCI driver must bound its DMA plan and contain controller timeouts",
    },
    .{
        .scopes = &.{"src/kernel/interrupts/interrupt64.S"},
        .snippets = &.{
            "isr_common_stub:",
            "endbr64",
            "clac",
            "call isrHandler",
            "ZIGOS_IDT_VALIDATE_RETURN_PREFIX %r12",
            "larl %eax, %eax",
            "ZIGOS_IDT_VALIDATE_RETURN_RIP_FLAGS %r12",
            "call zigos_handle_invalid_interrupt_return",
        },
        .match = .ordered,
        .reason = "interrupt entry must land on endbr64 and clear AC, and interrupt return must validate the privilege state it resumes",
    },
    .{
        .scopes = &.{"src/arch/cpu_features.zig"},
        .snippets = &.{ "fn enableModernFeatures(", "x86.writeCr4(cr4);", "x86.forbidSupervisorUserMemory();" },
        .match = .ordered,
        .reason = "SMAP enablement must clear inherited AC after the CR4 write",
    },
    .{
        .scopes = &.{"src/kernel/boot/init/core.zig"},
        .snippets = &.{ "gdt.init();", "syscall64.init(", "isr.init();", "try x86.enableLass();", "paging.init();" },
        .match = .ordered,
        .reason = "native descriptor, entry and LASS initialization must precede paging",
    },
    .{
        .scopes = &.{"src/kernel/smp_bringup.zig"},
        .snippets = &.{
            "fn apEntry(",
            "if (admission_policy.firstMissing(detected_features)) |missing|",
            "park();",
            "cpu_features.admitApplicationProcessorCache() catch",
            "park();",
            "cpu_identity.initialize(index);",
            "gdt.initCpu(index);",
            "cpu_features.enableModernFeatures(",
            "syscall64.initApplicationProcessor(",
            "idt.init();",
            "x86.enableLass() catch",
            "ADDRESS_PARTITION_REJECTED",
            "park();",
            "timer.initApplicationProcessor(features)",
            "TIMER_ADMISSION_REJECTED",
            "park();",
            "&bringup_cpus[index].online, true, .release)",
        },
        .match = .ordered,
        .reason = "an application processor must pass CPU, cache, LASS and timer admission, parking on failure, before it is published online",
    },
    .{
        .scopes = &.{"src/kernel/interrupts/x2apic.zig"},
        .snippets = &.{ "pub fn sendIpi(", "mfence; lfence", "writeApicMsr(X2APIC_ICR_MSR" },
        .match = .ordered,
        .reason = "x2APIC IPIs must drain prior stores before the non-serializing ICR write",
    },
    .{
        .scopes = &.{"src/kernel/smp.zig"},
        .snippets = &.{ "fn shootdown(", "x86.cli();", "tlb_requests.begin(", "sendParticipantIpis(", "tlb_requests.complete(", "tlb_requests.finish(" },
        .match = .ordered,
        .reason = "remote TLB shootdown must mask owner interrupt reentry and retire only fully acknowledged requests",
    },
    .{
        .scopes = &.{ "src/kernel/smp.zig", "src/arch/x86.zig", "src/arch/x86/invpcid.S" },
        .snippets = &.{ ".kernel => x86.invalidateAllTranslations()", "writeCr4(cr4 & ~CR4_PGE)", "mov $2, %rcx" },
        .reason = "kernel TLB retirement must invalidate every context including global translations",
    },
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var errors = std.ArrayList([]const u8).empty;

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
    try validateKernelTcbImports(allocator, io, &errors);
    var sources: SourceCache = .{ .allocator = allocator, .io = io, .errors = &errors };
    try validateRetiredSources(allocator, io, &errors, &sources);
    try validateSecurityControls(allocator, &errors, &sources);
    if (try readRequiredSource(allocator, io, &errors, PRODUCTION_CMDLINE_PATH)) |cmdline| {
        try validateProductionBootFlags(allocator, &errors, PRODUCTION_CMDLINE_PATH, cmdline);
    }
    if (try readOptionalSource(allocator, io, PRODUCTION_GRUB_CONFIG_PATH)) |grub_config| {
        try validateProductionBootFlags(allocator, &errors, PRODUCTION_GRUB_CONFIG_PATH, grub_config);
    }
    if (try readRequiredSource(allocator, io, &errors, NATIVE_SCHEDULER_LOOP_PATH)) |scheduler_loop| {
        try validateNativeSchedulerLoopSource(allocator, &errors, scheduler_loop);
    }

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
    var paths = std.ArrayList([]const u8).empty;
    try collectZigSources(allocator, io, errors, KERNEL_TCB_ROOT, &KERNEL_TCB_EXCLUDED_DIRS, &paths);
    for (paths.items) |path| {
        if (isOneOf(path, &KERNEL_TCB_EXCLUDED_FILES)) continue;
        const source = try common.readFileAlloc(allocator, io, path, common.source_file_max_bytes);
        for (KERNEL_TCB_FORBIDDEN_IMPORT_PREFIXES) |prefix| {
            if (std.mem.indexOf(u8, source, prefix) == null) continue;
            try common.addError(errors, allocator, "kernel TCB forbids product import {s} in {s}", .{ prefix, path });
        }
    }
}

fn collectZigSources(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    path: []const u8,
    excluded_dirs: []const []const u8,
    paths: *std.ArrayList([]const u8),
) !void {
    var dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true, .follow_symlinks = false }) catch |err| {
        try common.addError(errors, allocator, "Source scan could not open {s}: {s}", .{ path, @errorName(err) });
        return;
    };
    defer dir.close(io);

    var iterator = dir.iterate();
    while (iterator.next(io) catch |err| {
        try common.addError(errors, allocator, "Source scan failed in {s}: {s}", .{ path, @errorName(err) });
        return;
    }) |entry| {
        const child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ path, entry.name });
        switch (entry.kind) {
            .directory => if (!isOneOf(child, excluded_dirs)) {
                try collectZigSources(allocator, io, errors, child, excluded_dirs, paths);
            },
            .file => if (std.mem.endsWith(u8, entry.name, ".zig")) try paths.append(allocator, child),
            else => {},
        }
    }
}

fn readOptionalSource(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !?[]const u8 {
    return common.readFileAlloc(allocator, io, path, common.source_file_max_bytes) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
}

const ScopedSource = struct { path: []const u8, text: []const u8 };

/// Reads each scope once for the ban and control tables.
const SourceCache = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    scopes: std.StringHashMapUnmanaged([]const ScopedSource) = .empty,

    fn get(self: *SourceCache, scope: []const u8) ![]const ScopedSource {
        if (self.scopes.get(scope)) |cached| return cached;
        var sources = std.ArrayList(ScopedSource).empty;
        if (std.mem.endsWith(u8, scope, "/")) {
            var paths = std.ArrayList([]const u8).empty;
            try collectZigSources(self.allocator, self.io, self.errors, scope[0 .. scope.len - 1], &.{}, &paths);
            for (paths.items) |path| {
                const text = try common.readFileAlloc(self.allocator, self.io, path, common.source_file_max_bytes);
                try sources.append(self.allocator, .{ .path = path, .text = text });
            }
        } else if (try readOptionalSource(self.allocator, self.io, scope)) |text| {
            try sources.append(self.allocator, .{ .path = scope, .text = text });
        }
        try self.scopes.put(self.allocator, scope, sources.items);
        return sources.items;
    }
};

fn validateRetiredSources(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    sources: *SourceCache,
) !void {
    for (RETIRED_PATHS) |retired| {
        if (common.pathExists(io, retired.path)) {
            try common.addError(errors, allocator, "{s} must stay removed: {s}", .{ retired.path, retired.reason });
        }
    }
    for (RETIRED_SOURCES) |ban| {
        for (ban.paths) |scope| {
            for (try sources.get(scope)) |source| try checkRetiredSource(allocator, errors, ban, source);
        }
    }
}

fn checkRetiredSource(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    ban: SourceBan,
    source: ScopedSource,
) !void {
    for (ban.snippets) |snippet| {
        if (std.mem.indexOf(u8, source.text, snippet) != null) {
            try common.addError(errors, allocator, "{s}: {s}; found retired snippet: {s}", .{ source.path, ban.reason, snippet });
        }
    }
}

fn validateSecurityControls(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    sources: *SourceCache,
) !void {
    for (SECURITY_CONTROLS) |control| {
        var scoped = std.ArrayList(ScopedSource).empty;
        for (control.scopes) |scope| {
            const found = try sources.get(scope);
            if (found.len == 0) {
                try common.addError(errors, allocator, "{s}; security control scope is missing: {s}", .{ control.reason, scope });
            }
            try scoped.appendSlice(allocator, found);
        }
        try checkSecurityControl(allocator, errors, control, scoped.items);
    }
}

fn checkSecurityControl(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    control: SecurityControl,
    sources: []const ScopedSource,
) !void {
    switch (control.match) {
        .any_scope => for (control.snippets) |snippet| {
            for (sources) |source| {
                if (std.mem.indexOf(u8, source.text, snippet) != null) break;
            } else {
                try common.addError(errors, allocator, "{s}; missing security control: {s}", .{ control.reason, snippet });
            }
        },
        .each_scope => for (sources) |source| {
            for (control.snippets) |snippet| {
                if (std.mem.indexOf(u8, source.text, snippet) == null) {
                    try common.addError(errors, allocator, "{s}: {s}; missing security control: {s}", .{ source.path, control.reason, snippet });
                }
            }
        },
        .ordered => for (sources) |source| {
            var offset: usize = 0;
            var anchor_end: usize = 0;
            for (control.snippets, 0..) |snippet, index| {
                const position = std.mem.indexOfPos(u8, source.text, offset, snippet) orelse {
                    try common.addError(errors, allocator, "{s}: {s}; missing or out-of-order security control: {s}", .{ source.path, control.reason, snippet });
                    continue;
                };
                offset = position + snippet.len;
                if (index == 0) anchor_end = offset;
                if (index != 0 and index + 1 == control.snippets.len and std.mem.indexOfPos(u8, source.text, anchor_end, snippet) != position) {
                    try common.addError(errors, allocator, "{s}: {s}; guarded step also appears before its checks: {s}", .{ source.path, control.reason, snippet });
                }
            }
        },
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
    try validateFirstHardwareTargetMarkerFiles(allocator, io, errors);

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

fn markerFileHasActiveLine(source: []const u8, expected: []const u8) bool {
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.eql(u8, line, expected)) return true;
    }
    return false;
}

fn validateFirstHardwareTargetMarkerFiles(
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

    for (RETIRED_TRACK_CLAIMS) |claim| {
        for (RETIRED_TRACK_CLAIM_FIELDS) |field_name| {
            if (trackListContains(track, field_name, claim)) {
                try common.addError(errors, allocator, "Production readiness track {s} must not claim migration support in {s}: {s}", .{ track_id, field_name, claim });
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
        const source = try readOptionalSource(allocator, io, relative_path) orelse continue;
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

fn validateProductionBootFlags(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    path: []const u8,
    source: []const u8,
) !void {
    for ([_][]const u8{ "model_inventory", "qemu_software_cpu_fallback", "qemu_tsc_frequency_hz", "smoke_fault" }) |flag| {
        if (std.mem.indexOf(u8, source, flag) != null) {
            try common.addError(errors, allocator, "production boot defaults must not enable modeled hardware, a fabricated clock or smoke fault injection ({s}): {s}", .{ path, flag });
        }
    }
}

fn isOneOf(value: []const u8, allowed: []const []const u8) bool {
    for (allowed) |candidate| {
        if (std.mem.eql(u8, value, candidate)) return true;
    }
    return false;
}

test "retired source bans flag each reintroduced snippet" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const ban: SourceBan = .{
        .paths = &.{"src/kernel/timer/timer.zig"},
        .snippets = &.{ "PIT_CHANNEL0", "io.outb" },
        .reason = "fixture ban",
    };

    var clean = std.ArrayList([]const u8).empty;
    try checkRetiredSource(allocator, &clean, ban, .{ .path = "fixture.zig", .text = "const deadline = tsc.read();\n" });
    try std.testing.expectEqual(@as(usize, 0), clean.items.len);

    var restored = std.ArrayList([]const u8).empty;
    try checkRetiredSource(allocator, &restored, ban, .{ .path = "fixture.zig", .text = "io.outb(PIT_CHANNEL0, 0);\n" });
    try std.testing.expectEqual(@as(usize, 2), restored.items.len);
    try std.testing.expect(common.errorContains(restored.items, "fixture ban"));
}

test "source scopes skip missing files but require directory trees" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var errors = std.ArrayList([]const u8).empty;
    var sources: SourceCache = .{ .allocator = arena_state.allocator(), .io = std.testing.io, .errors = &errors };

    try std.testing.expectEqual(@as(usize, 0), (try sources.get("src/kernel/retired_fixture.zig")).len);
    try std.testing.expectEqual(@as(usize, 0), errors.items.len);

    try std.testing.expectEqual(@as(usize, 0), (try sources.get("src/kernel/retired_fixture/")).len);
    try std.testing.expect(common.errorContains(errors.items, "src/kernel/retired_fixture"));

    const drivers = try sources.get("src/kernel/drivers/");
    try std.testing.expect(drivers.len > 1);
    try std.testing.expectEqual(drivers.ptr, (try sources.get("src/kernel/drivers/")).ptr);
}

test "any-scope security controls may move between sources but must not disappear" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const control: SecurityControl = .{
        .scopes = &.{ "broker.zig", "helper.zig" },
        .snippets = &.{ "BusMasteringNotRevoked", "pollFaultForDevice" },
        .reason = "fixture control",
    };

    var moved = std.ArrayList([]const u8).empty;
    try checkSecurityControl(allocator, &moved, control, &.{
        .{ .path = "broker.zig", .text = "return error.BusMasteringNotRevoked;" },
        .{ .path = "helper.zig", .text = "intel_vtd.pollFaultForDevice(device)" },
    });
    try std.testing.expectEqual(@as(usize, 0), moved.items.len);

    var dropped = std.ArrayList([]const u8).empty;
    try checkSecurityControl(allocator, &dropped, control, &.{
        .{ .path = "broker.zig", .text = "return error.BusMasteringNotRevoked;" },
        .{ .path = "helper.zig", .text = "" },
    });
    try std.testing.expectEqual(@as(usize, 1), dropped.items.len);
    try std.testing.expect(common.errorContains(dropped.items, "pollFaultForDevice"));
}

test "each-scope security controls fail when one driver drops a control another keeps" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const control: SecurityControl = .{
        .scopes = &.{ "xhci_hw.zig", "intel_i225_hw.zig" },
        .snippets = &.{ "return error.BusMasteringNotRevoked", ".requesterProtected(" },
        .match = .each_scope,
        .reason = "fixture control",
    };
    const guarded = "if (bus_master) return error.BusMasteringNotRevoked;\nif (!vtd.requesterProtected(dev)) return;\n";

    var kept = std.ArrayList([]const u8).empty;
    try checkSecurityControl(allocator, &kept, control, &.{
        .{ .path = "xhci_hw.zig", .text = guarded },
        .{ .path = "intel_i225_hw.zig", .text = guarded },
    });
    try std.testing.expectEqual(@as(usize, 0), kept.items.len);

    var dropped = std.ArrayList([]const u8).empty;
    try checkSecurityControl(allocator, &dropped, control, &.{
        .{ .path = "xhci_hw.zig", .text = "if (bus_master) return error.BusMasteringNotRevoked;\n" },
        .{ .path = "intel_i225_hw.zig", .text = guarded },
    });
    try std.testing.expectEqual(@as(usize, 1), dropped.items.len);
    try std.testing.expect(common.errorContains(dropped.items, "xhci_hw.zig: fixture control; missing security control: .requesterProtected("));
}

test "ordered security controls reject a step moved after the publication it guards" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const control: SecurityControl = .{
        .scopes = &.{"smp_bringup.zig"},
        .snippets = &.{ "fn apEntry(", "timer.initApplicationProcessor(features)", "park();", "online = true" },
        .match = .ordered,
        .reason = "fixture control",
    };

    var admitted = std.ArrayList([]const u8).empty;
    try checkSecurityControl(allocator, &admitted, control, &.{.{
        .path = "smp_bringup.zig",
        .text = "fn park() void {}\nfn apEntry() void {\n    if (!timer.initApplicationProcessor(features)) park();\n    online = true;\n}\n",
    }});
    try std.testing.expectEqual(@as(usize, 0), admitted.items.len);

    var reordered = std.ArrayList([]const u8).empty;
    try checkSecurityControl(allocator, &reordered, control, &.{.{
        .path = "smp_bringup.zig",
        .text = "fn park() void {}\nfn apEntry() void {\n    online = true;\n    if (!timer.initApplicationProcessor(features)) park();\n}\n",
    }});
    try std.testing.expectEqual(@as(usize, 1), reordered.items.len);
    try std.testing.expect(common.errorContains(reordered.items, "out-of-order security control: online = true"));

    var published_early = std.ArrayList([]const u8).empty;
    try checkSecurityControl(allocator, &published_early, control, &.{.{
        .path = "smp_bringup.zig",
        .text = "fn apEntry() void {\n    online = true;\n    if (!timer.initApplicationProcessor(features)) park();\n    online = true;\n}\n",
    }});
    try std.testing.expectEqual(@as(usize, 1), published_early.items.len);
    try std.testing.expect(common.errorContains(published_early.items, "guarded step also appears before its checks: online = true"));
}

test "secure-by-design gate requires every release control" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const manifest_json =
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
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, allocator, manifest_json, .{});
    var errors = std.ArrayList([]const u8).empty;
    try validateSecureByDesignReleaseGate(allocator, std.testing.io, &errors, parsed);
    try std.testing.expect(common.errorContains(errors.items, "missing required secure-by-design control: fuzzing"));
    try std.testing.expect(common.errorContains(errors.items, "policy_artifacts must be non-empty"));
}

test "first hardware target gate rejects an incomplete subsystem list" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const manifest_json =
        \\{
        \\  "first_hardware_target": {
        \\    "id": "asus-nuc15crsu7",
        \\    "vendor": "Intel",
        \\    "product": "NUC 15 Pro Mini PC",
        \\    "sku": "RNUC15CRSU7",
        \\    "status": "hardware_required",
        \\    "selection_reason": "fixture",
        \\    "boot_medium": "UEFI",
        \\    "serial_capture": "fixture",
        \\    "required_subsystems": ["uefi_boot"],
        \\    "reference_artifacts": ["src/native/platform/hardware_target.zig"],
        \\    "qemu_preflight_commands": ["zig build iso"],
        \\    "proof_bundle_requirements": ["fixture"],
        \\    "hardware_exit_criteria": ["fixture"],
        \\    "current_hardware_evidence": [],
        \\    "open_gaps": ["fixture"]
        \\  }
        \\}
    ;
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, allocator, manifest_json, .{});
    var errors = std.ArrayList([]const u8).empty;
    try validateFirstHardwareTarget(allocator, std.testing.io, &errors, parsed);
    try std.testing.expect(common.errorContains(errors.items, "missing required subsystem: acpi_tables"));
    try std.testing.expect(common.errorContains(errors.items, "missing required QEMU preflight command: zig build iso-verification"));
}

test "production boot defaults reject modeled hardware and fixed clock overrides" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    for ([_][]const u8{
        "model_inventory",
        "qemu_tsc_frequency_hz=2400000000",
        "qemu_software_cpu_fallback",
        "smoke_fault=storage_checkpoint_tamper",
        "console=serial model_inventory qemu_tsc_frequency_hz=2400000000",
    }) |source| {
        var errors = std.ArrayList([]const u8).empty;
        try validateProductionBootFlags(allocator, &errors, "production boot fixture", source);
        try std.testing.expect(errors.items.len > 0);
    }
    for ([_][]const u8{ "", "\n", "console=serial\n" }) |source| {
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
