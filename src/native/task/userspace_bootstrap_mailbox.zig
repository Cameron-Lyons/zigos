const std = @import("std");

pub const SECTION_NAME = ".zigos_userspace_bootstrap";
pub const VERSION: u16 = 3;
pub const MAILBOX_RESERVED_BYTES: usize = 3;
pub const MMU_ISOLATION_PROOF_ROLE_TAG: u32 = 0xA116;
pub const FOREIGN_SHARED_MEMORY_PROBE_ADDR: u32 = 0x7000_0000;
pub const PROOF_SYSCALL_POINTER_DENIED_PULSE: u16 = 0x41;
pub const PROOF_FOREIGN_MEMORY_ACCESS_FAULT_CODE: u8 = 0x72;

const userspace_flags = @import("userspace_flags.zig");
pub const FLAG_OWNS_UI_SURFACE = userspace_flags.FLAG_OWNS_UI_SURFACE;
const FLAG_PERMISSION_REVIEW = userspace_flags.FLAG_PERMISSION_REVIEW;
const FLAG_BACKGROUND_ELIGIBLE = userspace_flags.FLAG_BACKGROUND_ELIGIBLE;
const FLAG_STORAGE_BOUNDARY = userspace_flags.FLAG_STORAGE_BOUNDARY;
const FLAG_NETWORK_BOUNDARY = userspace_flags.FLAG_NETWORK_BOUNDARY;
const FLAG_POLICY_BOUNDARY = userspace_flags.FLAG_POLICY_BOUNDARY;
const FLAG_DRIVER_BOUNDARY = userspace_flags.FLAG_DRIVER_BOUNDARY;
const FLAG_MMU_PROOF_PROBE = userspace_flags.FLAG_MMU_PROOF_PROBE;

const COMPONENT_CLASS_SESSION_MANAGER: u8 = 0;
const COMPONENT_CLASS_APP_COMPONENT: u8 = 1;

pub const Stage = enum(u8) {
    boot = 0x10,
    descriptor_ready = 0x20,
    mailbox_ready = 0x30,
    syscall_ready = 0x40,
    service_ready = 0x48,
    steady = 0x50,
    fault = 0xF0,
};

pub const ServiceKind = enum(u8) {
    generic = 0,
    storage = 1,
    sync = 2,
    network = 3,
    package = 4,
    compositor = 5,
};

pub const YieldDisposition = enum(u32) {
    runnable = 0,
    wait_for_event = 1,
};

pub const UiModelKind = enum(u8) {
    none,
    notes,
    viewer,
    capture,
    permission_review,
    compositor,
    generic,
};

pub const UiStateFlags = packed struct(u8) {
    dirty: bool = false,
    recovery_visible: bool = false,
    active: bool = false,
    input_overflow: bool = false,
    _reserved: u4 = 0,
};

pub fn yieldDisposition(raw: u32) ?YieldDisposition {
    return std.enums.fromInt(YieldDisposition, raw);
}

pub const Detail = enum(u8) {
    unknown = 0,
    session = 1,
    app = 2,
    review = 3,
    network = 4,
    storage = 5,
    ui = 6,
    background = 7,
    policy = 8,
    driver = 10,
    proof = 11,
};

pub const ResourceMask = packed struct(u32) {
    time_query: bool = false,
    resource_query: bool = false,
    accounting_query: bool = false,
    _reserved: u29 = 0,
};

pub const ServiceStatusFlags = packed struct(u32) {
    endpoint_created: bool = false,
    loopback_connected: bool = false,
    request_received: bool = false,
    response_received: bool = false,
    all_operations_completed: bool = false,
    _reserved: u27 = 0,
};

pub const Mailbox = extern struct {
    version: u16 = VERSION,
    stage: u8 = @intFromEnum(Stage.boot),
    detail: u8 = @intFromEnum(Detail.unknown),
    fault_code: u8 = 0,
    _reserved0: [MAILBOX_RESERVED_BYTES]u8 = [_]u8{0} ** MAILBOX_RESERVED_BYTES,
    authority_capability_id: u64 = 0,
    task_id: u64 = 0,
    service_id: u64 = 0,
    resource_mask: u32 = 0,
    service_kind: u8 = @intFromEnum(ServiceKind.generic),
    service_ready: u8 = 0,
    service_operation_count: u16 = 0,
    service_state_hash: u64 = 0,
    service_endpoint_id: u64 = 0,
    service_peer_endpoint_id: u64 = 0,
    service_ipc_roundtrips: u16 = 0,
    service_status_flags: u32 = 0,
    last_counter: u32 = 0,
    _reserved1: [4]u8 = [_]u8{0} ** 4,
    input_capability_id: u64 = 0,
    input_event_count: u64 = 0,
    last_input_sequence: u64 = 0,
    last_input_window_id: u64 = 0,
    last_input_surface_id: u64 = 0,
    last_input_kind: u8 = 0,
    last_input_text: u8 = 0,
    last_input_port_id: u8 = 0,
    last_input_slot_id: u8 = 0,
    _reserved2: [4]u8 = [_]u8{0} ** 4,
    ui_model_kind: u8 = @intFromEnum(UiModelKind.none),
    ui_state_flags: u8 = 0,
    ui_focus_index: u16 = 0,
    ui_text_length: u16 = 0,
    ui_cursor: u16 = 0,
    ui_commit_count: u32 = 0,
    ui_activation_count: u32 = 0,
    ui_state_revision: u64 = 0,
    ui_interaction_hash: u64 = 0,
};

pub const ABI_SIZE_BYTES: usize = 160;
pub const ABI_ALIGNMENT: usize = 8;

comptime {
    if (@offsetOf(Mailbox, "ui_interaction_hash") + @sizeOf(@FieldType(Mailbox, "ui_interaction_hash")) != ABI_SIZE_BYTES) {
        @compileError("userspace bootstrap mailbox fields no longer match the wire ABI");
    }
}

pub fn classifyDetail(component_class: u8, contract_flags: u32) Detail {
    if ((contract_flags & FLAG_PERMISSION_REVIEW) != 0) return .review;
    if ((contract_flags & FLAG_NETWORK_BOUNDARY) != 0) return .network;
    if ((contract_flags & FLAG_DRIVER_BOUNDARY) != 0) return .driver;
    if ((contract_flags & FLAG_STORAGE_BOUNDARY) != 0) return .storage;
    if ((contract_flags & FLAG_POLICY_BOUNDARY) != 0) return .policy;
    if ((contract_flags & FLAG_MMU_PROOF_PROBE) != 0) return .proof;
    if ((contract_flags & FLAG_OWNS_UI_SURFACE) != 0) return .ui;
    if ((contract_flags & FLAG_BACKGROUND_ELIGIBLE) != 0) return .background;
    if (component_class == COMPONENT_CLASS_SESSION_MANAGER) return .session;
    if (component_class == COMPONENT_CLASS_APP_COMPONENT) return .app;
    return .unknown;
}

pub fn packCounter(stage: Stage, detail: Detail, pulse: u16) u32 {
    return (@as(u32, @intFromEnum(stage)) << 24) |
        (@as(u32, @intFromEnum(detail)) << 16) |
        @as(u32, pulse);
}

pub fn stageFromCounter(counter: u32) Stage {
    return @enumFromInt(@as(u8, @truncate(counter >> 24)));
}

test "mailbox counter encoding preserves stage and detail" {
    const counter = packCounter(.steady, .network, 42);
    try @import("std").testing.expectEqual(Stage.steady, stageFromCounter(counter));
    try @import("std").testing.expectEqual(@as(u8, @intFromEnum(Detail.network)), @as(u8, @truncate(counter >> 16)));
    try @import("std").testing.expectEqual(@as(u16, 42), @as(u16, @truncate(counter)));
}

test "userspace yield dispositions reject unknown scheduler requests" {
    try @import("std").testing.expectEqual(YieldDisposition.runnable, yieldDisposition(0).?);
    try @import("std").testing.expectEqual(YieldDisposition.wait_for_event, yieldDisposition(1).?);
    try @import("std").testing.expect(yieldDisposition(2) == null);
}

test "mailbox records userspace service readiness separately from generic heartbeat" {
    var mailbox = Mailbox{};
    mailbox.service_kind = @intFromEnum(ServiceKind.storage);
    mailbox.service_ready = 1;
    mailbox.service_operation_count = 3;
    mailbox.service_state_hash = 0xA5;
    mailbox.service_endpoint_id = 10;
    mailbox.service_peer_endpoint_id = 11;
    mailbox.service_ipc_roundtrips = 3;
    mailbox.service_status_flags = @bitCast(ServiceStatusFlags{
        .endpoint_created = true,
        .loopback_connected = true,
        .request_received = true,
        .response_received = true,
        .all_operations_completed = true,
    });

    try @import("std").testing.expectEqual(ServiceKind.storage, @as(ServiceKind, @enumFromInt(mailbox.service_kind)));
    try @import("std").testing.expectEqual(@as(u8, 1), mailbox.service_ready);
    try @import("std").testing.expectEqual(@as(u16, 3), mailbox.service_operation_count);
    try @import("std").testing.expectEqual(@as(u64, 0xA5), mailbox.service_state_hash);
    try @import("std").testing.expectEqual(@as(u64, 10), mailbox.service_endpoint_id);
    try @import("std").testing.expectEqual(@as(u64, 11), mailbox.service_peer_endpoint_id);
    try @import("std").testing.expectEqual(@as(u16, 3), mailbox.service_ipc_roundtrips);
    const flags: ServiceStatusFlags = @bitCast(mailbox.service_status_flags);
    try @import("std").testing.expect(flags.all_operations_completed);
}

test "mailbox records focused input consumption without architecture-dependent padding" {
    try @import("std").testing.expectEqual(@as(usize, ABI_ALIGNMENT), @alignOf(Mailbox));
    try @import("std").testing.expectEqual(@as(usize, 80), @offsetOf(Mailbox, "input_capability_id"));
    try @import("std").testing.expectEqual(@as(usize, 120), @offsetOf(Mailbox, "last_input_kind"));
    try @import("std").testing.expectEqual(@as(usize, 128), @offsetOf(Mailbox, "ui_model_kind"));
    try @import("std").testing.expectEqual(@as(usize, 144), @offsetOf(Mailbox, "ui_state_revision"));
    try @import("std").testing.expectEqual(@as(usize, ABI_SIZE_BYTES), @sizeOf(Mailbox));
}
