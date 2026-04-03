pub const SECTION_NAME = ".zigos_userspace_bootstrap";
pub const VERSION: u16 = 1;

const FLAG_OWNS_UI_SURFACE: u32 = 1 << 1;
const FLAG_PERMISSION_REVIEW: u32 = 1 << 2;
const FLAG_BACKGROUND_ELIGIBLE: u32 = 1 << 3;
const FLAG_STORAGE_BOUNDARY: u32 = 1 << 4;
const FLAG_NETWORK_BOUNDARY: u32 = 1 << 5;
const FLAG_POLICY_BOUNDARY: u32 = 1 << 6;
const FLAG_DRIVER_BOUNDARY: u32 = 1 << 7;
const FLAG_COMPATIBILITY_BOUNDARY: u32 = 1 << 8;

const COMPONENT_CLASS_SESSION_MANAGER: u8 = 0;
const COMPONENT_CLASS_APP_COMPONENT: u8 = 1;

pub const Stage = enum(u8) {
    boot = 0x10,
    descriptor_ready = 0x20,
    mailbox_ready = 0x30,
    syscall_ready = 0x40,
    steady = 0x50,
    fault = 0xF0,
};

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
    compatibility = 9,
    driver = 10,
};

pub const ResourceMask = packed struct(u32) {
    time_query: bool = false,
    resource_query: bool = false,
    accounting_query: bool = false,
    _reserved: u29 = 0,
};

pub const Mailbox = extern struct {
    version: u16 = VERSION,
    stage: u8 = @intFromEnum(Stage.boot),
    detail: u8 = @intFromEnum(Detail.unknown),
    fault_code: u8 = 0,
    _reserved0: [3]u8 = [_]u8{0} ** 3,
    authority_capability_id: u64 = 0,
    task_id: u64 = 0,
    service_id: u64 = 0,
    resource_mask: u32 = 0,
    last_counter: u32 = 0,
};

pub fn classifyDetail(component_class: u8, contract_flags: u32) Detail {
    if ((contract_flags & FLAG_PERMISSION_REVIEW) != 0) return .review;
    if ((contract_flags & FLAG_NETWORK_BOUNDARY) != 0) return .network;
    if ((contract_flags & FLAG_DRIVER_BOUNDARY) != 0) return .driver;
    if ((contract_flags & FLAG_STORAGE_BOUNDARY) != 0) return .storage;
    if ((contract_flags & FLAG_POLICY_BOUNDARY) != 0) return .policy;
    if ((contract_flags & FLAG_COMPATIBILITY_BOUNDARY) != 0) return .compatibility;
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
