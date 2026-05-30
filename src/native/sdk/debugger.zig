const std = @import("std");
const typed_component_abi = @import("../services/typed_component_abi.zig");
const native_util = @import("../core/util.zig");

pub const MAX_EVENTS: usize = 96;
pub const MAX_LABEL_BYTES: usize = 96;

pub const EventKind = enum(u8) {
    idl_parsed,
    codegen_emitted,
    package_installed,
    package_updated,
    package_rolled_back,
    package_removed,
    compatibility_launched,
    abi_message_checked,
    breakpoint_hit,
};

pub const Event = struct {
    kind: EventKind = .idl_parsed,
    tick: u64 = 0,
    accepted: bool = false,
    label_len: usize = 0,
    label: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    detail_len: usize = 0,
    detail: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,

    pub fn labelSlice(self: *const Event) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn detailSlice(self: *const Event) []const u8 {
        return self.detail[0..self.detail_len];
    }
};

pub const Error = typed_component_abi.Error || error{
    DebugEventLogFull,
    DebugLabelTooLong,
    DebugDetailTooLong,
    DebugOutputTooLong,
};

pub const Session = struct {
    event_count: usize = 0,
    events: [MAX_EVENTS]Event = [_]Event{.{}} ** MAX_EVENTS,

    pub fn init() Session {
        return .{};
    }

    pub fn record(
        self: *Session,
        kind: EventKind,
        tick: u64,
        label: []const u8,
        detail: []const u8,
        accepted: bool,
    ) Error!void {
        if (self.event_count >= self.events.len) return error.DebugEventLogFull;
        var event = Event{
            .kind = kind,
            .tick = tick,
            .accepted = accepted,
        };
        event.label_len = native_util.copyTextExact(&event.label, label) catch return error.DebugLabelTooLong;
        event.detail_len = native_util.copyTextExact(&event.detail, detail) catch return error.DebugDetailTooLong;
        self.events[self.event_count] = event;
        self.event_count += 1;
    }

    pub fn countKind(self: *const Session, kind: EventKind) usize {
        var count: usize = 0;
        for (self.events[0..self.event_count]) |event| {
            if (event.kind == kind) count += 1;
        }
        return count;
    }

    pub fn latest(self: *const Session) ?*const Event {
        if (self.event_count == 0) return null;
        return &self.events[self.event_count - 1];
    }

    pub fn inspectMessage(
        self: *Session,
        tick: u64,
        comptime interface: typed_component_abi.InterfaceKey,
        operation_id: typed_component_abi.OperationId,
        header: typed_component_abi.WireHeader,
        actual_request_len: usize,
        actual_response_len: usize,
    ) Error!void {
        const iface = typed_component_abi.Interface(interface);
        typed_component_abi.validateMessage(
            iface,
            operation_id,
            header,
            actual_request_len,
            actual_response_len,
        ) catch |err| {
            try self.record(.abi_message_checked, tick, iface.name, @errorName(err), false);
            return err;
        };
        try self.record(.abi_message_checked, tick, iface.name, @tagName(operation_id), true);
    }

    pub fn hitBreakpoint(self: *Session, tick: u64, label: []const u8) Error!void {
        try self.record(.breakpoint_hit, tick, label, "developer-breakpoint", true);
    }

    pub fn exportText(self: *const Session, output: []u8) Error![]const u8 {
        var cursor: usize = 0;
        for (self.events[0..self.event_count]) |event| {
            try appendFmt(
                output,
                &cursor,
                "tick={d} kind={s} accepted={s} label={s} detail={s}\n",
                .{
                    event.tick,
                    @tagName(event.kind),
                    native_util.yesNo(event.accepted),
                    event.labelSlice(),
                    event.detailSlice(),
                },
            );
        }
        return output[0..cursor];
    }
};

fn appendFmt(output: []u8, cursor: *usize, comptime fmt: []const u8, args: anytype) Error!void {
    const written = std.fmt.bufPrint(output[cursor.*..], fmt, args) catch return error.DebugOutputTooLong;
    cursor.* += written.len;
}

test "debugger records ABI checks and exports a redaction-safe trace" {
    var session = Session.init();
    const iface = typed_component_abi.Interface(.package_install);
    const header = typed_component_abi.WireHeader{
        .interface_major = iface.version_major,
        .interface_minor = iface.version_minor,
        .operation = @intFromEnum(typed_component_abi.OperationId.package_rollback),
        .request_len = @sizeOf(typed_component_abi.PackageRollbackRequest),
        .response_len = @sizeOf(typed_component_abi.PackageRollbackResponse),
        .correlation_id = 7,
        .subject_task_id = 9,
    };

    try session.inspectMessage(
        10,
        .package_install,
        .package_rollback,
        header,
        @sizeOf(typed_component_abi.PackageRollbackRequest),
        @sizeOf(typed_component_abi.PackageRollbackResponse),
    );
    try session.hitBreakpoint(11, "after-rollback");
    try std.testing.expectEqual(@as(usize, 1), session.countKind(.abi_message_checked));
    try std.testing.expectEqual(@as(usize, 1), session.countKind(.breakpoint_hit));

    var output: [512]u8 = undefined;
    const text = try session.exportText(&output);
    try std.testing.expect(std.mem.indexOf(u8, text, "kind=abi_message_checked") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "after-rollback") != null);
}
