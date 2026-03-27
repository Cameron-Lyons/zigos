const std = @import("std");
const contract = @import("contract.zig");
const manifest = @import("manifest.zig");
const principal = @import("principal.zig");

pub const MAX_EVENTS: usize = 64;
pub const MAX_DETAIL_BYTES: usize = 96;

pub const EventKind = enum(u8) {
    permission_decision,
    process_crash,
    driver_restart,
    update_transition,
    sync_conflict,
    device_trust_change,
};

pub const ExportOptions = struct {
    include_protected_content: bool = false,
};

pub const Event = struct {
    sequence: u64 = 0,
    kind: EventKind,
    tick: u64,
    subject: principal.PrincipalId,
    task_id: u64 = 0,
    workspace_id: u64 = 0,
    related_id: u64 = 0,
    detail_code: u32 = 0,
    service_class: contract.ServiceClass = .task_runtime,
    permission_kind: ?manifest.PermissionKind = null,
    allowed: bool = false,
    detail_protected: bool = false,
    detail_len: usize = 0,
    detail: [MAX_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_DETAIL_BYTES,

    pub fn detailSlice(self: *const Event) []const u8 {
        return self.detail[0..self.detail_len];
    }
};

pub const Error = error{
    EventTableFull,
    NoSpaceLeft,
};

const EventSlot = struct {
    in_use: bool = false,
    event: Event = zeroEvent(),
};

pub const Ledger = struct {
    next_sequence: u64 = 1,
    events: [MAX_EVENTS]EventSlot = [_]EventSlot{EventSlot{}} ** MAX_EVENTS,

    pub fn init() Ledger {
        return .{};
    }

    pub fn recordPermissionDecision(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        permission_kind: manifest.PermissionKind,
        allowed: bool,
        tick: u64,
        detail: []const u8,
        protected: bool,
    ) Error!void {
        try self.append(.{
            .kind = .permission_decision,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .permission_kind = permission_kind,
            .allowed = allowed,
            .detail_protected = protected,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordProcessCrash(
        self: *Ledger,
        service_class: contract.ServiceClass,
        service_subject: principal.PrincipalId,
        tick: u64,
        code: u32,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .process_crash,
            .tick = tick,
            .subject = service_subject,
            .service_class = service_class,
            .detail_code = code,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordDriverRestart(
        self: *Ledger,
        service_class: contract.ServiceClass,
        service_subject: principal.PrincipalId,
        device_capability_id: u64,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .driver_restart,
            .tick = tick,
            .subject = service_subject,
            .service_class = service_class,
            .related_id = device_capability_id,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordUpdateTransition(
        self: *Ledger,
        subject: principal.PrincipalId,
        tick: u64,
        rolled_back: bool,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .update_transition,
            .tick = tick,
            .subject = subject,
            .allowed = !rolled_back,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordSyncConflict(
        self: *Ledger,
        subject: principal.PrincipalId,
        workspace_id: u64,
        tick: u64,
        detail: []const u8,
        protected: bool,
    ) Error!void {
        try self.append(.{
            .kind = .sync_conflict,
            .tick = tick,
            .subject = subject,
            .workspace_id = workspace_id,
            .detail_protected = protected,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordDeviceTrustChange(
        self: *Ledger,
        subject: principal.PrincipalId,
        device_id: principal.PrincipalId,
        trusted: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .device_trust_change,
            .tick = tick,
            .subject = subject,
            .related_id = device_id.serial,
            .allowed = trusted,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn latestKind(self: *const Ledger, kind: EventKind) ?Event {
        var index = self.events.len;
        while (index > 0) {
            index -= 1;
            const slot = self.events[index];
            if (!slot.in_use) continue;
            if (slot.event.kind == kind) return slot.event;
        }
        return null;
    }

    pub fn exportText(self: *const Ledger, buffer: []u8, options: ExportOptions) Error![]const u8 {
        var used: usize = 0;
        for (self.events) |slot| {
            if (!slot.in_use) continue;
            const event = slot.event;
            const detail = if (event.detail_protected and !options.include_protected_content)
                "redacted"
            else
                event.detailSlice();

            try appendFmt(buffer, &used, "#{d} tick={d} kind={s} subject={s}:{d}", .{
                event.sequence,
                event.tick,
                @tagName(event.kind),
                @tagName(event.subject.kind),
                event.subject.serial,
            });
            if (event.permission_kind) |permission_kind| {
                try appendFmt(buffer, &used, " permission={s} allowed={s}", .{
                    @tagName(permission_kind),
                    yesNo(event.allowed),
                });
            }
            if (event.workspace_id != 0) {
                try appendFmt(buffer, &used, " workspace={d}", .{event.workspace_id});
            }
            if (event.related_id != 0) {
                try appendFmt(buffer, &used, " related={d}", .{event.related_id});
            }
            if (event.detail_code != 0) {
                try appendFmt(buffer, &used, " code={d}", .{event.detail_code});
            }
            if (event.kind == .process_crash or event.kind == .driver_restart) {
                try appendFmt(buffer, &used, " service={s}", .{@tagName(event.service_class)});
            }
            try appendFmt(buffer, &used, " detail={s}\n", .{detail});
        }
        return buffer[0..used];
    }

    fn append(self: *Ledger, event: Event) Error!void {
        for (&self.events) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.event = event;
            slot.event.sequence = self.next_sequence;
            self.next_sequence += 1;
            return;
        }
        return error.EventTableFull;
    }
};

fn zeroEvent() Event {
    return .{
        .sequence = 0,
        .kind = .permission_decision,
        .tick = 0,
        .subject = .{ .kind = .service, .serial = 0 },
    };
}

fn copyText(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
}

fn clampedDetailLen(src: []const u8) usize {
    return @min(src.len, MAX_DETAIL_BYTES);
}

fn copyTextInto(src: []const u8) [MAX_DETAIL_BYTES]u8 {
    var out = [_]u8{0} ** MAX_DETAIL_BYTES;
    _ = copyText(&out, src);
    return out;
}

fn yesNo(value: bool) []const u8 {
    return if (value) "yes" else "no";
}

fn appendFmt(buffer: []u8, used: *usize, comptime fmt: []const u8, args: anytype) Error!void {
    const rendered = std.fmt.bufPrint(buffer[used.*..], fmt, args) catch return error.NoSpaceLeft;
    used.* += rendered.len;
}

test "event ledger exports structured redacted diagnostics and audit history" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 7 };
    const service_subject = principal.PrincipalId{ .kind = .service, .serial = 9 };
    const device_subject = principal.PrincipalId{ .kind = .device, .serial = 42 };

    try ledger.recordPermissionDecision(user, 11, .screen_capture, false, 20, "org policy denied capture", true);
    try ledger.recordProcessCrash(.network_stack, service_subject, 21, 5001, "segfault");
    try ledger.recordDriverRestart(.media_print_helpers, service_subject, 88, 22, "audio-print restarted");
    try ledger.recordUpdateTransition(service_subject, 23, true, "rolled back to stable-a");
    try ledger.recordSyncConflict(user, 5, 24, "documents/tax-return.pdf conflict", true);
    try ledger.recordDeviceTrustChange(user, device_subject, false, 25, "device revoked");

    var buffer: [2048]u8 = undefined;
    const exported = try ledger.exportText(&buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "service=network_stack") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "related=42") != null);

    const full = try ledger.exportText(&buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "tax-return.pdf") != null);
    try std.testing.expectEqual(EventKind.device_trust_change, ledger.latestKind(.device_trust_change).?.kind);
}
