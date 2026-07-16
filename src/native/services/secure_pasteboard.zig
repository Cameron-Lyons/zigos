const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");

const copyText = native_util.copyText;

pub const MAX_GRANTS: usize = 16;
pub const MAX_PAYLOAD_BYTES: usize = 512;
pub const MAX_PURPOSE_BYTES: usize = 96;

pub const Error = event_ledger.Error || error{
    EmptyPayload,
    ExpiredGrant,
    DestinationSubjectMismatch,
    ForegroundSessionMismatch,
    GrantAlreadyConsumed,
    GrantNotFound,
    GrantRevoked,
    GrantTableFull,
    InvalidDestination,
    MissingForegroundSession,
    MissingUserGesture,
    OutputBufferTooSmall,
    PayloadTooLarge,
    PasteboardTokenIdExhausted,
    PurposeMismatch,
    PurposeRequired,
    PurposeTooLong,
    SourceMismatch,
};

pub const OfferRequest = struct {
    subject: principal.PrincipalId,
    destination: principal.PrincipalId,
    source_task_id: u64,
    destination_task_id: u64,
    user_gesture_id: u64,
    foreground_session_id: u64,
    expires_at_ticks: u64,
    now_ticks: u64,
    purpose: []const u8,
    payload: []const u8,
    sensitivity: manifest.DataSensitivity = .private_user_data,
    read_once: bool = true,
    detail: []const u8 = "",
};

pub const ReadRequest = struct {
    subject: principal.PrincipalId,
    destination_task_id: u64,
    token_id: u64,
    user_gesture_id: u64,
    foreground_session_id: u64,
    now_ticks: u64,
    expected_purpose: []const u8 = "",
    detail: []const u8 = "",
};

pub const RevokeRequest = struct {
    subject: principal.PrincipalId,
    source_task_id: u64,
    token_id: u64,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const Grant = struct {
    token_id: u64 = 0,
    subject: principal.PrincipalId = .{ .kind = .app, .serial = 0 },
    destination: principal.PrincipalId = .{ .kind = .app, .serial = 0 },
    source_task_id: u64 = 0,
    destination_task_id: u64 = 0,
    user_gesture_id: u64 = 0,
    foreground_session_id: u64 = 0,
    expires_at_ticks: u64 = 0,
    sensitivity: manifest.DataSensitivity = .internal_data,
    read_once: bool = true,
    consumed: bool = false,
    revoked: bool = false,
    payload_len: usize = 0,
    payload: [MAX_PAYLOAD_BYTES]u8 = [_]u8{0} ** MAX_PAYLOAD_BYTES,
    purpose_len: usize = 0,
    purpose: [MAX_PURPOSE_BYTES]u8 = [_]u8{0} ** MAX_PURPOSE_BYTES,

    pub fn payloadSlice(self: *const Grant) []const u8 {
        return self.payload[0..self.payload_len];
    }

    pub fn purposeSlice(self: *const Grant) []const u8 {
        return self.purpose[0..self.purpose_len];
    }
};

const Slot = struct {
    in_use: bool = false,
    grant: Grant = .{},
};

fn slotTokenKey(slot: *const Slot) u64 {
    return slot.grant.token_id;
}

const GrantArena = indexed_arena.IndexedArenaWithKey(u64, Slot, MAX_GRANTS, MAX_GRANTS * 2, slotTokenKey);

pub const Service = struct {
    next_token_id: u64 = 1,
    slots: GrantArena = GrantArena.init(),

    pub fn init() Service {
        return .{};
    }

    pub fn offer(self: *Service, request: OfferRequest, ledger: ?*event_ledger.Ledger) Error!*Grant {
        if (request.user_gesture_id == 0) {
            try recordOffer(ledger, request, 0, false, "pasteboard offer denied: missing user gesture");
            return error.MissingUserGesture;
        }
        if (request.foreground_session_id == 0) {
            try recordOffer(ledger, request, 0, false, "pasteboard offer denied: missing foreground session");
            return error.MissingForegroundSession;
        }
        if (request.destination_task_id == 0 or request.destination_task_id == request.source_task_id) {
            try recordOffer(ledger, request, 0, false, "pasteboard offer denied: invalid destination");
            return error.InvalidDestination;
        }
        if (request.expires_at_ticks <= request.now_ticks) {
            try recordOffer(ledger, request, 0, false, "pasteboard offer denied: expired grant");
            return error.ExpiredGrant;
        }
        if (request.purpose.len == 0) {
            try recordOffer(ledger, request, 0, false, "pasteboard offer denied: missing purpose");
            return error.PurposeRequired;
        }
        if (request.purpose.len > MAX_PURPOSE_BYTES) {
            try recordOffer(ledger, request, 0, false, "pasteboard offer denied: purpose too long");
            return error.PurposeTooLong;
        }
        if (request.payload.len == 0) {
            try recordOffer(ledger, request, 0, false, "pasteboard offer denied: empty payload");
            return error.EmptyPayload;
        }
        if (request.payload.len > MAX_PAYLOAD_BYTES) {
            try recordOffer(ledger, request, 0, false, "pasteboard offer denied: payload too large");
            return error.PayloadTooLarge;
        }

        if (self.slots.countInUse() >= MAX_GRANTS) {
            try recordOffer(ledger, request, 0, false, "pasteboard offer denied: grant table full");
            return error.GrantTableFull;
        }
        const token_id = self.next_token_id;
        if (token_id == 0) {
            try recordOffer(ledger, request, 0, false, "pasteboard offer denied: token id exhausted");
            return error.PasteboardTokenIdExhausted;
        }
        const grant = Grant{
            .token_id = token_id,
            .subject = request.subject,
            .destination = request.destination,
            .source_task_id = request.source_task_id,
            .destination_task_id = request.destination_task_id,
            .user_gesture_id = request.user_gesture_id,
            .foreground_session_id = request.foreground_session_id,
            .expires_at_ticks = request.expires_at_ticks,
            .sensitivity = request.sensitivity,
            .read_once = request.read_once,
            .payload_len = request.payload.len,
            .payload = copyPayloadInto(request.payload),
            .purpose_len = request.purpose.len,
            .purpose = copyPurposeInto(request.purpose),
        };

        const slot = self.slots.reserve(token_id) orelse {
            try recordOffer(ledger, request, 0, false, "pasteboard offer denied: grant table full");
            return error.GrantTableFull;
        };
        errdefer _ = self.slots.remove(token_id);
        try recordOffer(ledger, request, token_id, true, request.detail);
        slot.grant = grant;
        self.next_token_id +%= 1;
        return &slot.grant;
    }

    pub fn read(self: *Service, request: ReadRequest, output: []u8, ledger: ?*event_ledger.Ledger) Error![]const u8 {
        if (request.user_gesture_id == 0) {
            try recordRead(ledger, request, false, "pasteboard read denied: missing user gesture");
            return error.MissingUserGesture;
        }
        if (request.foreground_session_id == 0) {
            try recordRead(ledger, request, false, "pasteboard read denied: missing foreground session");
            return error.MissingForegroundSession;
        }

        const grant = self.find(request.token_id) orelse {
            try recordRead(ledger, request, false, "pasteboard read denied: missing grant");
            return error.GrantNotFound;
        };
        if (grant.revoked) {
            try recordRead(ledger, request, false, request.detail);
            return error.GrantRevoked;
        }
        if (grant.consumed and grant.read_once) {
            try recordRead(ledger, request, false, request.detail);
            return error.GrantAlreadyConsumed;
        }
        if (grant.destination_task_id != request.destination_task_id) {
            try recordRead(ledger, request, false, request.detail);
            return error.InvalidDestination;
        }
        if (!grant.destination.eql(request.subject)) {
            try recordRead(ledger, request, false, request.detail);
            return error.DestinationSubjectMismatch;
        }
        if (grant.foreground_session_id != request.foreground_session_id) {
            try recordRead(ledger, request, false, request.detail);
            return error.ForegroundSessionMismatch;
        }
        if (request.now_ticks >= grant.expires_at_ticks) {
            try recordRead(ledger, request, false, request.detail);
            return error.ExpiredGrant;
        }
        if (request.expected_purpose.len != 0 and !std.mem.eql(u8, grant.purposeSlice(), request.expected_purpose)) {
            try recordRead(ledger, request, false, request.detail);
            return error.PurposeMismatch;
        }
        if (output.len < grant.payload_len) {
            try recordRead(ledger, request, false, "pasteboard read denied: output buffer too small");
            return error.OutputBufferTooSmall;
        }

        try recordRead(ledger, request, true, request.detail);
        @memcpy(output[0..grant.payload_len], grant.payloadSlice());
        grant.consumed = true;
        return output[0..grant.payload_len];
    }

    pub fn revoke(self: *Service, request: RevokeRequest, ledger: ?*event_ledger.Ledger) Error!void {
        const grant = self.find(request.token_id) orelse {
            try recordRevoke(ledger, request, false, "pasteboard revoke denied: missing grant");
            return error.GrantNotFound;
        };
        if (grant.source_task_id != request.source_task_id) {
            try recordRevoke(ledger, request, false, request.detail);
            return error.SourceMismatch;
        }
        try recordRevoke(ledger, request, true, request.detail);
        grant.revoked = true;
    }

    pub fn find(self: *Service, token_id: u64) ?*Grant {
        const slot = self.slots.get(token_id) orelse return null;
        return &slot.grant;
    }

};

fn recordOffer(ledger: ?*event_ledger.Ledger, request: OfferRequest, token_id: u64, allowed: bool, detail: []const u8) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordPasteboardAccess(
            request.subject,
            request.source_task_id,
            token_id,
            allowed,
            request.user_gesture_id != 0,
            request.foreground_session_id != 0,
            request.read_once,
            request.now_ticks,
            detail,
        );
    }
}

fn recordRead(ledger: ?*event_ledger.Ledger, request: ReadRequest, allowed: bool, detail: []const u8) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordPasteboardAccess(
            request.subject,
            request.destination_task_id,
            request.token_id,
            allowed,
            request.user_gesture_id != 0,
            request.foreground_session_id != 0,
            true,
            request.now_ticks,
            detail,
        );
    }
}

fn recordRevoke(ledger: ?*event_ledger.Ledger, request: RevokeRequest, allowed: bool, detail: []const u8) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordPasteboardAccess(
            request.subject,
            request.source_task_id,
            request.token_id,
            allowed,
            true,
            true,
            true,
            request.now_ticks,
            detail,
        );
    }
}

fn copyPayloadInto(payload: []const u8) [MAX_PAYLOAD_BYTES]u8 {
    var buffer: [MAX_PAYLOAD_BYTES]u8 = [_]u8{0} ** MAX_PAYLOAD_BYTES;
    _ = copyText(&buffer, payload);
    return buffer;
}

fn copyPurposeInto(purpose: []const u8) [MAX_PURPOSE_BYTES]u8 {
    var buffer: [MAX_PURPOSE_BYTES]u8 = [_]u8{0} ** MAX_PURPOSE_BYTES;
    _ = copyText(&buffer, purpose);
    return buffer;
}

test "secure pasteboard rejects overlong purposes without issuing grants" {
    var service = Service.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 7101 };
    const destination = principal.PrincipalId{ .kind = .app, .serial = 7102 };
    const oversized_purpose = [_]u8{'p'} ** (MAX_PURPOSE_BYTES + 1);

    try std.testing.expectError(error.PurposeTooLong, service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 71,
        .destination_task_id = 72,
        .user_gesture_id = 5,
        .foreground_session_id = 8,
        .expires_at_ticks = 50,
        .now_ticks = 10,
        .purpose = oversized_purpose[0..],
        .payload = "private pasteboard payload",
    }, null));
    try std.testing.expectEqual(@as(usize, 0), service.slots.countInUse());
    try std.testing.expect(service.find(1) == null);
    try std.testing.expectEqual(@as(u64, 1), service.next_token_id);

    const grant = try service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 71,
        .destination_task_id = 72,
        .user_gesture_id = 5,
        .foreground_session_id = 8,
        .expires_at_ticks = 50,
        .now_ticks = 11,
        .purpose = "paste into note",
        .payload = "private pasteboard payload",
    }, null);
    try std.testing.expectEqual(@as(u64, 1), grant.token_id);
    try std.testing.expectEqualStrings("paste into note", grant.purposeSlice());
    try std.testing.expectEqual(@as(usize, 1), service.slots.countInUse());
}

test "secure pasteboard token ids stop at exhaustion" {
    var service = Service.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 7111 };
    const destination = principal.PrincipalId{ .kind = .app, .serial = 7112 };

    service.next_token_id = std.math.maxInt(u64);
    const max_grant = try service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 81,
        .destination_task_id = 82,
        .user_gesture_id = 5,
        .foreground_session_id = 8,
        .expires_at_ticks = 50,
        .now_ticks = 10,
        .purpose = "paste into note",
        .payload = "private pasteboard payload",
    }, null);
    try std.testing.expectEqual(std.math.maxInt(u64), max_grant.token_id);
    try std.testing.expectEqual(@as(u64, 0), service.next_token_id);
    try std.testing.expect(service.find(0) == null);

    try std.testing.expectError(error.PasteboardTokenIdExhausted, service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 83,
        .destination_task_id = 84,
        .user_gesture_id = 6,
        .foreground_session_id = 8,
        .expires_at_ticks = 51,
        .now_ticks = 11,
        .purpose = "paste into note",
        .payload = "private pasteboard payload",
    }, null));
    try std.testing.expectEqual(@as(usize, 1), service.slots.countInUse());

    var full_service = Service.init();
    for (0..MAX_GRANTS) |index| {
        const source_task_id: u64 = @intCast(100 + index);
        const destination_task_id: u64 = @intCast(200 + index);
        _ = try full_service.offer(.{
            .subject = source,
            .destination = destination,
            .source_task_id = source_task_id,
            .destination_task_id = destination_task_id,
            .user_gesture_id = 8,
            .foreground_session_id = 9,
            .expires_at_ticks = 80,
            .now_ticks = 20,
            .purpose = "paste into note",
            .payload = "private pasteboard payload",
        }, null);
    }
    const next_before_full = full_service.next_token_id;
    try std.testing.expectError(error.GrantTableFull, full_service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 300,
        .destination_task_id = 301,
        .user_gesture_id = 8,
        .foreground_session_id = 9,
        .expires_at_ticks = 80,
        .now_ticks = 20,
        .purpose = "paste into note",
        .payload = "private pasteboard payload",
    }, null));
    try std.testing.expectEqual(next_before_full, full_service.next_token_id);
}

test "secure pasteboard requires foreground gestures destination scope expiry and read once" {
    var service = Service.init();
    var ledger = event_ledger.Ledger.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 7001 };
    const destination = principal.PrincipalId{ .kind = .app, .serial = 7002 };
    const imposter = principal.PrincipalId{ .kind = .app, .serial = 7003 };

    try std.testing.expectError(error.MissingUserGesture, service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 71,
        .destination_task_id = 72,
        .user_gesture_id = 0,
        .foreground_session_id = 8,
        .expires_at_ticks = 50,
        .now_ticks = 10,
        .purpose = "paste into note",
        .payload = "private pasteboard payload",
    }, &ledger));
    try std.testing.expectError(error.MissingForegroundSession, service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 71,
        .destination_task_id = 72,
        .user_gesture_id = 5,
        .foreground_session_id = 0,
        .expires_at_ticks = 50,
        .now_ticks = 10,
        .purpose = "paste into note",
        .payload = "private pasteboard payload",
    }, &ledger));

    const grant = try service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 71,
        .destination_task_id = 72,
        .user_gesture_id = 5,
        .foreground_session_id = 8,
        .expires_at_ticks = 50,
        .now_ticks = 11,
        .purpose = "paste into note",
        .payload = "private pasteboard payload",
        .detail = "private pasteboard payload",
    }, &ledger);

    try std.testing.expectError(error.InvalidDestination, service.read(.{
        .subject = destination,
        .destination_task_id = 73,
        .token_id = grant.token_id,
        .user_gesture_id = 6,
        .foreground_session_id = 8,
        .now_ticks = 12,
        .expected_purpose = "paste into note",
        .detail = "wrong destination tried private pasteboard payload",
    }, &.{}, &ledger));
    try std.testing.expectError(error.DestinationSubjectMismatch, service.read(.{
        .subject = imposter,
        .destination_task_id = 72,
        .token_id = grant.token_id,
        .user_gesture_id = 6,
        .foreground_session_id = 8,
        .now_ticks = 12,
        .expected_purpose = "paste into note",
        .detail = "wrong principal tried private pasteboard payload",
    }, &.{}, &ledger));
    try std.testing.expectError(error.ExpiredGrant, service.read(.{
        .subject = destination,
        .destination_task_id = 72,
        .token_id = grant.token_id,
        .user_gesture_id = 6,
        .foreground_session_id = 8,
        .now_ticks = 50,
        .expected_purpose = "paste into note",
        .detail = "expired private pasteboard payload",
    }, &.{}, &ledger));

    var buffer: [MAX_PAYLOAD_BYTES]u8 = undefined;
    const pasted = try service.read(.{
        .subject = destination,
        .destination_task_id = 72,
        .token_id = grant.token_id,
        .user_gesture_id = 6,
        .foreground_session_id = 8,
        .now_ticks = 13,
        .expected_purpose = "paste into note",
        .detail = "private pasteboard payload",
    }, buffer[0..], &ledger);
    try std.testing.expectEqualStrings("private pasteboard payload", pasted);
    try std.testing.expectError(error.GrantAlreadyConsumed, service.read(.{
        .subject = destination,
        .destination_task_id = 72,
        .token_id = grant.token_id,
        .user_gesture_id = 7,
        .foreground_session_id = 8,
        .now_ticks = 14,
        .expected_purpose = "paste into note",
        .detail = "private pasteboard payload replay",
    }, buffer[0..], &ledger));

    const revoked = try service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 71,
        .destination_task_id = 72,
        .user_gesture_id = 9,
        .foreground_session_id = 8,
        .expires_at_ticks = 80,
        .now_ticks = 20,
        .purpose = "paste into note",
        .payload = "revoked private pasteboard payload",
        .detail = "revoked private pasteboard payload",
    }, &ledger);
    try service.revoke(.{
        .subject = source,
        .source_task_id = 71,
        .token_id = revoked.token_id,
        .now_ticks = 21,
        .detail = "revoked private pasteboard payload",
    }, &ledger);
    try std.testing.expectError(error.GrantRevoked, service.read(.{
        .subject = destination,
        .destination_task_id = 72,
        .token_id = revoked.token_id,
        .user_gesture_id = 10,
        .foreground_session_id = 8,
        .now_ticks = 22,
        .expected_purpose = "paste into note",
        .detail = "revoked private pasteboard payload",
    }, buffer[0..], &ledger));

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expect(summary.pasteboard_events >= 9);
    try std.testing.expect(summary.pasteboard_denials >= 6);
    try std.testing.expect(summary.protected_details_redacted >= summary.pasteboard_events);

    var export_buffer: [2048]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "private pasteboard payload") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=pasteboard_access") != null);
}
