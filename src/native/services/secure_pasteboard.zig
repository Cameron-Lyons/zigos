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
pub const BOUNDED_GRANT_SCAN = true;
pub const DIRECT_GRANT_LOOKUP = true;
pub const RECLAIMS_TERMINAL_GRANTS = true;
pub const COMPACT_GRANT_LENGTHS = true;
pub const SERVICE_SIZE_CEILING_BYTES: usize = 11_144;

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
    PurposeMismatch,
    PurposeRequired,
    PurposeTooLong,
    SourceMismatch,
};

pub const TokenId = indexed_arena.GenerationalHandle("SecurePasteboardGrant");

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
    payload_len: u16 = 0,
    payload: [MAX_PAYLOAD_BYTES]u8 = [_]u8{0} ** MAX_PAYLOAD_BYTES,
    purpose_len: u8 = 0,
    purpose: [MAX_PURPOSE_BYTES]u8 = [_]u8{0} ** MAX_PURPOSE_BYTES,

    pub fn payloadSlice(self: *const Grant) []const u8 {
        return self.payload[0..@as(usize, self.payload_len)];
    }

    pub fn purposeSlice(self: *const Grant) []const u8 {
        return self.purpose[0..@as(usize, self.purpose_len)];
    }
};

pub const Service = struct {
    grants: [MAX_GRANTS]Grant = [_]Grant{.{}} ** MAX_GRANTS,
    grant_count: u8 = 0,
    next_reusable_grant: u8 = 0,

    comptime {
        if (@sizeOf(@This()) > SERVICE_SIZE_CEILING_BYTES) {
            @compileError("secure pasteboard service exceeds its fixed-state size ceiling");
        }
    }

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

        const grant_index = self.availableGrantIndex(request.now_ticks) orelse {
            try recordOffer(ledger, request, 0, false, "pasteboard offer denied: grant table full");
            return error.GrantTableFull;
        };
        const token_id = self.nextTokenId(grant_index);
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
            .payload_len = @intCast(request.payload.len),
            .payload = copyPayloadInto(request.payload),
            .purpose_len = @intCast(request.purpose.len),
            .purpose = copyPurposeInto(request.purpose),
        };

        try recordOffer(ledger, request, token_id, true, request.detail);
        if (self.grants[grant_index].token_id == 0) self.grant_count += 1;
        self.grants[grant_index] = grant;
        self.next_reusable_grant = @intCast((grant_index + 1) % MAX_GRANTS);
        return &self.grants[grant_index];
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
        const payload_len = @as(usize, grant.payload_len);
        if (output.len < payload_len) {
            try recordRead(ledger, request, false, "pasteboard read denied: output buffer too small");
            return error.OutputBufferTooSmall;
        }

        try recordRead(ledger, request, true, request.detail);
        @memcpy(output[0..payload_len], grant.payloadSlice());
        grant.consumed = true;
        return output[0..payload_len];
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
        const token = TokenId{ .value = token_id };
        if (token.isZero()) return null;
        const grant_index = token.slotIndex();
        if (grant_index >= MAX_GRANTS) return null;
        const grant = &self.grants[grant_index];
        return if (grant.token_id == token_id) grant else null;
    }

    pub fn grantCount(self: *const Service) usize {
        return @as(usize, self.grant_count);
    }

    fn availableGrantIndex(self: *const Service, now_ticks: u64) ?usize {
        for (0..MAX_GRANTS) |offset| {
            const grant_index = (@as(usize, self.next_reusable_grant) + offset) % MAX_GRANTS;
            if (self.grants[grant_index].token_id == 0) return grant_index;
        }
        for (0..MAX_GRANTS) |offset| {
            const grant_index = (@as(usize, self.next_reusable_grant) + offset) % MAX_GRANTS;
            if (grantReusableAt(&self.grants[grant_index], now_ticks)) return grant_index;
        }
        return null;
    }

    fn nextTokenId(self: *const Service, grant_index: usize) u64 {
        const current_generation = (TokenId{ .value = self.grants[grant_index].token_id }).generation();
        const incremented = current_generation +% 1;
        const generation = if (incremented == 0) 1 else incremented;
        return TokenId.fromParts(grant_index, generation).value;
    }

};

fn grantReusableAt(grant: *const Grant, now_ticks: u64) bool {
    return grant.revoked or (grant.read_once and grant.consumed) or now_ticks >= grant.expires_at_ticks;
}

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
    try std.testing.expectEqual(@as(usize, 0), service.grantCount());
    try std.testing.expect(service.find(1) == null);

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
    try std.testing.expectEqual(TokenId.fromParts(0, 1).value, grant.token_id);
    try std.testing.expectEqualStrings("paste into note", grant.purposeSlice());
    try std.testing.expectEqual(@as(usize, 1), service.grantCount());
}

test "secure pasteboard uses direct generational tokens through bounded capacity" {
    var service = Service.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 7111 };
    const destination = principal.PrincipalId{ .kind = .app, .serial = 7112 };

    var first_token_id: u64 = 0;
    for (0..MAX_GRANTS) |index| {
        const grant = try service.offer(.{
            .subject = source,
            .destination = destination,
            .source_task_id = 100 + index,
            .destination_task_id = 200 + index,
            .user_gesture_id = 8,
            .foreground_session_id = 9,
            .expires_at_ticks = 80,
            .now_ticks = 20,
            .purpose = "paste into note",
            .payload = "private pasteboard payload",
        }, null);
        const token = TokenId{ .value = grant.token_id };
        try std.testing.expectEqual(index, token.slotIndex());
        try std.testing.expectEqual(@as(u32, 1), token.generation());
        if (index == 0) first_token_id = grant.token_id;
    }
    try std.testing.expectEqual(MAX_GRANTS, service.grantCount());
    try std.testing.expect(service.find(0) == null);
    try std.testing.expect(service.find(TokenId.fromParts(MAX_GRANTS, 1).value) == null);

    try std.testing.expectError(error.GrantTableFull, service.offer(.{
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

    service.grants[0].revoked = true;
    const replacement = try service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 302,
        .destination_task_id = 303,
        .user_gesture_id = 9,
        .foreground_session_id = 9,
        .expires_at_ticks = 80,
        .now_ticks = 21,
        .purpose = "paste into note",
        .payload = "private pasteboard payload",
    }, null);
    try std.testing.expectEqual(@as(usize, 0), (TokenId{ .value = replacement.token_id }).slotIndex());
    try std.testing.expectEqual(@as(u32, 2), (TokenId{ .value = replacement.token_id }).generation());
    try std.testing.expect(service.find(first_token_id) == null);

    const wrapped_from = TokenId.fromParts(0, std.math.maxInt(u32)).value;
    replacement.token_id = wrapped_from;
    replacement.revoked = true;
    const wrapped = try service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 304,
        .destination_task_id = 305,
        .user_gesture_id = 10,
        .foreground_session_id = 9,
        .expires_at_ticks = 80,
        .now_ticks = 22,
        .purpose = "paste into note",
        .payload = "private pasteboard payload",
    }, null);
    try std.testing.expectEqual(@as(usize, 0), (TokenId{ .value = wrapped.token_id }).slotIndex());
    try std.testing.expectEqual(@as(u32, 1), (TokenId{ .value = wrapped.token_id }).generation());
    try std.testing.expect(service.find(wrapped_from) == null);
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

    const consumed_token_id = grant.token_id;
    const revoked_token_id = revoked.token_id;
    const persistent = try service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 80,
        .destination_task_id = 81,
        .user_gesture_id = 11,
        .foreground_session_id = 8,
        .expires_at_ticks = 1_000,
        .now_ticks = 23,
        .purpose = "paste repeatedly",
        .payload = "persistent private pasteboard payload",
        .read_once = false,
    }, null);
    const persistent_token_id = persistent.token_id;
    const expired = try service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 82,
        .destination_task_id = 83,
        .user_gesture_id = 12,
        .foreground_session_id = 8,
        .expires_at_ticks = 24,
        .now_ticks = 23,
        .purpose = "paste before expiry",
        .payload = "expiring private pasteboard payload",
    }, null);
    const expired_token_id = expired.token_id;

    for (0..MAX_GRANTS - 1) |index| {
        const source_task_id: u64 = @intCast(100 + index);
        const rolling = try service.offer(.{
            .subject = source,
            .destination = destination,
            .source_task_id = source_task_id,
            .destination_task_id = 200 + index,
            .user_gesture_id = 20 + index,
            .foreground_session_id = 8,
            .expires_at_ticks = 200,
            .now_ticks = 50 + index,
            .purpose = "paste rolling payload",
            .payload = "rolling private pasteboard payload",
        }, null);
        try service.revoke(.{
            .subject = source,
            .source_task_id = source_task_id,
            .token_id = rolling.token_id,
            .now_ticks = 51 + index,
        }, null);
    }
    try std.testing.expectEqual(MAX_GRANTS, service.grantCount());
    try std.testing.expect(service.find(consumed_token_id) == null);
    try std.testing.expect(service.find(revoked_token_id) == null);
    try std.testing.expect(service.find(expired_token_id) == null);
    try std.testing.expect(service.find(persistent_token_id) != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expect(summary.pasteboard_events >= 9);
    try std.testing.expect(summary.pasteboard_denials >= 6);
    try std.testing.expect(summary.protected_details_redacted >= summary.pasteboard_events);

    var export_buffer: [2048]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "private pasteboard payload") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=pasteboard_access") != null);
}
