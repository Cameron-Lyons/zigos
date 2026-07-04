const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");

pub const MAX_SESSIONS: usize = 16;

pub const Error = event_ledger.Error || error{
    BackgroundCaptureDenied,
    CaptureBudgetExceeded,
    CaptureSessionBindingMismatch,
    CaptureSessionExpired,
    CaptureSessionNotFound,
    CaptureSessionRevoked,
    CaptureTableFull,
    ForegroundSessionRequired,
    InvalidCaptureKind,
    InvalidLease,
    PolicyDenied,
    PrivacyIndicatorRequired,
    SubjectMismatch,
    TaskMismatch,
};

pub const CaptureKind = enum(u8) {
    camera,
    microphone,
    location,
    sensor,
    screen,

    pub fn permissionKind(self: CaptureKind) manifest.PermissionKind {
        return switch (self) {
            .camera => .camera,
            .microphone => .mic,
            .location => .location,
            .sensor => .sensor,
            .screen => .screen_capture,
        };
    }
};

const CAPTURE_KIND_COUNT: usize = @typeInfo(CaptureKind).@"enum".fields.len;

pub const StartRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    device_id: u64,
    kind: CaptureKind,
    foreground_session_id: u64,
    user_gesture_id: u64 = 0,
    expires_at_ticks: u64,
    now_ticks: u64,
    sample_budget: u32 = 1,
    indicator_visible: bool = false,
    background: bool = false,
    sensitivity: manifest.DataSensitivity = .private_user_data,
    detail: []const u8 = "",
};

pub const SampleRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    session_id: u64,
    expected_device_id: u64,
    expected_foreground_session_id: u64,
    expected_kind: CaptureKind,
    now_ticks: u64,
    bytes: usize = 0,
    detail: []const u8 = "",
};

pub const StopRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    session_id: u64,
    expected_device_id: u64,
    expected_foreground_session_id: u64,
    expected_kind: CaptureKind,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const Session = struct {
    id: u64 = 0,
    subject: principal.PrincipalId = .{ .kind = .app, .serial = 0 },
    task_id: u64 = 0,
    device_id: u64 = 0,
    kind: CaptureKind = .camera,
    foreground_session_id: u64 = 0,
    user_gesture_id: u64 = 0,
    expires_at_ticks: u64 = 0,
    sample_budget: u32 = 0,
    sample_count: u32 = 0,
    indicator_visible: bool = false,
    background: bool = false,
    active: bool = false,
    revoked: bool = false,
    sensitivity: manifest.DataSensitivity = .internal_data,
};

const Slot = struct {
    in_use: bool = false,
    session: Session = .{},
};

fn slotSessionKey(slot: *const Slot) u64 {
    return slot.session.id;
}

const SessionArena = indexed_arena.IndexedArenaWithKey(u64, Slot, MAX_SESSIONS, MAX_SESSIONS * 2, slotSessionKey);
const ActiveSessionIndex = indexed_arena.MultimapIndex(MAX_SESSIONS, 1, 2);
const ActiveKindIndex = indexed_arena.MultimapIndex(MAX_SESSIONS, CAPTURE_KIND_COUNT, MAX_SESSIONS * 2);
const ACTIVE_SESSION_KEY: u64 = 1;

pub const Service = struct {
    next_session_id: u64 = 1,
    slots: SessionArena = SessionArena.init(),
    active_session_count: usize = 0,
    privacy_indicator_counts: [CAPTURE_KIND_COUNT]usize = [_]usize{0} ** CAPTURE_KIND_COUNT,
    active_session_index: ActiveSessionIndex = ActiveSessionIndex.init(),
    active_kind_index: ActiveKindIndex = ActiveKindIndex.init(),

    pub fn init() Service {
        return .{};
    }

    pub fn start(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: StartRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*Session {
        if (request.foreground_session_id == 0) {
            try recordStart(ledger, request, 0, false);
            return error.ForegroundSessionRequired;
        }
        if (!request.indicator_visible) {
            try recordStart(ledger, request, 0, false);
            return error.PrivacyIndicatorRequired;
        }
        if (request.background) {
            try recordStart(ledger, request, 0, false);
            return error.BackgroundCaptureDenied;
        }
        if (request.expires_at_ticks <= request.now_ticks or request.sample_budget == 0) {
            try recordStart(ledger, request, 0, false);
            return error.InvalidLease;
        }

        const decision = policies.sensitiveCaptureDecision(subjects, .{
            .kind = request.kind.permissionKind(),
            .lease_ticks = request.expires_at_ticks - request.now_ticks,
            .sample_budget = request.sample_budget,
            .foreground_session = request.foreground_session_id != 0,
            .visible_indicator = request.indicator_visible,
            .background = request.background,
        });
        if (!decision.allowed) {
            try recordStart(ledger, request, 0, false);
            return error.PolicyDenied;
        }

        const session_id = self.next_session_id;
        const slot_index = self.slots.reserveIndex(session_id) orelse {
            try recordStart(ledger, request, 0, false);
            return error.CaptureTableFull;
        };
        const slot = &self.slots.slots[slot_index];
        slot.session = .{
            .id = session_id,
            .subject = request.subject,
            .task_id = request.task_id,
            .device_id = request.device_id,
            .kind = request.kind,
            .foreground_session_id = request.foreground_session_id,
            .user_gesture_id = request.user_gesture_id,
            .expires_at_ticks = request.expires_at_ticks,
            .sample_budget = request.sample_budget,
            .indicator_visible = request.indicator_visible,
            .background = request.background,
            .active = true,
            .sensitivity = request.sensitivity,
        };
        self.accountActiveSession(slot_index, &slot.session);
        self.advanceNextSessionId();
        try recordStart(ledger, request, slot.session.id, true);
        return &slot.session;
    }

    pub fn sample(self: *Service, request: SampleRequest, ledger: ?*event_ledger.Ledger) Error!*Session {
        const session = self.find(request.session_id) orelse {
            try recordSample(ledger, request, false, false, false, false, "capture sample denied: missing session");
            return error.CaptureSessionNotFound;
        };
        if (!session.subject.eql(request.subject)) {
            try recordSampleFromSession(ledger, request, session, false, "capture sample denied: subject mismatch");
            return error.SubjectMismatch;
        }
        if (session.task_id != request.task_id) {
            try recordSampleFromSession(ledger, request, session, false, "capture sample denied: task mismatch");
            return error.TaskMismatch;
        }
        if (!captureBindingMatches(session, request.expected_device_id, request.expected_foreground_session_id, request.expected_kind)) {
            try recordSampleFromSession(ledger, request, session, false, "capture sample denied: binding mismatch");
            return error.CaptureSessionBindingMismatch;
        }
        if (session.revoked or !session.active) {
            try recordSampleFromSession(ledger, request, session, false, request.detail);
            return error.CaptureSessionRevoked;
        }
        if (request.now_ticks >= session.expires_at_ticks) {
            self.deactivateSession(request.session_id, session, false);
            try recordSampleFromSession(ledger, request, session, false, request.detail);
            return error.CaptureSessionExpired;
        }
        if (session.sample_count >= session.sample_budget) {
            try recordSampleFromSession(ledger, request, session, false, request.detail);
            return error.CaptureBudgetExceeded;
        }

        session.sample_count += 1;
        try recordSampleFromSession(ledger, request, session, true, request.detail);
        return session;
    }

    pub fn stop(self: *Service, request: StopRequest, ledger: ?*event_ledger.Ledger) Error!*Session {
        const session = self.find(request.session_id) orelse {
            try recordStop(ledger, request, false, false, false, "capture stop denied: missing session");
            return error.CaptureSessionNotFound;
        };
        if (!session.subject.eql(request.subject)) {
            try recordStopFromSession(ledger, request, session, false, "capture stop denied: subject mismatch");
            return error.SubjectMismatch;
        }
        if (session.task_id != request.task_id) {
            try recordStopFromSession(ledger, request, session, false, "capture stop denied: task mismatch");
            return error.TaskMismatch;
        }
        if (!captureBindingMatches(session, request.expected_device_id, request.expected_foreground_session_id, request.expected_kind)) {
            try recordStopFromSession(ledger, request, session, false, "capture stop denied: binding mismatch");
            return error.CaptureSessionBindingMismatch;
        }
        self.deactivateSession(request.session_id, session, true);
        try recordStopFromSession(ledger, request, session, true, request.detail);
        return session;
    }

    pub fn find(self: *Service, session_id: u64) ?*Session {
        const slot = self.slots.get(session_id) orelse return null;
        return &slot.session;
    }

    fn advanceNextSessionId(self: *Service) void {
        self.next_session_id +%= 1;
        if (self.next_session_id == 0) self.next_session_id = 1;
    }

    pub fn activeSessionCount(self: *const Service) usize {
        return self.active_session_count;
    }

    pub fn activeSessionCountAt(self: *const Service, now_ticks: u64) usize {
        if (self.active_session_count == 0) return 0;
        var count: usize = 0;
        var slot_index = self.active_session_index.head(ACTIVE_SESSION_KEY);
        while (slot_index != indexed_arena.no_index) : (slot_index = self.active_session_index.next(slot_index)) {
            const slot = self.activeSessionSlotAt(slot_index);
            if (sessionLiveAt(&slot.session, now_ticks)) count += 1;
        }
        return count;
    }

    pub fn privacyIndicatorActive(self: *const Service, kind: CaptureKind) bool {
        return self.privacy_indicator_counts[captureKindIndex(kind)] != 0;
    }

    pub fn privacyIndicatorActiveAt(self: *const Service, kind: CaptureKind, now_ticks: u64) bool {
        if (!self.privacyIndicatorActive(kind)) return false;
        var slot_index = self.active_kind_index.head(captureKindKey(kind));
        while (slot_index != indexed_arena.no_index) : (slot_index = self.active_kind_index.next(slot_index)) {
            const slot = self.activeSessionSlotAt(slot_index);
            if (sessionLiveAt(&slot.session, now_ticks) and slot.session.indicator_visible) {
                return true;
            }
        }
        return false;
    }

    fn accountActiveSession(self: *Service, slot_index: usize, session: *const Session) void {
        if (!session.active or session.revoked) return;
        if (!self.active_session_index.append(ACTIVE_SESSION_KEY, slot_index)) {
            native_util.impossibleByInvariant("sensitive capture active-session index covers session slots");
        }
        if (!self.active_kind_index.append(captureKindKey(session.kind), slot_index)) {
            native_util.impossibleByInvariant("sensitive capture active-kind index covers session slots");
        }
        self.active_session_count += 1;
        if (session.indicator_visible) {
            self.privacy_indicator_counts[captureKindIndex(session.kind)] += 1;
        }
    }

    fn deactivateSession(self: *Service, session_id: u64, session: *Session, revoked: bool) void {
        if (session.active and !session.revoked) {
            const slot_index = self.slots.slotIndexOf(session_id) orelse {
                native_util.impossibleByInvariant("sensitive capture active session has an arena slot");
            };
            if (!self.active_session_index.remove(ACTIVE_SESSION_KEY, slot_index)) {
                native_util.impossibleByInvariant("sensitive capture active-session index missing live session");
            }
            if (!self.active_kind_index.remove(captureKindKey(session.kind), slot_index)) {
                native_util.impossibleByInvariant("sensitive capture active-kind index missing live session");
            }
            if (self.active_session_count == 0) native_util.impossibleByInvariant("sensitive capture active count underflow");
            self.active_session_count -= 1;
            if (session.indicator_visible) {
                const kind_index = captureKindIndex(session.kind);
                if (self.privacy_indicator_counts[kind_index] == 0) native_util.impossibleByInvariant("sensitive capture privacy indicator count underflow");
                self.privacy_indicator_counts[kind_index] -= 1;
            }
        }
        session.active = false;
        if (revoked) session.revoked = true;
    }

    fn activeSessionSlotAt(self: *const Service, slot_index: usize) *const Slot {
        if (slot_index >= MAX_SESSIONS) native_util.impossibleByInvariant("sensitive capture active index points outside slots");
        const slot = &self.slots.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("sensitive capture active index points at free slot");
        if (!slot.session.active or slot.session.revoked) native_util.impossibleByInvariant("sensitive capture active index points at inactive slot");
        return slot;
    }
};

fn captureKindIndex(kind: CaptureKind) usize {
    return @intFromEnum(kind);
}

fn captureKindKey(kind: CaptureKind) u64 {
    return @as(u64, @intFromEnum(kind)) + 1;
}

fn sessionLiveAt(session: *const Session, now_ticks: u64) bool {
    return session.active and !session.revoked and now_ticks < session.expires_at_ticks;
}

fn captureBindingMatches(
    session: *const Session,
    expected_device_id: u64,
    expected_foreground_session_id: u64,
    expected_kind: CaptureKind,
) bool {
    return session.device_id == expected_device_id and
        session.foreground_session_id == expected_foreground_session_id and
        session.kind == expected_kind;
}

fn recordStart(
    ledger: ?*event_ledger.Ledger,
    request: StartRequest,
    session_id: u64,
    allowed: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordSensitiveCapture(
            request.subject,
            request.task_id,
            session_id,
            allowed,
            request.kind.permissionKind(),
            request.foreground_session_id != 0,
            request.indicator_visible,
            request.background,
            false,
            false,
            request.now_ticks,
            request.detail,
        );
    }
}

fn recordSampleFromSession(
    ledger: ?*event_ledger.Ledger,
    request: SampleRequest,
    session: *const Session,
    allowed: bool,
    detail: []const u8,
) event_ledger.Error!void {
    try recordSample(
        ledger,
        request,
        allowed,
        session.foreground_session_id != 0,
        session.indicator_visible,
        session.background,
        detail,
    );
}

fn recordSample(
    ledger: ?*event_ledger.Ledger,
    request: SampleRequest,
    allowed: bool,
    foreground_session: bool,
    indicator_visible: bool,
    background: bool,
    detail: []const u8,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordSensitiveCapture(
            request.subject,
            request.task_id,
            request.session_id,
            allowed,
            null,
            foreground_session,
            indicator_visible,
            background,
            true,
            false,
            request.now_ticks,
            detail,
        );
    }
}

fn recordStopFromSession(
    ledger: ?*event_ledger.Ledger,
    request: StopRequest,
    session: *const Session,
    allowed: bool,
    detail: []const u8,
) event_ledger.Error!void {
    try recordStop(ledger, request, allowed, session.indicator_visible, session.background, detail);
}

fn recordStop(
    ledger: ?*event_ledger.Ledger,
    request: StopRequest,
    allowed: bool,
    indicator_visible: bool,
    background: bool,
    detail: []const u8,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordSensitiveCapture(
            request.subject,
            request.task_id,
            request.session_id,
            allowed,
            null,
            true,
            indicator_visible,
            background,
            false,
            true,
            request.now_ticks,
            detail,
        );
    }
}

test "sensitive capture broker requires foreground visible leased sessions and revokes samples" {
    const signing = @import("../core/signing.zig");

    var policies = policy_object.Directory.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 991 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 992 };
    const signer = signing.SignerIdentity{ .label = "capture-policy", .seed = signing.seedFromByte(0xc9) };
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .label = "capture policy",
        .camera_allowed = true,
        .microphone_allowed = true,
        .sensors_allowed = true,
        .screen_capture_allowed = true,
        .location_allowed = true,
        .require_capture_indicator = true,
        .require_sensitive_capture_foreground = true,
        .allow_background_capture = false,
        .max_sensitive_capture_lease_ticks = 50,
        .max_sensitive_capture_samples = 2,
    }, signer);

    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    var service = Service.init();
    var ledger = event_ledger.Ledger.init();

    try std.testing.expectError(error.ForegroundSessionRequired, service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 42,
        .device_id = 7,
        .kind = .camera,
        .foreground_session_id = 0,
        .expires_at_ticks = 25,
        .now_ticks = 10,
        .sample_budget = 1,
        .indicator_visible = true,
        .detail = "private camera frame denied",
    }, &ledger));
    try std.testing.expectError(error.PrivacyIndicatorRequired, service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 42,
        .device_id = 7,
        .kind = .camera,
        .foreground_session_id = 5,
        .expires_at_ticks = 25,
        .now_ticks = 10,
        .sample_budget = 1,
        .indicator_visible = false,
        .detail = "private camera frame denied",
    }, &ledger));
    try std.testing.expectError(error.BackgroundCaptureDenied, service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 42,
        .device_id = 7,
        .kind = .camera,
        .foreground_session_id = 5,
        .expires_at_ticks = 25,
        .now_ticks = 10,
        .sample_budget = 1,
        .indicator_visible = true,
        .background = true,
        .detail = "private camera frame denied",
    }, &ledger));
    try std.testing.expectError(error.PolicyDenied, service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 42,
        .device_id = 7,
        .kind = .camera,
        .foreground_session_id = 5,
        .expires_at_ticks = 80,
        .now_ticks = 10,
        .sample_budget = 1,
        .indicator_visible = true,
        .detail = "private camera frame lease denied",
    }, &ledger));

    const session = try service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 42,
        .device_id = 7,
        .kind = .camera,
        .foreground_session_id = 5,
        .expires_at_ticks = 45,
        .now_ticks = 11,
        .sample_budget = 2,
        .indicator_visible = true,
        .detail = "private camera frame allowed",
    }, &ledger);
    try std.testing.expectEqual(@as(usize, 1), service.activeSessionCount());
    try std.testing.expectEqual(@as(usize, 1), service.active_session_index.count(ACTIVE_SESSION_KEY));
    try std.testing.expectEqual(@as(usize, 1), service.active_kind_index.count(captureKindKey(.camera)));
    try std.testing.expect(service.privacyIndicatorActive(.camera));
    try std.testing.expectEqual(@as(usize, 1), service.activeSessionCountAt(44));
    try std.testing.expectEqual(@as(usize, 0), service.activeSessionCountAt(45));
    try std.testing.expect(service.privacyIndicatorActiveAt(.camera, 44));
    try std.testing.expect(!service.privacyIndicatorActiveAt(.camera, 45));

    try std.testing.expectError(error.CaptureSessionBindingMismatch, service.sample(.{
        .subject = app,
        .task_id = 42,
        .session_id = session.id,
        .expected_device_id = 8,
        .expected_foreground_session_id = 5,
        .expected_kind = .camera,
        .now_ticks = 12,
        .bytes = 4096,
        .detail = "private camera wrong binding",
    }, &ledger));
    try std.testing.expectEqual(@as(u32, 0), service.find(session.id).?.sample_count);

    _ = try service.sample(.{
        .subject = app,
        .task_id = 42,
        .session_id = session.id,
        .expected_device_id = 7,
        .expected_foreground_session_id = 5,
        .expected_kind = .camera,
        .now_ticks = 12,
        .bytes = 4096,
        .detail = "private camera frame sample one",
    }, &ledger);
    _ = try service.sample(.{
        .subject = app,
        .task_id = 42,
        .session_id = session.id,
        .expected_device_id = 7,
        .expected_foreground_session_id = 5,
        .expected_kind = .camera,
        .now_ticks = 13,
        .bytes = 4096,
        .detail = "private camera frame sample two",
    }, &ledger);
    try std.testing.expectError(error.CaptureBudgetExceeded, service.sample(.{
        .subject = app,
        .task_id = 42,
        .session_id = session.id,
        .expected_device_id = 7,
        .expected_foreground_session_id = 5,
        .expected_kind = .camera,
        .now_ticks = 14,
        .bytes = 4096,
        .detail = "private camera frame sample replay",
    }, &ledger));
    _ = try service.stop(.{
        .subject = app,
        .task_id = 42,
        .session_id = session.id,
        .expected_device_id = 7,
        .expected_foreground_session_id = 5,
        .expected_kind = .camera,
        .now_ticks = 15,
        .detail = "private camera frame stopped",
    }, &ledger);
    try std.testing.expectEqual(@as(usize, 0), service.activeSessionCount());
    try std.testing.expectEqual(@as(usize, 0), service.active_session_index.count(ACTIVE_SESSION_KEY));
    try std.testing.expectEqual(@as(usize, 0), service.active_kind_index.count(captureKindKey(.camera)));
    try std.testing.expect(!service.privacyIndicatorActive(.camera));

    const first_mic = try service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 43,
        .device_id = 9,
        .kind = .microphone,
        .foreground_session_id = 6,
        .expires_at_ticks = 30,
        .now_ticks = 16,
        .sample_budget = 1,
        .indicator_visible = true,
        .detail = "private microphone sample allowed",
    }, &ledger);
    const second_mic = try service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 44,
        .device_id = 10,
        .kind = .microphone,
        .foreground_session_id = 7,
        .expires_at_ticks = 30,
        .now_ticks = 17,
        .sample_budget = 1,
        .indicator_visible = true,
        .detail = "private microphone sample allowed",
    }, &ledger);
    try std.testing.expectEqual(@as(usize, 2), service.activeSessionCount());
    try std.testing.expectEqual(@as(usize, 2), service.active_session_index.count(ACTIVE_SESSION_KEY));
    try std.testing.expectEqual(@as(usize, 2), service.active_kind_index.count(captureKindKey(.microphone)));
    try std.testing.expectEqual(@as(usize, 2), service.privacy_indicator_counts[captureKindIndex(.microphone)]);
    try std.testing.expect(service.privacyIndicatorActive(.microphone));
    _ = try service.stop(.{
        .subject = app,
        .task_id = 43,
        .session_id = first_mic.id,
        .expected_device_id = 9,
        .expected_foreground_session_id = 6,
        .expected_kind = .microphone,
        .now_ticks = 18,
        .detail = "private microphone first stopped",
    }, &ledger);
    try std.testing.expectEqual(@as(usize, 1), service.activeSessionCount());
    try std.testing.expectEqual(@as(usize, 1), service.active_session_index.count(ACTIVE_SESSION_KEY));
    try std.testing.expectEqual(@as(usize, 1), service.active_kind_index.count(captureKindKey(.microphone)));
    try std.testing.expectEqual(@as(usize, 1), service.privacy_indicator_counts[captureKindIndex(.microphone)]);
    try std.testing.expect(service.privacyIndicatorActive(.microphone));
    try std.testing.expectError(error.CaptureSessionExpired, service.sample(.{
        .subject = app,
        .task_id = 44,
        .session_id = second_mic.id,
        .expected_device_id = 10,
        .expected_foreground_session_id = 7,
        .expected_kind = .microphone,
        .now_ticks = 30,
        .bytes = 2048,
        .detail = "private microphone expired",
    }, &ledger));
    try std.testing.expectEqual(@as(usize, 0), service.activeSessionCount());
    try std.testing.expectEqual(@as(usize, 0), service.active_session_index.count(ACTIVE_SESSION_KEY));
    try std.testing.expectEqual(@as(usize, 0), service.active_kind_index.count(captureKindKey(.microphone)));
    try std.testing.expectEqual(@as(usize, 0), service.privacy_indicator_counts[captureKindIndex(.microphone)]);
    try std.testing.expect(!service.privacyIndicatorActive(.microphone));

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expect(summary.sensitive_capture_events >= 9);
    try std.testing.expect(summary.sensitive_capture_denials >= 5);
    try std.testing.expect(summary.protected_details_redacted >= summary.sensitive_capture_events);

    var export_buffer: [4096]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "private camera frame") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=sensitive_capture") != null);
}

test "sensitive capture session ids wrap without publishing id zero" {
    const signing = @import("../core/signing.zig");

    var policies = policy_object.Directory.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 993 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 994 };
    const signer = signing.SignerIdentity{ .label = "capture-wrap-policy", .seed = signing.seedFromByte(0xca) };
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .label = "capture wrap policy",
        .camera_allowed = true,
        .require_capture_indicator = true,
        .require_sensitive_capture_foreground = true,
        .allow_background_capture = false,
        .max_sensitive_capture_lease_ticks = 50,
        .max_sensitive_capture_samples = 1,
    }, signer);

    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    var service = Service.init();
    service.next_session_id = std.math.maxInt(u64);

    const first = try service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 43,
        .device_id = 7,
        .kind = .camera,
        .foreground_session_id = 5,
        .expires_at_ticks = 45,
        .now_ticks = 11,
        .sample_budget = 1,
        .indicator_visible = true,
        .detail = "private camera frame allowed",
    }, null);
    try std.testing.expectEqual(std.math.maxInt(u64), first.id);
    try std.testing.expectEqual(@as(u64, 1), service.next_session_id);
    try std.testing.expect(service.find(0) == null);

    const second = try service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 44,
        .device_id = 8,
        .kind = .camera,
        .foreground_session_id = 6,
        .expires_at_ticks = 45,
        .now_ticks = 12,
        .sample_budget = 1,
        .indicator_visible = true,
        .detail = "private camera frame allowed",
    }, null);
    try std.testing.expectEqual(@as(u64, 1), second.id);
    try std.testing.expectEqual(@as(u64, 2), service.next_session_id);
    try std.testing.expectEqual(@as(usize, 2), service.activeSessionCount());
}
