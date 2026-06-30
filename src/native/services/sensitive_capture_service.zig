const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
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

pub const Service = struct {
    next_session_id: u64 = 1,
    slots: SessionArena = SessionArena.init(),

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
        const session = Session{
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

        const slot = self.slots.reserve(session_id) orelse {
            try recordStart(ledger, request, 0, false);
            return error.CaptureTableFull;
        };
        errdefer _ = self.slots.remove(session_id);
        try recordStart(ledger, request, session_id, true);
        slot.session = session;
        self.advanceNextSessionId();
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
            session.active = false;
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
        session.active = false;
        session.revoked = true;
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
        var count: usize = 0;
        for (&self.slots.slots) |*slot| {
            if (slot.in_use and slot.session.active and !slot.session.revoked) count += 1;
        }
        return count;
    }

    pub fn activeSessionCountAt(self: *const Service, now_ticks: u64) usize {
        var count: usize = 0;
        for (&self.slots.slots) |*slot| {
            if (slot.in_use and sessionLiveAt(&slot.session, now_ticks)) count += 1;
        }
        return count;
    }

    pub fn privacyIndicatorActive(self: *const Service, kind: CaptureKind) bool {
        for (&self.slots.slots) |*slot| {
            if (!slot.in_use) continue;
            if (slot.session.active and !slot.session.revoked and slot.session.kind == kind and slot.session.indicator_visible) {
                return true;
            }
        }
        return false;
    }

    pub fn privacyIndicatorActiveAt(self: *const Service, kind: CaptureKind, now_ticks: u64) bool {
        for (&self.slots.slots) |*slot| {
            if (!slot.in_use) continue;
            if (sessionLiveAt(&slot.session, now_ticks) and slot.session.kind == kind and slot.session.indicator_visible) {
                return true;
            }
        }
        return false;
    }
};

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

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expect(summary.sensitive_capture_events >= 9);
    try std.testing.expect(summary.sensitive_capture_denials >= 5);
    try std.testing.expect(summary.protected_details_redacted >= summary.sensitive_capture_events);

    var export_buffer: [2048]u8 = undefined;
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
