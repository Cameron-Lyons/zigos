const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");

pub const MAX_SESSIONS: usize = 16;
pub const BOUNDED_SESSION_SCAN = true;
pub const RECLAIMS_INACTIVE_SESSION_SLOTS = true;
pub const SERVICE_SIZE_CEILING_BYTES: usize = 1_440;

pub const Error = event_ledger.Error || error{
    BackgroundCaptureDenied,
    CaptureBudgetExceeded,
    CaptureSessionIdExhausted,
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

pub const Service = struct {
    next_session_id: u64 = 1,
    slots: [MAX_SESSIONS]Slot = [_]Slot{.{}} ** MAX_SESSIONS,
    session_count: u8 = 0,
    next_reusable_slot: u8 = 0,
    active_session_count: u8 = 0,
    privacy_indicator_counts: [CAPTURE_KIND_COUNT]u8 = [_]u8{0} ** CAPTURE_KIND_COUNT,

    comptime {
        if (@sizeOf(@This()) > SERVICE_SIZE_CEILING_BYTES) {
            @compileError("sensitive capture service exceeds its fixed-state size ceiling");
        }
    }

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
        if (session_id == 0) {
            try recordStart(ledger, request, 0, false);
            return error.CaptureSessionIdExhausted;
        }
        const slot_index = self.availableSessionSlot(request.now_ticks) orelse {
            try recordStart(ledger, request, 0, false);
            return error.CaptureTableFull;
        };
        try recordStart(ledger, request, session_id, true);
        const slot = &self.slots[slot_index];
        if (slot.in_use) {
            if (slot.session.active and !slot.session.revoked) {
                self.deactivateSession(&slot.session, false);
            }
        } else {
            slot.in_use = true;
            self.session_count += 1;
        }
        self.next_reusable_slot = @intCast((slot_index + 1) % MAX_SESSIONS);
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
        self.accountActiveSession(&slot.session);
        self.next_session_id +%= 1;
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
            self.deactivateSession(session, false);
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
        self.deactivateSession(session, true);
        try recordStopFromSession(ledger, request, session, true, request.detail);
        return session;
    }

    pub fn find(self: *Service, session_id: u64) ?*Session {
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.session.id == session_id) return &slot.session;
        }
        return null;
    }

    pub fn sessionCount(self: *const Service) usize {
        return @as(usize, self.session_count);
    }

    pub fn activeSessionCount(self: *const Service) usize {
        return @as(usize, self.active_session_count);
    }

    pub fn activeSessionCountAt(self: *const Service, now_ticks: u64) usize {
        if (self.active_session_count == 0) return 0;
        var count: usize = 0;
        for (&self.slots) |*slot| {
            if (slot.in_use and sessionLiveAt(&slot.session, now_ticks)) count += 1;
        }
        return count;
    }

    pub fn privacyIndicatorCount(self: *const Service, kind: CaptureKind) usize {
        return @as(usize, self.privacy_indicator_counts[captureKindIndex(kind)]);
    }

    pub fn privacyIndicatorActive(self: *const Service, kind: CaptureKind) bool {
        return self.privacyIndicatorCount(kind) != 0;
    }

    pub fn privacyIndicatorActiveAt(self: *const Service, kind: CaptureKind, now_ticks: u64) bool {
        if (!self.privacyIndicatorActive(kind)) return false;
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.session.kind == kind and sessionLiveAt(&slot.session, now_ticks) and slot.session.indicator_visible) {
                return true;
            }
        }
        return false;
    }

    fn availableSessionSlot(self: *const Service, now_ticks: u64) ?usize {
        for (0..MAX_SESSIONS) |offset| {
            const slot_index = (@as(usize, self.next_reusable_slot) + offset) % MAX_SESSIONS;
            if (!self.slots[slot_index].in_use) return slot_index;
        }
        for (0..MAX_SESSIONS) |offset| {
            const slot_index = (@as(usize, self.next_reusable_slot) + offset) % MAX_SESSIONS;
            const slot = &self.slots[slot_index];
            if (sessionLiveAt(&slot.session, now_ticks)) continue;
            return slot_index;
        }
        return null;
    }

    fn accountActiveSession(self: *Service, session: *const Session) void {
        if (!session.active or session.revoked) return;
        self.active_session_count += 1;
        if (session.indicator_visible) {
            self.privacy_indicator_counts[captureKindIndex(session.kind)] += 1;
        }
    }

    fn deactivateSession(self: *Service, session: *Session, revoked: bool) void {
        if (session.active and !session.revoked) {
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
};

fn captureKindIndex(kind: CaptureKind) usize {
    return @intFromEnum(kind);
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
    try std.testing.expectEqual(@as(usize, 1), service.privacyIndicatorCount(.camera));
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
    try std.testing.expectEqual(@as(usize, 0), service.privacyIndicatorCount(.camera));
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
    try std.testing.expectEqual(@as(usize, 2), service.privacyIndicatorCount(.microphone));
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
    try std.testing.expectEqual(@as(usize, 1), service.privacyIndicatorCount(.microphone));
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
    try std.testing.expectEqual(@as(usize, 0), service.privacyIndicatorCount(.microphone));
    try std.testing.expect(!service.privacyIndicatorActive(.microphone));

    const retired_camera_session_id = session.id;
    for (0..MAX_SESSIONS + 2) |index| {
        const now_ticks = 40 + index * 2;
        const rolling = try service.start(&policies, subjects, .{
            .subject = app,
            .task_id = 100 + index,
            .device_id = 200 + index,
            .kind = .camera,
            .foreground_session_id = 300 + index,
            .expires_at_ticks = now_ticks + 10,
            .now_ticks = now_ticks,
            .sample_budget = 1,
            .indicator_visible = true,
        }, null);
        _ = try service.stop(.{
            .subject = app,
            .task_id = 100 + index,
            .session_id = rolling.id,
            .expected_device_id = 200 + index,
            .expected_foreground_session_id = 300 + index,
            .expected_kind = .camera,
            .now_ticks = now_ticks + 1,
        }, null);
    }
    try std.testing.expectEqual(MAX_SESSIONS, service.sessionCount());
    try std.testing.expectEqual(@as(usize, 0), service.activeSessionCount());
    try std.testing.expect(service.find(retired_camera_session_id) == null);

    var full_service = Service.init();
    for (0..MAX_SESSIONS) |index| {
        _ = try full_service.start(&policies, subjects, .{
            .subject = app,
            .task_id = 400 + index,
            .device_id = 500 + index,
            .kind = .camera,
            .foreground_session_id = 600 + index,
            .expires_at_ticks = 150,
            .now_ticks = 100,
            .sample_budget = 1,
            .indicator_visible = true,
        }, null);
    }
    try std.testing.expectError(error.CaptureTableFull, full_service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 700,
        .device_id = 800,
        .kind = .camera,
        .foreground_session_id = 900,
        .expires_at_ticks = 150,
        .now_ticks = 101,
        .sample_budget = 1,
        .indicator_visible = true,
    }, null));
    try std.testing.expectEqual(MAX_SESSIONS, full_service.activeSessionCount());
    try std.testing.expectEqual(MAX_SESSIONS, full_service.privacyIndicatorCount(.camera));

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expect(summary.sensitive_capture_events >= 9);
    try std.testing.expect(summary.sensitive_capture_denials >= 5);
    try std.testing.expect(summary.protected_details_redacted >= summary.sensitive_capture_events);

    var export_buffer: [4096]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "private camera frame") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=sensitive_capture") != null);
}

test "sensitive capture session ids stop at exhaustion" {
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
    try std.testing.expectEqual(@as(u64, 0), service.next_session_id);
    try std.testing.expect(service.find(0) == null);

    try std.testing.expectError(error.CaptureSessionIdExhausted, service.start(&policies, subjects, .{
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
    }, null));
    try std.testing.expectEqual(@as(u64, 0), service.next_session_id);
    try std.testing.expectEqual(@as(usize, 1), service.activeSessionCount());
    try std.testing.expectEqual(@as(usize, 1), service.sessionCount());
    try std.testing.expectEqual(std.math.maxInt(u64), service.find(std.math.maxInt(u64)).?.id);
}
