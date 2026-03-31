const std = @import("std");
const abi = @import("../core/abi.zig");
const contract = @import("../session/contract.zig");
const denial_explanation = @import("../policy/denial_explanation.zig");
const immutable_base = @import("immutable_base.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const workspace = @import("../storage/workspace.zig");
const copyText = native_util.copyText;

pub const MAX_EVENTS: usize = 64;
pub const MAX_DETAIL_BYTES: usize = 96;
pub const state_workspace_label = "system-diagnostics";

const MAX_PERSISTED_EVENTS: usize = MAX_EVENTS;
const MAX_PERSISTED_DETAIL_BYTES: usize = MAX_DETAIL_BYTES;
const MAX_PERSISTED_LABEL_BYTES: usize = denial_explanation.MAX_LABEL_BYTES;
const state_entry_path = "state/event-ledger";
const event_entry_prefix = "events/";
const persistent_header_magic: u32 = 0x454C4731;
const permission_kind_none: u8 = 0xFF;

const PersistentHeader = extern struct {
    magic: u32 = persistent_header_magic,
    next_sequence: u64 = 1,
};

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
    denial_reason: abi.DenialReason = .none,
    user_approval_can_resolve: bool = false,
    retry_safe: bool = false,
    policy_label_len: usize = 0,
    policy_label: [denial_explanation.MAX_LABEL_BYTES]u8 = [_]u8{0} ** denial_explanation.MAX_LABEL_BYTES,
    missing_capability_len: usize = 0,
    missing_capability: [denial_explanation.MAX_LABEL_BYTES]u8 = [_]u8{0} ** denial_explanation.MAX_LABEL_BYTES,
    detail_protected: bool = false,
    detail_len: usize = 0,
    detail: [MAX_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_DETAIL_BYTES,

    pub fn detailSlice(self: *const Event) []const u8 {
        return self.detail[0..self.detail_len];
    }

    pub fn policyLabelSlice(self: *const Event) []const u8 {
        return self.policy_label[0..self.policy_label_len];
    }

    pub fn missingCapabilitySlice(self: *const Event) []const u8 {
        return self.missing_capability[0..self.missing_capability_len];
    }
};

pub const Error = anyerror;

const EventSlot = struct {
    in_use: bool = false,
    event: Event = zeroEvent(),
};

pub const Ledger = struct {
    storage: ?*storage_service.Service = null,
    owner: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    state_signer: signing.SignerIdentity = .{
        .label = "",
        .seed = [_]u8{0} ** 32,
    },
    workspace_id: u64 = 0,
    loaded_existing_state: bool = false,
    next_sequence: u64 = 1,
    events: [MAX_EVENTS]EventSlot = [_]EventSlot{EventSlot{}} ** MAX_EVENTS,

    pub fn init() Ledger {
        return .{};
    }

    pub fn initPersistent(
        storage: *storage_service.Service,
        owner: principal.PrincipalId,
        state_signer: signing.SignerIdentity,
    ) Error!Ledger {
        const workspace_record = storage.findWorkspace(owner, state_workspace_label) orelse
            storage.findWorkspaceByLabel(state_workspace_label) orelse
            try storage.createWorkspace(.{
                .owner = owner,
                .label = state_workspace_label,
            });

        var ledger = Ledger{
            .storage = storage,
            .owner = owner,
            .state_signer = state_signer,
            .workspace_id = workspace_record.id,
        };

        if (storage.resolve(workspace_record.id, state_entry_path)) |_| {
            try ledger.loadPersistedEvents();
            ledger.loaded_existing_state = true;
        } else |err| switch (err) {
            error.EntryNotFound => {},
            else => return err,
        }

        return ledger;
    }

    pub fn recordPermissionDecision(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        permission_kind: manifest.PermissionKind,
        allowed: bool,
        denial_reason: abi.DenialReason,
        tick: u64,
        detail: []const u8,
        protected: bool,
    ) Error!void {
        const explanation = if (allowed)
            denial_explanation.none()
        else
            denial_explanation.forPermissionDecision(permission_kind, denial_reason);
        try self.append(.{
            .kind = .permission_decision,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .permission_kind = permission_kind,
            .allowed = allowed,
            .denial_reason = denial_reason,
            .user_approval_can_resolve = explanation.user_approval_can_resolve,
            .retry_safe = explanation.retry_safe,
            .policy_label_len = clampedExplanationLen(explanation.policySlice()),
            .policy_label = copyExplanationTextInto(explanation.policySlice()),
            .missing_capability_len = clampedExplanationLen(explanation.missingCapabilitySlice()),
            .missing_capability = copyExplanationTextInto(explanation.missingCapabilitySlice()),
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
        slot_index: usize,
        failure: immutable_base.HealthFailure,
        rolled_back: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .update_transition,
            .tick = tick,
            .subject = subject,
            .related_id = slot_index,
            .detail_code = @intFromEnum(failure),
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
                if (!event.allowed) {
                    try appendFmt(buffer, &used, " denial={s} policy={s} missing={s} approval={s} retry_safe={s}", .{
                        @tagName(event.denial_reason),
                        event.policyLabelSlice(),
                        event.missingCapabilitySlice(),
                        yesNo(event.user_approval_can_resolve),
                        yesNo(event.retry_safe),
                    });
                }
            }
            switch (event.kind) {
                .update_transition => {
                    try appendFmt(buffer, &used, " slot={d} rollback={s} failure={s}", .{
                        event.related_id,
                        yesNo(!event.allowed),
                        updateFailureLabel(event.detail_code),
                    });
                },
                .device_trust_change => {
                    try appendFmt(buffer, &used, " device={d} trusted={s}", .{
                        event.related_id,
                        yesNo(event.allowed),
                    });
                },
                else => {},
            }
            if (event.workspace_id != 0) {
                try appendFmt(buffer, &used, " workspace={d}", .{event.workspace_id});
            }
            if (event.related_id != 0 and event.kind != .update_transition and event.kind != .device_trust_change) {
                try appendFmt(buffer, &used, " related={d}", .{event.related_id});
            }
            if (event.detail_code != 0 and event.kind != .update_transition) {
                try appendFmt(buffer, &used, " code={d}", .{event.detail_code});
            }
            if (event.kind == .process_crash or event.kind == .driver_restart) {
                try appendFmt(buffer, &used, " service={s}", .{@tagName(event.service_class)});
            }
            try appendFmt(buffer, &used, " detail={s}\n", .{detail});
        }
        return buffer[0..used];
    }

    pub fn absorb(self: *Ledger, source: *const Ledger) Error!void {
        for (source.events) |slot| {
            if (!slot.in_use) continue;
            var event = slot.event;
            event.sequence = 0;
            try self.append(event);
        }
    }

    fn append(self: *Ledger, event: Event) Error!void {
        for (&self.events) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.event = event;
            slot.event.sequence = self.next_sequence;
            self.next_sequence += 1;
            try self.persist(event.tick);
            return;
        }
        return error.EventTableFull;
    }

    fn persist(self: *Ledger, tick: u64) Error!void {
        const storage = self.storage orelse return;
        var recent: [MAX_PERSISTED_EVENTS]PersistentEvent = [_]PersistentEvent{zeroPersistentEvent()} ** MAX_PERSISTED_EVENTS;
        const recent_events = self.recentEventsForPersistence(&recent);

        var header = PersistentHeader{ .next_sequence = self.next_sequence };
        const header_payload = std.mem.asBytes(&header);
        const existing_header = storage.resolve(self.workspace_id, state_entry_path) catch |err| switch (err) {
            error.EntryNotFound => null,
            else => return err,
        };

        try storage.beginTransaction(self.workspace_id);
        const existing_entries = storage.entries(self.workspace_id) catch &.{};

        var persisted_paths: [MAX_PERSISTED_EVENTS][workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
        var persisted_path_lens: [MAX_PERSISTED_EVENTS]usize = [_]usize{0} ** MAX_PERSISTED_EVENTS;
        for (recent_events, 0..) |event, index| {
            persisted_path_lens[index] = try writeEventEntryPath(&persisted_paths[index], event.sequence);
        }

        for (existing_entries) |entry| {
            if (!std.mem.startsWith(u8, entry.pathSlice(), event_entry_prefix)) continue;
            var keep_entry = false;
            for (persisted_path_lens, 0..) |path_len, index| {
                if (path_len == 0) continue;
                if (std.mem.eql(u8, entry.pathSlice(), persisted_paths[index][0..path_len])) {
                    keep_entry = true;
                    break;
                }
            }
            if (!keep_entry) try storage.stageDelete(self.workspace_id, entry.pathSlice());
        }

        const header_result = try storage.putVersion(.{
            .preferred_object_id = stateObjectId(),
            .object_type = .document,
            .payload = header_payload,
            .metadata = try object_store.signMetadata(
                self.state_signer,
                "event-ledger-state",
                "application/zigos-event-ledger",
                .document,
                header_payload,
                tick,
            ),
            .parent_version_id = if (existing_header) |entry| entry.version_id else null,
        });
        try storage.stagePut(self.workspace_id, state_entry_path, header_result.object_id, header_result.version_id, .document);

        for (recent_events, 0..) |event, index| {
            const path = persisted_paths[index][0..persisted_path_lens[index]];
            const existing_event = storage.resolve(self.workspace_id, path) catch |err| switch (err) {
                error.EntryNotFound => null,
                else => return err,
            };
            if (existing_event != null) continue;

            var payload_record = PersistentEventRecord.fromEvent(event);
            const payload = std.mem.asBytes(&payload_record);
            const result = try storage.putVersion(.{
                .preferred_object_id = eventObjectId(event.sequence),
                .object_type = .document,
                .payload = payload,
                .metadata = try object_store.signMetadata(
                    self.state_signer,
                    "event-ledger-entry",
                    "application/zigos-event-ledger-entry",
                    .document,
                    payload,
                    tick,
                ),
                .parent_version_id = if (existing_event) |entry| entry.version_id else null,
            });
            try storage.stagePut(self.workspace_id, path, result.object_id, result.version_id, .document);
        }

        _ = try storage.commit(self.workspace_id, tick);
    }

    fn loadPersistedEvents(self: *Ledger) Error!void {
        const storage = self.storage orelse return;
        self.events = [_]EventSlot{EventSlot{}} ** MAX_EVENTS;
        self.next_sequence = 1;

        if (storage.resolve(self.workspace_id, state_entry_path)) |entry| {
            const version = storage.store.version(entry.version_id) orelse return error.CorruptState;
            self.next_sequence = try parseHeader(version.payloadSlice());
        } else |err| switch (err) {
            error.EntryNotFound => return,
            else => return err,
        }

        const entries = try storage.entries(self.workspace_id);
        var loaded_count: usize = 0;
        for (entries) |entry| {
            if (!std.mem.startsWith(u8, entry.pathSlice(), event_entry_prefix)) continue;
            if (loaded_count >= self.events.len) break;
            const version = storage.store.version(entry.version_id) orelse return error.CorruptState;
            self.events[loaded_count].in_use = true;
            self.events[loaded_count].event = (try parsePersistentEvent(version.payloadSlice())).intoEvent();
            loaded_count += 1;
        }

        var index: usize = 1;
        while (index < loaded_count) : (index += 1) {
            var cursor = index;
            while (cursor > 0 and self.events[cursor - 1].event.sequence > self.events[cursor].event.sequence) : (cursor -= 1) {
                const tmp = self.events[cursor - 1];
                self.events[cursor - 1] = self.events[cursor];
                self.events[cursor] = tmp;
            }
        }

        if (loaded_count > 0 and self.next_sequence <= self.events[loaded_count - 1].event.sequence) {
            self.next_sequence = self.events[loaded_count - 1].event.sequence + 1;
        }
    }

    fn recentEventsForPersistence(
        self: *const Ledger,
        buffer: *[MAX_PERSISTED_EVENTS]PersistentEvent,
    ) []const PersistentEvent {
        var total_in_use: usize = 0;
        for (self.events) |slot| {
            if (slot.in_use) total_in_use += 1;
        }

        const keep = @min(total_in_use, MAX_PERSISTED_EVENTS);
        var start = total_in_use - keep;
        var write_index: usize = 0;
        for (self.events) |slot| {
            if (!slot.in_use) continue;
            if (start != 0) {
                start -= 1;
                continue;
            }
            buffer[write_index] = PersistentEvent.fromEvent(slot.event);
            write_index += 1;
        }
        return buffer[0..write_index];
    }
};

const PersistentEvent = struct {
    sequence: u64 = 0,
    kind: EventKind = .permission_decision,
    tick: u64 = 0,
    subject: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    task_id: u64 = 0,
    workspace_id: u64 = 0,
    related_id: u64 = 0,
    detail_code: u32 = 0,
    service_class: contract.ServiceClass = .task_runtime,
    permission_kind: ?manifest.PermissionKind = null,
    allowed: bool = false,
    denial_reason: abi.DenialReason = .none,
    user_approval_can_resolve: bool = false,
    retry_safe: bool = false,
    detail_protected: bool = false,
    policy_label_len: usize = 0,
    policy_label: [MAX_PERSISTED_LABEL_BYTES]u8 = [_]u8{0} ** MAX_PERSISTED_LABEL_BYTES,
    missing_capability_len: usize = 0,
    missing_capability: [MAX_PERSISTED_LABEL_BYTES]u8 = [_]u8{0} ** MAX_PERSISTED_LABEL_BYTES,
    detail_len: usize = 0,
    detail: [MAX_PERSISTED_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_PERSISTED_DETAIL_BYTES,

    fn fromEvent(event: Event) PersistentEvent {
        var persisted = zeroPersistentEvent();
        persisted.sequence = event.sequence;
        persisted.kind = event.kind;
        persisted.tick = event.tick;
        persisted.subject = event.subject;
        persisted.task_id = event.task_id;
        persisted.workspace_id = event.workspace_id;
        persisted.related_id = event.related_id;
        persisted.detail_code = event.detail_code;
        persisted.service_class = event.service_class;
        persisted.permission_kind = event.permission_kind;
        persisted.allowed = event.allowed;
        persisted.denial_reason = event.denial_reason;
        persisted.user_approval_can_resolve = event.user_approval_can_resolve;
        persisted.retry_safe = event.retry_safe;
        persisted.detail_protected = event.detail_protected;
        persisted.policy_label_len = copyText(&persisted.policy_label, event.policyLabelSlice());
        persisted.missing_capability_len = copyText(&persisted.missing_capability, event.missingCapabilitySlice());
        persisted.detail_len = copyText(&persisted.detail, event.detailSlice());
        return persisted;
    }

    fn intoEvent(self: PersistentEvent) Event {
        var event = zeroEvent();
        event.sequence = self.sequence;
        event.kind = self.kind;
        event.tick = self.tick;
        event.subject = self.subject;
        event.task_id = self.task_id;
        event.workspace_id = self.workspace_id;
        event.related_id = self.related_id;
        event.detail_code = self.detail_code;
        event.service_class = self.service_class;
        event.permission_kind = self.permission_kind;
        event.allowed = self.allowed;
        event.denial_reason = self.denial_reason;
        event.user_approval_can_resolve = self.user_approval_can_resolve;
        event.retry_safe = self.retry_safe;
        event.detail_protected = self.detail_protected;
        event.policy_label_len = copyText(&event.policy_label, self.policy_label[0..self.policy_label_len]);
        event.missing_capability_len = copyText(&event.missing_capability, self.missing_capability[0..self.missing_capability_len]);
        event.detail_len = copyText(&event.detail, self.detail[0..self.detail_len]);
        return event;
    }
};

const PersistentEventRecord = extern struct {
    sequence: u64 = 0,
    kind: u8 = 0,
    subject_kind: u8 = 0,
    service_class: u8 = 0,
    permission_kind: u8 = permission_kind_none,
    denial_reason: u16 = 0,
    flags: u8 = 0,
    policy_label_len: u8 = 0,
    missing_capability_len: u8 = 0,
    detail_len: u8 = 0,
    _reserved: [6]u8 = [_]u8{0} ** 6,
    tick: u64 = 0,
    subject_serial: u64 = 0,
    task_id: u64 = 0,
    workspace_id: u64 = 0,
    related_id: u64 = 0,
    detail_code: u32 = 0,
    _tail_reserved: [4]u8 = [_]u8{0} ** 4,
    policy_label: [MAX_PERSISTED_LABEL_BYTES]u8 = [_]u8{0} ** MAX_PERSISTED_LABEL_BYTES,
    missing_capability: [MAX_PERSISTED_LABEL_BYTES]u8 = [_]u8{0} ** MAX_PERSISTED_LABEL_BYTES,
    detail: [MAX_PERSISTED_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_PERSISTED_DETAIL_BYTES,

    fn fromEvent(event: PersistentEvent) PersistentEventRecord {
        var record = PersistentEventRecord{
            .sequence = event.sequence,
            .kind = @intFromEnum(event.kind),
            .subject_kind = @intFromEnum(event.subject.kind),
            .service_class = @intFromEnum(event.service_class),
            .permission_kind = if (event.permission_kind) |permission_kind| @intFromEnum(permission_kind) else permission_kind_none,
            .denial_reason = @intFromEnum(event.denial_reason),
            .tick = event.tick,
            .subject_serial = event.subject.serial,
            .task_id = event.task_id,
            .workspace_id = event.workspace_id,
            .related_id = event.related_id,
            .detail_code = event.detail_code,
            .policy_label_len = @intCast(event.policy_label_len),
            .missing_capability_len = @intCast(event.missing_capability_len),
            .detail_len = @intCast(event.detail_len),
            .policy_label = event.policy_label,
            .missing_capability = event.missing_capability,
            .detail = event.detail,
        };
        if (event.allowed) record.flags |= 1 << 0;
        if (event.user_approval_can_resolve) record.flags |= 1 << 1;
        if (event.retry_safe) record.flags |= 1 << 2;
        if (event.detail_protected) record.flags |= 1 << 3;
        return record;
    }

    fn intoEvent(self: PersistentEventRecord) Error!PersistentEvent {
        var event = zeroPersistentEvent();
        event.sequence = self.sequence;
        event.kind = std.meta.intToEnum(EventKind, self.kind) catch return error.CorruptState;
        event.tick = self.tick;
        event.subject = .{
            .kind = std.meta.intToEnum(principal.PrincipalKind, self.subject_kind) catch return error.CorruptState,
            .serial = self.subject_serial,
        };
        event.task_id = self.task_id;
        event.workspace_id = self.workspace_id;
        event.related_id = self.related_id;
        event.detail_code = self.detail_code;
        event.service_class = std.meta.intToEnum(contract.ServiceClass, self.service_class) catch return error.CorruptState;
        event.permission_kind = if (self.permission_kind == permission_kind_none)
            null
        else
            (std.meta.intToEnum(manifest.PermissionKind, self.permission_kind) catch return error.CorruptState);
        event.allowed = (self.flags & (1 << 0)) != 0;
        event.denial_reason = std.meta.intToEnum(abi.DenialReason, self.denial_reason) catch return error.CorruptState;
        event.user_approval_can_resolve = (self.flags & (1 << 1)) != 0;
        event.retry_safe = (self.flags & (1 << 2)) != 0;
        event.detail_protected = (self.flags & (1 << 3)) != 0;
        event.policy_label_len = @min(@as(usize, self.policy_label_len), MAX_PERSISTED_LABEL_BYTES);
        event.missing_capability_len = @min(@as(usize, self.missing_capability_len), MAX_PERSISTED_LABEL_BYTES);
        event.detail_len = @min(@as(usize, self.detail_len), MAX_PERSISTED_DETAIL_BYTES);
        event.policy_label = self.policy_label;
        event.missing_capability = self.missing_capability;
        event.detail = self.detail;
        return event;
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

fn zeroPersistentEvent() PersistentEvent {
    return .{};
}

fn clampedDetailLen(src: []const u8) usize {
    return @min(src.len, MAX_DETAIL_BYTES);
}

fn clampedExplanationLen(src: []const u8) usize {
    return @min(src.len, denial_explanation.MAX_LABEL_BYTES);
}

fn copyTextInto(src: []const u8) [MAX_DETAIL_BYTES]u8 {
    var out = [_]u8{0} ** MAX_DETAIL_BYTES;
    _ = copyText(&out, src);
    return out;
}

fn copyExplanationTextInto(src: []const u8) [denial_explanation.MAX_LABEL_BYTES]u8 {
    var out = [_]u8{0} ** denial_explanation.MAX_LABEL_BYTES;
    _ = copyText(&out, src);
    return out;
}

fn yesNo(value: bool) []const u8 {
    return if (value) "yes" else "no";
}

fn updateFailureLabel(code: u32) []const u8 {
    const failure = std.meta.intToEnum(immutable_base.HealthFailure, @as(u8, @intCast(code))) catch return "corrupt";
    return @tagName(failure);
}

fn appendFmt(buffer: []u8, used: *usize, comptime fmt: []const u8, args: anytype) Error!void {
    const rendered = std.fmt.bufPrint(buffer[used.*..], fmt, args) catch return error.NoSpaceLeft;
    used.* += rendered.len;
}

fn stateObjectId() u64 {
    return native_util.fnv1a64WithSeed(0xED6E7EEC0D000001, "phase6:event-ledger:state");
}

fn eventObjectId(sequence: u64) u64 {
    const slot_index = @as(usize, @intCast((sequence - 1) % MAX_PERSISTED_EVENTS));
    return native_util.fnv1a64WithSeed(
        0xED6E7EEC0D000101 + @as(u64, @intCast(slot_index)),
        "phase6:event-ledger:event-slot",
    );
}

fn parseHeader(payload: []const u8) Error!u64 {
    if (payload.len != @sizeOf(PersistentHeader)) return error.CorruptState;
    var header = std.mem.zeroes(PersistentHeader);
    @memcpy(std.mem.asBytes(&header), payload);
    if (header.magic != persistent_header_magic) return error.CorruptState;
    return header.next_sequence;
}

fn parsePersistentEvent(payload: []const u8) Error!PersistentEvent {
    if (payload.len != @sizeOf(PersistentEventRecord)) return error.CorruptState;
    var record = std.mem.zeroes(PersistentEventRecord);
    @memcpy(std.mem.asBytes(&record), payload);
    return record.intoEvent();
}

fn writeEventEntryPath(buffer: []u8, sequence: u64) Error!usize {
    const path = std.fmt.bufPrint(buffer, "{s}{d}", .{ event_entry_prefix, sequence }) catch return error.NoSpaceLeft;
    return path.len;
}

test "event ledger exports structured redacted diagnostics and audit history" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 7 };
    const service_subject = principal.PrincipalId{ .kind = .service, .serial = 9 };
    const device_subject = principal.PrincipalId{ .kind = .device, .serial = 42 };

    try ledger.recordPermissionDecision(user, 11, .screen_capture, false, .policy_denied, 20, "org policy denied capture", true);
    try ledger.recordProcessCrash(.network_stack, service_subject, 21, 5001, "segfault");
    try ledger.recordDriverRestart(.media_print_helpers, service_subject, 88, 22, "audio-print restarted");
    try ledger.recordUpdateTransition(service_subject, 1, .boot, true, 23, "rolled back to stable-a");
    try ledger.recordSyncConflict(user, 5, 24, "documents/tax-return.pdf conflict", true);
    try ledger.recordDeviceTrustChange(user, device_subject, false, 25, "device revoked");

    var buffer: [2048]u8 = undefined;
    const exported = try ledger.exportText(&buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "service=network_stack") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "slot=1 rollback=yes failure=boot") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "device=42 trusted=no") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "policy=user-grant-policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "approval=yes") != null);

    const full = try ledger.exportText(&buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "tax-return.pdf") != null);
    try std.testing.expectEqual(EventKind.device_trust_change, ledger.latestKind(.device_trust_change).?.kind);
}

test "event ledger persists history across restart" {
    storage_service.Service.resetPersistentState();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 44 };
    const signer = signing.SignerIdentity{
        .label = "diagnostic-ledger",
        .seed = [_]u8{0xA7} ** 32,
    };

    var storage = storage_service.Service.init(901, 300, owner);
    var ledger = try Ledger.initPersistent(&storage, owner, signer);
    try ledger.recordUpdateTransition(owner, 1, .none, false, 10, "stable-b activated");
    try ledger.recordDeviceTrustChange(owner, .{ .kind = .device, .serial = 4 }, false, 11, "device revoked");

    var restarted_storage = storage_service.Service.init(901, 301, owner);
    var restarted = try Ledger.initPersistent(&restarted_storage, owner, signer);
    try std.testing.expect(restarted.loaded_existing_state);
    try std.testing.expectEqual(EventKind.device_trust_change, restarted.latestKind(.device_trust_change).?.kind);

    var buffer: [1024]u8 = undefined;
    const exported = try restarted.exportText(&buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=update_transition") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=device_trust_change") != null);

    storage_service.Service.resetPersistentState();
}

test "event ledger persistence retains full in-memory history and detail payloads" {
    storage_service.Service.resetPersistentState();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 45 };
    const signer = signing.SignerIdentity{
        .label = "diagnostic-ledger-bounded",
        .seed = [_]u8{0xA8} ** 32,
    };

    var storage = storage_service.Service.init(902, 302, owner);
    var ledger = try Ledger.initPersistent(&storage, owner, signer);

    var tick: u64 = 10;
    while (tick < 18) : (tick += 1) {
        var detail_buffer: [96]u8 = undefined;
        const detail = try std.fmt.bufPrint(&detail_buffer, "event-{d}-detail-abcdefghijklmnopqrstuvwxyz-0123456789", .{tick});
        try ledger.recordUpdateTransition(
            owner,
            @as(usize, @intCast(tick % 2)),
            if ((tick % 2) == 0) .storage else .none,
            (tick % 2) == 0,
            tick,
            detail,
        );
    }

    try std.testing.expectEqual(@as(usize, 9), storage.store.objectCount());

    var restarted_storage = storage_service.Service.init(902, 303, owner);
    var restarted = try Ledger.initPersistent(&restarted_storage, owner, signer);
    try std.testing.expectEqual(@as(u64, 9), restarted.next_sequence);

    var buffer: [2048]u8 = undefined;
    const exported = try restarted.exportText(&buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "#1 ") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "#8 ") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "abcdefghijklmnopqrstuvwxyz-0123456789") != null);

    storage_service.Service.resetPersistentState();
}
