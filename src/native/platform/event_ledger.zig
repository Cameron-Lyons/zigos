const std = @import("std");
const abi = @import("../core/abi.zig");
const contract = @import("../session/contract.zig");
const denial_explanation = @import("../policy/denial_explanation.zig");
const immutable_base = @import("immutable_base.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const native_ux = @import("native_ux.zig");
const notification_center = @import("../services/notification_center.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const workspace = @import("../storage/workspace.zig");
const copyText = native_util.copyText;
const yesNo = native_util.yesNo;

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
    permission_review,
    capability_grant,
    capability_revocation,
    notification,
    task_flow,
};

pub const ExportOptions = struct {
    include_protected_content: bool = false,
};

pub const Query = struct {
    kind: ?EventKind = null,
    subject: ?principal.PrincipalId = null,
    task_id: ?u64 = null,
    workspace_id: ?u64 = null,
    include_protected_content: bool = false,
};

pub const RemoteShareOptions = struct {
    include_protected_content: bool = false,
    personal_device: bool = true,
    user_opted_in: bool = false,
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

pub const Error = object_store.Error || workspace.Error || error{
    ConsentRequired,
    CorruptState,
    EventTableFull,
    NoSpaceLeft,
    SigningFailed,
};

const EventSlot = struct {
    in_use: bool = false,
    event: Event = zeroEvent(),
};

const event_kind_count = std.meta.fields(EventKind).len;
const no_event_index = std.math.maxInt(usize);

const IndexList = struct {
    head: usize = no_event_index,
    tail: usize = no_event_index,
    count: usize = 0,

    fn append(self: *IndexList, links: *[MAX_EVENTS]usize, event_index: usize) void {
        links[event_index] = no_event_index;
        if (self.tail == no_event_index) {
            self.head = event_index;
        } else {
            links[self.tail] = event_index;
        }
        self.tail = event_index;
        self.count += 1;
    }
};

const SubjectIndexSlot = struct {
    in_use: bool = false,
    subject: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    list: IndexList = .{},
};

const TaskIndexSlot = struct {
    in_use: bool = false,
    task_id: u64 = 0,
    list: IndexList = .{},
};

const QueryIndex = enum {
    kind,
    subject,
    task,
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
    header_version_id: u64 = 0,
    next_sequence: u64 = 1,
    events: [MAX_EVENTS]EventSlot = [_]EventSlot{EventSlot{}} ** MAX_EVENTS,
    kind_index: [event_kind_count]IndexList = [_]IndexList{IndexList{}} ** event_kind_count,
    subject_index: [MAX_EVENTS]SubjectIndexSlot = [_]SubjectIndexSlot{SubjectIndexSlot{}} ** MAX_EVENTS,
    task_index: [MAX_EVENTS]TaskIndexSlot = [_]TaskIndexSlot{TaskIndexSlot{}} ** MAX_EVENTS,
    next_by_kind: [MAX_EVENTS]usize = [_]usize{no_event_index} ** MAX_EVENTS,
    next_by_subject: [MAX_EVENTS]usize = [_]usize{no_event_index} ** MAX_EVENTS,
    next_by_task: [MAX_EVENTS]usize = [_]usize{no_event_index} ** MAX_EVENTS,
    persistence_batch_depth: usize = 0,
    pending_persist_first_sequence: u64 = 0,
    pending_persist_count: usize = 0,
    pending_persist_latest_tick: u64 = 0,

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

    pub fn beginPersistenceBatch(self: *Ledger) void {
        self.persistence_batch_depth += 1;
    }

    pub fn flushPersistenceBatch(self: *Ledger) Error!void {
        if (self.persistence_batch_depth != 0) self.persistence_batch_depth -= 1;
        if (self.persistence_batch_depth != 0 or self.pending_persist_count == 0) return;

        const first_sequence = self.pending_persist_first_sequence;
        const latest_sequence = first_sequence + @as(u64, @intCast(self.pending_persist_count)) - 1;
        try self.persistRange(first_sequence, latest_sequence, self.pending_persist_latest_tick);
        self.clearPendingPersistence();
    }

    pub fn pendingPersistenceCount(self: *const Ledger) usize {
        return self.pending_persist_count;
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

    pub fn recordPermissionReview(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        permission_kind: manifest.PermissionKind,
        approved: bool,
        tick: u64,
        detail: []const u8,
        protected: bool,
    ) Error!void {
        try self.append(.{
            .kind = .permission_review,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .permission_kind = permission_kind,
            .allowed = approved,
            .detail_protected = protected,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordCapabilityGrant(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        capability_id: u64,
        permission_kind: ?manifest.PermissionKind,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .capability_grant,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = capability_id,
            .permission_kind = permission_kind,
            .allowed = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordCapabilityRevocation(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        capability_id: u64,
        permission_kind: ?manifest.PermissionKind,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .capability_revocation,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = capability_id,
            .permission_kind = permission_kind,
            .allowed = false,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordNotification(
        self: *Ledger,
        notification: notification_center.Notification,
        tick: u64,
    ) Error!void {
        try self.append(.{
            .kind = .notification,
            .tick = tick,
            .subject = notification.source,
            .task_id = notification.task_id orelse 0,
            .related_id = notification.id,
            .detail_code = @intFromEnum(notification.reason),
            .allowed = !notification.suppressed,
            .detail_len = clampedDetailLen(notification.detailSlice()),
            .detail = copyTextInto(notification.detailSlice()),
        });
    }

    pub fn recordTaskFlow(
        self: *Ledger,
        flow: native_ux.FlowRecord,
        tick: u64,
    ) Error!void {
        try self.append(.{
            .kind = .task_flow,
            .tick = tick,
            .subject = flow.subject,
            .task_id = flow.task_id,
            .workspace_id = flow.workspace_id,
            .related_id = flow.id,
            .detail_code = @intFromEnum(flow.kind),
            .permission_kind = if (flow.kind == .review_permission_request) flow.permission_kind else null,
            .allowed = flow.approved,
            .detail_len = clampedDetailLen(flow.detailSlice()),
            .detail = copyTextInto(flow.detailSlice()),
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
        const list = self.kind_index[kindIndex(kind)];
        if (list.tail == no_event_index) return null;
        return self.events[list.tail].event;
    }

    pub fn queryEvents(self: *const Ledger, query: Query, output: []Event) []Event {
        var count: usize = 0;
        self.visitMatching(query, output.len, &count, output);
        return output[0..count];
    }

    pub fn countMatching(self: *const Ledger, query: Query) usize {
        var count: usize = 0;
        self.visitMatching(query, std.math.maxInt(usize), &count, null);
        return count;
    }

    pub fn exportText(self: *const Ledger, buffer: []u8, options: ExportOptions) Error![]const u8 {
        var used: usize = 0;
        var records: [MAX_EVENTS]Event = undefined;
        const events = self.queryEvents(.{
            .include_protected_content = options.include_protected_content,
        }, &records);
        for (events) |event| try renderTextEvent(event, buffer, &used);
        return buffer[0..used];
    }

    pub fn exportRemoteShare(
        self: *const Ledger,
        buffer: []u8,
        options: RemoteShareOptions,
    ) Error![]const u8 {
        if (options.personal_device and !options.user_opted_in) return error.ConsentRequired;
        return self.exportText(buffer, .{
            .include_protected_content = options.include_protected_content,
        });
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
        for (&self.events, 0..) |*slot, index| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.event = event;
            slot.event.sequence = self.next_sequence;
            self.next_sequence += 1;
            self.indexEvent(index) catch |err| {
                slot.* = EventSlot{};
                try self.rebuildIndexes();
                return err;
            };
            if (self.persistence_batch_depth == 0) {
                try self.persistRange(slot.event.sequence, slot.event.sequence, slot.event.tick);
            } else {
                self.markPendingPersistence(slot.event);
            }
            return;
        }
        return error.EventTableFull;
    }

    fn visitMatching(
        self: *const Ledger,
        query: Query,
        limit: usize,
        count: *usize,
        output: ?[]Event,
    ) void {
        var selected_index: ?QueryIndex = null;
        var selected_count: usize = std.math.maxInt(usize);
        if (query.kind) |kind| {
            selected_index = .kind;
            selected_count = self.kind_index[kindIndex(kind)].count;
        }
        if (query.subject) |subject| {
            if (self.findSubjectIndex(subject)) |index| {
                const candidate_count = self.subject_index[index].list.count;
                if (candidate_count < selected_count) {
                    selected_index = .subject;
                    selected_count = candidate_count;
                }
            } else {
                return;
            }
        }
        if (query.task_id) |task_id| {
            if (self.findTaskIndex(task_id)) |index| {
                const candidate_count = self.task_index[index].list.count;
                if (candidate_count < selected_count) {
                    selected_index = .task;
                    selected_count = candidate_count;
                }
            } else {
                return;
            }
        }
        if (selected_index) |index_kind| {
            switch (index_kind) {
                .kind => self.visitIndex(self.kind_index[kindIndex(query.kind.?)].head, &self.next_by_kind, query, limit, count, output),
                .subject => self.visitIndex(self.subject_index[self.findSubjectIndex(query.subject.?).?].list.head, &self.next_by_subject, query, limit, count, output),
                .task => self.visitIndex(self.task_index[self.findTaskIndex(query.task_id.?).?].list.head, &self.next_by_task, query, limit, count, output),
            }
            return;
        }

        for (self.events) |slot| {
            if (!slot.in_use) continue;
            if (!matchesQuery(slot.event, query)) continue;
            if (count.* >= limit) break;
            if (output) |records| records[count.*] = redactedForQuery(slot.event, query);
            count.* += 1;
        }
    }

    fn visitIndex(
        self: *const Ledger,
        head: usize,
        links: *const [MAX_EVENTS]usize,
        query: Query,
        limit: usize,
        count: *usize,
        output: ?[]Event,
    ) void {
        var cursor = head;
        while (cursor != no_event_index and count.* < limit) : (cursor = links[cursor]) {
            const slot = self.events[cursor];
            if (!slot.in_use or !matchesQuery(slot.event, query)) continue;
            if (output) |records| records[count.*] = redactedForQuery(slot.event, query);
            count.* += 1;
        }
    }

    fn indexEvent(self: *Ledger, event_index: usize) Error!void {
        const event = self.events[event_index].event;
        self.kind_index[kindIndex(event.kind)].append(&self.next_by_kind, event_index);
        try self.indexSubject(event.subject, event_index);
        if (event.task_id != 0) try self.indexTask(event.task_id, event_index);
    }

    fn indexSubject(self: *Ledger, subject: principal.PrincipalId, event_index: usize) Error!void {
        const slot_index = self.findOrCreateSubjectIndex(subject) orelse return error.EventTableFull;
        self.subject_index[slot_index].list.append(&self.next_by_subject, event_index);
    }

    fn indexTask(self: *Ledger, task_id: u64, event_index: usize) Error!void {
        const slot_index = self.findOrCreateTaskIndex(task_id) orelse return error.EventTableFull;
        self.task_index[slot_index].list.append(&self.next_by_task, event_index);
    }

    fn findSubjectIndex(self: *const Ledger, subject: principal.PrincipalId) ?usize {
        for (self.subject_index, 0..) |slot, index| {
            if (slot.in_use and slot.subject.eql(subject)) return index;
        }
        return null;
    }

    fn findTaskIndex(self: *const Ledger, task_id: u64) ?usize {
        for (self.task_index, 0..) |slot, index| {
            if (slot.in_use and slot.task_id == task_id) return index;
        }
        return null;
    }

    fn findOrCreateSubjectIndex(self: *Ledger, subject: principal.PrincipalId) ?usize {
        if (self.findSubjectIndex(subject)) |index| return index;
        for (&self.subject_index, 0..) |*slot, index| {
            if (slot.in_use) continue;
            slot.* = .{ .in_use = true, .subject = subject };
            return index;
        }
        return null;
    }

    fn findOrCreateTaskIndex(self: *Ledger, task_id: u64) ?usize {
        if (self.findTaskIndex(task_id)) |index| return index;
        for (&self.task_index, 0..) |*slot, index| {
            if (slot.in_use) continue;
            slot.* = .{ .in_use = true, .task_id = task_id };
            return index;
        }
        return null;
    }

    fn rebuildIndexes(self: *Ledger) Error!void {
        self.kind_index = [_]IndexList{IndexList{}} ** event_kind_count;
        self.subject_index = [_]SubjectIndexSlot{SubjectIndexSlot{}} ** MAX_EVENTS;
        self.task_index = [_]TaskIndexSlot{TaskIndexSlot{}} ** MAX_EVENTS;
        self.next_by_kind = [_]usize{no_event_index} ** MAX_EVENTS;
        self.next_by_subject = [_]usize{no_event_index} ** MAX_EVENTS;
        self.next_by_task = [_]usize{no_event_index} ** MAX_EVENTS;
        for (self.events, 0..) |slot, index| {
            if (!slot.in_use) continue;
            try self.indexEvent(index);
        }
    }

    fn markPendingPersistence(self: *Ledger, event: Event) void {
        if (self.storage == null) return;
        if (self.pending_persist_count == 0) {
            self.pending_persist_first_sequence = event.sequence;
        }
        self.pending_persist_count += 1;
        self.pending_persist_latest_tick = event.tick;
    }

    fn clearPendingPersistence(self: *Ledger) void {
        self.pending_persist_first_sequence = 0;
        self.pending_persist_count = 0;
        self.pending_persist_latest_tick = 0;
    }

    fn findEventBySequence(self: *const Ledger, sequence: u64) ?Event {
        for (self.events) |slot| {
            if (slot.in_use and slot.event.sequence == sequence) return slot.event;
        }
        return null;
    }

    fn persistRange(self: *Ledger, first_sequence: u64, latest_sequence: u64, latest_tick: u64) Error!void {
        const storage = self.storage orelse return;
        var header = PersistentHeader{ .next_sequence = self.next_sequence };
        const header_payload = std.mem.asBytes(&header);
        const previous_header_version_id = if (self.header_version_id != 0)
            self.header_version_id
        else blk: {
            const existing_header = storage.resolve(self.workspace_id, state_entry_path) catch |err| switch (err) {
                error.EntryNotFound => break :blk 0,
                else => return err,
            };
            break :blk existing_header.version_id;
        };

        try storage.beginTransaction(self.workspace_id);
        var expired_sequence = first_sequence;
        while (expired_sequence <= latest_sequence) : (expired_sequence += 1) {
            if (expired_sequence <= MAX_PERSISTED_EVENTS) continue;
            var expired_path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
            const expired_path = expired_path_buffer[0..try writeEventEntryPath(
                &expired_path_buffer,
                expired_sequence - MAX_PERSISTED_EVENTS,
            )];
            storage.stageDelete(self.workspace_id, expired_path) catch |err| switch (err) {
                error.EntryNotFound => {},
                else => return err,
            };
        }

        const header_result = try storage.putVersion(.{
            .preferred_object_id = stateObjectId(),
            .object_type = .document,
            .payload = header_payload,
            .metadata = try signLedgerMetadata(
                self.state_signer,
                "event-ledger-state",
                "application/zigos-event-ledger",
                .document,
                header_payload,
                latest_tick,
            ),
            .parent_version_id = if (previous_header_version_id != 0) previous_header_version_id else null,
        });
        try storage.stagePut(self.workspace_id, state_entry_path, header_result.object_id, header_result.version_id, .document);
        self.header_version_id = header_result.version_id;

        var sequence = first_sequence;
        while (sequence <= latest_sequence) : (sequence += 1) {
            const event = self.findEventBySequence(sequence) orelse return error.CorruptState;
            var event_path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
            const event_path = event_path_buffer[0..try writeEventEntryPath(&event_path_buffer, event.sequence)];
            var payload_record = PersistentEventRecord.fromEvent(PersistentEvent.fromEvent(event));
            const payload = std.mem.asBytes(&payload_record);
            const result = try storage.putVersion(.{
                .preferred_object_id = eventObjectId(event.sequence),
                .object_type = .document,
                .payload = payload,
                .metadata = try signLedgerMetadata(
                    self.state_signer,
                    "event-ledger-entry",
                    "application/zigos-event-ledger-entry",
                    .document,
                    payload,
                    event.tick,
                ),
                .parent_version_id = null,
            });
            try storage.stagePut(self.workspace_id, event_path, result.object_id, result.version_id, .document);
        }

        _ = try storage.commit(self.workspace_id, latest_tick);
    }

    fn loadPersistedEvents(self: *Ledger) Error!void {
        const storage = self.storage orelse return;
        self.events = [_]EventSlot{EventSlot{}} ** MAX_EVENTS;
        try self.rebuildIndexes();
        self.next_sequence = 1;
        self.header_version_id = 0;

        if (storage.resolve(self.workspace_id, state_entry_path)) |entry| {
            const version = storage.version(entry.version_id) orelse return error.CorruptState;
            self.next_sequence = try parseHeader(try storage.versionPayload(version));
            self.header_version_id = entry.version_id;
        } else |err| switch (err) {
            error.EntryNotFound => return,
            else => return err,
        }

        const entries = try storage.entries(self.workspace_id);
        var loaded_count: usize = 0;
        for (entries) |entry| {
            if (!std.mem.startsWith(u8, entry.pathSlice(), event_entry_prefix)) continue;
            if (loaded_count >= self.events.len) break;
            const version = storage.version(entry.version_id) orelse return error.CorruptState;
            self.events[loaded_count].in_use = true;
            self.events[loaded_count].event = (try parsePersistentEvent(try storage.versionPayload(version))).intoEvent();
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
        try self.rebuildIndexes();
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
        event.kind = std.enums.fromInt(EventKind, self.kind) orelse return error.CorruptState;
        event.tick = self.tick;
        event.subject = .{
            .kind = std.enums.fromInt(principal.PrincipalKind, self.subject_kind) orelse return error.CorruptState,
            .serial = self.subject_serial,
        };
        event.task_id = self.task_id;
        event.workspace_id = self.workspace_id;
        event.related_id = self.related_id;
        event.detail_code = self.detail_code;
        event.service_class = std.enums.fromInt(contract.ServiceClass, self.service_class) orelse return error.CorruptState;
        event.permission_kind = if (self.permission_kind == permission_kind_none)
            null
        else
            (std.enums.fromInt(manifest.PermissionKind, self.permission_kind) orelse return error.CorruptState);
        event.allowed = (self.flags & (1 << 0)) != 0;
        event.denial_reason = std.enums.fromInt(abi.DenialReason, self.denial_reason) orelse return error.CorruptState;
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

fn updateFailureLabel(code: u32) []const u8 {
    const failure = std.enums.fromInt(immutable_base.HealthFailure, @as(u8, @intCast(code))) orelse return "corrupt";
    return @tagName(failure);
}

fn notificationReasonLabel(code: u32) []const u8 {
    if (code > std.math.maxInt(u8)) return "corrupt";
    const reason = std.enums.fromInt(notification_center.Reason, @as(u8, @intCast(code))) orelse return "corrupt";
    return @tagName(reason);
}

fn flowKindLabel(code: u32) []const u8 {
    if (code > std.math.maxInt(u8)) return "corrupt";
    const kind = std.enums.fromInt(native_ux.FlowKind, @as(u8, @intCast(code))) orelse return "corrupt";
    return @tagName(kind);
}

fn kindIndex(kind: EventKind) usize {
    return @intFromEnum(kind);
}

fn matchesQuery(event: Event, query: Query) bool {
    if (query.kind) |kind| {
        if (event.kind != kind) return false;
    }
    if (query.subject) |subject| {
        if (!event.subject.eql(subject)) return false;
    }
    if (query.task_id) |task_id| {
        if (event.task_id != task_id) return false;
    }
    if (query.workspace_id) |workspace_id| {
        if (event.workspace_id != workspace_id) return false;
    }
    return true;
}

fn redactedForQuery(event: Event, query: Query) Event {
    if (!event.detail_protected or query.include_protected_content) return event;
    var redacted = event;
    redacted.detail_len = copyText(&redacted.detail, "redacted");
    return redacted;
}

fn renderTextEvent(event: Event, buffer: []u8, used: *usize) Error!void {
    try appendFmt(buffer, used, "#{d} tick={d} kind={s} subject={s}:{d}", .{
        event.sequence,
        event.tick,
        @tagName(event.kind),
        @tagName(event.subject.kind),
        event.subject.serial,
    });
    if (event.permission_kind) |permission_kind| {
        try appendFmt(buffer, used, " permission={s} allowed={s}", .{
            @tagName(permission_kind),
            yesNo(event.allowed),
        });
        if (!event.allowed) {
            try appendFmt(buffer, used, " denial={s} policy={s} missing={s} approval={s} retry_safe={s}", .{
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
            try appendFmt(buffer, used, " slot={d} rollback={s} failure={s}", .{
                event.related_id,
                yesNo(!event.allowed),
                updateFailureLabel(event.detail_code),
            });
        },
        .device_trust_change => {
            try appendFmt(buffer, used, " device={d} trusted={s}", .{
                event.related_id,
                yesNo(event.allowed),
            });
        },
        .capability_grant, .capability_revocation => {
            try appendFmt(buffer, used, " capability={d}", .{event.related_id});
        },
        .notification => {
            try appendFmt(buffer, used, " notification={d} reason={s} visible={s}", .{
                event.related_id,
                notificationReasonLabel(event.detail_code),
                yesNo(event.allowed),
            });
        },
        .task_flow => {
            try appendFmt(buffer, used, " flow={d} flow_kind={s} approved={s}", .{
                event.related_id,
                flowKindLabel(event.detail_code),
                yesNo(event.allowed),
            });
        },
        else => {},
    }
    if (event.workspace_id != 0) {
        try appendFmt(buffer, used, " workspace={d}", .{event.workspace_id});
    }
    if (event.related_id != 0 and event.kind != .update_transition and event.kind != .device_trust_change) {
        try appendFmt(buffer, used, " related={d}", .{event.related_id});
    }
    if (event.detail_code != 0 and event.kind != .update_transition) {
        try appendFmt(buffer, used, " code={d}", .{event.detail_code});
    }
    if (event.kind == .process_crash or event.kind == .driver_restart) {
        try appendFmt(buffer, used, " service={s}", .{@tagName(event.service_class)});
    }
    try appendFmt(buffer, used, " detail={s}\n", .{event.detailSlice()});
}

fn appendFmt(buffer: []u8, used: *usize, comptime fmt: []const u8, args: anytype) Error!void {
    const rendered = std.fmt.bufPrint(buffer[used.*..], fmt, args) catch return error.NoSpaceLeft;
    used.* += rendered.len;
}

fn signLedgerMetadata(
    identity: signing.SignerIdentity,
    label: []const u8,
    content_type: []const u8,
    object_type: object_store.ObjectType,
    payload: []const u8,
    created_at_ticks: u64,
) Error!object_store.SignedMetadata {
    return object_store.signMetadata(
        identity,
        label,
        content_type,
        object_type,
        payload,
        created_at_ticks,
    ) catch error.SigningFailed;
}

fn stateObjectId() u64 {
    return native_util.fnv1a64WithSeed(0xED6E7EEC0D000001, "platform:event-ledger:state");
}

fn eventObjectId(sequence: u64) u64 {
    const slot_index = @as(usize, @intCast((sequence - 1) % MAX_PERSISTED_EVENTS));
    return native_util.fnv1a64WithSeed(
        0xED6E7EEC0D000101 + @as(u64, @intCast(slot_index)),
        "platform:event-ledger:event-slot",
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
