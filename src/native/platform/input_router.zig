const builtin = @import("builtin");
const std = @import("std");
const xhci = @import("../../kernel/drivers/xhci.zig");
const abi = @import("../core/abi.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const input_driver_task = @import("../drivers/input_driver_task.zig");
const compositor_session = @import("compositor_session.zig");
const trusted_pin = @import("trusted_pin_entry.zig");
const task_runtime = @import("../task/task_runtime.zig");
const root = @import("root");

pub const MAX_KEYBOARDS: usize = 4;
pub const MAX_INBOXES: usize = compositor_session.MAX_WINDOWS + 1;
pub const MAX_QUEUED_EVENTS: usize = 32;
pub const MAX_EVENTS_PER_INBOX: usize = 16;
pub const DEFAULT_REPORT_BUDGET: usize = 16;
pub const HEAP_BACKED_EVENT_SLOTS_ON_FREESTANDING = true;
pub const EVENT_SLOT_HANDLE_SIZE_CEILING_BYTES: usize = 8;

const NO_EVENT_INDEX: u8 = std.math.maxInt(u8);
const NO_INBOX_INDEX: u8 = std.math.maxInt(u8);
const INBOX_INDEX_CAPACITY: usize = MAX_INBOXES * 2;

comptime {
    std.debug.assert(MAX_QUEUED_EVENTS <= NO_EVENT_INDEX);
    std.debug.assert(MAX_INBOXES <= NO_INBOX_INDEX);
}

pub const HardwareReportSource = struct {
    poll_report: *const fn () ?xhci.HardwareBootKeyboardReport,
    input_proof: *const fn () ?xhci.InputProof,
};

pub const RoutedKeyboardEvent = struct {
    sequence: u64,
    tick: u64,
    window_id: u64,
    task_id: u64,
    surface_id: u64,
    port_id: u8,
    slot_id: u8,
    event: input_driver_task.KeyboardEvent,
};

const KeyboardIdentity = struct {
    port_id: u8,
    slot_id: u8,
    interface_number: u8,
    endpoint_id: u8,
    vendor_id: u16,
    product_id: u16,

    fn fromReport(report: xhci.HardwareBootKeyboardReport) KeyboardIdentity {
        return .{
            .port_id = report.port_id,
            .slot_id = report.slot_id,
            .interface_number = report.interface_number,
            .endpoint_id = report.endpoint_id,
            .vendor_id = report.vendor_id,
            .product_id = report.product_id,
        };
    }

    fn eql(self: KeyboardIdentity, other: KeyboardIdentity) bool {
        return std.meta.eql(self, other);
    }
};

const KeyboardSlot = struct {
    in_use: bool = false,
    identity: KeyboardIdentity = .{
        .port_id = 0,
        .slot_id = 0,
        .interface_number = 0,
        .endpoint_id = 0,
        .vendor_id = 0,
        .product_id = 0,
    },
    decoder: input_driver_task.Decoder = .{},
    saw_neutral: bool = false,
};

const EventSlot = struct {
    event: RoutedKeyboardEvent = undefined,
    next: u8 = NO_EVENT_INDEX,
};

const EventSlotArray = [MAX_QUEUED_EVENTS]EventSlot;
const heap_backed_event_slots = builtin.target.os.tag == .freestanding and HEAP_BACKED_EVENT_SLOTS_ON_FREESTANDING;
const EventSlotBacking = if (heap_backed_event_slots) ?*EventSlotArray else EventSlotArray;
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    root.kernel_memory
else
    struct {};

const Inbox = struct {
    in_use: bool = false,
    task_id: u64 = 0,
    head: u8 = NO_EVENT_INDEX,
    tail: u8 = NO_EVENT_INDEX,
    count: u8 = 0,
    wake_pending: bool = false,
    wake_queued: bool = false,
    previous_wake_index: u8 = NO_INBOX_INDEX,
    next_wake_index: u8 = NO_INBOX_INDEX,
    previous_active_index: u8 = NO_INBOX_INDEX,
    next_active_index: u8 = NO_INBOX_INDEX,
};

const InboxArena = indexed_arena.IndexedArenaWithKey(u64, Inbox, MAX_INBOXES, INBOX_INDEX_CAPACITY, inboxTaskId);

pub const Router = struct {
    source: ?HardwareReportSource = null,
    compositor: ?*compositor_session.Session = null,
    compositor_task_id: u64 = 0,
    keyboards: [MAX_KEYBOARDS]KeyboardSlot = [_]KeyboardSlot{.{}} ** MAX_KEYBOARDS,
    inboxes: InboxArena = InboxArena.init(),
    active_inbox_head: u8 = NO_INBOX_INDEX,
    active_inbox_tail: u8 = NO_INBOX_INDEX,
    wake_head: u8 = NO_INBOX_INDEX,
    wake_tail: u8 = NO_INBOX_INDEX,
    event_slots: EventSlotBacking = if (heap_backed_event_slots) null else [_]EventSlot{.{}} ** MAX_QUEUED_EVENTS,
    free_event_head: u8 = NO_EVENT_INDEX,
    event_pool_initialized: bool = false,
    queued_event_count: u8 = 0,
    last_report_sequence: u64 = 0,
    // Report replay protection belongs to the bound hardware source. Event
    // ordering belongs to this router's lifetime, including source replacement
    // while applications retain their last received sequence.
    last_event_sequence: u64 = 0,
    routing_epoch: u64 = 1,
    reports_accepted: usize = 0,
    trusted_entry: ?*trusted_pin.Entry = null,
    trusted_revision: u64 = 0,
    drain_until_neutral: bool = false,
    released_since_boundary: bool = false,

    comptime {
        if (heap_backed_event_slots and @sizeOf(EventSlotBacking) > EVENT_SLOT_HANDLE_SIZE_CEILING_BYTES) {
            @compileError("heap-backed input event slots exceed their handle size ceiling");
        }
    }

    fn eventSlots(self: *Router) ?*EventSlotArray {
        if (comptime heap_backed_event_slots) return self.event_slots;
        return &self.event_slots;
    }

    fn ensureEventSlots(self: *Router) ?*EventSlotArray {
        if (self.eventSlots()) |slots| return slots;
        if (comptime heap_backed_event_slots) {
            const allocation = kernel_memory.kmalloc(@sizeOf(EventSlotArray)) orelse return null;
            const slots: *EventSlotArray = @ptrCast(@alignCast(allocation));
            initializeEventSlots(slots);
            self.free_event_head = 0;
            self.queued_event_count = 0;
            self.event_pool_initialized = true;
            self.event_slots = slots;
            return slots;
        }
        return &self.event_slots;
    }

    pub fn deinit(self: *Router) void {
        self.clearTrustedEntry();
        self.routing_epoch +|= 1;
        self.dropAllInboxes();
        if (comptime heap_backed_event_slots) {
            if (self.event_slots) |slots| {
                @memset(std.mem.asBytes(slots), 0);
                kernel_memory.kfree(@ptrCast(slots));
                self.event_slots = null;
            }
        } else {
            self.event_slots = [_]EventSlot{.{}} ** MAX_QUEUED_EVENTS;
        }
        self.free_event_head = NO_EVENT_INDEX;
        self.event_pool_initialized = false;
        self.queued_event_count = 0;
    }

    pub fn bindHardwareSource(self: *Router, source: HardwareReportSource) void {
        if (self.trusted_entry) |entry| entry.lock(entry.last_ticks);
        self.routing_epoch +|= 1;
        self.dropAllInboxes();
        self.source = source;
        self.last_report_sequence = 0;
        self.keyboards = [_]KeyboardSlot{.{}} ** MAX_KEYBOARDS;
    }

    pub fn clearHardwareSource(self: *Router) void {
        if (self.trusted_entry) |entry| entry.inputInterrupted(entry.last_ticks);
        self.routing_epoch +|= 1;
        self.dropAllInboxes();
        self.source = null;
        self.last_report_sequence = 0;
        self.keyboards = [_]KeyboardSlot{.{}} ** MAX_KEYBOARDS;
    }

    pub fn bindCompositor(
        self: *Router,
        compositor: *compositor_session.Session,
        compositor_task_id: u64,
    ) void {
        if (self.compositor != null and
            (self.compositor.? != compositor or self.compositor_task_id != compositor_task_id))
        {
            if (self.trusted_entry) |entry| entry.inputInterrupted(entry.last_ticks);
            self.compositor.?.authentication_view = null;
            self.routing_epoch +|= 1;
            self.dropAllInboxes();
        }
        self.compositor = compositor;
        self.compositor_task_id = compositor_task_id;
        compositor.authentication_view = if (self.trusted_entry) |entry| &entry.view else null;
    }

    pub fn clearCompositor(self: *Router) void {
        if (self.trusted_entry) |entry| entry.inputInterrupted(entry.last_ticks);
        if (self.compositor) |compositor| compositor.authentication_view = null;
        self.routing_epoch +|= 1;
        self.compositor = null;
        self.compositor_task_id = 0;
        self.dropAllInboxes();
    }

    // Native service binding only. Apps cannot request this through the input
    // ABI. Binding always locks the authenticator and discards old gestures.
    pub fn bindTrustedEntry(self: *Router, entry: *trusted_pin.Entry, now_ticks: u64) void {
        self.clearTrustedEntry();
        self.trusted_entry = entry;
        entry.lock(now_ticks);
        if (self.compositor) |compositor| compositor.authentication_view = &entry.view;
        self.synchronizeTrustedInput();
    }

    // Teardown by the exclusive desktop owner; revoke authority before dropping
    // this binding. Keep Entry alive until both router and compositor detach.
    pub fn clearTrustedEntry(self: *Router) void {
        if (self.trusted_entry) |entry| {
            entry.lock(entry.last_ticks);
            if (self.compositor) |compositor| compositor.authentication_view = null;
            self.trusted_entry = null;
            self.trusted_revision = 0;
            self.routing_epoch +|= 1;
            self.dropAllInboxes();
            self.drain_until_neutral = true;
            self.released_since_boundary = false;
        }
    }

    pub fn synchronizeTrustedInput(self: *Router) void {
        const entry = self.trusted_entry orelse return;
        if (self.trusted_revision == entry.revision and entry.revision != std.math.maxInt(u64)) return;
        self.trusted_revision = entry.revision;
        self.routing_epoch +|= 1;
        self.dropAllInboxes();
        self.drain_until_neutral = true;
        self.released_since_boundary = false;
    }

    pub fn service(self: *Router, now_ticks: u64, report_budget: usize) usize {
        var events_routed: usize = 0;
        if (self.trusted_entry) |entry| entry.tick(now_ticks);
        self.synchronizeTrustedInput();
        const source = self.source orelse return 0;
        const compositor = self.compositor orelse return 0;
        self.pruneStaleInboxes(compositor);

        for (0..report_budget) |_| {
            var report = source.poll_report() orelse {
                // Drain the complete old queue and observe a fresh release.
                // Other keyboards' held keys remain suppressed by their own
                // decoders, including a keyboard unplugged while holding keys.
                if (self.drain_until_neutral and self.released_since_boundary) self.drain_until_neutral = false;
                break;
            };
            defer std.crypto.secureZero(u8, &report.bytes);

            if (!validTopology(report)) {
                if (self.trusted_entry) |entry| if (entry.capturing()) {
                    entry.inputInterrupted(now_ticks);
                    self.synchronizeTrustedInput();
                };
                continue;
            }
            if (report.sequence <= self.last_report_sequence) {
                continue;
            }
            self.last_report_sequence = report.sequence;

            const keyboard = self.keyboardFor(report) orelse continue;
            var decoded = keyboard.decoder.decode(report.bytes) catch {
                if (self.trusted_entry) |entry| {
                    if (entry.capturing()) entry.lock(now_ticks);
                    self.synchronizeTrustedInput();
                }
                continue;
            };
            defer std.crypto.secureZero(u8, std.mem.asBytes(&decoded));
            if (std.mem.allEqual(u8, &report.bytes, 0)) {
                keyboard.saw_neutral = true;
                self.released_since_boundary = true;
            }
            self.reports_accepted +|= 1;

            if (self.drain_until_neutral) continue;
            if (self.trusted_entry) |entry| {
                if (secureAttention(report.bytes)) {
                    entry.lock(now_ticks);
                    self.synchronizeTrustedInput();
                    events_routed += 1;
                    continue;
                }
                if (!keyboard.saw_neutral) continue;
                if (entry.capturing()) {
                    for (decoded.slice()) |event| entry.handle(event, now_ticks);
                    events_routed += decoded.count;
                    self.synchronizeTrustedInput();
                    continue;
                }
            }

            for (decoded.slice()) |event| {
                if (self.routeEvent(compositor, report, event, now_ticks)) {
                    events_routed += 1;
                }
            }
        }

        return events_routed;
    }

    pub fn pollForTask(self: *Router, task_id: u64) ?RoutedKeyboardEvent {
        self.synchronizeTrustedInput();
        if (self.drain_until_neutral or (if (self.trusted_entry) |entry| entry.capturing() else false)) return null;
        const inbox_index = self.findInboxIndex(task_id) orelse return null;
        const inbox = &self.inboxes.slots[inbox_index];
        if (inbox.count == 0) return null;
        const event_index = inbox.head;
        const event_slots = self.eventSlots() orelse
            native_util.impossibleByInvariant("queued input events retain their slot backing");
        const event_slot = &event_slots[event_index];
        const event = event_slot.event;
        inbox.head = event_slot.next;
        inbox.count -= 1;
        if (inbox.count == 0) {
            inbox.tail = NO_EVENT_INDEX;
            inbox.wake_pending = false;
            self.unlinkWake(inbox_index);
        }
        self.releaseEvent(event_index);
        return event;
    }

    pub fn pollAbiForTask(self: *Router, task_id: u64) ?abi.InputEventDescriptor {
        const routed = self.pollForTask(task_id) orelse return null;
        return .{
            .sequence = routed.sequence,
            .tick = routed.tick,
            .window_id = routed.window_id,
            .task_id = routed.task_id,
            .surface_id = routed.surface_id,
            .port_id = routed.port_id,
            .slot_id = routed.slot_id,
            .length = 2,
            .bytes = abi.inputPacket(inputByte(routed.event.kind), routed.event.data),
        };
    }

    pub fn queuedForTask(self: *const Router, task_id: u64) usize {
        const inbox_index = self.findInboxIndex(task_id) orelse return 0;
        return @intCast(self.inboxes.slots[inbox_index].count);
    }

    pub fn dropForTask(self: *Router, task_id: u64) usize {
        const inbox_index = self.findInboxIndex(task_id) orelse return 0;
        const inbox = &self.inboxes.slots[inbox_index];
        const dropped: usize = @intCast(inbox.count);
        self.releaseInboxEvents(inbox);
        self.unlinkWake(inbox_index);
        self.unlinkActiveInbox(inbox_index);
        if (!self.inboxes.removeIndex(inbox_index)) native_util.impossibleByInvariant("indexed input inbox remains live until task drop");
        return dropped;
    }

    pub fn pollWakeTarget(self: *Router) ?u64 {
        if (self.wake_head == NO_INBOX_INDEX) return null;
        const inbox_index: usize = self.wake_head;
        if (inbox_index >= MAX_INBOXES) native_util.impossibleByInvariant("input wake queue head points outside inbox slots");
        const inbox = &self.inboxes.slots[inbox_index];
        if (!inbox.in_use or !inbox.wake_pending) native_util.impossibleByInvariant("input wake queue points at an inactive inbox");
        self.unlinkWake(inbox_index);
        inbox.wake_pending = false;
        return inbox.task_id;
    }

    pub fn inputProof(self: *const Router) ?xhci.InputProof {
        const source = self.source orelse return null;
        return source.input_proof();
    }

    fn routeEvent(
        self: *Router,
        compositor: *compositor_session.Session,
        report: xhci.HardwareBootKeyboardReport,
        event: input_driver_task.KeyboardEvent,
        now_ticks: u64,
    ) bool {
        switch (event.kind) {
            .task_switch_next, .task_switch_previous => {
                self.routing_epoch +|= 1;
                _ = compositor.switchVisible(if (event.kind == .task_switch_next) .next else .previous) catch {
                    return false;
                };
                self.markWake(self.compositor_task_id);
                return true;
            },
            else => {},
        }

        const active = compositor.activeWindow();
        const global = event.kind == .show_recovery or event.kind == .dismiss_recovery;
        const target_task_id = if (global)
            self.compositor_task_id
        else if (active) |window|
            if (window.modal and window.reviewer_task_id != 0)
                window.reviewer_task_id
            else if (window.subject_task_id != 0)
                window.subject_task_id
            else
                self.compositor_task_id
        else
            self.compositor_task_id;
        if (target_task_id == 0) return false;

        const sequence = std.math.add(u64, self.last_event_sequence, 1) catch return false;
        const routed = RoutedKeyboardEvent{
            .sequence = sequence,
            .tick = now_ticks,
            .window_id = if (active) |window| window.id else 0,
            .task_id = target_task_id,
            .surface_id = if (active) |window| window.ui_surface_id orelse 0 else 0,
            .port_id = report.port_id,
            .slot_id = report.slot_id,
            .event = event,
        };
        const inbox_index = self.inboxForIndex(target_task_id) orelse return false;
        const inbox = &self.inboxes.slots[inbox_index];
        if (inbox.count == MAX_EVENTS_PER_INBOX) return false;
        const event_index = self.allocateEvent() orelse return false;
        const event_slots = self.eventSlots() orelse
            native_util.impossibleByInvariant("allocated input events retain their slot backing");
        self.last_event_sequence = sequence;
        const was_empty = inbox.count == 0;
        event_slots[event_index] = .{ .event = routed };
        if (inbox.tail == NO_EVENT_INDEX) {
            inbox.head = event_index;
        } else {
            event_slots[inbox.tail].next = event_index;
        }
        inbox.tail = event_index;
        inbox.count += 1;
        if (was_empty) self.queueWake(inbox_index);
        return true;
    }

    fn keyboardFor(self: *Router, report: xhci.HardwareBootKeyboardReport) ?*KeyboardSlot {
        const identity = KeyboardIdentity.fromReport(report);
        for (&self.keyboards) |*slot| {
            if (slot.in_use and slot.identity.eql(identity)) return slot;
        }
        for (&self.keyboards) |*slot| {
            if (slot.in_use) continue;
            slot.* = .{ .in_use = true, .identity = identity };
            return slot;
        }
        return null;
    }

    fn inboxForIndex(self: *Router, task_id: u64) ?usize {
        if (self.findInboxIndex(task_id)) |inbox_index| return inbox_index;
        if (task_id == 0) return null;
        const inbox_index = self.inboxes.reserveIndex(task_id) orelse return null;
        const inbox = &self.inboxes.slots[inbox_index];
        inbox.task_id = task_id;
        self.linkActiveInbox(inbox_index);
        return inbox_index;
    }

    fn findInboxIndex(self: *const Router, task_id: u64) ?usize {
        if (task_id == 0) return null;
        const inbox_index = self.inboxes.slotIndexOf(task_id) orelse return null;
        if (inbox_index >= MAX_INBOXES) native_util.impossibleByInvariant("input inbox index points outside slots");
        const inbox = &self.inboxes.slots[inbox_index];
        if (!inbox.in_use or inbox.task_id != task_id) native_util.impossibleByInvariant("input inbox index points at the wrong slot");
        return inbox_index;
    }

    fn markWake(self: *Router, task_id: u64) void {
        if (task_id == 0) return;
        const inbox_index = self.inboxForIndex(task_id) orelse return;
        self.queueWake(inbox_index);
    }

    fn queueWake(self: *Router, inbox_index: usize) void {
        if (inbox_index >= MAX_INBOXES) native_util.impossibleByInvariant("input wake enqueue points outside inbox slots");
        const inbox = &self.inboxes.slots[inbox_index];
        if (!inbox.in_use) native_util.impossibleByInvariant("input wake enqueue requires a live inbox");
        inbox.wake_pending = true;
        if (inbox.wake_queued) return;

        const encoded_index: u8 = @intCast(inbox_index);
        inbox.previous_wake_index = self.wake_tail;
        inbox.next_wake_index = NO_INBOX_INDEX;
        inbox.wake_queued = true;
        if (self.wake_tail == NO_INBOX_INDEX) {
            self.wake_head = encoded_index;
        } else {
            if (self.wake_tail >= MAX_INBOXES) native_util.impossibleByInvariant("input wake queue tail points outside inbox slots");
            self.inboxes.slots[self.wake_tail].next_wake_index = encoded_index;
        }
        self.wake_tail = encoded_index;
    }

    fn unlinkWake(self: *Router, inbox_index: usize) void {
        if (inbox_index >= MAX_INBOXES) native_util.impossibleByInvariant("input wake unlink points outside inbox slots");
        const inbox = &self.inboxes.slots[inbox_index];
        if (!inbox.wake_queued) return;

        const previous = inbox.previous_wake_index;
        const next = inbox.next_wake_index;
        if (previous == NO_INBOX_INDEX) {
            self.wake_head = next;
        } else {
            if (previous >= MAX_INBOXES) native_util.impossibleByInvariant("input wake previous link points outside inbox slots");
            self.inboxes.slots[previous].next_wake_index = next;
        }
        if (next == NO_INBOX_INDEX) {
            self.wake_tail = previous;
        } else {
            if (next >= MAX_INBOXES) native_util.impossibleByInvariant("input wake next link points outside inbox slots");
            self.inboxes.slots[next].previous_wake_index = previous;
        }
        inbox.wake_queued = false;
        inbox.previous_wake_index = NO_INBOX_INDEX;
        inbox.next_wake_index = NO_INBOX_INDEX;
    }

    fn pruneStaleInboxes(self: *Router, compositor: *const compositor_session.Session) void {
        var inbox_index: usize = self.active_inbox_head;
        while (inbox_index != NO_INBOX_INDEX) {
            if (inbox_index >= MAX_INBOXES) native_util.impossibleByInvariant("active input inbox chain points outside slots");
            const inbox = &self.inboxes.slots[inbox_index];
            if (!inbox.in_use) native_util.impossibleByInvariant("active input inbox chain points at a free slot");
            const next_index = inbox.next_active_index;
            if (inbox.task_id == self.compositor_task_id or compositor.taskOwnsVisibleWindow(inbox.task_id)) {
                inbox_index = next_index;
                continue;
            }
            self.releaseInboxEvents(inbox);
            self.unlinkWake(inbox_index);
            self.unlinkActiveInbox(inbox_index);
            if (!self.inboxes.removeIndex(inbox_index)) native_util.impossibleByInvariant("stale input inbox remains live until pruning");
            inbox_index = next_index;
        }
    }

    fn dropAllInboxes(self: *Router) void {
        var inbox_index: usize = self.active_inbox_head;
        while (inbox_index != NO_INBOX_INDEX) {
            if (inbox_index >= MAX_INBOXES) native_util.impossibleByInvariant("active input inbox reset points outside slots");
            const inbox = &self.inboxes.slots[inbox_index];
            if (!inbox.in_use) native_util.impossibleByInvariant("active input inbox reset points at a free slot");
            inbox_index = inbox.next_active_index;
        }
        self.inboxes.reset();
        self.active_inbox_head = NO_INBOX_INDEX;
        self.active_inbox_tail = NO_INBOX_INDEX;
        self.wake_head = NO_INBOX_INDEX;
        self.wake_tail = NO_INBOX_INDEX;
        self.resetEventPool();
    }

    fn allocateEvent(self: *Router) ?u8 {
        const event_slots = self.ensureEventSlots() orelse return null;
        if (!self.event_pool_initialized) self.resetEventPool();
        if (self.free_event_head == NO_EVENT_INDEX) return null;
        const event_index = self.free_event_head;
        self.free_event_head = event_slots[event_index].next;
        event_slots[event_index].next = NO_EVENT_INDEX;
        self.queued_event_count += 1;
        return event_index;
    }

    fn releaseEvent(self: *Router, event_index: u8) void {
        const event_slots = self.eventSlots() orelse
            native_util.impossibleByInvariant("released input events retain their slot backing");
        std.crypto.secureZero(u8, std.mem.asBytes(&event_slots[event_index].event));
        event_slots[event_index].next = self.free_event_head;
        self.free_event_head = event_index;
        self.queued_event_count -= 1;
    }

    fn releaseInboxEvents(self: *Router, inbox: *Inbox) void {
        const event_slots = self.eventSlots() orelse {
            if (inbox.head != NO_EVENT_INDEX) {
                native_util.impossibleByInvariant("input inbox events retain their slot backing");
            }
            return;
        };
        var event_index = inbox.head;
        while (event_index != NO_EVENT_INDEX) {
            const next = event_slots[event_index].next;
            self.releaseEvent(event_index);
            event_index = next;
        }
    }

    fn resetEventPool(self: *Router) void {
        const event_slots = self.eventSlots();
        if (event_slots) |slots| initializeEventSlots(slots);
        self.free_event_head = if (event_slots != null) 0 else NO_EVENT_INDEX;
        self.queued_event_count = 0;
        self.event_pool_initialized = event_slots != null;
    }

    fn linkActiveInbox(self: *Router, inbox_index: usize) void {
        if (inbox_index >= MAX_INBOXES) native_util.impossibleByInvariant("active input inbox append points outside slots");
        const inbox = &self.inboxes.slots[inbox_index];
        if (!inbox.in_use) native_util.impossibleByInvariant("active input inbox append requires a live slot");
        const encoded_index: u8 = @intCast(inbox_index);
        inbox.previous_active_index = self.active_inbox_tail;
        inbox.next_active_index = NO_INBOX_INDEX;
        if (self.active_inbox_tail == NO_INBOX_INDEX) {
            self.active_inbox_head = encoded_index;
        } else {
            if (self.active_inbox_tail >= MAX_INBOXES) native_util.impossibleByInvariant("active input inbox tail points outside slots");
            self.inboxes.slots[self.active_inbox_tail].next_active_index = encoded_index;
        }
        self.active_inbox_tail = encoded_index;
    }

    fn unlinkActiveInbox(self: *Router, inbox_index: usize) void {
        if (inbox_index >= MAX_INBOXES) native_util.impossibleByInvariant("active input inbox unlink points outside slots");
        const inbox = &self.inboxes.slots[inbox_index];
        if (!inbox.in_use) native_util.impossibleByInvariant("active input inbox unlink requires a live slot");
        const previous = inbox.previous_active_index;
        const next = inbox.next_active_index;
        if (previous == NO_INBOX_INDEX) {
            if (self.active_inbox_head != inbox_index) native_util.impossibleByInvariant("active input inbox head matches its first link");
            self.active_inbox_head = next;
        } else {
            if (previous >= MAX_INBOXES) native_util.impossibleByInvariant("active input inbox previous link points outside slots");
            self.inboxes.slots[previous].next_active_index = next;
        }
        if (next == NO_INBOX_INDEX) {
            if (self.active_inbox_tail != inbox_index) native_util.impossibleByInvariant("active input inbox tail matches its final link");
            self.active_inbox_tail = previous;
        } else {
            if (next >= MAX_INBOXES) native_util.impossibleByInvariant("active input inbox next link points outside slots");
            self.inboxes.slots[next].previous_active_index = previous;
        }
        inbox.previous_active_index = NO_INBOX_INDEX;
        inbox.next_active_index = NO_INBOX_INDEX;
    }
};

pub const event_slot_layout = .{
    .heap_backs_slots_on_freestanding = HEAP_BACKED_EVENT_SLOTS_ON_FREESTANDING,
    .slot_backing_size_bytes = @sizeOf(EventSlotArray),
    .freestanding_handle_size_bytes = if (HEAP_BACKED_EVENT_SLOTS_ON_FREESTANDING) @sizeOf(?*EventSlotArray) else @sizeOf(EventSlotArray),
};

fn initializeEventSlots(event_slots: *EventSlotArray) void {
    for (event_slots, 0..) |*slot, index| {
        std.crypto.secureZero(u8, std.mem.asBytes(&slot.event));
        slot.next = if (index + 1 < event_slots.len)
            @intCast(index + 1)
        else
            NO_EVENT_INDEX;
    }
}

fn secureAttention(report: [input_driver_task.BOOT_KEYBOARD_REPORT_BYTES]u8) bool {
    const control: u8 = (1 << 0) | (1 << 4);
    const alt: u8 = (1 << 2) | (1 << 6);
    if (report[0] & control == 0 or report[0] & alt == 0 or report[0] & ~(control | alt) != 0) return false;
    return std.mem.indexOfScalar(u8, report[2..], 0x4c) != null;
}

test "allocated input event slots initialize their reusable free list" {
    const event_slots = try std.testing.allocator.create(EventSlotArray);
    defer std.testing.allocator.destroy(event_slots);
    initializeEventSlots(event_slots);

    try std.testing.expectEqual(@as(u8, 1), event_slots[0].next);
    try std.testing.expectEqual(NO_EVENT_INDEX, event_slots[MAX_QUEUED_EVENTS - 1].next);
}

fn validTopology(report: xhci.HardwareBootKeyboardReport) bool {
    return report.sequence != 0 and report.port_id != 0 and report.slot_id != 0 and
        report.endpoint_id != 0;
}

fn inboxTaskId(inbox: *const Inbox) u64 {
    return inbox.task_id;
}

fn inputByte(kind: input_driver_task.EventKind) u8 {
    return switch (kind) {
        .text => abi.InputByte.text,
        .backspace => abi.InputByte.backspace,
        .commit_text => abi.InputByte.commit_text,
        .focus_next => abi.InputByte.focus_next,
        .focus_previous => abi.InputByte.focus_previous,
        .activate => abi.InputByte.activate,
        .task_switch_next => abi.InputByte.task_switch_next,
        .task_switch_previous => abi.InputByte.task_switch_previous,
        .show_recovery => abi.InputByte.show_recovery,
        .dismiss_recovery => abi.InputByte.dismiss_recovery,
        .cursor_left => abi.InputByte.cursor_left,
        .cursor_right => abi.InputByte.cursor_right,
        .cursor_up => abi.InputByte.cursor_up,
        .cursor_down => abi.InputByte.cursor_down,
        .line_start => abi.InputByte.line_start,
        .line_end => abi.InputByte.line_end,
        .document_start => abi.InputByte.document_start,
        .document_end => abi.InputByte.document_end,
        .delete_forward => abi.InputByte.delete_forward,
        .select_all => abi.InputByte.select_all,
        .undo => abi.InputByte.undo,
        .redo => abi.InputByte.redo,
        .copy => abi.InputByte.copy,
        .cut => abi.InputByte.cut,
        .paste => abi.InputByte.paste,
        .page_up => abi.InputByte.page_up,
        .page_down => abi.InputByte.page_down,
    };
}

const TestFeed = struct {
    reports: [8]xhci.HardwareBootKeyboardReport = [_]xhci.HardwareBootKeyboardReport{.{}} ** 8,
    count: usize = 0,
    cursor: usize = 0,
};

var test_feed = TestFeed{};

test "input router isolates trusted PIN entry and drains both routing boundaries" {
    var compositor = compositor_session.Session.init();
    defer compositor.deinit();
    var router = Router{};
    defer router.deinit();
    var backend = @import("../../tests/fixtures/pin_authenticator.zig").Fixture{};
    var entry = trusted_pin.Entry{ .authenticator = backend.authenticator(), .input_timeout_ticks = 50 };
    router.bindCompositor(&compositor, 99);
    router.bindHardwareSource(.{ .poll_report = pollTestReport, .input_proof = noTestProof });
    test_feed = .{};
    test_feed.reports[0] = makeTestReport(1, 1, 0, &.{0x04});
    test_feed.count = 1;
    _ = router.service(1, 16);
    try std.testing.expectEqual(@as(usize, 1), router.queuedForTask(99));
    const old_epoch = router.routing_epoch;
    router.bindTrustedEntry(&entry, 2);
    try std.testing.expect(router.routing_epoch > old_epoch);
    try std.testing.expect(router.pollForTask(99) == null);
    try std.testing.expect(router.pollWakeTarget() == null);
    test_feed = .{};
    test_feed.reports[0] = makeTestReport(2, 1, 0, &.{0x1e});
    test_feed.reports[1] = makeTestReport(3, 1, 0, &.{});
    test_feed.count = 2;
    _ = router.service(3, 16);
    try std.testing.expectEqual(@as(u8, 0), entry.view.digits);
    try std.testing.expect(!router.drain_until_neutral);
    var sequence: u64 = 3;
    for (backend.expected) |byte| {
        test_feed = .{};
        sequence += 1;
        test_feed.reports[0] = makeTestReport(sequence, 1, 0, &.{if (byte == '0') 0x27 else byte - '1' + 0x1e});
        sequence += 1;
        test_feed.reports[1] = makeTestReport(sequence, 1, 0, &.{});
        test_feed.count = 2;
        _ = router.service(4, 16);
        try std.testing.expect(router.pollForTask(99) == null);
        try std.testing.expect(router.pollWakeTarget() == null);
    }
    test_feed = .{};
    sequence += 1;
    test_feed.reports[0] = makeTestReport(sequence, 1, 4, &.{0x2b}); // Alt+Tab stays exclusive.
    sequence += 1;
    test_feed.reports[1] = makeTestReport(sequence, 1, 0, &.{});
    sequence += 1;
    test_feed.reports[2] = makeTestReport(sequence, 1, 0, &.{ 0x28, 0x1e }); // Submit ignores trailing key.
    test_feed.count = 3;
    _ = router.service(5, 16);
    try std.testing.expectEqual(trusted_pin.Status.pending, entry.view.status);
    try std.testing.expectEqual(@as(u8, 8), entry.view.digits);
    try std.testing.expect(entry.prepareVerification(5));
    entry.verify(5);
    try std.testing.expect(backend.active);
    try std.testing.expect(router.pollForTask(99) == null);
    test_feed = .{};
    sequence += 1;
    test_feed.reports[0] = makeTestReport(sequence, 1, 0, &.{ 0x28, 0x1e });
    sequence += 1;
    test_feed.reports[1] = makeTestReport(sequence, 1, 0, &.{});
    sequence += 1;
    test_feed.reports[2] = makeTestReport(sequence, 1, 0, &.{0x05});
    sequence += 1;
    test_feed.reports[3] = makeTestReport(sequence, 1, 0, &.{});
    test_feed.count = 4;
    _ = router.service(6, 16);
    try std.testing.expect(router.pollForTask(99) == null);
    test_feed = .{};
    sequence += 1;
    test_feed.reports[0] = makeTestReport(sequence, 1, 0, &.{0x06});
    test_feed.count = 1;
    _ = router.service(7, 16);
    try std.testing.expectEqual(@as(u8, 'c'), router.pollForTask(99).?.event.data);
    // Secure attention wins over every other key in the same hardware report.
    test_feed = .{};
    sequence += 1;
    test_feed.reports[0] = makeTestReport(sequence, 1, 5, &.{ 0x1e, 0x4c });
    test_feed.count = 1;
    _ = router.service(8, 16);
    try std.testing.expect(entry.capturing() and !backend.active);
    try std.testing.expect(router.pollForTask(99) == null);
    try std.testing.expectEqual(@as(u8, 0), entry.view.digits);
    for (backend.expected) |byte| entry.handle(.{ .kind = .text, .data = byte }, 9);
    entry.handle(.{ .kind = .activate }, 9);
    try std.testing.expect(entry.prepareVerification(9));
    entry.verify(9);
    test_feed = .{};
    sequence += 1;
    test_feed.reports[0] = makeTestReport(sequence, 1, 0, &.{});
    test_feed.count = 1;
    _ = router.service(10, 16);
    test_feed = .{};
    sequence += 1;
    test_feed.reports[0] = makeTestReport(sequence, 2, 5, &.{0x4c}); // First report from a new keyboard.
    test_feed.count = 1;
    _ = router.service(11, 16);
    try std.testing.expect(entry.capturing() and !backend.active);
    test_feed = .{};
    sequence += 1;
    test_feed.reports[0] = makeTestReport(sequence, 2, 0, &.{});
    test_feed.count = 1;
    _ = router.service(12, 16);
    test_feed = .{};
    sequence += 1;
    test_feed.reports[0] = makeTestReport(sequence, 2, 0, &.{0x1e});
    sequence += 1;
    test_feed.reports[1] = makeTestReport(sequence, 0, 0, &.{0x1f}); // Broken transport identity.
    test_feed.count = 2;
    _ = router.service(13, 16);
    try std.testing.expectEqual(trusted_pin.Status.unavailable, entry.view.status);
    try std.testing.expect(std.mem.allEqual(u8, &entry.pin, 0));
    try std.testing.expect(router.pollForTask(99) == null);
    compositor.reset();
    try std.testing.expect(compositor.authentication_view == &entry.view);
    router.clearHardwareSource();
    try std.testing.expectEqual(trusted_pin.Status.unavailable, entry.view.status);
    try std.testing.expect(std.mem.allEqual(u8, &entry.pin, 0));
}

fn pollTestReport() ?xhci.HardwareBootKeyboardReport {
    if (test_feed.cursor == test_feed.count) return null;
    defer test_feed.cursor += 1;
    return test_feed.reports[test_feed.cursor];
}

fn noTestProof() ?xhci.InputProof {
    return null;
}

fn makeTestReport(sequence: u64, slot_id: u8, modifiers: u8, keys: []const u8) xhci.HardwareBootKeyboardReport {
    var report = xhci.HardwareBootKeyboardReport{
        .sequence = sequence,
        .port_id = slot_id,
        .slot_id = slot_id,
        .interface_number = 1,
        .endpoint_id = 3,
        .vendor_id = 0x046D,
        .product_id = 0xC31C,
    };
    report.bytes[0] = modifiers;
    @memcpy(report.bytes[2..][0..keys.len], keys);
    return report;
}

fn testTaskBudget() task_runtime.ResourceBudget {
    return .{
        .cpu_time_ticks = 1_000,
        .memory_bytes = 64 * 1024,
        .endpoint_slots = 4,
        .shared_memory_bytes = 4 * 1024,
        .background_allowed = false,
    };
}

test "input router numbers every decoded key independently of hardware reports" {
    var compositor = compositor_session.Session.init();
    var router = Router{};
    defer router.deinit();
    router.bindCompositor(&compositor, 99);
    router.bindHardwareSource(.{ .poll_report = pollTestReport, .input_proof = noTestProof });
    test_feed = .{};
    test_feed.reports[0] = makeTestReport(80, 1, 0, &.{ 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 });
    test_feed.reports[1] = makeTestReport(81, 2, 0, &.{ 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F });
    test_feed.reports[2] = makeTestReport(81, 2, 0, &.{0x10}); // Replayed report.
    test_feed.reports[3] = makeTestReport(82, 1, 0, &.{}); // Release is not an event.
    test_feed.reports[4] = makeTestReport(83, 1, 0, &.{0x10});
    test_feed.count = 5;
    try std.testing.expectEqual(@as(usize, 13), router.service(42, DEFAULT_REPORT_BUDGET));
    var previous: u64 = 0;
    for ("abcdefghijklm", 0..) |byte, index| {
        const event = router.pollAbiForTask(99).?;
        try std.testing.expect(event.sequence > previous);
        try std.testing.expectEqual(@as(u64, 42), event.tick);
        try std.testing.expectEqual(@as(u8, if (index >= 6 and index < 12) 2 else 1), event.slot_id);
        try std.testing.expectEqual(abi.InputByte.text, event.bytes[0]);
        try std.testing.expectEqual(byte, event.bytes[1]);
        previous = event.sequence;
    }
    try std.testing.expect(router.pollAbiForTask(99) == null);
    try std.testing.expectEqual(@as(usize, 4), router.reports_accepted);
}

test "input router keeps event ordering across source and compositor rebinding" {
    var compositors = [_]compositor_session.Session{ .init(), .init() };
    var router = Router{};
    defer router.deinit();
    var previous: u64 = 0;
    for (0..5) |index| {
        switch (index) {
            2 => router.clearHardwareSource(),
            3 => router.clearCompositor(),
            4 => router.deinit(),
            else => {},
        }
        router.bindCompositor(&compositors[index % 2], 99);
        router.bindHardwareSource(.{ .poll_report = pollTestReport, .input_proof = noTestProof });
        test_feed = .{};
        // A replacement source can start at one while the app is still alive.
        test_feed.reports[0] = makeTestReport(if (index == 0) 500 else 1, 1, 0, &.{ 0x04, 0x05 });
        test_feed.count = 1;
        try std.testing.expectEqual(@as(usize, 2), router.service(42, DEFAULT_REPORT_BUDGET));
        const event = router.pollAbiForTask(99).?;
        try std.testing.expect(event.sequence > previous);
        previous = event.sequence;
        // Rebinding must discard the remaining key and its wake notification.
        try std.testing.expectEqual(@as(usize, 1), router.queuedForTask(99));
    }
}

test "input router exhausts event identities without wrapping or resetting them" {
    var compositor = compositor_session.Session.init();
    var router = Router{ .last_event_sequence = std.math.maxInt(u64) - 1 };
    defer router.deinit();
    router.bindCompositor(&compositor, 99);
    router.bindHardwareSource(.{ .poll_report = pollTestReport, .input_proof = noTestProof });
    test_feed = .{};
    test_feed.reports[0] = makeTestReport(1, 1, 0, &.{ 0x04, 0x05 });
    test_feed.count = 1;
    try std.testing.expectEqual(@as(usize, 1), router.service(42, DEFAULT_REPORT_BUDGET));
    const event = router.pollAbiForTask(99).?;
    try std.testing.expectEqual(std.math.maxInt(u64), event.sequence);
    try std.testing.expectEqual(@as(u8, 'a'), event.bytes[1]);
    try std.testing.expect(router.pollAbiForTask(99) == null);
    router.deinit();
    router.bindHardwareSource(.{ .poll_report = pollTestReport, .input_proof = noTestProof });
    test_feed.cursor = 0;
    try std.testing.expectEqual(@as(usize, 0), router.service(43, DEFAULT_REPORT_BUDGET));
    try std.testing.expect(router.pollAbiForTask(99) == null);
    try std.testing.expect(router.pollWakeTarget() == null);
    try std.testing.expectEqual(@as(usize, 0), router.inboxes.countInUse());
    try std.testing.expectEqual(@as(u8, 0), router.queued_event_count);
}

test "input router delivers cursor editing semantics only to the focused task" {
    var runtime = task_runtime.Runtime.init();
    const app = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 5 },
        .component_class = .app_component,
        .budget = testTaskBudget(),
        .ui_surface_id = 45,
        .local_only = true,
    });
    var compositor = compositor_session.Session.init();
    _ = try compositor.openDocumentView(app, 7, "notes.md");
    var router = Router{};
    router.bindHardwareSource(.{ .poll_report = pollTestReport, .input_proof = noTestProof });
    router.bindCompositor(&compositor, 99);
    const usages = [_]u8{ 0x4A, 0x4D, 0x4F, 0x50, 0x51, 0x52, 0x4C, 0x4A, 0x4D, 0x50, 0x4F, 0x4A, 0x4D, 0x04, 0x1D, 0x1D };
    const modifiers = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 1, 1, 3 };
    const operations = [_]u8{
        abi.InputByte.line_start,     abi.InputByte.line_end,       abi.InputByte.cursor_right,
        abi.InputByte.cursor_left,    abi.InputByte.cursor_down,    abi.InputByte.cursor_up,
        abi.InputByte.delete_forward, abi.InputByte.document_start, abi.InputByte.document_end,
        abi.InputByte.cursor_left,    abi.InputByte.cursor_right,   abi.InputByte.document_start,
        abi.InputByte.document_end,   abi.InputByte.select_all,     abi.InputByte.undo,
        abi.InputByte.redo,
    };
    for (usages, operations, 0..) |usage, op, index| {
        test_feed = .{};
        test_feed.reports[0] = makeTestReport(index * 2 + 1, 1, modifiers[index], &.{usage});
        test_feed.reports[1] = makeTestReport(index * 2 + 2, 1, 0, &.{});
        test_feed.count = 2;
        try std.testing.expectEqual(@as(usize, 1), router.service(10, DEFAULT_REPORT_BUDGET));
        try std.testing.expect(router.pollAbiForTask(99) == null);
        const event = router.pollAbiForTask(app.id).?;
        try std.testing.expectEqual(op, event.bytes[0]);
        try std.testing.expectEqual(@as(u8, if (index >= 9 and index <= 12) abi.INPUT_EXTEND_SELECTION else 0), event.bytes[1]);
        try std.testing.expectEqual(app.id, event.task_id);
        try std.testing.expect(router.pollAbiForTask(app.id) == null);
    }
}

test "input router gives each keyboard independent transitions and targets modal review ownership" {
    var runtime = task_runtime.Runtime.init();
    const app = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 1 },
        .component_class = .app_component,
        .budget = testTaskBudget(),
        .ui_surface_id = 41,
        .local_only = true,
    });
    var compositor = compositor_session.Session.init();
    const review = try compositor.openDocumentView(app, 7, "review.md");
    _ = try compositor.setModalReviewer(review.id, 77);

    test_feed = .{};
    test_feed.reports[0] = makeTestReport(1, 1, 0, &.{0x04});
    test_feed.reports[1] = makeTestReport(2, 2, 0, &.{0x04});
    test_feed.count = 2;

    var router = Router{};
    router.bindHardwareSource(.{ .poll_report = pollTestReport, .input_proof = noTestProof });
    router.bindCompositor(&compositor, 99);
    const events_routed = router.service(10, DEFAULT_REPORT_BUDGET);
    try std.testing.expectEqual(@as(usize, 2), events_routed);
    try std.testing.expectEqual(@as(usize, 2), router.queuedForTask(77));
    const wire_event = router.pollAbiForTask(77).?;
    try std.testing.expectEqual(@as(u64, 1), wire_event.sequence);
    try std.testing.expectEqual(review.id, wire_event.window_id);
    try std.testing.expectEqual(@as(u64, 77), wire_event.task_id);
    try std.testing.expectEqual(abi.InputByte.text, wire_event.bytes[0]);
    try std.testing.expectEqual(@as(u8, 'a'), wire_event.bytes[1]);
    try std.testing.expectEqual(@as(u8, 'a'), router.pollForTask(77).?.event.data);
    try std.testing.expect(router.pollForTask(app.id) == null);
}

test "input router indexes inboxes and unlinks reused wake slots" {
    var router = Router{};
    const first_index = router.inboxForIndex(11).?;
    const second_index = router.inboxForIndex(22).?;
    try std.testing.expectEqual(@as(?usize, first_index), router.inboxes.slotIndexOf(11));
    try std.testing.expectEqual(@as(?usize, second_index), router.inboxes.slotIndexOf(22));
    try std.testing.expectEqual(@as(usize, 2), router.inboxes.countInUse());
    try std.testing.expectEqual(@as(u8, @intCast(first_index)), router.active_inbox_head);
    try std.testing.expectEqual(@as(u8, @intCast(second_index)), router.active_inbox_tail);

    router.queueWake(first_index);
    router.queueWake(first_index);
    router.queueWake(second_index);
    try std.testing.expectEqual(@as(usize, 0), router.dropForTask(11));
    try std.testing.expect(router.inboxes.slotIndexOf(11) == null);
    try std.testing.expectEqual(@as(usize, 1), router.inboxes.countInUse());

    const replacement_index = router.inboxForIndex(33).?;
    try std.testing.expectEqual(first_index, replacement_index);
    router.queueWake(replacement_index);
    try std.testing.expectEqual(@as(?u64, 22), router.pollWakeTarget());
    try std.testing.expectEqual(@as(?u64, 33), router.pollWakeTarget());
    try std.testing.expect(router.pollWakeTarget() == null);
    try std.testing.expectEqual(@as(u8, @intCast(second_index)), router.active_inbox_head);
    try std.testing.expectEqual(@as(u8, @intCast(replacement_index)), router.active_inbox_tail);
}

test "input router saturates its inbox arena and preserves the active chain across reuse" {
    var router = Router{};
    var slot_indexes: [MAX_INBOXES]usize = [_]usize{0} ** MAX_INBOXES;
    for (&slot_indexes, 0..) |*slot_index, task_offset| {
        slot_index.* = router.inboxForIndex(@intCast(task_offset + 1)).?;
    }

    try std.testing.expectEqual(@as(usize, MAX_INBOXES), router.inboxes.countInUse());
    try std.testing.expect(router.inboxForIndex(MAX_INBOXES + 1) == null);
    try std.testing.expectEqual(@as(u8, @intCast(slot_indexes[0])), router.active_inbox_head);
    try std.testing.expectEqual(@as(u8, @intCast(slot_indexes[MAX_INBOXES - 1])), router.active_inbox_tail);

    const removed_offset = MAX_INBOXES / 2;
    const removed_slot_index = slot_indexes[removed_offset];
    try std.testing.expectEqual(@as(usize, 0), router.dropForTask(@intCast(removed_offset + 1)));
    const replacement_index = router.inboxForIndex(MAX_INBOXES + 1).?;
    try std.testing.expectEqual(removed_slot_index, replacement_index);
    try std.testing.expectEqual(@as(usize, MAX_INBOXES), router.inboxes.countInUse());
    try std.testing.expectEqual(@as(u8, @intCast(replacement_index)), router.active_inbox_tail);

    var seen: [MAX_INBOXES]bool = [_]bool{false} ** MAX_INBOXES;
    var previous = NO_INBOX_INDEX;
    var active_index: usize = router.active_inbox_head;
    var active_count: usize = 0;
    while (active_index != NO_INBOX_INDEX) {
        try std.testing.expect(active_index < MAX_INBOXES);
        try std.testing.expect(!seen[active_index]);
        seen[active_index] = true;
        const inbox = &router.inboxes.slots[active_index];
        try std.testing.expect(inbox.in_use);
        try std.testing.expectEqual(previous, inbox.previous_active_index);
        previous = @intCast(active_index);
        active_index = inbox.next_active_index;
        active_count += 1;
    }
    try std.testing.expectEqual(@as(usize, MAX_INBOXES), active_count);
    try std.testing.expectEqual(router.active_inbox_tail, previous);
}

test "input router applies task switching before routing later reports" {
    var runtime = task_runtime.Runtime.init();
    const first = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 11 },
        .component_class = .app_component,
        .budget = testTaskBudget(),
        .ui_surface_id = 51,
        .local_only = true,
    });
    const second = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 12 },
        .component_class = .app_component,
        .budget = testTaskBudget(),
        .ui_surface_id = 52,
        .local_only = true,
    });
    var compositor = compositor_session.Session.init();
    const first_window = try compositor.openDocumentView(first, 1, "first.md");
    _ = try compositor.openDocumentView(second, 2, "second.md");

    test_feed = .{};
    test_feed.reports[0] = makeTestReport(1, 1, 0, &.{0x04});
    test_feed.reports[1] = makeTestReport(2, 1, 0, &.{});
    test_feed.reports[2] = makeTestReport(3, 1, 1 << 2, &.{0x2B});
    test_feed.reports[3] = makeTestReport(4, 1, 0, &.{});
    test_feed.reports[4] = makeTestReport(5, 1, 0, &.{0x05});
    test_feed.count = 5;

    var router = Router{};
    router.bindHardwareSource(.{ .poll_report = pollTestReport, .input_proof = noTestProof });
    router.bindCompositor(&compositor, 99);
    const events_routed = router.service(20, DEFAULT_REPORT_BUDGET);
    try std.testing.expectEqual(@as(usize, 3), events_routed);
    try std.testing.expectEqual(first_window.id, compositor.active_window_id);
    try std.testing.expectEqual(@as(u8, 'a'), router.pollForTask(second.id).?.event.data);
    try std.testing.expectEqual(@as(u8, 'b'), router.pollForTask(first.id).?.event.data);

    var woke_first = false;
    var woke_second = false;
    var woke_compositor = false;
    while (router.pollWakeTarget()) |task_id| {
        if (task_id == first.id) woke_first = true;
        if (task_id == second.id) woke_second = true;
        if (task_id == 99) woke_compositor = true;
    }
    try std.testing.expect(!woke_first and !woke_second and woke_compositor);
}

test "input router rejects stale and malformed reports and prunes closed-window input" {
    var runtime = task_runtime.Runtime.init();
    const app = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 21 },
        .component_class = .app_component,
        .budget = testTaskBudget(),
        .ui_surface_id = 61,
        .local_only = true,
    });
    var compositor = compositor_session.Session.init();
    _ = try compositor.openDocumentView(app, 1, "stale.md");

    test_feed = .{};
    test_feed.reports[0] = makeTestReport(2, 1, 0, &.{0x04});
    test_feed.reports[1] = makeTestReport(2, 1, 0, &.{0x05});
    test_feed.reports[2] = makeTestReport(3, 1, 0, &.{0x06});
    test_feed.reports[2].bytes[1] = 1;
    test_feed.count = 3;

    var router = Router{};
    router.bindHardwareSource(.{ .poll_report = pollTestReport, .input_proof = noTestProof });
    router.bindCompositor(&compositor, 99);
    const events_routed = router.service(30, DEFAULT_REPORT_BUDGET);
    try std.testing.expectEqual(@as(usize, 1), events_routed);
    try std.testing.expectEqual(@as(usize, 1), router.reports_accepted);
    try std.testing.expectEqual(@as(usize, 1), router.queuedForTask(app.id));

    const compositor_inbox_index = router.inboxForIndex(99).?;
    const stale_inbox_index = router.inboxForIndex(404).?;
    router.queueWake(compositor_inbox_index);
    router.queueWake(stale_inbox_index);
    try std.testing.expectEqual(@as(usize, 3), router.inboxes.countInUse());

    try std.testing.expectEqual(@as(usize, 1), compositor.closeWindowsForTask(app.id));
    _ = router.service(31, DEFAULT_REPORT_BUDGET);
    try std.testing.expectEqual(@as(usize, 0), router.queuedForTask(app.id));
    try std.testing.expect(router.inboxes.slotIndexOf(app.id) == null);
    try std.testing.expect(router.inboxes.slotIndexOf(404) == null);
    try std.testing.expectEqual(@as(?usize, compositor_inbox_index), router.inboxes.slotIndexOf(99));
    try std.testing.expectEqual(@as(usize, 1), router.inboxes.countInUse());
    try std.testing.expectEqual(@as(u8, @intCast(compositor_inbox_index)), router.active_inbox_head);
    try std.testing.expectEqual(@as(u8, @intCast(compositor_inbox_index)), router.active_inbox_tail);
    try std.testing.expectEqual(@as(?u64, 99), router.pollWakeTarget());
    try std.testing.expect(router.pollWakeTarget() == null);

    const replacement_index = router.inboxForIndex(505).?;
    try std.testing.expectEqual(stale_inbox_index, replacement_index);
    try std.testing.expectEqual(@as(usize, 2), router.inboxes.countInUse());
    try std.testing.expectEqual(@as(u8, @intCast(replacement_index)), router.active_inbox_tail);
}

test "input router keeps compositor switching responsive when a focused inbox is full" {
    var runtime = task_runtime.Runtime.init();
    const first = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 31 },
        .component_class = .app_component,
        .budget = testTaskBudget(),
        .ui_surface_id = 71,
        .local_only = true,
    });
    const second = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 32 },
        .component_class = .app_component,
        .budget = testTaskBudget(),
        .ui_surface_id = 72,
        .local_only = true,
    });
    const third = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 33 },
        .component_class = .app_component,
        .budget = testTaskBudget(),
        .ui_surface_id = 73,
        .local_only = true,
    });
    var compositor = compositor_session.Session.init();
    const first_window = try compositor.openDocumentView(first, 1, "first.md");
    const second_window = try compositor.openDocumentView(second, 2, "second.md");
    _ = try compositor.openDocumentView(third, 3, "third.md");

    var router = Router{};
    router.bindCompositor(&compositor, 99);
    const report = makeTestReport(1, 1, 0, &.{0x04});
    for (0..MAX_EVENTS_PER_INBOX) |_| {
        try std.testing.expect(router.routeEvent(&compositor, report, .{ .kind = .text, .data = 'a' }, 40));
    }
    try std.testing.expect(!router.routeEvent(&compositor, report, .{ .kind = .text, .data = 'b' }, 41));
    try std.testing.expect(router.routeEvent(&compositor, report, .{ .kind = .task_switch_next }, 42));
    try std.testing.expectEqual(first_window.id, compositor.active_window_id);

    for (0..MAX_EVENTS_PER_INBOX) |_| {
        try std.testing.expect(router.routeEvent(&compositor, report, .{ .kind = .text, .data = 'c' }, 43));
    }
    try std.testing.expectEqual(@as(u8, MAX_QUEUED_EVENTS), router.queued_event_count);
    try std.testing.expect(router.routeEvent(&compositor, report, .{ .kind = .task_switch_next }, 44));
    try std.testing.expectEqual(second_window.id, compositor.active_window_id);
    try std.testing.expect(!router.routeEvent(&compositor, report, .{ .kind = .text, .data = 'd' }, 45));

    var previous_sequence = router.pollForTask(third.id).?.sequence;
    try std.testing.expect(router.routeEvent(&compositor, report, .{ .kind = .text, .data = 'd' }, 46));
    try std.testing.expectEqual(@as(u8, MAX_QUEUED_EVENTS), router.queued_event_count);

    try std.testing.expectEqual(@as(usize, MAX_EVENTS_PER_INBOX - 1), router.dropForTask(third.id));
    try std.testing.expectEqual(@as(usize, 0), router.queuedForTask(third.id));
    try std.testing.expectEqual(@as(u8, MAX_EVENTS_PER_INBOX + 1), router.queued_event_count);
    for (0..MAX_EVENTS_PER_INBOX) |_| {
        const event = router.pollForTask(first.id).?;
        try std.testing.expect(event.sequence > previous_sequence);
        previous_sequence = event.sequence;
    }
    try std.testing.expect(router.pollForTask(second.id).?.sequence > previous_sequence);
    try std.testing.expectEqual(@as(u8, 0), router.queued_event_count);
}
