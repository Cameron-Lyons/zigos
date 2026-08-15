const std = @import("std");
const xhci = @import("../../kernel/drivers/xhci.zig");
const input_driver_task = @import("../drivers/input_driver_task.zig");
const compositor_session = @import("compositor_session.zig");
const task_runtime = @import("../task/task_runtime.zig");

pub const MAX_KEYBOARDS: usize = 4;
pub const MAX_INBOXES: usize = compositor_session.MAX_WINDOWS + 1;
pub const MAX_QUEUED_EVENTS: usize = 32;
pub const MAX_EVENTS_PER_INBOX: usize = 16;
pub const DEFAULT_REPORT_BUDGET: usize = 16;

const NO_EVENT_INDEX: u8 = std.math.maxInt(u8);

comptime {
    std.debug.assert(MAX_QUEUED_EVENTS <= NO_EVENT_INDEX);
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

pub const ServiceResult = struct {
    reports_polled: usize = 0,
    reports_accepted: usize = 0,
    events_routed: usize = 0,
    events_dropped: usize = 0,
    focus_switches: usize = 0,
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
};

const EventSlot = struct {
    event: RoutedKeyboardEvent = undefined,
    next: u8 = NO_EVENT_INDEX,
};

const Inbox = struct {
    in_use: bool = false,
    task_id: u64 = 0,
    head: u8 = NO_EVENT_INDEX,
    tail: u8 = NO_EVENT_INDEX,
    count: u8 = 0,
    wake_pending: bool = false,
};

pub const Router = struct {
    source: ?HardwareReportSource = null,
    compositor: ?*compositor_session.Session = null,
    compositor_task_id: u64 = 0,
    keyboards: [MAX_KEYBOARDS]KeyboardSlot = [_]KeyboardSlot{.{}} ** MAX_KEYBOARDS,
    inboxes: [MAX_INBOXES]Inbox = [_]Inbox{.{}} ** MAX_INBOXES,
    event_slots: [MAX_QUEUED_EVENTS]EventSlot = [_]EventSlot{.{}} ** MAX_QUEUED_EVENTS,
    free_event_head: u8 = NO_EVENT_INDEX,
    event_pool_initialized: bool = false,
    queued_event_count: u8 = 0,
    last_sequence: u64 = 0,
    reports_polled: usize = 0,
    reports_accepted: usize = 0,
    invalid_reports: usize = 0,
    stale_reports: usize = 0,
    untracked_keyboard_reports: usize = 0,
    events_routed: usize = 0,
    events_dropped: usize = 0,
    stale_events_dropped: usize = 0,
    focus_switches: usize = 0,

    pub fn bindHardwareSource(self: *Router, source: HardwareReportSource) void {
        self.dropAllInboxes();
        self.source = source;
        self.last_sequence = 0;
        self.keyboards = [_]KeyboardSlot{.{}} ** MAX_KEYBOARDS;
    }

    pub fn clearHardwareSource(self: *Router) void {
        self.dropAllInboxes();
        self.source = null;
        self.last_sequence = 0;
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
            self.dropAllInboxes();
        }
        self.compositor = compositor;
        self.compositor_task_id = compositor_task_id;
    }

    pub fn clearCompositor(self: *Router) void {
        self.compositor = null;
        self.compositor_task_id = 0;
        self.dropAllInboxes();
    }

    pub fn service(self: *Router, now_ticks: u64, report_budget: usize) ServiceResult {
        var result = ServiceResult{};
        const source = self.source orelse return result;
        const compositor = self.compositor orelse return result;
        const focus_switches_before = self.focus_switches;
        self.pruneStaleInboxes(compositor);

        while (result.reports_polled < report_budget) {
            const report = source.poll_report() orelse break;
            result.reports_polled += 1;
            self.reports_polled += 1;

            if (!validTopology(report)) {
                self.invalid_reports += 1;
                continue;
            }
            if (self.last_sequence != 0 and report.sequence <= self.last_sequence) {
                self.stale_reports += 1;
                continue;
            }
            self.last_sequence = report.sequence;

            const keyboard = self.keyboardFor(report) orelse {
                self.untracked_keyboard_reports += 1;
                continue;
            };
            _ = keyboard.decoder.submit(report.bytes) catch {
                self.invalid_reports += 1;
                continue;
            };
            result.reports_accepted += 1;
            self.reports_accepted += 1;

            while (keyboard.decoder.poll()) |event| {
                if (self.routeEvent(compositor, report, event, now_ticks)) {
                    result.events_routed += 1;
                } else {
                    result.events_dropped += 1;
                }
            }
        }

        result.focus_switches = self.focus_switches - focus_switches_before;
        return result;
    }

    pub fn pollForTask(self: *Router, task_id: u64) ?RoutedKeyboardEvent {
        const inbox = self.findInbox(task_id) orelse return null;
        if (inbox.count == 0) return null;
        const event_index = inbox.head;
        const event_slot = &self.event_slots[event_index];
        const event = event_slot.event;
        inbox.head = event_slot.next;
        inbox.count -= 1;
        if (inbox.count == 0) {
            inbox.tail = NO_EVENT_INDEX;
            inbox.wake_pending = false;
        }
        self.releaseEvent(event_index);
        return event;
    }

    pub fn queuedForTask(self: *const Router, task_id: u64) usize {
        const inbox = self.findInboxConst(task_id) orelse return 0;
        return @intCast(inbox.count);
    }

    pub fn pollWakeTarget(self: *Router) ?u64 {
        for (&self.inboxes) |*inbox| {
            if (!inbox.in_use or !inbox.wake_pending) continue;
            inbox.wake_pending = false;
            return inbox.task_id;
        }
        return null;
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
                _ = compositor.switchVisible(if (event.kind == .task_switch_next) .next else .previous) catch {
                    self.events_dropped += 1;
                    return false;
                };
                self.focus_switches += 1;
                self.events_routed += 1;
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
        if (target_task_id == 0) {
            self.events_dropped += 1;
            return false;
        }

        const routed = RoutedKeyboardEvent{
            .sequence = report.sequence,
            .tick = now_ticks,
            .window_id = if (active) |window| window.id else 0,
            .task_id = target_task_id,
            .surface_id = if (active) |window| window.ui_surface_id orelse 0 else 0,
            .port_id = report.port_id,
            .slot_id = report.slot_id,
            .event = event,
        };
        const inbox = self.inboxFor(target_task_id) orelse {
            self.events_dropped += 1;
            return false;
        };
        if (inbox.count == MAX_EVENTS_PER_INBOX) {
            self.events_dropped += 1;
            return false;
        }
        const event_index = self.allocateEvent() orelse {
            self.events_dropped += 1;
            return false;
        };
        const was_empty = inbox.count == 0;
        self.event_slots[event_index] = .{ .event = routed };
        if (inbox.tail == NO_EVENT_INDEX) {
            inbox.head = event_index;
        } else {
            self.event_slots[inbox.tail].next = event_index;
        }
        inbox.tail = event_index;
        inbox.count += 1;
        self.events_routed += 1;
        if (was_empty) inbox.wake_pending = true;
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

    fn inboxFor(self: *Router, task_id: u64) ?*Inbox {
        if (self.findInbox(task_id)) |inbox| return inbox;
        for (&self.inboxes) |*inbox| {
            if (inbox.in_use) continue;
            inbox.* = .{ .in_use = true, .task_id = task_id };
            return inbox;
        }
        return null;
    }

    fn findInbox(self: *Router, task_id: u64) ?*Inbox {
        for (&self.inboxes) |*inbox| {
            if (inbox.in_use and inbox.task_id == task_id) return inbox;
        }
        return null;
    }

    fn findInboxConst(self: *const Router, task_id: u64) ?*const Inbox {
        for (&self.inboxes) |*inbox| {
            if (inbox.in_use and inbox.task_id == task_id) return inbox;
        }
        return null;
    }

    fn markWake(self: *Router, task_id: u64) void {
        if (task_id == 0) return;
        const inbox = self.inboxFor(task_id) orelse return;
        inbox.wake_pending = true;
    }

    fn pruneStaleInboxes(self: *Router, compositor: *const compositor_session.Session) void {
        for (&self.inboxes) |*inbox| {
            if (!inbox.in_use or inbox.task_id == self.compositor_task_id) continue;
            if (taskOwnsVisibleWindow(compositor, inbox.task_id)) continue;
            self.stale_events_dropped += inbox.count;
            self.releaseInboxEvents(inbox);
            inbox.* = .{};
        }
    }

    fn dropAllInboxes(self: *Router) void {
        for (&self.inboxes) |*inbox| {
            self.stale_events_dropped += inbox.count;
            inbox.* = .{};
        }
        self.resetEventPool();
    }

    fn allocateEvent(self: *Router) ?u8 {
        if (!self.event_pool_initialized) self.resetEventPool();
        if (self.free_event_head == NO_EVENT_INDEX) return null;
        const event_index = self.free_event_head;
        self.free_event_head = self.event_slots[event_index].next;
        self.event_slots[event_index].next = NO_EVENT_INDEX;
        self.queued_event_count += 1;
        return event_index;
    }

    fn releaseEvent(self: *Router, event_index: u8) void {
        self.event_slots[event_index].next = self.free_event_head;
        self.free_event_head = event_index;
        self.queued_event_count -= 1;
    }

    fn releaseInboxEvents(self: *Router, inbox: *Inbox) void {
        var event_index = inbox.head;
        while (event_index != NO_EVENT_INDEX) {
            const next = self.event_slots[event_index].next;
            self.releaseEvent(event_index);
            event_index = next;
        }
    }

    fn resetEventPool(self: *Router) void {
        for (&self.event_slots, 0..) |*slot, index| {
            slot.next = if (index + 1 < self.event_slots.len)
                @intCast(index + 1)
            else
                NO_EVENT_INDEX;
        }
        self.free_event_head = 0;
        self.queued_event_count = 0;
        self.event_pool_initialized = true;
    }
};

fn validTopology(report: xhci.HardwareBootKeyboardReport) bool {
    return report.sequence != 0 and report.port_id != 0 and report.slot_id != 0 and
        report.endpoint_id != 0;
}

fn taskOwnsVisibleWindow(compositor: *const compositor_session.Session, task_id: u64) bool {
    for (0..compositor.window_count) |index| {
        const window = compositor.windowAtOrder(index) orelse continue;
        if (!window.visible) continue;
        if (window.subject_task_id == task_id or
            (window.modal and window.reviewer_task_id == task_id)) return true;
    }
    return false;
}

const TestFeed = struct {
    reports: [8]xhci.HardwareBootKeyboardReport = [_]xhci.HardwareBootKeyboardReport{.{}} ** 8,
    count: usize = 0,
    cursor: usize = 0,
};

var test_feed = TestFeed{};

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
    review.modal = true;
    review.reviewer_task_id = 77;

    test_feed = .{};
    test_feed.reports[0] = makeTestReport(1, 1, 0, &.{0x04});
    test_feed.reports[1] = makeTestReport(2, 2, 0, &.{0x04});
    test_feed.count = 2;

    var router = Router{};
    router.bindHardwareSource(.{ .poll_report = pollTestReport, .input_proof = noTestProof });
    router.bindCompositor(&compositor, 99);
    const serviced = router.service(10, DEFAULT_REPORT_BUDGET);
    try std.testing.expectEqual(@as(usize, 2), serviced.reports_accepted);
    try std.testing.expectEqual(@as(usize, 2), router.queuedForTask(77));
    try std.testing.expectEqual(@as(u8, 'a'), router.pollForTask(77).?.event.text);
    try std.testing.expectEqual(@as(u8, 'a'), router.pollForTask(77).?.event.text);
    try std.testing.expect(router.pollForTask(app.id) == null);
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
    const serviced = router.service(20, DEFAULT_REPORT_BUDGET);
    try std.testing.expectEqual(@as(usize, 1), serviced.focus_switches);
    try std.testing.expectEqual(first_window.id, compositor.active_window_id);
    try std.testing.expectEqual(@as(u8, 'a'), router.pollForTask(second.id).?.event.text);
    try std.testing.expectEqual(@as(u8, 'b'), router.pollForTask(first.id).?.event.text);

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
    const serviced = router.service(30, DEFAULT_REPORT_BUDGET);
    try std.testing.expectEqual(@as(usize, 1), serviced.reports_accepted);
    try std.testing.expectEqual(@as(usize, 1), router.stale_reports);
    try std.testing.expectEqual(@as(usize, 1), router.invalid_reports);
    try std.testing.expectEqual(@as(usize, 1), router.queuedForTask(app.id));

    try std.testing.expectEqual(@as(usize, 1), compositor.closeWindowsForTask(app.id));
    _ = router.service(31, DEFAULT_REPORT_BUDGET);
    try std.testing.expectEqual(@as(usize, 0), router.queuedForTask(app.id));
    try std.testing.expectEqual(@as(usize, 1), router.stale_events_dropped);
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
        try std.testing.expect(router.routeEvent(&compositor, report, .{ .kind = .text, .text = 'a' }, 40));
    }
    try std.testing.expect(!router.routeEvent(&compositor, report, .{ .kind = .text, .text = 'b' }, 41));
    try std.testing.expect(router.routeEvent(&compositor, report, .{ .kind = .task_switch_next }, 42));
    try std.testing.expectEqual(first_window.id, compositor.active_window_id);
    try std.testing.expectEqual(@as(usize, 1), router.events_dropped);
    try std.testing.expectEqual(@as(usize, 1), router.focus_switches);

    for (0..MAX_EVENTS_PER_INBOX) |_| {
        try std.testing.expect(router.routeEvent(&compositor, report, .{ .kind = .text, .text = 'c' }, 43));
    }
    try std.testing.expectEqual(@as(u8, MAX_QUEUED_EVENTS), router.queued_event_count);
    try std.testing.expect(router.routeEvent(&compositor, report, .{ .kind = .task_switch_next }, 44));
    try std.testing.expectEqual(second_window.id, compositor.active_window_id);
    try std.testing.expect(!router.routeEvent(&compositor, report, .{ .kind = .text, .text = 'd' }, 45));

    try std.testing.expect(router.pollForTask(third.id) != null);
    try std.testing.expect(router.routeEvent(&compositor, report, .{ .kind = .text, .text = 'd' }, 46));
    try std.testing.expectEqual(@as(u8, MAX_QUEUED_EVENTS), router.queued_event_count);
    try std.testing.expectEqual(@as(usize, 2), router.events_dropped);
    try std.testing.expectEqual(@as(usize, 2), router.focus_switches);
}
