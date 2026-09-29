//! Closed set of native identity interactions sharing exclusive input routing.
//! This is not an application ABI; owners and their views stay at stable addresses.
const auth = @import("trusted_auth_entry.zig");
const setup = @import("trusted_setup_entry.zig");
const input = @import("../drivers/input_driver_task.zig");

pub const View = union(enum) {
    none,
    authentication: *const auth.View,
    setup: *const setup.View,
    pub fn visible(self: View) bool {
        return switch (self) {
            .none => false,
            .authentication => |view| view.status != .hidden,
            .setup => true,
        };
    }
};

pub const Entry = union(enum) {
    authentication: *auth.Entry,
    setup: *setup.Entry,
    pub fn view(self: Entry) View {
        return switch (self) {
            .authentication => |entry| .{ .authentication = &entry.view },
            .setup => |entry| .{ .setup = &entry.view },
        };
    }
    pub fn revision(self: Entry) u64 {
        return switch (self) {
            inline else => |entry| entry.revision,
        };
    }
    pub fn lastTicks(self: Entry) u64 {
        return switch (self) {
            inline else => |entry| entry.last_ticks,
        };
    }
    pub fn capturing(self: Entry) bool {
        return switch (self) {
            inline else => |entry| entry.capturing(),
        };
    }
    pub fn nextWake(self: Entry) ?u64 {
        return switch (self) {
            inline else => |entry| entry.nextWake(),
        };
    }
    pub fn lock(self: Entry, now: u64) void {
        switch (self) {
            inline else => |entry| entry.lock(now),
        }
    }
    pub fn tick(self: Entry, now: u64) void {
        switch (self) {
            inline else => |entry| entry.tick(now),
        }
    }
    pub fn inputInterrupted(self: Entry, now: u64) void {
        switch (self) {
            inline else => |entry| entry.inputInterrupted(now),
        }
    }
    pub fn handle(self: Entry, event: input.KeyboardEvent, now: u64) void {
        switch (self) {
            inline else => |entry| entry.handle(event, now),
        }
    }
    pub fn quiesce(self: Entry) void {
        switch (self) {
            inline else => |entry| entry.quiesce(),
        }
    }
    pub fn prepareWork(self: Entry, now: u64) bool {
        return switch (self) {
            .authentication => |entry| entry.prepareVerification(now),
            .setup => |entry| entry.prepareWork(now),
        };
    }
    pub fn runWork(self: Entry, now: u64) void {
        switch (self) {
            .authentication => |entry| entry.verify(now),
            .setup => |entry| entry.runWork(now),
        }
    }
};
