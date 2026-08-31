const std = @import("std");
const xhci = @import("../../kernel/drivers/xhci.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const permission_review_service = @import("../policy/permission_review_service.zig");
const transient_state = @import("transient_state.zig");

pub const HEAP_BACKED_ON_FREESTANDING = transient_state.HEAP_BACKED_ON_FREESTANDING;
pub const HANDLE_SIZE_CEILING_BYTES = transient_state.HANDLE_SIZE_CEILING_BYTES;
pub const STATE_SIZE_CEILING_BYTES: usize = @sizeOf(permission_review_service.ModeledInputSource) +
    compositor_session.CHECKPOINT_STORE_SIZE_CEILING_BYTES;

pub const State = struct {
    modeled_input: permission_review_service.ModeledInputSource,
    compositor_checkpoint: compositor_session.CheckpointStore,

    pub fn initializeAllocated(self: *State) xhci.Error!void {
        try self.modeled_input.initDefaultInto();
        self.compositor_checkpoint.initializeAllocated();
    }

    comptime {
        if (@sizeOf(@This()) > STATE_SIZE_CEILING_BYTES) {
            @compileError("production evidence state exceeded its fixed-state size ceiling");
        }
    }
};

const Storage = transient_state.ScopedState(State);

pub const Instance = struct {
    storage: Storage = .{},

    pub fn initInto(self: *Instance) (xhci.Error || error{NoSpaceLeft})!void {
        const state = try self.storage.begin();
        errdefer self.storage.deinit();
        try state.initializeAllocated();
    }

    pub fn deinit(self: *Instance) void {
        self.storage.deinit();
    }

    pub fn ptr(self: *Instance) *State {
        return self.storage.ptr();
    }
};

pub const FREESTANDING_HANDLE_SIZE_BYTES = transient_state.freestandingHandleSize(State);

test "host production evidence state retains initialized value storage" {
    try std.testing.expectEqual(@sizeOf(State), @sizeOf(Instance));
    try std.testing.expectEqual(STATE_SIZE_CEILING_BYTES, @sizeOf(State));

    var instance: Instance = .{};
    try instance.initInto();
    defer instance.deinit();

    const state = instance.ptr();
    try std.testing.expectEqual(@as(usize, 0), state.modeled_input.reports_consumed);
    try std.testing.expect(state.modeled_input.controller.configuredBootKeyboard() != null);
    try std.testing.expect(!state.compositor_checkpoint.valid);
}
