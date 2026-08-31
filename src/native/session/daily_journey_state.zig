const builtin = @import("builtin");
const std = @import("std");
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/memory/memory.zig")
else
    struct {};
const manifest = @import("../policy/manifest.zig");
const native_ux = @import("../platform/native_ux.zig");
const policy_object = @import("../policy/policy_object.zig");
const public_store = @import("../services/public_store.zig");

pub const HEAP_BACKED_ON_FREESTANDING = true;
pub const HANDLE_SIZE_CEILING_BYTES: usize = 8;
pub const STATE_SIZE_CEILING_BYTES: usize = policy_object.DIRECTORY_SIZE_CEILING_BYTES +
    native_ux.CONTROLLER_SIZE_CEILING_BYTES + public_store.CHANNEL_SIZE_CEILING_BYTES;
const heap_backed = builtin.target.os.tag == .freestanding and HEAP_BACKED_ON_FREESTANDING;

pub const State = struct {
    policies: policy_object.Directory,
    ux: native_ux.Controller,
    store_channel: public_store.Channel,

    pub inline fn initializeAllocated(
        self: *State,
        source_identity: []const u8,
        update_channel: manifest.UpdateChannel,
    ) void {
        self.policies.initializeAllocated();
        self.ux.initializeAllocated();
        self.store_channel.initializeAllocated(source_identity, update_channel);
    }

    comptime {
        if (@sizeOf(@This()) > STATE_SIZE_CEILING_BYTES) {
            @compileError("daily journey state exceeded its fixed-state size ceiling");
        }
    }
};

const Backing = if (heap_backed) ?*State else State;

pub const Instance = struct {
    backing: Backing = if (heap_backed) null else undefined,

    pub inline fn initInto(
        self: *Instance,
        source_identity: []const u8,
        update_channel: manifest.UpdateChannel,
    ) error{NoSpaceLeft}!void {
        if (comptime heap_backed) {
            self.backing = null;
            const allocation = kernel_memory.kmalloc(@sizeOf(State)) orelse return error.NoSpaceLeft;
            const state: *State = @ptrCast(@alignCast(allocation));
            state.initializeAllocated(source_identity, update_channel);
            self.backing = state;
        } else {
            self.backing.initializeAllocated(source_identity, update_channel);
        }
    }

    pub fn deinit(self: *Instance) void {
        if (comptime heap_backed) {
            if (self.backing) |state| {
                @memset(std.mem.asBytes(state), 0);
                kernel_memory.kfree(@ptrCast(state));
                self.backing = null;
            }
        } else {
            self.* = undefined;
        }
    }

    pub fn ptr(self: *Instance) *State {
        if (comptime heap_backed) return self.backing.?;
        return &self.backing;
    }
};

pub const FREESTANDING_HANDLE_SIZE_BYTES: usize = if (HEAP_BACKED_ON_FREESTANDING)
    @sizeOf(?*State)
else
    @sizeOf(State);

test "host daily journey state retains initialized value storage" {
    if (heap_backed) return;
    try std.testing.expectEqual(@sizeOf(State), @sizeOf(Instance));
    try std.testing.expectEqual(STATE_SIZE_CEILING_BYTES, @sizeOf(State));

    var instance: Instance = undefined;
    try instance.initInto("store:test/daily", .beta);
    defer instance.deinit();

    const state = instance.ptr();
    try std.testing.expectEqualStrings("store:test/daily", state.store_channel.source_identity);
    try std.testing.expectEqual(manifest.UpdateChannel.beta, state.store_channel.update_channel);
    try std.testing.expectEqual(@as(usize, 0), state.ux.flow_count);
    try std.testing.expectEqual(@as(u8, 0), state.store_channel.release_count);
    try std.testing.expectEqual(@as(u8, 0), state.store_channel.trusted_publisher_count);
}
