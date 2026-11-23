const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const native_ux = @import("../platform/native_ux.zig");
const policy_object = @import("../policy/policy_object.zig");
const public_store = @import("../services/public_store.zig");
const table_backing = @import("../core/table_backing.zig");

pub const STATE_SIZE_CEILING_BYTES: usize = policy_object.DIRECTORY_SIZE_CEILING_BYTES +
    native_ux.CONTROLLER_SIZE_CEILING_BYTES + public_store.CHANNEL_SIZE_CEILING_BYTES;

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

pub const Instance = struct {
    storage: table_backing.Lazy(State, null) = .{},

    pub inline fn initInto(
        self: *Instance,
        source_identity: []const u8,
        update_channel: manifest.UpdateChannel,
    ) error{NoSpaceLeft}!void {
        self.storage.release();
        const state = try self.storage.ensure();
        state.initializeAllocated(source_identity, update_channel);
    }

    pub fn deinit(self: *Instance) void {
        self.storage.release();
    }

    pub fn ptr(self: *Instance) *State {
        return self.storage.get().?;
    }
};

test "daily journey state initializes its heap storage" {
    try std.testing.expectEqual(STATE_SIZE_CEILING_BYTES, @sizeOf(State));

    var instance: Instance = .{};
    try instance.initInto("store:test/daily", .beta);
    defer instance.deinit();

    const state = instance.ptr();
    try std.testing.expectEqualStrings("store:test/daily", state.store_channel.source_identity);
    try std.testing.expectEqual(manifest.UpdateChannel.beta, state.store_channel.update_channel);
    try std.testing.expectEqual(@as(usize, 0), state.ux.flow_count);
    try std.testing.expectEqual(@as(u8, 0), state.store_channel.release_count);
    try std.testing.expectEqual(@as(u8, 0), state.store_channel.trusted_publisher_count);
}
