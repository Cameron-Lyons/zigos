const builtin = @import("builtin");
const std = @import("std");
const channel = @import("../storage/document_channel.zig");
const component_port = @import("../kernel_api/component_port.zig");
const storage_service = @import("../storage/storage_service.zig");
const mailbox = @import("../task/userspace_bootstrap_mailbox.zig");
const kernel_memory = if (builtin.target.os.tag == .freestanding) @import("../../kernel/memory/memory.zig") else struct {};

pub const OpenRequest = channel.OpenRequest;
pub const MAX_CHANNELS: usize = 4;
pub const DISPATCH_BUDGET: usize = 2;
const Channels = [MAX_CHANNELS]channel.Channel;
const heap_backed = builtin.target.os.tag == .freestanding;
const Backing = if (heap_backed) ?*Channels else Channels;

pub const Sessions = struct {
    backing: Backing = if (heap_backed) null else [_]channel.Channel{.{}} ** MAX_CHANNELS,
    cursor: u8 = 0,

    fn channels(self: *Sessions) ?*Channels {
        if (comptime heap_backed) return self.backing;
        return &self.backing;
    }

    fn channelsConst(self: *const Sessions) ?*const Channels {
        if (comptime heap_backed) return self.backing;
        return &self.backing;
    }

    fn ensureChannels(self: *Sessions) error{NoSpaceLeft}!*Channels {
        if (self.channels()) |items| return items;
        if (comptime heap_backed) {
            const allocation = kernel_memory.kmalloc(@sizeOf(Channels)) orelse return error.NoSpaceLeft;
            const items: *Channels = @ptrCast(@alignCast(allocation));
            for (items) |*item| item.* = .{};
            self.backing = items;
            return items;
        }
        return &self.backing;
    }

    pub fn open(self: *Sessions, kernel: *component_port.KernelPort, storage: *storage_service.Service, request: OpenRequest, now_ticks: u64) !mailbox.DocumentBinding {
        const items = try self.ensureChannels();
        for (items) |*item| {
            if (item.server != null and item.taskId() == request.authority.task_id) return error.DocumentAlreadyOpen;
        }
        for (items) |*item| {
            if (item.server == null) return item.open(kernel, storage, request, now_ticks);
        }
        return error.DocumentTableFull;
    }

    pub fn closeTask(self: *Sessions, task_id: u64, now_ticks: u64) void {
        const items = self.channels() orelse return;
        for (items) |*item| {
            if (item.taskId() == task_id) item.close(now_ticks);
        }
    }

    // Explicit clipboard gestures use the document's existing authority and
    // session policy context. They never grant ambient clipboard observation.
    pub fn allowsClipboard(self: *Sessions, task_id: u64, writing: bool, now_ticks: u64) bool {
        const items = self.channels() orelse return false;
        for (items) |*item| {
            const server = if (item.server) |*value| value else continue;
            if (item.taskId() != task_id) continue;
            const task = server.kernel.kernel.runtime.findConst(task_id) orelse return false;
            if (task.state != .active or !task.owner.eql(server.binding.authority.principal) or
                !task.hasCapability(server.binding.authority.capability_id)) return false;
            var authority = server.binding.authority;
            authority.now_ticks = now_ticks;
            const entry = server.storage.openEntry(authority, server.binding.workspace_id, server.binding.path, if (writing) .write else .read) catch return false;
            if (entry.object_id.raw() != server.binding.object_id or entry.object_type != .document) return false;
            const context = server.binding.signer.key.authority orelse return false;
            var subjects = context.subjects;
            subjects.workspace_id = server.binding.workspace_id;
            return context.policies.permissionKindDecision(subjects, .clipboard).allowed;
        }
        return false;
    }

    pub fn service(self: *Sessions, now_ticks: u64) bool {
        const items = self.channels() orelse return false;
        var progress: usize = 0;
        for (0..MAX_CHANNELS) |_| {
            const item = &items[self.cursor];
            self.cursor = @intCast((self.cursor + 1) % MAX_CHANNELS);
            if (item.server != null and item.runOnce(now_ticks)) progress += 1;
            if (progress == DISPATCH_BUDGET) break;
        }
        return progress != 0;
    }

    pub fn hasPendingWork(self: *const Sessions) bool {
        const items = self.channelsConst() orelse return false;
        for (items) |*item| {
            if (item.hasPendingWork()) return true;
        }
        return false;
    }

    pub fn deinit(self: *Sessions, now_ticks: u64) void {
        const items = self.channels() orelse return;
        for (items) |*item| item.close(now_ticks);
        if (comptime heap_backed) {
            @memset(std.mem.asBytes(items), 0);
            kernel_memory.kfree(@ptrCast(items));
            self.backing = null;
        }
        self.cursor = 0;
    }
};

comptime {
    if (heap_backed and @sizeOf(Sessions) > 16) @compileError("document session handle exceeds its resident size bound");
}
