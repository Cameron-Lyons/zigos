const builtin = @import("builtin");
const std = @import("std");
const channel = @import("../storage/document_channel.zig");
const component_port = @import("../kernel_api/component_port.zig");
const storage_service = @import("../storage/storage_service.zig");
const mailbox = @import("../task/userspace_bootstrap_mailbox.zig");
const object_signer = @import("../storage/sealed_object_signer.zig");
const kernel_memory = if (builtin.target.os.tag == .freestanding) @import("../../kernel/memory/memory.zig") else struct {};

pub const OpenRequest = channel.OpenRequest;
pub const MAX_CHANNELS: usize = 4;
pub const DISPATCH_BUDGET: usize = 2;
const Channels = [MAX_CHANNELS]channel.Channel;
const heap_backed = builtin.target.os.tag == .freestanding;
const Backing = if (heap_backed) ?*Channels else Channels;

pub const Sessions = struct {
    backing: Backing = if (heap_backed) null else @as([MAX_CHANNELS]channel.Channel, @splat(.{})),
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

    pub fn hasLiveDocument(self: *const Sessions, task_id: u64, capability_id: u64, workspace_id: u64, object_id: u64, path: []const u8) bool {
        const items = self.channelsConst() orelse return false;
        for (items) |*item| if (item.server) |*server| {
            const binding = server.binding;
            if (!server.closing and binding.authority.task_id == task_id and binding.authority.capability_id == capability_id and
                binding.workspace_id == workspace_id and binding.object_id == object_id and std.mem.eql(u8, binding.path, path)) return true;
        };
        return false;
    }

    pub fn cancelForAuthority(self: *Sessions, authority: *const object_signer.Authority, now_ticks: u64) void {
        const items = self.channels() orelse return;
        for (items) |*item| {
            if (item.server) |*server| if (server.binding.signer.key.authority == authority) item.close(now_ticks);
        }
    }

    pub fn hasAuthority(self: *const Sessions, authority: *const object_signer.Authority) bool {
        const items = self.channelsConst() orelse return false;
        for (items) |*item| {
            if (item.server) |*server| if (server.binding.signer.key.authority == authority) return true;
        }
        return false;
    }

    // Explicit clipboard gestures use the document's existing authority and
    // session policy context. They never grant ambient clipboard observation.
    pub fn allowsClipboard(self: *Sessions, task_id: u64, writing: bool, now_ticks: u64) bool {
        const items = self.channels() orelse return false;
        for (items) |*item| {
            const server = if (item.server) |*value| value else continue;
            if (item.taskId() != task_id) continue;
            if (server.closing) return false;
            const task = server.kernel.kernel.runtime.findConst(task_id) orelse return false;
            if (task.state != .active or !task.owner.eql(server.binding.authority.principal) or
                !task.hasCapability(server.binding.authority.capability_id)) return false;
            var authority = server.binding.authority;
            authority.now_ticks = now_ticks;
            const entry = server.storage.openEntry(authority, server.binding.workspace_id, server.binding.path, if (writing) .write else .read) catch return false;
            if (entry.object_id.raw() != server.binding.object_id or entry.object_type != .document) return false;
            server.binding.signer.validateService(server.storage.core.owner, server.storage.core.task_id, now_ticks) catch return false;
            const context = server.binding.signer.key.authority orelse return false;
            var subjects = context.subjects;
            subjects.workspace_id = server.binding.workspace_id;
            return context.policies.permissionKindDecision(subjects, .clipboard).allowed;
        }
        return false;
    }

    pub fn service(self: *Sessions, now_ticks: u64) bool {
        return self.serviceOwned(null, now_ticks);
    }

    pub fn serviceForSigner(self: *Sessions, signer: object_signer.Signer, now_ticks: u64) bool {
        return self.serviceOwned(signer, now_ticks);
    }

    fn serviceOwned(self: *Sessions, signer: ?object_signer.Signer, now_ticks: u64) bool {
        const items = self.channels() orelse return false;
        var progress: usize = 0;
        for (0..MAX_CHANNELS) |_| {
            const item = &items[self.cursor];
            self.cursor = @intCast((self.cursor + 1) % MAX_CHANNELS);
            if (signer) |key| if (!matchesSigner(item, key)) continue;
            if (item.server != null and item.runOnce(now_ticks)) progress += 1;
            if (progress == DISPATCH_BUDGET) break;
        }
        return progress != 0;
    }

    pub fn hasPendingWork(self: *const Sessions) bool {
        return self.hasPendingOwned(null);
    }

    pub fn hasPendingForSigner(self: *const Sessions, signer: object_signer.Signer) bool {
        return self.hasPendingOwned(signer);
    }

    fn hasPendingOwned(self: *const Sessions, signer: ?object_signer.Signer) bool {
        const items = self.channelsConst() orelse return false;
        for (items) |*item| {
            if (signer) |key| if (!matchesSigner(item, key)) continue;
            if (item.hasPendingWork()) return true;
        }
        return false;
    }

    pub fn requireQuiescent(self: *const Sessions) error{DocumentOperationBusy}!void {
        const items = self.channelsConst() orelse return;
        for (items) |*item| {
            if (item.server) |*server| if (server.running) return error.DocumentOperationBusy;
        }
    }

    pub fn deinit(self: *Sessions, now_ticks: u64) error{DocumentOperationBusy}!void {
        // Refuse before any endpoint, channel or backing storage is changed.
        try self.requireQuiescent();
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

fn matchesSigner(item: *const channel.Channel, signer: object_signer.Signer) bool {
    const server = if (item.server) |*value| value else return false;
    const key = server.binding.signer.key;
    return key.authority == signer.key.authority and key.handle_id == signer.key.handle_id and
        std.mem.eql(u8, &key.sealed_digest, &signer.key.sealed_digest);
}

comptime {
    if (heap_backed and @sizeOf(Sessions) > 16) @compileError("document session handle exceeds its resident size bound");
}
