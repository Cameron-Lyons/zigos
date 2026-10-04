const std = @import("std");
const component_port = @import("../kernel_api/component_port.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const ids = @import("../core/ids.zig");
const object_signer = @import("sealed_object_signer.zig");
const mailbox = @import("../task/userspace_bootstrap_mailbox.zig");
const ipc = @import("document_save_ipc.zig");
const storage_service = @import("storage_service.zig");
const workspace = @import("workspace.zig");

pub const OpenRequest = struct {
    authority: storage_service.AuthorityContext,
    client_bootstrap_capability_id: u64,
    server_bootstrap_capability_id: u64,
    workspace_id: u64,
    path: []const u8,
    signer: object_signer.Signer,
};

// Initialize and retain in stable storage. The server borrows only this
// channel's path copy and the session-owned signing authority and StoragePort.
pub const Channel = struct {
    server: ?ipc.Server = null,
    storage: storage_service.StoragePort = undefined,
    client_endpoint_id: u64 = 0,
    server_endpoint_id: u64 = 0,
    path: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined,

    pub fn open(
        self: *Channel,
        kernel: *component_port.KernelPort,
        core: *storage_service.Service,
        request: OpenRequest,
        now_ticks: u64,
    ) !mailbox.DocumentBinding {
        if (self.server != null) return error.DocumentAlreadyOpen;
        if (request.path.len > self.path.len) return error.PathTooLong;
        const task = kernel.kernel.runtime.find(request.authority.task_id) orelse return error.TaskNotFound;
        if (task.state != .active or !task.owner.eql(request.authority.principal) or
            !task.hasCapability(request.authority.capability_id)) return error.PermissionDenied;
        const service = kernel.kernel.runtime.find(core.task_id) orelse return error.TaskNotFound;
        if (service.state != .active or !service.owner.eql(core.owner)) return error.PermissionDenied;

        self.storage = storage_service.StoragePort.init(core, kernel.kernel.capability_table);
        var authority = request.authority;
        authority.now_ticks = now_ticks;
        const view = try self.storage.openEntry(authority, request.workspace_id, request.path, .read);
        if (view.object_type != .document) return error.NotDocument;
        try self.storage.requireDocumentWrite(authority, request.workspace_id, request.path, view.object_id.raw());
        try request.signer.validateService(core.owner, core.task_id, now_ticks);

        const client = try kernel.endpointCreate(.{
            .header = component_port.makeHeader(.endpoint_create, task.id),
            .authority_capability_id = request.client_bootstrap_capability_id,
            .owner_task_id = task.id,
            .label = "document-client",
            .flags = .{ .local_only = true },
        }, now_ticks);
        errdefer kernel.kernel.retireEndpoint(ids.endpoint(client.endpoint.endpoint_id), now_ticks) catch unreachable;
        const server = try kernel.endpointCreate(.{
            .header = component_port.makeHeader(.endpoint_create, core.task_id),
            .authority_capability_id = request.server_bootstrap_capability_id,
            .owner_task_id = core.task_id,
            .label = "document-service",
            .flags = .{ .local_only = true, .service_port = true },
        }, now_ticks);
        errdefer kernel.kernel.retireEndpoint(ids.endpoint(server.endpoint.endpoint_id), now_ticks) catch unreachable;
        _ = try kernel.endpointConnect(.{
            .header = component_port.makeHeader(.endpoint_connect, task.id),
            .endpoint_capability_id = client.capability_id,
            .peer_endpoint_capability_id = server.capability_id,
            .peer_endpoint_id = server.endpoint.endpoint_id,
        }, now_ticks);

        @memcpy(self.path[0..request.path.len], request.path);
        self.client_endpoint_id = client.endpoint.endpoint_id;
        self.server_endpoint_id = server.endpoint.endpoint_id;
        self.server = .{
            .kernel = kernel,
            .storage = &self.storage,
            .binding = .{
                .client_endpoint_id = self.client_endpoint_id,
                .server_endpoint_capability_id = server.capability_id,
                .authority = authority,
                .workspace_id = request.workspace_id,
                .path = self.path[0..request.path.len],
                .object_id = view.object_id.raw(),
                .signer = request.signer,
            },
        };
        return .{
            .endpoint_capability_id = client.capability_id,
            .service_endpoint_id = self.server_endpoint_id,
            .object_id = view.object_id.raw(),
            .version_id = view.version_id.raw(),
        };
    }

    pub fn taskId(self: *const Channel) u64 {
        return if (self.server) |*server| server.binding.authority.task_id else 0;
    }

    pub fn hasPendingWork(self: *const Channel) bool {
        const server = if (self.server) |*value| value else return false;
        if (server.running) return false;
        if (server.closing) return true;
        switch (self.peerState()) {
            .closed => return true,
            .suspended => return false,
            .active => {},
        }
        const table = server.kernel.kernel.endpoint_table;
        if (server.pending_reply != null) {
            const client = table.descriptor(ids.endpoint(self.client_endpoint_id)) catch return true;
            return client.queued_messages < endpoint.MAX_ENDPOINT_QUEUE;
        }
        const source = table.descriptor(ids.endpoint(self.server_endpoint_id)) catch return true;
        return source.queued_messages != 0;
    }

    const PeerState = enum { closed, suspended, active };

    fn peerState(self: *const Channel) PeerState {
        const server = if (self.server) |*value| value else return .closed;
        const runtime = server.kernel.kernel.runtime;
        const task = runtime.findConst(server.binding.authority.task_id) orelse return .closed;
        const service = runtime.findConst(server.storage.core.task_id) orelse return .closed;
        if (task.state == .terminated or service.state == .terminated) return .closed;
        _ = server.kernel.kernel.endpoint_table.descriptor(ids.endpoint(self.client_endpoint_id)) catch return .closed;
        _ = server.kernel.kernel.endpoint_table.descriptor(ids.endpoint(self.server_endpoint_id)) catch return .closed;
        if (task.state == .suspended or service.state == .suspended) return .suspended;
        return .active;
    }

    // One request or retained reply per call. A dead client cannot leave a
    // queued commit that executes after its document channel is closed.
    pub fn runOnce(self: *Channel, now_ticks: u64) bool {
        const server = if (self.server) |*value| value else return false;
        if (server.running) return false;
        if (server.closing) {
            self.close(now_ticks);
            return true;
        }
        switch (self.peerState()) {
            .closed => {
                self.close(now_ticks);
                return true;
            },
            .suspended => return false,
            .active => {},
        }
        const progress = server.runOnce(now_ticks) catch {
            self.close(now_ticks);
            return true;
        };
        if (server.closing) self.close(now_ticks);
        return progress;
    }

    pub fn close(self: *Channel, now_ticks: u64) void {
        const server = if (self.server) |*value| value else return;
        server.closing = true;
        const kernel = server.kernel.kernel;
        for ([_]u64{ self.server_endpoint_id, self.client_endpoint_id }) |endpoint_id| {
            kernel.retireEndpoint(ids.endpoint(endpoint_id), now_ticks) catch |err| switch (err) {
                error.EndpointNotFound => {},
                else => unreachable,
            };
        }
        // Cancel and detach immediately, but a suspended command still borrows
        // this server, its path and upload bytes until its terminal return.
        if (server.running) return;
        // Assign the inactive optional before erasing it: Debug assignments
        // may poison its payload, which must not retain upload or signing bytes.
        self.server = null;
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

comptime {
    if (@sizeOf(Channel) > 1280) @compileError("document channel exceeds its bounded storage");
}
