const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const workspace = @import("workspace.zig");
const copyText = native_util.copyText;

pub const AccessMode = enum(u8) {
    read,
    write,
};

pub const ResolveRequest = struct {
    workspace_id: u64,
    path: []const u8,
    access: AccessMode,
};

pub const View = struct {
    authoritative: bool = false,
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    object_type: object_store.ObjectType,
    readable: bool,
    writable: bool,
    path_len: usize,
    path: [96]u8,

    pub fn pathSlice(self: *const View) []const u8 {
        return self.path[0..self.path_len];
    }
};

pub const Error = error{
    CapabilityRequired,
    CapabilityNotFound,
    CapabilityRevoked,
    ObjectMissing,
    PathNotFound,
    PermissionDenied,
    WorkspaceScopeViolation,
};

pub const ResolveEntryFn = *const fn (
    context: *const anyopaque,
    workspace_id: u64,
    path: []const u8,
) workspace.Error!workspace.Entry;

pub const HasVersionFn = *const fn (context: *const anyopaque, version_id: u64) bool;

pub const Bridge = struct {
    context: *const anyopaque,
    capability_table: *const capability.CapabilityTable,
    resolve_entry: ResolveEntryFn,
    has_version: HasVersionFn,

    pub fn init(
        context: *const anyopaque,
        capability_table: *const capability.CapabilityTable,
        resolve_entry: ResolveEntryFn,
        has_version: HasVersionFn,
    ) Bridge {
        return .{
            .context = context,
            .capability_table = capability_table,
            .resolve_entry = resolve_entry,
            .has_version = has_version,
        };
    }

    pub fn resolve(
        self: *Bridge,
        request: ResolveRequest,
        requester: principal.PrincipalId,
        authority_capability_id: u64,
        now_ticks: u64,
    ) Error!View {
        const normalized_path = normalizePath(request.path);
        const entry = self.resolve_entry(self.context, request.workspace_id, normalized_path) catch return error.PathNotFound;
        const authority = self.capability_table.requireUsable(authority_capability_id, now_ticks) catch |err| switch (err) {
            error.CapabilityNotFound => return error.CapabilityNotFound,
            error.CapabilityRevoked => return error.CapabilityRevoked,
            else => unreachable,
        };
        if (!authority.holder.eql(requester)) return error.PermissionDenied;
        if (authority.scope.workspace_id) |workspace_id| {
            if (workspace_id != request.workspace_id) return error.WorkspaceScopeViolation;
        }

        switch (authority.target.kind) {
            .object => if (authority.target.id != entry.object_id) return error.PermissionDenied,
            .workspace => if (authority.target.id != request.workspace_id) return error.WorkspaceScopeViolation,
            else => return error.CapabilityRequired,
        }

        const wants_write = request.access == .write;
        if (wants_write and !authority.rights.object_write) return error.PermissionDenied;
        if (!wants_write and !authority.rights.object_read) return error.PermissionDenied;
        if (!self.has_version(self.context, entry.version_id)) return error.ObjectMissing;

        var view = View{
            .workspace_id = request.workspace_id,
            .object_id = entry.object_id,
            .version_id = entry.version_id,
            .object_type = entry.object_type,
            .readable = authority.rights.object_read,
            .writable = authority.rights.object_write,
            .path_len = 0,
            .path = [_]u8{0} ** 96,
        };
        view.path_len = copyText(&view.path, normalized_path);
        return view;
    }
};

fn normalizePath(path: []const u8) []const u8 {
    if (path.len != 0 and path[0] == '/') return path[1..];
    return path;
}

test "file bridge is derived, permission-aware, and non-authoritative" {
    const TestContext = struct {
        store: *object_store.Store,
        workspaces: *const workspace.Directory,
    };

    var store = object_store.Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0x91} ** 32,
    };
    const object = try store.putVersion(.{
        .preferred_object_id = 900,
        .object_type = .document,
        .payload = "hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "hello", 10),
    });

    var workspaces = workspace.Directory.init();
    const notes = try workspaces.create(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });
    try workspaces.beginTransaction(notes.id);
    try workspaces.stagePut(notes.id, "documents/notes.md", object.object_id, object.version_id, .document);
    _ = try workspaces.commit(notes.id, 20);
    var test_context = TestContext{
        .store = &store,
        .workspaces = &workspaces,
    };

    const resolve_entry = struct {
        fn call(context: *const anyopaque, workspace_id: u64, path: []const u8) workspace.Error!workspace.Entry {
            const bridge_context: *const TestContext = @ptrCast(@alignCast(context));
            return bridge_context.workspaces.resolve(workspace_id, path);
        }
    }.call;
    const has_version = struct {
        fn call(context: *const anyopaque, version_id: u64) bool {
            const bridge_context: *const TestContext = @ptrCast(@alignCast(context));
            return bridge_context.store.version(version_id) != null;
        }
    }.call;
    var capabilities = capability.CapabilityTable.init();
    var bridge = Bridge.init(&test_context, &capabilities, resolve_entry, has_version);
    const read_capability = try capabilities.mint(.{
        .holder = .{ .kind = .user, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .object, .id = object.object_id },
        .rights = .{ .object_read = true },
        .scope = .{
            .task_id = 7,
            .workspace_id = notes.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
        .audit = .{},
    });
    const view = try bridge.resolve(.{
        .workspace_id = notes.id,
        .path = "/documents/notes.md",
        .access = .read,
    }, read_capability.holder, read_capability.id, 30);
    try std.testing.expect(!view.authoritative);
    try std.testing.expectEqualStrings("documents/notes.md", view.pathSlice());
    try std.testing.expectEqual(object.version_id, view.version_id);

    try std.testing.expectError(error.PermissionDenied, bridge.resolve(.{
        .workspace_id = notes.id,
        .path = "documents/notes.md",
        .access = .write,
    }, read_capability.holder, read_capability.id, 30));

    const invalid_capability = try capabilities.mint(.{
        .holder = .{ .kind = .user, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 44 },
        .rights = .{},
        .scope = .{},
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
        .audit = .{},
    });
    try std.testing.expectError(error.CapabilityRequired, bridge.resolve(.{
        .workspace_id = notes.id,
        .path = "documents/notes.md",
        .access = .read,
    }, invalid_capability.holder, invalid_capability.id, 30));
}
