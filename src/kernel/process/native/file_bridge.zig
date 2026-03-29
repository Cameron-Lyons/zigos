const std = @import("std");
const capability = @import("capability.zig");
const native_util = @import("util.zig");
const object_store = @import("object_store.zig");
const signing = @import("signing.zig");
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
    ObjectMissing,
    PathNotFound,
    PermissionDenied,
    WorkspaceScopeViolation,
};

pub const Bridge = struct {
    store: *object_store.Store,
    workspaces: *workspace.Directory,

    pub fn init(store: *object_store.Store, workspaces: *workspace.Directory) Bridge {
        return .{
            .store = store,
            .workspaces = workspaces,
        };
    }

    pub fn resolve(
        self: *Bridge,
        request: ResolveRequest,
        authority: capability.Capability,
        now_ticks: u64,
    ) Error!View {
        const normalized_path = normalizePath(request.path);
        const entry = self.workspaces.resolve(request.workspace_id, normalized_path) catch return error.PathNotFound;

        if (!authority.lease.isActive(now_ticks)) return error.PermissionDenied;
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
        if (self.store.version(entry.version_id) == null) return error.ObjectMissing;

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

    var bridge = Bridge.init(&store, &workspaces);
    const read_capability = capability.Capability{
        .id = 1,
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
        .revocation_generation = 1,
        .audit = .{},
    };
    const view = try bridge.resolve(.{
        .workspace_id = notes.id,
        .path = "/documents/notes.md",
        .access = .read,
    }, read_capability, 30);
    try std.testing.expect(!view.authoritative);
    try std.testing.expectEqualStrings("documents/notes.md", view.pathSlice());
    try std.testing.expectEqual(object.version_id, view.version_id);

    try std.testing.expectError(error.PermissionDenied, bridge.resolve(.{
        .workspace_id = notes.id,
        .path = "documents/notes.md",
        .access = .write,
    }, read_capability, 30));

    const invalid_capability = capability.Capability{
        .id = 2,
        .holder = .{ .kind = .user, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 44 },
        .rights = .{},
        .scope = .{},
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
        .revocation_generation = 1,
        .audit = .{},
    };
    try std.testing.expectError(error.CapabilityRequired, bridge.resolve(.{
        .workspace_id = notes.id,
        .path = "documents/notes.md",
        .access = .read,
    }, invalid_capability, 30));
}
