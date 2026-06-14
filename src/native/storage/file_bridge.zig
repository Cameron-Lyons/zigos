const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const ids = @import("../core/ids.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const workspace = @import("workspace.zig");

pub const AccessMode = enum(u8) {
    read,
    write,
};

pub const MAX_BRIDGE_PATH_BYTES: usize = workspace.MAX_ENTRY_PATH_BYTES;

pub const ResolveRequest = struct {
    workspace_id: u64,
    path: []const u8,
    access: AccessMode,
};

pub const View = struct {
    authoritative: bool = false,
    export_only: bool = true,
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    object_type: object_store.ObjectType,
    readable: bool,
    writable: bool,
    path_len: usize,
    path: [MAX_BRIDGE_PATH_BYTES]u8,

    pub fn pathSlice(self: *const View) []const u8 {
        return self.path[0..self.path_len];
    }
};

pub const Error = error{
    CapabilityRequired,
    CapabilityNotFound,
    CapabilityRevoked,
    ObjectMissing,
    PathAuthorityRejected,
    PathSyntaxInvalid,
    PathTooLong,
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
        const bridge_path = validateBridgePath(request.path) catch |err| switch (err) {
            error.PathAuthorityRejected => return error.PathAuthorityRejected,
            error.PathSyntaxInvalid => return error.PathSyntaxInvalid,
            error.PathTooLong => return error.PathTooLong,
        };
        const authority = self.capability_table.requireUsable(authority_capability_id, now_ticks) catch |err| switch (err) {
            error.CapabilityNotFound => return error.CapabilityNotFound,
            error.CapabilityRevoked => return error.CapabilityRevoked,
            else => native_util.impossibleByInvariantError("file bridge authority lookup only reports not-found or revoked capabilities", err),
        };
        if (!authority.holder.eql(requester)) return error.PermissionDenied;
        if (authority.scope.workspace_id) |workspace_id| {
            if (workspace_id != request.workspace_id) return error.WorkspaceScopeViolation;
        }

        switch (authority.target.kind) {
            .workspace => if (authority.target.id != request.workspace_id) return error.WorkspaceScopeViolation,
            .object => {},
            else => return error.CapabilityRequired,
        }

        const wants_write = request.access == .write;
        // File bridges are derived views. Mutations must go through storage objects
        // and workspace transactions, never through a bridge path.
        if (wants_write) return error.PermissionDenied;
        if (!wants_write and !authority.rights.has(.object_read)) return error.PermissionDenied;

        const entry = switch (authority.target.kind) {
            .workspace => blk: {
                break :blk self.resolve_entry(self.context, request.workspace_id, bridge_path) catch return error.PathNotFound;
            },
            .object => blk: {
                const resolved = self.resolve_entry(self.context, request.workspace_id, bridge_path) catch return error.PermissionDenied;
                if (authority.target.id != resolved.object_id.raw()) return error.PermissionDenied;
                break :blk resolved;
            },
            else => native_util.impossibleByInvariant("authority target kind was validated before resolving file bridge entry"),
        };

        if (!self.has_version(self.context, entry.version_id.raw())) return error.ObjectMissing;

        var view = View{
            .workspace_id = request.workspace_id,
            .object_id = entry.object_id.raw(),
            .version_id = entry.version_id.raw(),
            .object_type = entry.object_type,
            .readable = authority.rights.has(.object_read),
            .writable = false,
            .path_len = 0,
            .path = [_]u8{0} ** MAX_BRIDGE_PATH_BYTES,
        };
        view.path_len = native_util.copyTextExact(&view.path, bridge_path) catch return error.PathTooLong;
        return view;
    }
};

pub fn validateBridgePath(path: []const u8) error{ PathAuthorityRejected, PathSyntaxInvalid, PathTooLong }![]const u8 {
    if (path.len == 0) return error.PathSyntaxInvalid;
    if (path.len > MAX_BRIDGE_PATH_BYTES) return error.PathTooLong;
    if (path[0] == '/' or path[0] == '~') return error.PathAuthorityRejected;
    if (looksLikeDrivePath(path)) return error.PathAuthorityRejected;

    var segment_start: usize = 0;
    for (path, 0..) |byte, index| {
        switch (byte) {
            0, '\\' => return error.PathAuthorityRejected,
            '/' => {
                if (!validBridgeSegment(path[segment_start..index])) return error.PathSyntaxInvalid;
                segment_start = index + 1;
            },
            else => {},
        }
    }
    if (!validBridgeSegment(path[segment_start..])) return error.PathSyntaxInvalid;
    return path;
}

fn validBridgeSegment(segment: []const u8) bool {
    if (segment.len == 0) return false;
    if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
    return true;
}

fn looksLikeDrivePath(path: []const u8) bool {
    return path.len >= 2 and std.ascii.isAlphabetic(path[0]) and path[1] == ':';
}

test "file bridge is derived, permission-aware, and non-authoritative" {
    const TestContext = struct {
        store: *object_store.Store,
        workspaces: *const workspace.Directory,
    };

    var store = object_store.Store.init();
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = signing.seedFromByte(0x91),
    };
    const object = try store.putVersion(.{
        .preferred_object_id = ids.object(900),
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
            return bridge_context.workspaces.resolve(ids.workspace(workspace_id), path);
        }
    }.call;
    const has_version = struct {
        fn call(context: *const anyopaque, version_id: u64) bool {
            const bridge_context: *const TestContext = @ptrCast(@alignCast(context));
            return bridge_context.store.version(ids.version(version_id)) != null;
        }
    }.call;
    var capabilities = capability.CapabilityTable.init();
    var bridge = Bridge.init(&test_context, &capabilities, resolve_entry, has_version);
    const read_capability = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .user, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .object, .id = object.object_id.raw() },
        .rights = .{ .object = .{ .object_read = true } },
        .scope = .{
            .task_id = 7,
            .workspace_id = notes.id.raw(),
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
        .workspace_id = notes.id.raw(),
        .path = "documents/notes.md",
        .access = .read,
    }, read_capability.holder, read_capability.id, 30);
    try std.testing.expect(!view.authoritative);
    try std.testing.expect(view.export_only);
    try std.testing.expect(!view.writable);
    try std.testing.expectEqualStrings("documents/notes.md", view.pathSlice());
    try std.testing.expectEqual(object.version_id.raw(), view.version_id);

    try std.testing.expectError(error.PathAuthorityRejected, bridge.resolve(.{
        .workspace_id = notes.id.raw(),
        .path = "/documents/notes.md",
        .access = .read,
    }, read_capability.holder, read_capability.id, 30));
    try std.testing.expectError(error.PathAuthorityRejected, bridge.resolve(.{
        .workspace_id = notes.id.raw(),
        .path = "~/documents/notes.md",
        .access = .read,
    }, read_capability.holder, read_capability.id, 30));
    try std.testing.expectError(error.PathAuthorityRejected, bridge.resolve(.{
        .workspace_id = notes.id.raw(),
        .path = "C:\\Users\\writer\\notes.md",
        .access = .read,
    }, read_capability.holder, read_capability.id, 30));
    try std.testing.expectError(error.PathSyntaxInvalid, bridge.resolve(.{
        .workspace_id = notes.id.raw(),
        .path = "../documents/notes.md",
        .access = .read,
    }, read_capability.holder, read_capability.id, 30));
    try std.testing.expectError(error.PathSyntaxInvalid, bridge.resolve(.{
        .workspace_id = notes.id.raw(),
        .path = "documents//notes.md",
        .access = .read,
    }, read_capability.holder, read_capability.id, 30));
    try std.testing.expectError(error.PathSyntaxInvalid, bridge.resolve(.{
        .workspace_id = notes.id.raw(),
        .path = "",
        .access = .read,
    }, read_capability.holder, read_capability.id, 30));

    try std.testing.expectError(error.PermissionDenied, bridge.resolve(.{
        .workspace_id = notes.id.raw(),
        .path = "documents/notes.md",
        .access = .write,
    }, read_capability.holder, read_capability.id, 30));
    try std.testing.expectError(error.PermissionDenied, bridge.resolve(.{
        .workspace_id = notes.id.raw(),
        .path = "documents/missing.md",
        .access = .read,
    }, read_capability.holder, read_capability.id, 30));
    try std.testing.expectError(error.PermissionDenied, bridge.resolve(.{
        .workspace_id = notes.id.raw(),
        .path = "documents/missing.md",
        .access = .read,
    }, .{ .kind = .user, .serial = 2 }, read_capability.id, 30));

    const invalid_capability = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .user, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 44 },
        .rights = .{ .service = .{} },
        .scope = .{},
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
        .audit = .{},
    });
    try std.testing.expectError(error.CapabilityRequired, bridge.resolve(.{
        .workspace_id = notes.id.raw(),
        .path = "documents/notes.md",
        .access = .read,
    }, invalid_capability.holder, invalid_capability.id, 30));
    try std.testing.expectError(error.CapabilityRequired, bridge.resolve(.{
        .workspace_id = notes.id.raw(),
        .path = "documents/missing.md",
        .access = .read,
    }, invalid_capability.holder, invalid_capability.id, 30));
}
