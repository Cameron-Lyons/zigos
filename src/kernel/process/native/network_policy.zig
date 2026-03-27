const std = @import("std");
const principal = @import("principal.zig");

pub const MAX_POLICIES: usize = 16;
pub const MAX_LABEL_BYTES: usize = 48;
pub const MAX_TARGET_BYTES: usize = 64;

pub const PolicyMode = enum(u8) {
    none,
    local_network,
    named_service_identity,
    named_domain,
    unrestricted_internet,
};

pub const DecisionReason = enum(u8) {
    none,
    policy_denied,
    destination_mismatch,
    explicit_grant_required,
};

pub const Destination = union(enum) {
    local_network,
    service_identity: []const u8,
    domain: []const u8,
    public_internet,
};

pub const CreateRequest = struct {
    owner: principal.PrincipalId,
    workspace_id: ?u64 = null,
    label: []const u8,
    mode: PolicyMode,
    target: []const u8 = "",
    explicit_internet_grant: bool = false,
};

pub const PolicyRecord = struct {
    id: u64,
    owner: principal.PrincipalId,
    workspace_id: ?u64,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    mode: PolicyMode,
    target_len: usize,
    target: [MAX_TARGET_BYTES]u8,
    explicit_internet_grant: bool,

    pub fn labelSlice(self: *const PolicyRecord) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn targetSlice(self: *const PolicyRecord) []const u8 {
        return self.target[0..self.target_len];
    }
};

pub const Decision = struct {
    allowed: bool,
    reason: DecisionReason = .none,
    matched_mode: PolicyMode = .none,
};

pub const Error = error{
    PolicyNotFound,
    PolicyTableFull,
};

const PolicySlot = struct {
    in_use: bool = false,
    policy: PolicyRecord = zeroPolicy(),
};

pub const Directory = struct {
    next_policy_id: u64 = 1,
    policies: [MAX_POLICIES]PolicySlot = [_]PolicySlot{PolicySlot{}} ** MAX_POLICIES,

    pub fn init() Directory {
        return .{};
    }

    pub fn reset(self: *Directory) void {
        self.next_policy_id = 1;
        for (&self.policies) |*slot| {
            slot.* = .{};
        }
    }

    pub fn create(self: *Directory, request: CreateRequest) Error!*PolicyRecord {
        for (&self.policies) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.policy = zeroPolicy();
            slot.policy.id = self.nextPolicyId();
            slot.policy.owner = request.owner;
            slot.policy.workspace_id = request.workspace_id;
            slot.policy.label_len = copyText(&slot.policy.label, request.label);
            slot.policy.mode = request.mode;
            slot.policy.target_len = copyText(&slot.policy.target, request.target);
            slot.policy.explicit_internet_grant = request.explicit_internet_grant;
            return &slot.policy;
        }
        return error.PolicyTableFull;
    }

    pub fn find(self: *Directory, policy_id: u64) ?*PolicyRecord {
        for (&self.policies) |*slot| {
            if (slot.in_use and slot.policy.id == policy_id) return &slot.policy;
        }
        return null;
    }

    pub fn authorize(self: *Directory, policy_id: u64, destination: Destination) Error!Decision {
        const policy = self.find(policy_id) orelse return error.PolicyNotFound;
        return switch (policy.mode) {
            .none => .{
                .allowed = false,
                .reason = .policy_denied,
                .matched_mode = .none,
            },
            .local_network => switch (destination) {
                .local_network => .{
                    .allowed = true,
                    .matched_mode = .local_network,
                },
                else => .{
                    .allowed = false,
                    .reason = .destination_mismatch,
                    .matched_mode = .local_network,
                },
            },
            .named_service_identity => switch (destination) {
                .service_identity => |identity| .{
                    .allowed = std.mem.eql(u8, identity, policy.targetSlice()),
                    .reason = if (std.mem.eql(u8, identity, policy.targetSlice())) .none else .destination_mismatch,
                    .matched_mode = .named_service_identity,
                },
                else => .{
                    .allowed = false,
                    .reason = .destination_mismatch,
                    .matched_mode = .named_service_identity,
                },
            },
            .named_domain => switch (destination) {
                .domain => |domain| .{
                    .allowed = std.mem.eql(u8, domain, policy.targetSlice()),
                    .reason = if (std.mem.eql(u8, domain, policy.targetSlice())) .none else .destination_mismatch,
                    .matched_mode = .named_domain,
                },
                else => .{
                    .allowed = false,
                    .reason = .destination_mismatch,
                    .matched_mode = .named_domain,
                },
            },
            .unrestricted_internet => blk: {
                if (!policy.explicit_internet_grant) {
                    break :blk .{
                        .allowed = false,
                        .reason = .explicit_grant_required,
                        .matched_mode = .unrestricted_internet,
                    };
                }
                break :blk switch (destination) {
                    .public_internet, .domain => .{
                        .allowed = true,
                        .matched_mode = .unrestricted_internet,
                    },
                    else => .{
                        .allowed = false,
                        .reason = .destination_mismatch,
                        .matched_mode = .unrestricted_internet,
                    },
                };
            },
        };
    }

    fn nextPolicyId(self: *Directory) u64 {
        defer self.next_policy_id += 1;
        return self.next_policy_id;
    }
};

fn zeroPolicy() PolicyRecord {
    return .{
        .id = 0,
        .owner = .{ .kind = .service, .serial = 0 },
        .workspace_id = null,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .mode = .none,
        .target_len = 0,
        .target = [_]u8{0} ** MAX_TARGET_BYTES,
        .explicit_internet_grant = false,
    };
}

fn copyText(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
}

test "network policy objects enforce local service domain and explicit internet grants" {
    var directory = Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 8 };

    const none_policy = try directory.create(.{
        .owner = owner,
        .label = "none",
        .mode = .none,
    });
    const local_policy = try directory.create(.{
        .owner = owner,
        .label = "local",
        .mode = .local_network,
    });
    const service_policy = try directory.create(.{
        .owner = owner,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
    });
    const domain_policy = try directory.create(.{
        .owner = owner,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    });
    const internet_policy = try directory.create(.{
        .owner = owner,
        .label = "internet",
        .mode = .unrestricted_internet,
        .explicit_internet_grant = true,
    });

    try std.testing.expect(!(try directory.authorize(none_policy.id, .public_internet)).allowed);
    try std.testing.expect((try directory.authorize(local_policy.id, .local_network)).allowed);
    try std.testing.expect(!(try directory.authorize(local_policy.id, .{ .domain = "relay.zigos.dev" })).allowed);
    try std.testing.expect((try directory.authorize(service_policy.id, .{ .service_identity = "overlay.notes.sync" })).allowed);
    try std.testing.expect(!(try directory.authorize(service_policy.id, .{ .service_identity = "overlay.other" })).allowed);
    try std.testing.expect((try directory.authorize(domain_policy.id, .{ .domain = "relay.zigos.dev" })).allowed);
    try std.testing.expect(!(try directory.authorize(domain_policy.id, .{ .domain = "example.com" })).allowed);
    try std.testing.expect((try directory.authorize(internet_policy.id, .public_internet)).allowed);
}
