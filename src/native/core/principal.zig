const std = @import("std");

pub const PrincipalKind = enum(u8) {
    user,
    device,
    app,
    service,
    policy_authority,
};

pub const PrincipalId = struct {
    kind: PrincipalKind,
    serial: u64,

    pub fn eql(self: PrincipalId, other: PrincipalId) bool {
        return self.kind == other.kind and self.serial == other.serial;
    }
};

pub const PrincipalRecord = struct {
    id: PrincipalId,
    label_len: usize,
    label: [48]u8,

    pub fn init(id: PrincipalId, label: []const u8) PrincipalRecord {
        var record = PrincipalRecord{
            .id = id,
            .label_len = @min(label.len, 47),
            .label = [_]u8{0} ** 48,
        };
        @memcpy(record.label[0..record.label_len], label[0..record.label_len]);
        return record;
    }

    pub fn labelSlice(self: *const PrincipalRecord) []const u8 {
        return self.label[0..self.label_len];
    }
};

pub fn kindName(kind: PrincipalKind) []const u8 {
    return switch (kind) {
        .user => "UserPrincipal",
        .device => "DevicePrincipal",
        .app => "AppPrincipal",
        .service => "ServicePrincipal",
        .policy_authority => "PolicyAuthorityPrincipal",
    };
}

test "principal records preserve identity and labels" {
    const id = PrincipalId{ .kind = .service, .serial = 7 };
    const record = PrincipalRecord.init(id, "session-manager");

    try std.testing.expect(record.id.eql(id));
    try std.testing.expectEqualStrings("session-manager", record.labelSlice());
    try std.testing.expectEqualStrings("ServicePrincipal", kindName(record.id.kind));
}
