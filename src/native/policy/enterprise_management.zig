const std = @import("std");
const device_graph = @import("../sync/device_graph.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const policy_object = @import("policy_object.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const Error = policy_object.Error || device_graph.Error || event_ledger.Error || error{
    NoActiveOrganizationPolicy,
    UnauthorizedCapability,
    SigningFailed,
    UnauthorizedAuthority,
    WrongOrganizationScope,
};

pub const AdminOperation = enum {
    apply_organization_policy,
    override_organization_policy,
    revoke_organization_policy,
    enroll_managed_device,
    revoke_managed_device,
};

pub const AdminCapabilityBundle = struct {
    apply_organization_policy: bool = false,
    override_organization_policy: bool = false,
    revoke_organization_policy: bool = false,
    enroll_managed_device: bool = false,
    revoke_managed_device: bool = false,

    pub fn permits(self: AdminCapabilityBundle, operation: AdminOperation) bool {
        return switch (operation) {
            .apply_organization_policy => self.apply_organization_policy,
            .override_organization_policy => self.override_organization_policy,
            .revoke_organization_policy => self.revoke_organization_policy,
            .enroll_managed_device => self.enroll_managed_device,
            .revoke_managed_device => self.revoke_managed_device,
        };
    }
};

pub const AdminSession = struct {
    organization_id: u64,
    authority: principal.PrincipalId,
    capabilities: AdminCapabilityBundle = .{},
};

pub const Manager = struct {
    organization_id: u64,
    authority_roots: *const principal.Keyring,
    policies: *policy_object.Directory,
    devices: *device_graph.Graph,
    ledger: *event_ledger.Ledger,

    pub fn init(
        organization_id: u64,
        authority_roots: *const principal.Keyring,
        policies: *policy_object.Directory,
        devices: *device_graph.Graph,
        ledger: *event_ledger.Ledger,
    ) Manager {
        return .{
            .organization_id = organization_id,
            .authority_roots = authority_roots,
            .policies = policies,
            .devices = devices,
            .ledger = ledger,
        };
    }

    pub fn applyOrganizationPolicy(
        self: *Manager,
        session: AdminSession,
        request: policy_object.CreateRequest,
        authority_signer: signing.SignerIdentity,
        tick: u64,
    ) Error!*policy_object.PolicyObject {
        return self.putOrganizationPolicy(session, request, authority_signer, tick, .applied, false);
    }

    pub fn overrideOrganizationPolicy(
        self: *Manager,
        session: AdminSession,
        request: policy_object.CreateRequest,
        authority_signer: signing.SignerIdentity,
        tick: u64,
    ) Error!*policy_object.PolicyObject {
        return self.putOrganizationPolicy(session, request, authority_signer, tick, .overridden, true);
    }

    pub fn revokeOrganizationPolicies(
        self: *Manager,
        session: AdminSession,
        authority_signer: signing.SignerIdentity,
        tick: u64,
    ) Error!usize {
        try self.requireAuthority(session, authority_signer, .revoke_organization_policy);
        const active_policy = self.policies.activeForScope(.organization, self.organization_id) orelse
            return error.NoActiveOrganizationPolicy;
        const active_policy_id = active_policy.id;
        const revoked = self.policies.revokePoliciesForScope(.organization, self.organization_id);
        if (revoked == 0) return error.NoActiveOrganizationPolicy;
        try self.ledger.recordPolicyChange(
            session.authority,
            active_policy_id,
            .revoked,
            tick,
            "organization policy revoked",
        );
        return revoked;
    }

    pub fn enrollManagedDevice(
        self: *Manager,
        session: AdminSession,
        authority_signer: signing.SignerIdentity,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        label: []const u8,
        user_authorizer: signing.SignerIdentity,
        device_identity: signing.SignerIdentity,
        tick: u64,
    ) Error!*device_graph.DeviceRecord {
        try self.requireAuthority(session, authority_signer, .enroll_managed_device);
        const device = try self.devices.enrollDevice(
            user_principal,
            device_principal,
            label,
            user_authorizer,
            device_identity,
            tick,
        );
        try self.ledger.recordDeviceTrustChange(
            session.authority,
            device_principal,
            true,
            tick,
            "managed device enrolled",
        );
        return device;
    }

    pub fn revokeManagedDevice(
        self: *Manager,
        session: AdminSession,
        authority_signer: signing.SignerIdentity,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        user_authorizer: signing.SignerIdentity,
        tick: u64,
    ) Error!void {
        try self.requireAuthority(session, authority_signer, .revoke_managed_device);
        try self.devices.revokeDevice(user_principal, device_principal, user_authorizer, tick);
        try self.ledger.recordDeviceTrustChange(
            session.authority,
            device_principal,
            false,
            tick,
            "managed device revoked",
        );
    }

    fn putOrganizationPolicy(
        self: *Manager,
        session: AdminSession,
        request: policy_object.CreateRequest,
        authority_signer: signing.SignerIdentity,
        tick: u64,
        action: event_ledger.PolicyChangeAction,
        require_existing: bool,
    ) Error!*policy_object.PolicyObject {
        const operation: AdminOperation = switch (action) {
            .applied => .apply_organization_policy,
            .overridden => .override_organization_policy,
            .revoked => .revoke_organization_policy,
        };
        try self.requireAuthority(session, authority_signer, operation);
        try self.requireOrganizationPolicyRequest(session, request);
        if (require_existing and self.policies.activeForScope(.organization, self.organization_id) == null) {
            return error.NoActiveOrganizationPolicy;
        }
        const policy = try self.createSignedPolicy(request, authority_signer);
        try self.ledger.recordPolicyChange(
            session.authority,
            policy.id,
            action,
            tick,
            policy.labelSlice(),
        );
        return policy;
    }

    fn requireAuthority(
        self: *const Manager,
        session: AdminSession,
        authority_signer: signing.SignerIdentity,
        operation: AdminOperation,
    ) Error!void {
        if (session.organization_id != self.organization_id) return error.WrongOrganizationScope;
        if (session.authority.kind != .policy_authority) return error.UnauthorizedAuthority;
        const public_key = signing.publicKey(authority_signer) catch return error.SigningFailed;
        if (!self.authority_roots.isPolicyAuthorityRootKey(session.authority, public_key)) {
            return error.UnauthorizedAuthority;
        }
        if (!session.capabilities.permits(operation)) return error.UnauthorizedCapability;
    }

    fn requireOrganizationPolicyRequest(
        self: *const Manager,
        session: AdminSession,
        request: policy_object.CreateRequest,
    ) Error!void {
        if (request.scope != .organization) return error.WrongOrganizationScope;
        if (request.subject_id != self.organization_id) return error.WrongOrganizationScope;
        if (!request.issuer.eql(session.authority)) return error.UnauthorizedAuthority;
    }

    fn createSignedPolicy(
        self: *Manager,
        request: policy_object.CreateRequest,
        authority_signer: signing.SignerIdentity,
    ) Error!*policy_object.PolicyObject {
        return self.policies.create(request, authority_signer) catch |err| switch (err) {
            error.InstallSourceTooLong => return error.InstallSourceTooLong,
            error.LabelTooLong => return error.LabelTooLong,
            error.NetworkDestinationTooLong => return error.NetworkDestinationTooLong,
            error.PolicyAlreadyRevoked => return error.PolicyAlreadyRevoked,
            error.PolicyNotFound => return error.PolicyNotFound,
            error.PolicyTableFull => return error.PolicyTableFull,
            error.SyncDestinationTooLong => return error.SyncDestinationTooLong,
            error.TooManyInstallSources => return error.TooManyInstallSources,
            error.TooManyNetworkDestinations => return error.TooManyNetworkDestinations,
            error.TooManySyncDestinations => return error.TooManySyncDestinations,
            else => return error.SigningFailed,
        };
    }
};

test "enterprise management applies overrides revokes and audits organization policy" {
    var roots = principal.Keyring.init();
    const authority = principal.PrincipalId{ .kind = .policy_authority, .serial = 42 };
    const authority_signer = signing.SignerIdentity{
        .label = "corp-root",
        .seed = [_]u8{0xA5} ** 32,
    };
    _ = try roots.bindPolicyAuthorityRoot(authority, try signing.publicKey(authority_signer));

    var policies = policy_object.Directory.init();
    var devices = device_graph.Graph.init();
    var ledger = event_ledger.Ledger.init();
    var manager = Manager.init(42, &roots, &policies, &devices, &ledger);
    const apply_only_session = AdminSession{
        .organization_id = 42,
        .authority = authority,
        .capabilities = .{ .apply_organization_policy = true },
    };
    const session = AdminSession{
        .organization_id = 42,
        .authority = authority,
        .capabilities = .{
            .apply_organization_policy = true,
            .override_organization_policy = true,
            .revoke_organization_policy = true,
        },
    };
    const subjects = policy_object.SubjectSet{ .organization_id = 42 };

    const untrusted_signer = signing.SignerIdentity{
        .label = "not-corp-root",
        .seed = [_]u8{0xA6} ** 32,
    };
    try std.testing.expectError(error.UnauthorizedAuthority, manager.applyOrganizationPolicy(session, .{
        .scope = .organization,
        .subject_id = 42,
        .issuer = authority,
        .label = "denied",
    }, untrusted_signer, 1));

    const baseline = try manager.applyOrganizationPolicy(apply_only_session, .{
        .scope = .organization,
        .subject_id = 42,
        .issuer = authority,
        .label = "corp-baseline",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{"store:zigos"},
        .network_egress_mode = .allow_list,
        .allowed_network_destinations = &.{"api.corp.example"},
        .allowed_sync_destinations = &.{"relay.corp.example"},
        .retention_days = 30,
        .audit_export_required = true,
    }, authority_signer, 10);
    try std.testing.expectEqual(@as(u32, 1), baseline.generation);
    try std.testing.expect(!policies.installSourceDecision(subjects, "repo:personal").allowed);
    try std.testing.expectEqual(event_ledger.PolicyChangeAction.applied, std.enums.fromInt(
        event_ledger.PolicyChangeAction,
        @as(u8, @intCast(ledger.latestKind(.policy_change).?.detail_code)),
    ).?);

    try std.testing.expectError(error.UnauthorizedCapability, manager.overrideOrganizationPolicy(apply_only_session, .{
        .scope = .organization,
        .subject_id = 42,
        .issuer = authority,
        .label = "not-delegated",
        .install_source_mode = .platform_store_only,
    }, authority_signer, 15));

    const override = try manager.overrideOrganizationPolicy(session, .{
        .scope = .organization,
        .subject_id = 42,
        .issuer = authority,
        .label = "corp-lockdown",
        .install_source_mode = .platform_store_only,
        .network_egress_mode = .none,
        .allowed_sync_destinations = &.{},
    }, authority_signer, 20);
    try std.testing.expectEqual(@as(u32, 2), override.generation);
    try std.testing.expectEqual(override.id, policies.activeForScope(.organization, 42).?.id);
    try std.testing.expect(!policies.networkEgressDecision(subjects, "api.corp.example").allowed);
    try std.testing.expectEqual(event_ledger.PolicyChangeAction.overridden, std.enums.fromInt(
        event_ledger.PolicyChangeAction,
        @as(u8, @intCast(ledger.latestKind(.policy_change).?.detail_code)),
    ).?);

    try std.testing.expectEqual(@as(usize, 2), try manager.revokeOrganizationPolicies(session, authority_signer, 30));
    try std.testing.expect(policies.activeForScope(.organization, 42) == null);
    try std.testing.expect(policies.installSourceDecision(subjects, "repo:personal").allowed);
    try std.testing.expectEqual(event_ledger.PolicyChangeAction.revoked, std.enums.fromInt(
        event_ledger.PolicyChangeAction,
        @as(u8, @intCast(ledger.latestKind(.policy_change).?.detail_code)),
    ).?);

    var export_buffer: [2048]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=policy_change") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "action=applied") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "action=overridden") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "action=revoked") != null);
}

test "enterprise management gates device trust administration through existing graph and audits it" {
    var roots = principal.Keyring.init();
    const authority = principal.PrincipalId{ .kind = .policy_authority, .serial = 77 };
    const authority_signer = signing.SignerIdentity{
        .label = "device-admin-root",
        .seed = [_]u8{0xB1} ** 32,
    };
    _ = try roots.bindPolicyAuthorityRoot(authority, try signing.publicKey(authority_signer));

    var policies = policy_object.Directory.init();
    var devices = device_graph.Graph.init();
    var ledger = event_ledger.Ledger.init();
    var manager = Manager.init(77, &roots, &policies, &devices, &ledger);

    const user = principal.PrincipalId{ .kind = .user, .serial = 7 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 700 };
    const user_signer = signing.SignerIdentity{
        .label = "managed-user-root",
        .seed = [_]u8{0xB2} ** 32,
    };
    const laptop_signer = signing.SignerIdentity{
        .label = "managed-laptop",
        .seed = [_]u8{0xB3} ** 32,
    };
    _ = try devices.ensureUserRoot(user, "managed-user", user_signer);

    const wrong_session = AdminSession{
        .organization_id = 77,
        .authority = .{ .kind = .policy_authority, .serial = 78 },
        .capabilities = .{ .enroll_managed_device = true },
    };
    try std.testing.expectError(error.UnauthorizedAuthority, manager.enrollManagedDevice(
        wrong_session,
        authority_signer,
        user,
        laptop,
        "laptop",
        user_signer,
        laptop_signer,
        10,
    ));

    const enroll_session = AdminSession{
        .organization_id = 77,
        .authority = authority,
        .capabilities = .{ .enroll_managed_device = true },
    };
    const session = AdminSession{
        .organization_id = 77,
        .authority = authority,
        .capabilities = .{
            .enroll_managed_device = true,
            .revoke_managed_device = true,
        },
    };
    const enrolled = try manager.enrollManagedDevice(
        enroll_session,
        authority_signer,
        user,
        laptop,
        "laptop",
        user_signer,
        laptop_signer,
        20,
    );
    try std.testing.expect(enrolled.isTrusted());
    try std.testing.expect(devices.isTrusted(laptop));
    try std.testing.expectEqual(event_ledger.EventKind.device_trust_change, ledger.latestKind(.device_trust_change).?.kind);
    try std.testing.expect(ledger.latestKind(.device_trust_change).?.allowed);

    try std.testing.expectError(error.UnauthorizedCapability, manager.revokeManagedDevice(
        enroll_session,
        authority_signer,
        user,
        laptop,
        user_signer,
        25,
    ));

    try manager.revokeManagedDevice(session, authority_signer, user, laptop, user_signer, 30);
    try std.testing.expect(!devices.isTrusted(laptop));
    try std.testing.expect(!ledger.latestKind(.device_trust_change).?.allowed);
    try std.testing.expectError(error.AlreadyRevoked, manager.revokeManagedDevice(
        session,
        authority_signer,
        user,
        laptop,
        user_signer,
        40,
    ));

    var export_buffer: [1024]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=device_trust_change") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "trusted=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "trusted=no") != null);
}
