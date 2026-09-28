const std = @import("std");
const object_signer = @import("../../native/storage/sealed_object_signer.zig");
const vault = @import("../../native/services/secret_vault_service.zig");
const policy = @import("../../native/policy/policy_object.zig");
const principal = @import("../../native/core/principal.zig");
const signing = @import("../../native/core/signing.zig");

// Explicit software sealing and policy fixtures. No production fallback.
// Retain this fixture at a stable address until all document channels close.
pub const Fixture = struct {
    service: vault.Service = .init(),
    policies: policy.Directory = .init(),
    authority: object_signer.Authority = undefined,

    pub fn init(self: *Fixture, owner: principal.PrincipalId, holder: principal.PrincipalId, task_id: u64, signer: signing.SignerIdentity) !object_signer.Signer {
        return self.initWithClipboard(owner, holder, task_id, signer, false);
    }

    pub fn initWithClipboard(self: *Fixture, owner: principal.PrincipalId, holder: principal.PrincipalId, task_id: u64, signer: signing.SignerIdentity, clipboard_allowed: bool) !object_signer.Signer {
        self.* = .{};
        self.service.attachHardwareProvider(@import("secret_provider.zig").provider());
        _ = try self.policies.create(.{
            .scope = .user,
            .subject_id = owner.serial,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .label = "document signing fixture",
            .secret_vault_allowed = true,
            .clipboard_allowed = clipboard_allowed,
            .require_hardware_backed_secrets = true,
            .deny_secret_raw_export = true,
            .max_secret_handle_lease_ticks = std.math.maxInt(u64),
        }, signer);
        self.authority = .{ .service = &self.service, .policies = &self.policies, .subjects = .{ .user_id = owner.serial }, .owner = owner, .holder = holder, .task_id = task_id };
        const secret = try self.service.importSecret(&self.policies, self.authority.subjects, .{ .owner = owner, .task_id = task_id, .label = signer.label, .raw = &signer.seed, .now_ticks = 0 }, null);
        const handle = try self.service.lendHandle(&self.policies, self.authority.subjects, .{
            .owner = owner,
            .holder = holder,
            .task_id = task_id,
            .secret_id = secret.id,
            .expires_at_ticks = std.math.maxInt(u64),
            .now_ticks = 0,
        }, null);
        return object_signer.Signer.bind(&self.authority, handle.id, 0);
    }
};
