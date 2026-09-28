const identity = @import("../../native/platform/os_identity.zig");
const vault = @import("../../native/services/secret_vault_service.zig");
const policy = @import("../../native/policy/policy_object.zig");
const principal = @import("../../native/core/principal.zig");
const signing = @import("../../native/core/signing.zig");

// Public replay domain used only by host tests and verification workloads.
pub const unlock_session = identity.unlock_context.Session{ .current = .{ .boot_instance = @splat(0x61), .session_nonce = @splat(0x62) }, .active = true };

// Explicit test/verification provisioning. The caller attaches a provider;
// identity requests receive only the resulting leased handle.
pub fn context(service: *vault.Service, policies: *const policy.Directory, owner: principal.PrincipalId) identity.VaultAuthority {
    return .{ .vault = service, .policies = policies, .subjects = .{ .user_id = owner.serial }, .holder = .{ .kind = .service, .serial = 0x4944 }, .task_id = 1, .now_ticks = 0, .unlock_session = &unlock_session };
}

pub fn at(authority: identity.VaultAuthority, tick: u64) identity.VaultAuthority {
    var current = authority;
    current.now_ticks = tick;
    return current;
}

pub fn provision(authority: identity.VaultAuthority, owner: principal.PrincipalId, signer: signing.SignerIdentity) vault.Error!u64 {
    const secret = try authority.vault.importSecret(authority.policies, authority.subjects, .{
        .owner = owner,
        .task_id = authority.task_id,
        .label = signer.label,
        .raw = &signer.seed,
        .now_ticks = authority.now_ticks,
    }, null);
    const handle = try authority.vault.lendHandle(authority.policies, authority.subjects, .{
        .owner = owner,
        .holder = authority.holder,
        .task_id = authority.task_id,
        .secret_id = secret.id,
        .now_ticks = authority.now_ticks,
        .expires_at_ticks = authority.now_ticks + 1000,
    }, null);
    return handle.id;
}
