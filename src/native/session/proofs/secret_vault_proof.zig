const std = @import("std");
const tpm = @import("../../platform/tpm2_sealing.zig");
const backend = @import("../../platform/tpm2_secret_provider.zig");
const secrets = @import("../../platform/secure_secret_store.zig");
const vault = @import("../../services/secret_vault_service.zig");
const policy = @import("../../policy/policy_object.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const objects = @import("../../storage/object_store.zig");
const console = @import("../../../kernel/utils/console.zig");

// Verification-only identities and authorization are supplied by the TPM proof.
const owner = principal.PrincipalId{ .kind = .user, .serial = 0x701 };
const app = principal.PrincipalId{ .kind = .app, .serial = 0x702 };
const label = "vault-signing-proof";
const content_type = "application/x-zigos-tpm-vault-proof";
const signer = signing.SignerIdentity{ .label = label, .seed = @splat(0xb8) };

pub fn run(manager: anytype, io: anytype, authorization: *const tpm.Key) !void {
    var client = tpm.Client{};
    defer client.close(io) catch {};
    try client.initialize(io);
    var adapter = backend.Backend(@TypeOf(io.*)){ .client = &client, .io = io, .authorization = authorization };
    var service = vault.Service.init();
    service.attachHardwareProvider(adapter.provider());
    defer service.attachHardwareProvider(.{});
    var policies = policy.Directory.init();
    const subjects = policy.SubjectSet{ .user_id = owner.serial };
    const storage = manager.storageServicePtr();
    var matches: [2]objects.ObjectQueryResult = undefined;
    const found = storage.queryObjects(.{ .object_type = .secret, .content_type = content_type }, &matches);
    if (found.len > 1) return error.DuplicateVaultProof;
    const restored = found.len == 1;
    var payload: [32 + @import("../../platform/secret_sealing.zig").MAX_BLOB_BYTES]u8 = undefined;
    var payload_len: usize = 0;
    var seed: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    defer io.known_key = null;
    var secret: *secrets.SecretRecord = undefined;
    if (restored) {
        const version = storage.latestVersion(found[0].object_id) orelse return error.MissingVaultProof;
        const bytes = try storage.versionPayload(version);
        if (bytes.len < 32 or bytes.len > payload.len) return error.InvalidVaultProof;
        @memcpy(payload[0..bytes.len], bytes);
        payload_len = bytes.len;
        secret = service.store.restoreSealed(owner, label, payload[32..payload_len], false) catch |err| {
            if (err != error.InvalidSealedSecret) return err;
            if (service.store.secret_count != 0) return error.PublishedForeignSecret;
            service.attachHardwareProvider(.{});
            try client.close(io);
            console.print("ZIGOS:TPM2:VAULT:WRONG_DEVICE\n");
            return;
        };
    } else {
        try io.random(&seed);
        io.known_key = &seed;
        secret = try service.importSecret(&policies, subjects, .{
            .owner = owner,
            .task_id = 4,
            .label = label,
            .raw = &seed,
            .now_ticks = 1,
        }, null);
        const blob = secret.sealedBlob() orelse return error.MissingVaultBlob;
        if (std.mem.indexOf(u8, blob, &seed) != null) return error.PlaintextVaultBlob;
        @memcpy(payload[32..][0..blob.len], blob);
        payload_len = 32 + blob.len;
        io.known_key = null;
        std.crypto.secureZero(u8, &seed);
    }
    if (secret.resident_material) return error.ResidentVaultMaterial;
    const handle = try service.lendHandle(&policies, subjects, .{
        .owner = owner,
        .holder = app,
        .task_id = 5,
        .secret_id = secret.id,
        .expires_at_ticks = 10,
        .now_ticks = 2,
        .allow_raw_export = true,
    }, null);
    const request = vault.SignRequest{ .holder = app, .task_id = 5, .handle_id = handle.id, .digest = @splat(0xe3), .now_ticks = 3 };
    const signature = try service.signDigest(&policies, subjects, request, null);
    if (!signing.verify(signature, &request.digest)) return error.InvalidVaultSignature;
    if (restored) {
        if (!std.mem.eql(u8, signature.publicKeySlice(), payload[0..32])) return error.RecoveredWrongVaultKey;
    } else @memcpy(payload[0..32], signature.publicKeySlice());
    var out: secrets.Value = @splat(0xaa);
    defer std.crypto.secureZero(u8, &out);
    if (service.exportRaw(&policies, subjects, .{ .holder = app, .task_id = 5, .handle_id = handle.id, .now_ticks = 3 }, null, &out)) |_| {
        return error.ExportedSealedSigningKey;
    } else |err| if (err != error.RawExportDenied or !std.mem.allEqual(u8, &out, 0)) return error.BadVaultExportDenial;
    var wrong = request;
    wrong.holder = owner;
    if (service.signDigest(&policies, subjects, wrong, null)) |_| return error.SignedForWrongHolder else |err| {
        if (err != error.HandleHolderMismatch) return err;
    }
    wrong = request;
    wrong.now_ticks = 10;
    if (service.signDigest(&policies, subjects, wrong, null)) |_| return error.SignedAfterExpiry else |err| {
        if (err != error.HandleExpired) return err;
    }
    for (0..3) |variant| {
        if (service.store.restoreSealed(if (variant == 0) app else owner, if (variant == 1) "wrong label" else label, payload[32..payload_len], variant == 2)) |_| return error.AcceptedChangedVaultBinding else |err| {
            if (err != error.InvalidSealedSecret or service.store.secret_count != 1) return error.BadVaultBindingDenial;
        }
    }
    // Exercise the full 96-byte envelope and export through caller-owned storage.
    var portable: secrets.Value = undefined;
    defer std.crypto.secureZero(u8, &portable);
    for (&portable, 0..) |*byte, i| byte.* = @intCast(i);
    const portable_secret = try service.importSecret(&policies, subjects, .{
        .owner = owner,
        .task_id = 4,
        .label = "portable",
        .raw = &portable,
        .exportable = true,
        .now_ticks = 4,
    }, null);
    const portable_handle = try service.lendHandle(&policies, subjects, .{
        .owner = owner,
        .holder = app,
        .task_id = 5,
        .secret_id = portable_secret.id,
        .expires_at_ticks = 10,
        .now_ticks = 4,
        .allow_raw_export = true,
    }, null);
    const exported = try service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 5,
        .handle_id = portable_handle.id,
        .now_ticks = 5,
    }, null, &out);
    if (!std.mem.eql(u8, &portable, exported) or portable_secret.resident_material) return error.BadPortableVaultSecret;
    try service.revoke(.{
        .subject = owner,
        .task_id = 4,
        .handle_id = handle.id,
        .secret_id = secret.id,
        .expected_holder = app,
        .expected_holder_task_id = 5,
        .now_ticks = 5,
    }, null);
    if (service.signDigest(&policies, subjects, request, null)) |_| return error.SignedAfterRevocation else |err| {
        if (err != error.HandleRevoked) return err;
    }
    service.attachHardwareProvider(.{});
    try client.close(io);
    if (!restored) {
        _ = try storage.putLocallySignedVersion(.{
            .object_type = .secret,
            .payload = payload[0..payload_len],
            .signer = signer,
            .label = label,
            .content_type = content_type,
            .created_at_ticks = 1,
        });
        const previous = storage.checkpoint_enabled;
        storage.checkpoint_enabled = true;
        defer storage.checkpoint_enabled = previous;
        _ = try storage.checkpointDurable();
    }
    console.print(if (restored) "ZIGOS:TPM2:VAULT:RECOVERED\n" else "ZIGOS:TPM2:VAULT:CREATED\n");
}
