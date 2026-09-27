const std = @import("std");
const tpm = @import("../../platform/tpm2_sealing.zig");
const backend = @import("../../platform/tpm2_secret_provider.zig");
const secrets = @import("../../platform/secure_secret_store.zig");
const vault = @import("../../services/secret_vault_service.zig");
const policy = @import("../../policy/policy_object.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const identity = @import("../../platform/os_identity.zig");
const device_graph = @import("../../sync/device_graph.zig");
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
    var secret: *const secrets.SecretRecord = undefined;
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
        secret = try service.generateSigningKey(&policies, subjects, .{
            .owner = owner,
            .task_id = 4,
            .label = label,
            .now_ticks = 1,
        }, null);
        const blob = secret.sealedBlob() orelse return error.MissingVaultBlob;
        @memcpy(payload[32..][0..blob.len], blob);
        payload_len = 32 + blob.len;
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
    try proveIdentityAssertions(&service, &policies, secret.id, payload[0..32]);
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
    // Generate again with identical owner/label and require a different public
    // key. The first key must remain usable after generating its sibling.
    const fresh_secret = try service.generateSigningKey(&policies, subjects, .{
        .owner = owner,
        .task_id = 4,
        .label = label,
        .now_ticks = 4,
    }, null);
    const fresh_handle = try service.lendHandle(&policies, subjects, .{
        .owner = owner,
        .holder = app,
        .task_id = 5,
        .secret_id = fresh_secret.id,
        .expires_at_ticks = 10,
        .now_ticks = 4,
    }, null);
    var fresh_request = request;
    fresh_request.handle_id = fresh_handle.id;
    fresh_request.now_ticks = 4;
    const fresh_signature = try service.signDigest(&policies, subjects, fresh_request, null);
    if (!signing.verify(fresh_signature, &fresh_request.digest) or
        std.mem.eql(u8, fresh_signature.publicKeySlice(), signature.publicKeySlice())) return error.ReusedGeneratedKey;
    const original_signature = try service.signDigest(&policies, subjects, request, null);
    if (!std.mem.eql(u8, original_signature.valueSlice(), signature.valueSlice())) return error.ReplacedGeneratedKey;
    try service.revoke(.{
        .subject = owner,
        .task_id = 4,
        .handle_id = fresh_handle.id,
        .secret_id = fresh_secret.id,
        .expected_holder = app,
        .expected_holder_task_id = 5,
        .now_ticks = 4,
    }, null);
    console.print("ZIGOS:TPM2:KEYGEN:DISTINCT\n");
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

// The graph and unlock proof are explicit verification fixtures. Credential
// signatures use the recovered real TPM-backed key, without a caller seed.
fn proveIdentityAssertions(service: *vault.Service, policies: *const policy.Directory, secret_id: u64, expected_public_key: *const signing.PublicKey) !void {
    const identity_service = principal.PrincipalId{ .kind = .service, .serial = 0x703 };
    const device = principal.PrincipalId{ .kind = .device, .serial = 0x704 };
    const owner_signer = signing.SignerIdentity{ .label = "identity-proof-owner", .seed = @splat(0xc1) };
    const device_signer = signing.SignerIdentity{ .label = "identity-proof-device", .seed = @splat(0xc2) };
    const subjects = policy.SubjectSet{ .user_id = owner.serial };
    const handle = try service.lendHandle(policies, subjects, .{
        .owner = owner,
        .holder = identity_service,
        .task_id = 6,
        .secret_id = secret_id,
        .expires_at_ticks = 10,
        .now_ticks = 2,
    }, null);
    var graph = device_graph.Graph.init();
    _ = try graph.ensureUserRoot(owner, "owner", owner_signer);
    _ = try graph.enrollDevice(owner, device, "device", owner_signer, device_signer, 1);
    var identities = identity.Store.init();
    var authority = identity.VaultAuthority{
        .vault = service,
        .policies = policies,
        .subjects = subjects,
        .holder = identity_service,
        .task_id = 6,
        .now_ticks = 3,
    };
    const credential = try identities.registerCredential(&graph, authority, .{
        .owner = owner,
        .device = device,
        .relying_party_id = "identity.example",
        .label = "TPM identity proof",
        .key_handle_id = handle.id,
    });
    if (!std.mem.eql(u8, &credential.credential_public_key, expected_public_key)) return error.IdentityKeyChanged;
    const request = identity.AssertionRequest{
        .credential_id = credential.id,
        .device = device,
        .relying_party_id = "identity.example",
        .origin = "https://identity.example",
        .challenge = "identity-proof",
        .local_unlock = try identity.createLocalUnlockProof(owner, device, "identity.example", "identity-proof", .device_pin, 2, 20, device_signer),
        .key_handle_id = handle.id,
    };
    const assertion = try identities.assertCredential(&graph, authority, request);
    if (!identity.verifyAssertion(&assertion, expected_public_key) or !assertion.hardware_backed_credential or assertion.assertion_counter != 1) return error.BadIdentityAssertion;
    var tampered = assertion;
    tampered.assertion_counter += 1;
    if (identity.verifyAssertion(&tampered, expected_public_key)) return error.UnboundIdentityCounter;
    authority.now_ticks = 10;
    if (identities.assertCredential(&graph, authority, request)) |_| return error.IdentitySignedAfterExpiry else |err| {
        if (err != error.HandleExpired) return err;
    }
    authority.now_ticks = 4;
    authority.task_id = 7;
    if (identities.assertCredential(&graph, authority, request)) |_| return error.IdentitySignedForWrongTask else |err| {
        if (err != error.HandleHolderMismatch) return err;
    }
    authority.task_id = 6;
    try service.revoke(.{
        .subject = owner,
        .task_id = 4,
        .handle_id = handle.id,
        .secret_id = secret_id,
        .expected_holder = identity_service,
        .expected_holder_task_id = 6,
        .now_ticks = 4,
    }, null);
    if (identities.assertCredential(&graph, authority, request)) |_| return error.IdentitySignedAfterRevocation else |err| {
        if (err != error.HandleRevoked) return err;
    }
    if (credential.assertion_count != 1 or credential.last_asserted_at_ticks != 3) return error.MutatedDeniedIdentityAssertion;
    console.print("ZIGOS:TPM2:IDENTITY:SIGNED\n");
}
