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
const catalog = @import("../../storage/vault_catalog.zig");
const object_signer = @import("../../storage/sealed_object_signer.zig");
const durable_identity = @import("../../services/durable_identity_service.zig");
const console = @import("../../../kernel/utils/console.zig");

// Verification-only identities and authorization are supplied by the TPM proof.
const owner = principal.PrincipalId{ .kind = .user, .serial = 0x701 };
const app = principal.PrincipalId{ .kind = .app, .serial = 0x702 };
const label = "vault-signing-proof";
const content_type = "application/x-zigos-tpm-vault-enrollment-proof";
const catalog_object_id: u64 = 0x7010001;
const signer = signing.SignerIdentity{ .label = label, .seed = @splat(0xb8) };

pub fn run(manager: anytype, io: anytype, authorization: *const tpm.Key) !void {
    var client = tpm.Client{};
    defer client.close(io) catch {};
    try client.initialize(io);
    var adapter = backend.Backend(@TypeOf(io.*)){ .client = &client, .io = io, .authorization = authorization };
    var service = vault.Service.init();
    var identities = identity.Store.init();
    service.attachHardwareProvider(adapter.provider());
    defer service.attachHardwareProvider(.{});
    var policies = policy.Directory.init();
    const subjects = policy.SubjectSet{ .user_id = owner.serial };
    const storage = manager.storageServicePtr();
    var matches: [2]objects.ObjectQueryResult = undefined;
    const found = storage.queryObjects(.{ .object_type = .secret, .content_type = content_type }, &matches);
    if (found.len > 1) return error.DuplicateVaultProof;
    const restored = found.len == 1;
    // The public fixture signer anchors enrollment only in this verification
    // workload. Production must obtain the pin from trusted enrollment state.
    var expected_key: signing.PublicKey = undefined;
    var catalog_scratch: [catalog.MAX_BYTES]u8 = undefined;
    var secret: *const secrets.SecretRecord = undefined;
    if (restored) {
        const version = storage.latestVersion(found[0].object_id) orelse return error.MissingVaultProof;
        const bytes = try storage.versionPayload(version);
        if (bytes.len != expected_key.len or !version.metadata.verifyFor(.secret, bytes) or
            !std.mem.eql(u8, version.metadata.signature.publicKeySlice(), &(try signing.publicKey(signer)))) return error.InvalidVaultProof;
        @memcpy(&expected_key, bytes);
        const generation = catalog.restore(storage, .{ .vault = &service, .identities = &identities }, .{ .object_id = catalog_object_id, .owner = owner, .public_key = expected_key, .minimum_generation = 2 }, &catalog_scratch) catch |err| {
            if (err != error.InvalidSealedSecret) return err;
            if (service.store.secret_count != 0 or identities.credential_count != 0) return error.PublishedForeignSecret;
            service.attachHardwareProvider(.{});
            try client.close(io);
            console.print("ZIGOS:TPM2:VAULT:WRONG_DEVICE\n");
            return;
        };
        if (generation != 2 or identities.credential_count != 2 or service.store.secret_count != 3 or service.activeHandleCount() != 0 or
            service.store.handles.countInUse() != 0) return error.InvalidRestoredVault;
        secret = service.store.describeSecret(1) orelse return error.MissingVaultProof;
        const portable_lease = try service.lendHandle(&policies, subjects, .{ .owner = owner, .holder = app, .task_id = 5, .secret_id = 3, .expires_at_ticks = 10, .now_ticks = 1, .allow_raw_export = true }, null);
        var recovered_bytes: secrets.Value = undefined;
        defer std.crypto.secureZero(u8, &recovered_bytes);
        const recovered_value = try service.exportRaw(&policies, subjects, .{ .holder = app, .task_id = 5, .handle_id = portable_lease.id, .now_ticks = 1 }, null, &recovered_bytes);
        if (recovered_value.len != secrets.MAX_VALUE_BYTES) return error.InvalidRestoredVault;
        for (recovered_value, 0..) |byte, i| if (byte != i) return error.InvalidRestoredVault;
        console.print("ZIGOS:TPM2:CATALOG:RESTORED\n");
    } else {
        secret = try service.generateSigningKey(&policies, subjects, .{
            .owner = owner,
            .task_id = 4,
            .label = label,
            .now_ticks = 1,
        }, null);
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
        if (!std.mem.eql(u8, signature.publicKeySlice(), &expected_key)) return error.RecoveredWrongVaultKey;
    } else @memcpy(&expected_key, signature.publicKeySlice());
    if (!restored) {
        const previous = storage.checkpoint_enabled;
        storage.checkpoint_enabled = false;
        defer storage.checkpoint_enabled = previous;
        _ = try storage.putLocallySignedVersion(.{ .object_type = .secret, .payload = &expected_key, .signer = signer, .label = label, .content_type = content_type, .created_at_ticks = 1 });
    }
    const catalog_handle = try service.lendHandle(&policies, subjects, .{ .owner = owner, .holder = storage.owner, .task_id = storage.task_id, .secret_id = secret.id, .expires_at_ticks = 20, .now_ticks = 2 }, null);
    var catalog_authority = object_signer.Authority{ .service = &service, .policies = &policies, .subjects = subjects, .owner = owner, .holder = storage.owner, .task_id = storage.task_id };
    const catalog_signer = try object_signer.Signer.bind(&catalog_authority, catalog_handle.id, 2);
    var durable_identities = durable_identity.Service{ .state = .{ .vault = &service, .identities = &identities }, .storage = storage, .signer = catalog_signer, .object_id = catalog_object_id, .version_id = if (restored) storage.latestVersion(catalog_object_id).?.id.raw() else 0 };
    try proveIdentityAssertions(&durable_identities, &policies, secret.id, &expected_key, restored, &catalog_scratch);
    try proveDocumentSigning(&service, &policies, secret.id, &expected_key);
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
    const initial_count = service.store.secret_count;
    for (0..3) |variant| {
        if (service.store.restoreSealed(if (variant == 0) app else owner, if (variant == 1) "wrong label" else label, secret.sealedBlob().?, variant == 2)) |_| return error.AcceptedChangedVaultBinding else |err| {
            if (err != error.InvalidSealedSecret or service.store.secret_count != initial_count) return error.BadVaultBindingDenial;
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
    if (!restored) {
        const receipt = try durable_identities.flush(7, &catalog_scratch);
        if (receipt.catalog_generation != 2 or receipt.checkpoint_generation == 0) return error.InvalidVaultCheckpoint;
        console.print("ZIGOS:TPM2:CATALOG:COMMITTED\n");
    }
    service.attachHardwareProvider(.{});
    try client.close(io);
    console.print(if (restored) "ZIGOS:TPM2:VAULT:RECOVERED\n" else "ZIGOS:TPM2:VAULT:CREATED\n");
}

fn proveDocumentSigning(service: *vault.Service, policies: *const policy.Directory, secret_id: u64, expected_key: *const signing.PublicKey) !void {
    const holder = principal.PrincipalId{ .kind = .service, .serial = 0x705 };
    const handle = try service.lendHandle(policies, .{ .user_id = owner.serial }, .{
        .owner = owner,
        .holder = holder,
        .task_id = 7,
        .secret_id = secret_id,
        .expires_at_ticks = 10,
        .now_ticks = 2,
    }, null);
    var authority = object_signer.Authority{ .service = service, .policies = policies, .subjects = .{ .user_id = owner.serial }, .owner = owner, .holder = holder, .task_id = 7 };
    const document_key = try object_signer.Signer.bind(&authority, handle.id, 3);
    const metadata = try document_key.signMetadata("documents/sealed.md", "TPM-backed document", 3);
    if (!metadata.verifyFor(.document, "TPM-backed document") or
        !std.mem.eql(u8, metadata.signature.publicKeySlice(), expected_key)) return error.InvalidDocumentSignature;
    try service.revoke(.{ .subject = owner, .task_id = 4, .handle_id = handle.id, .secret_id = secret_id, .expected_holder = holder, .expected_holder_task_id = 7, .now_ticks = 4 }, null);
    if (document_key.signMetadata("documents/sealed.md", "revoked", 4)) |_| return error.DocumentSignedAfterRevocation else |err| {
        if (err != error.HandleRevoked) return err;
    }
    console.print("ZIGOS:TPM2:DOCUMENT:SIGNING\n");
}

// The graph and unlock proof are explicit verification fixtures. Credential
// signatures use the recovered real TPM-backed key, without a caller seed.
fn proveIdentityAssertions(durable: *durable_identity.Service, policies: *const policy.Directory, secret_id: u64, expected_public_key: *const signing.PublicKey, restored: bool, scratch: *[catalog.MAX_BYTES]u8) !void {
    const service = durable.state.vault;
    const identities = durable.state.identities;
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
    var authority = identity.VaultAuthority{
        .vault = service,
        .policies = policies,
        .subjects = subjects,
        .holder = identity_service,
        .task_id = 6,
        .now_ticks = 3,
    };
    if (!restored) {
        _ = try identities.registerCredential(&graph, authority, .{ .owner = owner, .device = device, .relying_party_id = "identity.example", .label = "TPM identity proof", .key_handle_id = handle.id });
        const revoked = try identities.registerCredential(&graph, authority, .{ .owner = owner, .device = device, .relying_party_id = "revoked.example", .label = "TPM revoked credential", .key_handle_id = handle.id });
        try identities.revokeCredential(revoked.id, 3);
    }
    const credential = identities.findCredentialConst(1) orelse return error.MissingCredential;
    const expected_counter: u64 = if (restored) 2 else 1;
    if (credential.assertion_count != expected_counter - 1 or identities.findCredentialConst(2).?.status != .revoked) return error.LostCredentialState;
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
    const assertion = try durable.assertCredential(&graph, authority, request, scratch);
    if (!identity.verifyAssertion(&assertion, expected_public_key) or !assertion.hardware_backed_credential or assertion.assertion_counter != expected_counter) return error.BadIdentityAssertion;
    var revoked_request = request;
    revoked_request.credential_id = 2;
    if (durable.assertCredential(&graph, authority, revoked_request, scratch)) |_| return error.RevokedCredentialRestored else |err| {
        if (err != error.CredentialRevoked) return err;
    }
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
    if (credential.assertion_count != expected_counter or credential.last_asserted_at_ticks != 3) return error.MutatedDeniedIdentityAssertion;
    console.print("ZIGOS:TPM2:IDENTITY:SIGNED\n");
    console.print(if (restored) "ZIGOS:TPM2:CREDENTIALS:RESTORED\n" else "ZIGOS:TPM2:CREDENTIALS:COMMITTED\n");
}
