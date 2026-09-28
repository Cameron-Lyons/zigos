const std = @import("std");
const tpm = @import("../../platform/tpm2_sealing.zig");
const anchors = @import("../../platform/tpm2_vault_anchor.zig");
const provider = @import("../../platform/tpm2_secret_provider.zig");
const vault = @import("../../services/secret_vault_service.zig");
const identity = @import("../../platform/os_identity.zig");
const policy = @import("../../policy/policy_object.zig");
const principal = @import("../../core/principal.zig");
const catalog = @import("../../storage/vault_catalog.zig");
const object_signer = @import("../../storage/sealed_object_signer.zig");
const console = @import("../../../kernel/utils/console.zig");

// Disposable verification enrollment, deliberately interrupted before its first
// NV write. Its cold/reboot cases are independent of the PIN/session fixture.
// Production enrollment never receives this fixture authorization.
const owner = principal.PrincipalId{ .kind = .user, .serial = 0x703 };
const index: u32 = 0x0180_7013;
const object_id: u64 = 0x7010003;

pub fn run(manager: anytype, io: anytype, authorization: *const tpm.Key) !void {
    const Anchor = anchors.Backend(@TypeOf(io.*));
    var client = tpm.Client{};
    defer client.close(io) catch {};
    try client.createEnrollmentParent(io);
    const storage = manager.storageServicePtr();
    var adapter = provider.Backend(@TypeOf(io.*)){ .client = &client, .io = io, .authorization = authorization };
    var service = vault.Service.init();
    service.attachHardwareProvider(adapter.provider());
    defer service.attachHardwareProvider(.{});
    var identities = identity.Store.init();
    var policies = policy.Directory.init();
    const subjects = policy.SubjectSet{ .user_id = owner.serial };
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    if (storage.latestVersion(object_id) == null) {
        const key = try service.generateSigningKey(&policies, subjects, .{ .owner = owner, .task_id = 4, .label = "initial enrollment", .now_ticks = 1 }, null);
        const handle = try service.lendHandle(&policies, subjects, .{ .owner = owner, .holder = storage.owner, .task_id = storage.task_id, .secret_id = key.id, .expires_at_ticks = 10, .now_ticks = 2 }, null);
        var authority = object_signer.Authority{ .service = &service, .policies = &policies, .subjects = subjects, .owner = owner, .holder = storage.owner, .task_id = storage.task_id };
        const signer = try object_signer.Signer.bind(&authority, handle.id, 2);
        var session = catalog.Session{};
        _ = try session.save(storage, .{ .vault = &service, .identities = &identities }, signer, object_id, 0, 3, &scratch);
        const candidate = try catalog.inspectEnrollment(storage, object_id, owner, &scratch);
        var anchor = Anchor{ .client = &client, .io = io, .authorization = authorization, .index = index, .current = .{ .checkpoint = candidate.checkpoint, .device_root_pin = candidate.device_root_pin } };
        const writes = io.nv_writes;
        io.interrupt_nv_write = true;
        if (anchor.provision(storage, &scratch, null)) |_| return error.EnrollmentWasNotInterrupted else |err| {
            if (err != error.InterruptedVaultCheckpoint or !client.failed or io.nv_writes != writes) return error.BadEnrollmentInterruption;
        }
        const x86 = @import("../../../arch/x86.zig");
        x86.cli();
        console.print("ZIGOS:TPM2:ENROLLMENT_RECOVERY:INTERRUPTED\n");
        while (true) x86.hlt();
    }
    const initial = Anchor.read(&client, io, authorization, index) catch |err| blk: {
        if (err == error.NvIndexMissing) {
            const writes = io.nv_writes;
            if (Anchor.resumeProvision(&client, io, authorization, index, storage, object_id, owner, &scratch)) |_| return error.ReprovisionedMissingAnchor else |failure| {
                if (failure != error.NvIndexMissing or writes != io.nv_writes) return error.BadMissingEnrollmentFailure;
            }
            console.print("ZIGOS:TPM2:ENROLLMENT_RECOVERY:MISSING\n");
            return;
        }
        if (err != error.NvUninitialized) return err;
        break :blk @as(?anchors.Record, null);
    };
    var record: anchors.Record = undefined;
    if (initial) |existing| {
        record = existing;
    } else {
        // A different candidate cannot initialize the committed index.
        const candidate = try catalog.inspectEnrollment(storage, object_id, owner, &scratch);
        record = .{ .checkpoint = candidate.checkpoint, .device_root_pin = candidate.device_root_pin };
        var changed = record;
        changed.checkpoint.payload_digest[0] ^= 1;
        const writes = io.nv_writes;
        if (client.nvInitialize(io, try changed.enrollmentSpace(index), authorization, &(try changed.encode()))) |_| return error.AcceptedForeignEnrollment else |err| {
            if (err != error.NvBindingMismatch or writes != io.nv_writes) return error.BadEnrollmentBindingFailure;
        }
        io.corrupt_nv_write = true;
        if (Anchor.resumeProvision(&client, io, authorization, index, storage, object_id, owner, &scratch)) |_| return error.AcceptedLostEnrollmentReply else |err| {
            if (err != error.IntegrityFailure or !client.failed or io.nv_writes != writes + 1 or !service.store.empty()) return error.BadEnrollmentReplyFailure;
        }
        io.corrupt_nv_write = false;
        client.close(io) catch {};
        client = .{};
        try client.createEnrollmentParent(io);
        record = try Anchor.resumeProvision(&client, io, authorization, index, storage, object_id, owner, &scratch);
        if (io.nv_writes != writes + 1 or !service.store.empty() or identities.credential_count != 0) return error.EnrollmentRetryPublishedState;
        // The first public read lies about WRITTEN; the checked first-write
        // operation must reread it and refuse to overwrite the existing record.
        io.spoof_unwritten_once = true;
        if (Anchor.resumeProvision(&client, io, authorization, index, storage, object_id, owner, &scratch)) |_| return error.OverwroteInitializedEnrollment else |err| {
            if (err != error.NvAlreadyInitialized or io.spoof_unwritten_once or io.nv_writes != writes + 1) return error.BadEnrollmentRaceFailure;
        }
    }
    const writes = io.nv_writes;
    const verified = try Anchor.resumeProvision(&client, io, authorization, index, storage, object_id, owner, &scratch);
    if (!std.mem.eql(u8, &(try record.encode()), &(try verified.encode())) or writes != io.nv_writes) return error.EnrollmentRetryRewroteAnchor;
    _ = try catalog.restore(storage, .{ .vault = &service, .identities = &identities }, verified.trust(), &scratch);
    if (service.store.secret_count != 1 or service.activeHandleCount() != 0 or identities.credential_count != 0) return error.BadEnrollmentRestore;
    console.print(if (initial == null) "ZIGOS:TPM2:ENROLLMENT_RECOVERY:COMMITTED\n" else "ZIGOS:TPM2:ENROLLMENT_RECOVERY:VERIFIED\n");
}
