//! Verification-only enrollment authority for a disposable TPM and disk.
const std = @import("std");
const tpm = @import("../../platform/tpm2_sealing.zig");
const quote = tpm.quote;
const wire = @import("../../platform/tpm2_wire.zig");
const signing = @import("../../core/signing.zig");
const objects = @import("../../storage/object_store.zig");
const ids = @import("../../core/ids.zig");
const handoff = @import("../../../kernel/boot/handoff.zig");
const console = @import("../../../kernel/utils/console.zig");
const auth: tpm.Key = @splat(0xbd);
const parent_handle = 0x8100_7080;
const object_id = 0x708_0001;
const content_type = "application/x-zigos-tpm-quote-proof";
const signer = signing.SignerIdentity{ .label = "quote-proof-enrollment", .seed = @splat(0xc2) };
const MAX_BYTES = 4 + 34 + quote.PUBLIC_BYTES + 34 + 2 + tpm.MAX_BLOB_BYTES;

pub fn run(manager: anytype, io: anytype) !void {
    io.protected_authorizations = &.{auth};
    defer io.protected_authorizations = &.{};
    var client = tpm.Client{};
    defer client.close(io) catch {};
    const storage = manager.storageServicePtr();
    var blob = tpm.Blob{};
    var enrolled: quote.Identity = undefined;
    var parent: tpm.PersistentParent = undefined;
    const restored = storage.latestVersion(object_id) != null;
    if (storage.latestVersion(object_id)) |version| {
        var bytes: [MAX_BYTES]u8 = undefined;
        const payload = try storage.versionPayloadInto(version, &bytes);
        if (version.object_type != .secret or !std.mem.eql(u8, version.metadata.contentTypeSlice(), content_type) or
            !version.metadata.verifyFor(.secret, payload) or !std.mem.eql(u8, version.metadata.signature.publicKeySlice(), &(try signing.publicKey(signer))))
            return error.UntrustedQuoteEnrollment;
        // Trust comes from the independently fixed fixture authority above,
        // never a key supplied by the persisted quote or by ReadPublic alone.
        var r = wire.Reader{ .bytes = payload };
        if (!std.mem.eql(u8, try r.take(4), "ZQP1")) return error.InvalidQuoteEnrollment;
        parent = .{ .handle = parent_handle, .name = (try r.take(34))[0..34].* };
        try parent.validate();
        enrolled = .{ .public = (try r.take(quote.PUBLIC_BYTES))[0..quote.PUBLIC_BYTES].*, .qualified_name = (try r.take(34))[0..34].* };
        try enrolled.validate();
        const wrapped = try r.sized();
        if (wrapped.len > blob.bytes.len) return error.InvalidQuoteEnrollment;
        @memcpy(blob.bytes[0..wrapped.len], wrapped);
        blob.len = @intCast(wrapped.len);
        try r.end();
        client.openPersistent(io, parent) catch |err| {
            if (err != error.PersistentParentMissing or io.owner_commands != 0) return err;
            console.print("ZIGOS:TPM2:QUOTE:WRONG_DEVICE\n");
            return;
        };
    } else {
        try client.createEnrollmentParent(io);
        parent = .{ .handle = parent_handle, .name = client.parent_name };
        try client.persistParent(io, parent, null);
        try client.close(io);
        try client.openPersistent(io, parent);
        enrolled = try client.createAttestationKey(io, &auth, &blob);
        var bytes: [MAX_BYTES]u8 = undefined;
        var w = wire.Writer{ .bytes = &bytes };
        try w.put("ZQP1");
        try w.put(&parent.name);
        try w.put(&enrolled.public);
        try w.put(&enrolled.qualified_name);
        try w.sized(blob.slice());
        const payload = bytes[0..w.pos];
        _ = try storage.putVersion(.{ .preferred_object_id = ids.object(object_id), .object_type = .secret, .payload = payload, .metadata = try objects.signMetadata(signer, "TPM quote enrollment", content_type, .secret, payload, 1) });
        const previous = storage.checkpoint_enabled;
        storage.checkpoint_enabled = true;
        defer storage.checkpoint_enabled = previous;
        _ = try storage.checkpointDurable();
    }
    const info = handoff.capturedInfo() orelse return error.MissingBootInfo;
    const measured = info.boot_tpm orelse return error.MissingBootMeasurement;
    var evidence = quote.Evidence{};
    var nonce: tpm.Key = undefined;
    // Exceed the device's loaded object/session capacity to prove cleanup.
    for (0..8) |index| {
        var pending = try quote.Pending.init(io, enrolled, measured.pcr11, 100, 1000);
        nonce = pending.nonce;
        if (index != 0) if (pending.accept(evidence.slice(), 101)) |_| return error.ReplayedQuoteAccepted else |err| {
            if (err != error.QuoteMismatch) return err;
        };
        try client.quoteAttestation(io, blob.slice(), &auth, &enrolled, &nonce, &measured.pcr11, &evidence);
        _ = try pending.accept(evidence.slice(), 102);
        if (pending.accept(evidence.slice(), 103)) |_| return error.ReusedQuoteChallenge else |err| {
            if (err != error.QuoteChallengeConsumed) return err;
        }
        if (!std.mem.allEqual(u8, &client.command, 0) or !std.mem.allEqual(u8, &client.response, 0)) return error.ResidentQuoteAuthorization;
    }
    var changed = enrolled;
    changed.qualified_name[2] ^= 1;
    const commands = io.commands;
    if (client.quoteAttestation(io, blob.slice(), &auth, &changed, &nonce, &measured.pcr11, &evidence)) |_| return error.AcceptedSubstitutedQuoteKey else |err| {
        if (err != error.AttestationKeyChanged or io.commands != commands or evidence.len != 0) return error.BadQuoteKeyRejection;
    }
    var wrong_pcr = measured.pcr11;
    wrong_pcr[0] ^= 1;
    if (client.quoteAttestation(io, blob.slice(), &auth, &enrolled, &nonce, &wrong_pcr, &evidence)) |_| return error.AcceptedWrongQuotedPcr else |err| {
        if (err != error.QuoteMismatch or !std.mem.allEqual(u8, &evidence.bytes, 0) or evidence.len != 0) return error.BadQuotePcrRejection;
    }
    if (!restored) {
        var wrong_auth = auth;
        wrong_auth[0] ^= 1;
        if (client.quoteAttestation(io, blob.slice(), &wrong_auth, &enrolled, &nonce, &measured.pcr11, &evidence)) |_| return error.AcceptedWrongQuoteAuthorization else |err| {
            if (err != error.TpmError or client.last_tpm_error != 0x98e or evidence.len != 0) return error.BadQuoteAuthorizationRejection;
        }
    }
    var damaged = blob;
    damaged.bytes[42] ^= 1;
    if (client.quoteAttestation(io, damaged.slice(), &auth, &enrolled, &nonce, &measured.pcr11, &evidence)) |_| return error.AcceptedDamagedAttestationKey else |err| {
        if (err != error.TpmError or client.last_tpm_error != 0x1df or evidence.len != 0) return error.BadAttestationKeyRejection;
    }
    io.corrupt_quote = true;
    defer io.corrupt_quote = false;
    if (client.quoteAttestation(io, blob.slice(), &auth, &enrolled, &nonce, &measured.pcr11, &evidence)) |_| return error.AcceptedUnauthenticatedQuote else |err| {
        if (err != error.IntegrityFailure or !client.failed or !std.mem.allEqual(u8, &evidence.bytes, 0) or evidence.len != 0) return error.BadQuoteAuthenticationFailure;
    }
    try client.close(io);
    console.print(if (restored) "ZIGOS:TPM2:QUOTE:RECOVERED\n" else "ZIGOS:TPM2:QUOTE:CREATED\n");
}
