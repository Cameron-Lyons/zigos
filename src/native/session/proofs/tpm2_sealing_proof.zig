const std = @import("std");
const sealing = @import("../../platform/tpm2_sealing.zig");
const hardware = @import("../../../kernel/platform/tpm2_hw.zig");
const crb = @import("../../../kernel/platform/tpm2_crb.zig");
const spin = @import("../../../kernel/utils/spin.zig");
const kernel_random = @import("../../../kernel/platform/secure_random.zig");
const console = @import("../../../kernel/utils/console.zig");
const object_store = @import("../../storage/object_store.zig");
const signing = @import("../../core/signing.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

// This module is reachable only in verification kernels. These public fixtures
// authorize disposable test keys, never a production identity or secret vault.
const auth: sealing.Key = @splat(0x93);
// TPM Library Part 2: AUTH_FAIL for session 1 and INTEGRITY for parameter 1.
// Resource, lockout, and transport failures must not satisfy rejection proofs.
const authorization_failure: u32 = 0x98e;
const private_integrity_failure: u32 = 0x1df;
const signer = signing.SignerIdentity{ .label = "tpm-sealing-proof", .seed = signing.seedFromByte(0xC7) };
const content_type = "application/x-zigos-tpm-sealing-proof";

const Io = struct {
    known_key: ?*const sealing.Key = null,
    known_pin: ?[]const u8 = null,
    protected_authorizations: []const sealing.Key = &.{},
    corrupt_lockout_change: bool = false,
    corrupt_persistence: bool = false,
    corrupt_parent_public: bool = false,
    owner_commands: usize = 0,
    persist_commands: usize = 0,
    commands: usize = 0,
    da_resets: usize = 0,
    last_failed_command: u32 = 0,
    last_tpm_error: u32 = 0,
    corrupt_unseal: bool = false,
    corrupt_nv_read: bool = false,
    corrupt_nv_write: bool = false,
    interrupt_nv_write: bool = false,
    spoof_unwritten_once: bool = false,
    nv_writes: usize = 0,
    corrupted: bool = false,

    pub fn random(_: *@This(), out: []u8) !void {
        try kernel_random.fill(out);
    }
    pub fn execute(self: *@This(), command: []const u8, response: []u8, timeout_ms: u32) ![]u8 {
        if (std.mem.indexOf(u8, command, &auth) != null) return error.PlaintextAuthorization;
        if (self.known_pin) |pin| if (std.mem.indexOf(u8, command, pin) != null) return error.PlaintextPin;
        for (self.protected_authorizations) |key| if (std.mem.indexOf(u8, command, &key) != null) return error.PlaintextAuthorization;
        if (self.known_key) |key| {
            if (std.mem.indexOf(u8, command, key) != null) return error.PlaintextKey;
        }
        if (std.mem.indexOf(u8, command, "ZGVAnch1") != null) return error.PlaintextAnchor;
        if (std.mem.readInt(u32, command[6..10], .big) == 0x137) {
            if (self.interrupt_nv_write) return error.InterruptedVaultCheckpoint;
            self.nv_writes += 1;
        }
        const code = std.mem.readInt(u32, command[6..10], .big);
        self.commands += 1;
        if (code == 0x139) self.da_resets += 1;
        if (code == 0x120) self.persist_commands += 1;
        if (code == 0x120 or code == 0x129 or code == 0x12a or code == 0x131) self.owner_commands += 1;
        // Client.close must never FlushContext a persistent object.
        if (code == 0x165 and std.mem.readInt(u32, command[10..14], .big) >> 24 == 0x81) return error.FlushedPersistentParent;
        const reply = try hardware.execute(command, response, timeout_ms);
        const response_code = std.mem.readInt(u32, reply[6..10], .big);
        if (response_code != 0) {
            self.last_failed_command = code;
            self.last_tpm_error = response_code;
        }
        if (self.spoof_unwritten_once and std.mem.readInt(u32, command[6..10], .big) == 0x169 and std.mem.readInt(u32, reply[6..10], .big) == 0) {
            self.spoof_unwritten_once = false;
            const public_len = std.mem.readInt(u16, reply[10..12], .big);
            const attrs = std.mem.readInt(u32, reply[18..22], .big);
            if (attrs & 0x2000_0000 == 0 or reply.len != 12 + public_len + 36) return error.InvalidWrittenPublicArea;
            std.mem.writeInt(u32, reply[18..22], attrs & ~@as(u32, 0x2000_0000), .big);
            Sha256.hash(reply[12..][0..public_len], reply[16 + public_len ..][0..32], .{});
        }
        if (self.known_key) |key| {
            if (std.mem.indexOf(u8, reply, key) != null) return error.PlaintextKey;
        }
        if (std.mem.indexOf(u8, reply, "ZGVAnch1") != null) return error.PlaintextAnchor;
        if (((self.corrupt_persistence and code == 0x120) or
            (self.corrupt_parent_public and code == 0x173 and std.mem.readInt(u16, reply[0..2], .big) == 0x8002) or
            (self.corrupt_lockout_change and std.mem.readInt(u32, command[6..10], .big) == 0x129) or
            (self.corrupt_unseal and std.mem.readInt(u32, command[6..10], .big) == 0x15e) or
            (self.corrupt_nv_read and std.mem.readInt(u32, command[6..10], .big) == 0x14e) or
            (self.corrupt_nv_write and std.mem.readInt(u32, command[6..10], .big) == 0x137)) and
            std.mem.readInt(u32, reply[6..10], .big) == 0)
        {
            reply[reply.len - 1] ^= 1;
            self.corrupted = true;
        }
        return reply;
    }
};

pub fn run(manager: anytype) !void {
    if (!hardware.available()) return;
    try runTransportProof();
    var io = Io{};
    const handoff = @import("../../../kernel/boot/handoff.zig");
    if (handoff.capturedInfo()) |info| if (handoff.commandLineHasFlag(info, "tpm_ownership_proof")) {
        @import("tpm2_ownership_proof.zig").run(manager, &io) catch |err| {
            var line: [128]u8 = undefined;
            console.print(std.fmt.bufPrint(&line, "ZIGOS:TPM2:OWNER:FAIL {s} command={x} code={x}\n", .{ @errorName(err), io.last_failed_command, io.last_tpm_error }) catch "ZIGOS:TPM2:OWNER:FAIL\n");
            return err;
        };
        return;
    };
    var client = sealing.Client{};
    defer client.close(&io) catch {};
    @import("tpm2_pin_proof.zig").run(manager, &io) catch |err| {
        var line: [128]u8 = undefined;
        console.print(std.fmt.bufPrint(&line, "ZIGOS:TPM2:PIN:FAIL {s} command={x} code={x}\n", .{ @errorName(err), io.last_failed_command, io.last_tpm_error }) catch "ZIGOS:TPM2:PIN:FAIL\n");
        return err;
    };
    @import("tpm2_enrollment_proof.zig").run(manager, &io, &auth) catch |err| {
        var line: [128]u8 = undefined;
        console.print(std.fmt.bufPrint(&line, "ZIGOS:TPM2:ENROLLMENT_RECOVERY:FAIL {s}\n", .{@errorName(err)}) catch "ZIGOS:TPM2:ENROLLMENT_RECOVERY:FAIL\n");
        return err;
    };
    runWithClient(manager, &client, &io) catch |err| {
        var line: [128]u8 = undefined;
        console.print(std.fmt.bufPrint(&line, "ZIGOS:TPM2:SEAL:FAIL {s} code={x}\n", .{ @errorName(err), client.last_tpm_error }) catch "ZIGOS:TPM2:SEAL:FAIL\n");
        return err;
    };
    @import("secret_vault_proof.zig").run(manager, &io, &auth) catch |err| {
        var line: [128]u8 = undefined;
        console.print(std.fmt.bufPrint(&line, "ZIGOS:TPM2:VAULT:FAIL {s}\n", .{@errorName(err)}) catch "ZIGOS:TPM2:VAULT:FAIL\n");
        return err;
    };
}

fn cancelAndDrain(ticket: hardware.Ticket) !void {
    try hardware.cancel(ticket);
    while (true) {
        const reply = hardware.poll(ticket) catch |err| {
            if (err == error.Cancelled) return;
            return err;
        };
        if (reply != null) return error.CancelledReplyExposed;
        spin.hint();
    }
}

fn runTransportProof() !void {
    const command = crb.propertyCommand(crb.FAMILY_INDICATOR);
    var response: [27]u8 = undefined;
    defer std.crypto.secureZero(u8, &response);
    var active: ?hardware.Ticket = null;
    errdefer if (active) |ticket| cancelAndDrain(ticket) catch {};
    // Exercise cancellation before and after several polling boundaries.
    // GetCapability has no persistent side effects even if cancellation loses
    // the race to completion. This proof drives polls; it is not a UI worker.
    for ([_]usize{ 0, 1, 6 }) |handoff| {
        @memset(&response, 0xaa);
        const cancelled = try hardware.begin(&command, &response, 2000);
        active = cancelled;
        if (hardware.begin(&command, &response, 2000)) |_| {
            return error.ConcurrentTpmCommand;
        } else |err| if (err != error.Busy) return err;
        for (0..handoff) |_| {
            if (try hardware.poll(cancelled) != null) return error.EarlyTransportCompletion;
        }
        try cancelAndDrain(cancelled);
        active = null;
        if (!std.mem.allEqual(u8, &response, 0) or !hardware.available()) return error.BadTransportCancellation;

        const next = try hardware.begin(&command, &response, 2000);
        active = next;
        if (hardware.cancel(cancelled)) |_| {
            return error.StaleTransportCancellation;
        } else |err| if (err != error.NoCommand) return err;
        if (hardware.poll(cancelled)) |_| {
            return error.StaleTransportPoll;
        } else |err| if (err != error.NoCommand) return err;
        while (true) {
            if (try hardware.poll(next)) |reply| {
                active = null;
                if (try crb.parseProperty(reply, crb.FAMILY_INDICATOR) != 0x322e_3000) return error.BadTransportReply;
                break;
            }
            spin.hint();
        }
    }
    console.print("ZIGOS:TPM2:ASYNC_TRANSPORT:VERIFIED\n");
}

fn runWithClient(manager: anytype, client: *sealing.Client, io: *Io) !void {
    try client.createEnrollmentParent(io);
    const storage = manager.storageServicePtr();
    var matches: [2]object_store.ObjectQueryResult = undefined;
    const found = storage.queryObjects(.{ .object_type = .secret, .content_type = content_type }, &matches);
    if (found.len > 1) return error.DuplicateProofRecord;
    var payload: [32 + sealing.MAX_BLOB_BYTES]u8 = undefined;
    var payload_len: usize = 0;
    var key: sealing.Key = undefined;
    defer io.known_key = null;
    defer std.crypto.secureZero(u8, &key);
    var blob = sealing.Blob{};
    const restored = found.len == 1;
    if (restored) {
        const version = storage.latestVersion(found[0].object_id) orelse return error.MissingProofVersion;
        const stored = try storage.versionPayload(version);
        if (stored.len < 32 or stored.len > payload.len) return error.InvalidProofRecord;
        @memcpy(payload[0..stored.len], stored);
        payload_len = stored.len;
        client.unseal(io, payload[32..payload_len], &auth, &key) catch |err| {
            if (err != error.WrongDevice) return err;
            if (!std.mem.allEqual(u8, &key, 0)) return error.FailedOutputNotErased;
            // Bypass the client's parent-name guard in this negative proof so
            // that the new TPM itself must reject the old encrypted private area.
            if (payload_len < 32 + 38) return error.InvalidProofRecord;
            @memcpy(payload[36..][0..34], &client.parent_name);
            if (client.unseal(io, payload[32..payload_len], &auth, &key)) |_| {
                return error.ForeignTpmAcceptedPrivateArea;
            } else |foreign_error| {
                if (foreign_error != error.TpmError or client.last_tpm_error != private_integrity_failure or
                    !std.mem.allEqual(u8, &key, 0))
                    return error.BadForeignTpmFailure;
            }
            try client.close(io);
            console.print("ZIGOS:TPM2:SEAL:WRONG_DEVICE\n");
            return;
        };
        var digest: [32]u8 = undefined;
        Sha256.hash(&key, &digest, .{});
        if (!std.mem.eql(u8, &digest, payload[0..32])) return error.RecoveredWrongKey;
        blob.len = @intCast(payload_len - 32);
        @memcpy(blob.bytes[0..blob.len], payload[32..payload_len]);
    } else {
        try kernel_random.fill(&key);
        io.known_key = &key;
        try client.seal(io, &key, &auth, &blob);
        Sha256.hash(&key, payload[0..32], .{});
        @memcpy(payload[32..][0..blob.len], blob.slice());
        payload_len = 32 + blob.len;
    }
    io.known_key = &key;
    // Repeated operations exceed the TPM's transient/session slot count. A
    // missing FlushContext would exhaust device resources during this loop.
    for (0..8) |_| {
        var recovered: sealing.Key = undefined;
        defer std.crypto.secureZero(u8, &recovered);
        try client.unseal(io, blob.slice(), &auth, &recovered);
        if (!std.crypto.timing_safe.eql(sealing.Key, key, recovered)) return error.RecoveredWrongKey;
        if (!std.mem.allEqual(u8, &client.command, 0) or !std.mem.allEqual(u8, &client.response, 0))
            return error.ResidentCommandMaterial;
    }
    var wrong_auth = auth;
    wrong_auth[0] ^= 1;
    var denied: sealing.Key = @splat(0xaa);
    defer std.crypto.secureZero(u8, &denied);
    // Keep intentional wrong-auth attempts on the cold boot. Repeating them
    // across rollback boots would test DA lockout instead of vault freshness.
    if (!restored) if (client.unseal(io, blob.slice(), &wrong_auth, &denied)) |_| return error.AcceptedWrongAuthorization else |err| {
        if (err != error.TpmError or client.last_tpm_error != authorization_failure or
            !std.mem.allEqual(u8, &denied, 0)) return error.BadAuthorizationFailure;
    };
    var damaged = blob;
    damaged.bytes[42] ^= 1; // opaque private integrity digest, after the length fields
    denied = @splat(0xaa);
    if (client.unseal(io, damaged.slice(), &auth, &denied)) |_| return error.AcceptedDamagedBlob else |err| {
        if (err != error.TpmError or client.last_tpm_error != private_integrity_failure or
            !std.mem.allEqual(u8, &denied, 0)) return error.BadIntegrityFailure;
    }
    // A valid TPM response with a damaged session HMAC must not publish plaintext.
    io.corrupt_unseal = true;
    denied = @splat(0xaa);
    if (client.unseal(io, blob.slice(), &auth, &denied)) |_| return error.AcceptedDamagedResponse else |err| {
        if (err != error.IntegrityFailure or !io.corrupted or !client.failed or !std.mem.allEqual(u8, &denied, 0))
            return error.BadResponseAuthenticationFailure;
    }
    io.corrupt_unseal = false;
    try client.close(io);
    if (!restored) {
        _ = try storage.putLocallySignedVersion(.{
            .object_type = .secret,
            .payload = payload[0..payload_len],
            .signer = signer,
            .label = "tpm-sealed-key-proof",
            .content_type = content_type,
            .created_at_ticks = 1,
        });
        const previous = storage.checkpoint_enabled;
        storage.checkpoint_enabled = true;
        defer storage.checkpoint_enabled = previous;
        _ = try storage.checkpointDurable();
    }
    console.print(if (restored) "ZIGOS:TPM2:SEAL:RECOVERED\n" else "ZIGOS:TPM2:SEAL:CREATED\n");
}
