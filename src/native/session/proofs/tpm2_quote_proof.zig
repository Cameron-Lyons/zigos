//! Verification-only enrollment authority for a disposable TPM and disk.
const std = @import("std");
const tpm = @import("../../platform/tpm2_sealing.zig");
const quote = tpm.quote;
const wire = @import("../../platform/tpm2_wire.zig");
const signing = @import("../../core/signing.zig");
const attestation = @import("../../platform/attestation_service.zig");
const network_policy = @import("../../sync/network_policy.zig");
const transport = @import("../../sync/sync_transport_harness.zig");
const capability = @import("../../kernel_api/capability.zig");
const principal = @import("../../core/principal.zig");
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
    try proveRemoteAttestation(&client, io, blob.slice(), enrolled, measured.pcr11);
    try provePeerExchange(&client, io, blob.slice(), enrolled, measured.pcr11);
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

fn proveRemoteAttestation(client: *tpm.Client, io: anytype, blob: []const u8, identity: quote.Identity, pcr: tpm.Key) !void {
    // This verifier policy is a local verification fixture. Operational approved
    // PCR values must come from release policy, not from the prover's handoff.
    const target = principal.PrincipalId{ .kind = .device, .serial = 0x7081 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 0x7082 };
    const owner = principal.PrincipalId{ .kind = .service, .serial = 0x7083 };
    const enrollment = try attestation.tpm.Enrollment.init(target, identity, 2, "remote-tpm-root");
    var service = attestation.Service.init(target);
    var pending = try attestation.tpm.Pending.init(io, enrollment, pcr, .{
        .remote_party = "remote.tpm.proof",
        .policy_label = "remote-tpm-policy",
        .minimum_generation = 2,
        .revoked_generations = &.{1},
    }, 100, 1000);
    var response = attestation.tpm.Response{};
    var altered = pending.challenge;
    altered.request.policy_label[0] ^= 1;
    const wrong_context = altered.qualifyingData();
    try client.quoteAttestation(io, blob, &auth, &identity, &wrong_context, &pcr, &response);
    if (pending.accept(&response, 101)) |_| return error.RelabeledTpmQuoteAccepted else |err| {
        if (err != error.QuoteMismatch) return err;
    }
    altered = pending.challenge;
    altered.approved_pcr11[0] ^= 1;
    if (service.respondToTpmAttestationRequest(client, io, blob, &auth, &enrollment, &altered, &response)) |_| return error.WrongTpmBootAccepted else |err| {
        if (err != error.QuoteMismatch or service.visible_request_count != 0 or service.remote_nonce_history_count != 0 or
            response.len != 0 or !std.mem.allEqual(u8, &response.bytes, 0)) return error.BadTpmServiceFailure;
    }
    try service.respondToTpmAttestationRequest(client, io, blob, &auth, &enrollment, &pending.challenge, &response);
    if (service.visible_request_count != 1) return error.MissingVisibleTpmAttestation;
    const commands = io.commands;
    var unpublished = attestation.tpm.Response{};
    if (service.respondToTpmAttestationRequest(client, io, blob, &auth, &enrollment, &pending.challenge, &unpublished)) |_| return error.ReusedTpmServiceNonce else |err| {
        if (err != error.RemoteNonceReplay or io.commands != commands or service.visible_request_count != 1) return error.BadTpmServiceReplayRejection;
    }
    var expired = pending;
    if (expired.accept(&response, 1100)) |_| return error.ExpiredTpmResponseAccepted else |err| {
        if (err != error.QuoteChallengeExpired) return err;
    }
    var policies = network_policy.Directory.init();
    const policy = try policies.create(.{
        .owner = owner,
        .label = "remote-tpm-policy",
        .mode = .named_service_identity,
        .target = "remote.tpm.proof",
        .require_remote_attestation = true,
        .pinned_root_digest = attestation.tpm.bootDigest(&pcr),
        .pinned_attestation_verifier_metadata_digest = enrollment.digest(),
    });
    var capabilities = capability.CapabilityTable.init();
    const cap = try capabilities.mintBootRoot(.{
        .holder = owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = policy.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 0x7084, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });
    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var harness = transport.Harness.init();
    const request = network_policy.TpmServiceIdentityOpenRequest{
        .task_id = 0x7084,
        .principal_id = owner,
        .capability_id = cap.id,
        .policy_id = policy.id,
        .service_identity = "remote.tpm.proof",
        .pending = &pending,
        .response = &response,
        .now_ms = 102,
        .now_ticks = 10,
    };
    if (harness.openTpmServiceIdentity(&broker, request, source, source)) |_| return error.MisroutedTpmResponseAccepted else |err| {
        if (err != error.ProductionAttestationRequired or pending.verifier.consumed) return error.BadTpmPeerRejection;
    }
    var wrong_service = request;
    wrong_service.service_identity = "wrong.tpm.proof";
    if (harness.openTpmServiceIdentity(&broker, wrong_service, source, target)) |_| return error.WrongTpmServiceAccepted else |err| {
        if (err != error.ProductionAttestationRequired or pending.verifier.consumed) return error.BadTpmServiceRejection;
    }
    var session = try harness.openTpmServiceIdentity(&broker, request, source, target);
    defer session.deinit();
    try session.requireProductionAttestation();
    if (harness.openTpmServiceIdentity(&broker, request, source, target)) |_| return error.ReplayedTpmSessionAccepted else |err| {
        if (err != error.ProductionAttestationRequired or harness.created_sessions != 1) return error.BadTpmReplayRejection;
    }
    const packet = try harness.encryptPacket(&session, "TPM attested payload");
    var plaintext: [transport.MAX_PACKET_BYTES]u8 = undefined;
    if (!std.mem.eql(u8, try transport.decryptForSession(&session, packet, &plaintext), "TPM attested payload")) return error.TpmSessionPayloadMismatch;
    if (!std.mem.eql(u8, &session.peer_root_digest, &attestation.tpm.bootDigest(&pcr)) or
        !std.mem.eql(u8, &session.attestation_verifier_metadata_digest, &enrollment.digest())) return error.TpmSessionPinMismatch;
    console.print("ZIGOS:TPM2:REMOTE_ATTESTATION:VERIFIED\n");
}

// A real TPM quote crosses two independently established channel endpoints.
// The disposable verifier still uses a fixture enrollment authority and PCR policy.
fn provePeerExchange(client: *tpm.Client, io: anytype, blob: []const u8, identity: quote.Identity, pcr: tpm.Key) !void {
    const peer = @import("../../sync/peer_channel.zig");
    const exchange = @import("../../sync/peer_attestation.zig");
    const graph_mod = @import("../../sync/device_graph.zig");
    const root = signing.SignerIdentity{ .label = "quote-peer-root", .seed = @splat(0xd1) };
    const source_key = signing.SignerIdentity{ .label = "quote-peer-source", .seed = @splat(0xd2) };
    const target_key = signing.SignerIdentity{ .label = "quote-peer-target", .seed = @splat(0xd3) };
    const owner = principal.PrincipalId{ .kind = .user, .serial = 0x7090 };
    const source = principal.PrincipalId{ .kind = .device, .serial = 0x7091 };
    const target = principal.PrincipalId{ .kind = .device, .serial = 0x7092 };
    var graph = graph_mod.Graph.init();
    _ = try graph.ensureUserRoot(owner, "quote owner", root);
    _ = try graph.enrollDevice(owner, source, "quote verifier", root, source_key, 1);
    _ = try graph.enrollDevice(owner, target, "quote prover", root, target_key, 1);
    const remote_graph = graph;
    var a = try peer.Channel.initForVerification(&graph, try signing.publicKey(root), source, target, source_key, .initiator);
    defer a.close();
    var b = try peer.Channel.initForVerification(&remote_graph, try signing.publicKey(root), target, source, target_key, .responder);
    defer b.close();
    var frame: [peer.MAX_FRAME]u8 = undefined;
    try b.readHandshake(try a.writeHandshake(&frame, 20), 20);
    try a.readHandshake(try b.writeHandshake(&frame, 20), 20);
    try b.readHandshake(try a.writeHandshake(&frame, 20), 20);
    const enrollment = try attestation.tpm.Enrollment.init(target, identity, 2, "peer-quote-root");
    var pending = try attestation.tpm.Pending.init(io, enrollment, pcr, .{ .remote_party = "peer.quote.proof", .policy_label = "peer-quote-policy" }, 200, 1000);
    var verifier = try exchange.Exchange.init(&a, .{ .verify = &pending }, "", 20, 120);
    defer verifier.close();
    var prover = try exchange.Exchange.init(&b, .{ .prove = &enrollment }, "", 20, 120);
    defer prover.close();
    // Reverse fragments, including a repeated ciphertext, without any TPM I/O.
    const commands = io.commands;
    var index: usize = verifier.outgoing_count;
    while (index != 0) {
        index -= 1;
        const packet = verifier.outgoing[index][0..verifier.outgoing_lens[index]];
        for (0..2) |_| {
            if (!prover.admit(packet, 21) or !prover.service(21, @splat(0), rejectPeerSend)) return error.PeerChallengeNotAdmitted;
        }
    }
    if (io.commands != commands or prover.ready() or verifier.ready()) return error.PrematurePeerAttestation;
    const challenge = prover.quoteChallenge(21) orelse return error.MissingPeerQuoteChallenge;
    var service = attestation.Service.init(target);
    var response = attestation.tpm.Response{};
    try service.respondToTpmAttestationRequest(client, io, blob, &auth, &enrollment, &challenge, &response);
    try prover.completeQuote(&response, 22);
    index = prover.outgoing_count;
    while (index != 0) {
        index -= 1;
        if (!verifier.admit(prover.outgoing[index][0..prover.outgoing_lens[index]], 23) or !verifier.service(23, @splat(0), rejectPeerSend)) return error.PeerQuoteNotAdmitted;
    }
    if (!verifier.ready() or prover.ready() or verifier.accepted == null or service.visible_request_count != 1) return error.PeerQuoteNotVerified;
    if (!prover.admit(verifier.outgoing[0][0..verifier.outgoing_lens[0]], 24) or !prover.service(24, @splat(0), rejectPeerSend) or !prover.ready()) return error.PeerQuoteNotAcknowledged;
    var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
    if (!std.mem.eql(u8, "attested peer transfer", try b.open(&plaintext, try a.seal(&frame, "attested peer transfer", 25), 25))) return error.PeerQuoteChannelFailed;
    console.print("ZIGOS:TPM2:PEER_ATTESTATION:VERIFIED\n");
}

fn rejectPeerSend(_: [6]u8, _: []const u8) bool {
    return false;
}
