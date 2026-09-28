const std = @import("std");
const attest = @import("../platform/tpm_attestation.zig");
const quote = @import("../platform/tpm2_quote.zig");
const capability = @import("../kernel_api/capability.zig");
const principal = @import("../core/principal.zig");
const network = @import("network_policy.zig");
const driver = @import("../drivers/network_driver_task.zig");
const transport = @import("sync_transport.zig");

test "TPM remote attestation gates native driver and endpoint connections before transmission" {
    const Io = struct {
        var sends: usize = 0;
        fn send(_: [6]u8, _: []const u8) bool {
            sends += 1;
            return true;
        }
        fn mac() [6]u8 {
            return .{ 2, 0, 0, 0, 0, 1 };
        }
    };
    const Entropy = struct {
        value: u8 = 0x51,
        pub fn random(self: *@This(), out: []u8) !void {
            @memset(out, self.value);
            self.value += 1;
        }
    };
    var entropy = Entropy{};
    Io.sends = 0;
    driver.reset();
    defer driver.reset();
    const device = driver.NetworkDevice{ .send = Io.send, .receive = driver.noNetworkFrame, .getMacAddress = Io.mac };
    try std.testing.expect(driver.activateDevice(&device, 79));
    const source = principal.PrincipalId{ .kind = .device, .serial = 901 };
    const target = principal.PrincipalId{ .kind = .device, .serial = 902 };
    const owner = principal.PrincipalId{ .kind = .service, .serial = 79 };
    const pcr: quote.Digest = @splat(0x31);
    const initial = try quote.testing.QuoteFixture.initFor(@splat(1), pcr);
    const enrolled = try attest.Enrollment.init(target, initial.identity, 2, "tpm-network-root");
    var policies = network.Directory.init();
    const policy = try policies.create(.{
        .owner = owner,
        .label = "tpm-network-policy",
        .mode = .named_service_identity,
        .target = "peer.tpm.example",
        .require_remote_attestation = true,
        .pinned_root_digest = attest.bootDigest(&pcr),
        .pinned_attestation_verifier_metadata_digest = enrolled.digest(),
    });
    var capabilities = capability.CapabilityTable.init();
    const cap = try capabilities.mintBootRoot(.{
        .holder = owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = policy.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 79, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });
    var broker = network.EgressBroker.init(&policies, &capabilities);
    var stack = driver.NativeNetworkStack.init();
    defer stack.deinit();
    try stack.bindPeerLink(target, .{ 2, 0, 0, 0, 0, 2 });
    var native = transport.NativeTransportService.init();
    inline for (.{ false, true }) |endpoint| {
        var pending = try attest.Pending.init(&entropy, enrolled, pcr, .{ .remote_party = "peer.tpm.example", .policy_label = "tpm-network-policy" }, 100, 1000);
        var fixture = try quote.testing.QuoteFixture.initFor(pending.challenge.qualifyingData(), pcr);
        var request = network.TpmServiceIdentityOpenRequest{
            .task_id = 79,
            .principal_id = owner,
            .capability_id = cap.id,
            .policy_id = policy.id,
            .service_identity = "peer.tpm.example",
            .pending = &pending,
            .response = &fixture.evidence,
            .now_ms = 101,
            .now_ticks = 10,
        };
        const denied = if (endpoint) error.ProductionAttestationRequired else error.EgressDenied;
        const sends = Io.sends;
        if (endpoint) {
            try std.testing.expectError(denied, native.openTpmServiceIdentity(&broker, request, 79, 80, source, source));
        } else {
            try std.testing.expectError(denied, stack.openTpmServiceIdentity(&broker, request, source, source));
        }
        try std.testing.expect(!pending.verifier.consumed);
        request.service_identity = "wrong.tpm.example";
        if (endpoint) {
            try std.testing.expectError(denied, native.openTpmServiceIdentity(&broker, request, 79, 80, source, target));
        } else {
            try std.testing.expectError(denied, stack.openTpmServiceIdentity(&broker, request, source, target));
        }
        request.service_identity = "peer.tpm.example";
        fixture.evidence.bytes[fixture.evidence.len - 1] ^= 1;
        if (endpoint) {
            try std.testing.expectError(denied, native.openTpmServiceIdentity(&broker, request, 79, 80, source, target));
        } else {
            try std.testing.expectError(denied, stack.openTpmServiceIdentity(&broker, request, source, target));
        }
        try std.testing.expectEqual(sends, Io.sends);
        try std.testing.expect(!pending.verifier.consumed);
        fixture.evidence.bytes[fixture.evidence.len - 1] ^= 1;
        if (endpoint) {
            var connection = try native.openTpmServiceIdentity(&broker, request, 79, 80, source, target);
            defer native.disconnect(&connection);
            try connection.session.requireProductionAttestation();
            try std.testing.expectEqualSlices(u8, &enrolled.digest(), &connection.session.attestation_verifier_metadata_digest);
            try std.testing.expectError(denied, native.openTpmServiceIdentity(&broker, request, 79, 80, source, target));
        } else {
            const connection = try stack.openTpmServiceIdentity(&broker, request, source, target);
            try std.testing.expectEqualSlices(u8, &enrolled.digest(), &connection.attestation_verifier_metadata_digest);
            try std.testing.expectError(denied, stack.openTpmServiceIdentity(&broker, request, source, target));
            const frame = try stack.sendServiceIdentityFrameBrokered(&broker, &connection, "quoted TPM session", 11);
            try std.testing.expect(frame.flags.verified_remote_attestation);
            try std.testing.expect(frame.flags.attestation_verifier_metadata_digest_bound);
            try std.testing.expectEqual(sends + 1, Io.sends);
        }
        // An authentic quote cannot bypass the network policy's independently
        // configured boot pin. Once verified, even a policy denial spends it.
        pending = try attest.Pending.init(&entropy, enrolled, pcr, .{ .remote_party = "peer.tpm.example", .policy_label = "tpm-network-policy" }, 100, 1000);
        fixture = try quote.testing.QuoteFixture.initFor(pending.challenge.qualifyingData(), pcr);
        const sends_before_pin_failure = Io.sends;
        policies.find(policy.id).?.pinned_root_digest[0] ^= 1;
        if (endpoint) {
            try std.testing.expectError(error.EgressDenied, native.openTpmServiceIdentity(&broker, request, 79, 80, source, target));
        } else {
            try std.testing.expectError(error.EgressDenied, stack.openTpmServiceIdentity(&broker, request, source, target));
        }
        policies.find(policy.id).?.pinned_root_digest[0] ^= 1;
        try std.testing.expect(pending.verifier.consumed);
        try std.testing.expectEqual(sends_before_pin_failure, Io.sends);
        pending = try attest.Pending.init(&entropy, enrolled, pcr, .{ .remote_party = "peer.tpm.example", .policy_label = "tpm-network-policy" }, 100, 1000);
        fixture = try quote.testing.QuoteFixture.initFor(pending.challenge.qualifyingData(), pcr);
        request.now_ms = 1100;
        if (endpoint) {
            try std.testing.expectError(denied, native.openTpmServiceIdentity(&broker, request, 79, 80, source, source));
        } else {
            try std.testing.expectError(denied, stack.openTpmServiceIdentity(&broker, request, source, source));
        }
        try std.testing.expect(pending.verifier.consumed);
        request.now_ms = 101;
        if (endpoint) {
            try std.testing.expectError(denied, native.openTpmServiceIdentity(&broker, request, 79, 80, source, target));
        } else {
            try std.testing.expectError(denied, stack.openTpmServiceIdentity(&broker, request, source, target));
        }
    }
}
