const std = @import("std");
const durable_identity_service = @import("../../native/services/durable_identity_service.zig");

const component_abi_schema = @import("../../native/services/component_abi_schema.zig");
const indexing_service = @import("../../kernel/boot/benchmark/models/indexing_service.zig");
const media_print_service = @import("../../kernel/boot/benchmark/models/media_print_service.zig");
const notification_center = @import("../../native/services/notification_center.zig");
const package_service = @import("../../native/services/package_service.zig");
const service_authority = @import("../../native/services/service_authority.zig");
const service_registry = @import("../../native/services/service_registry.zig");
const secure_pasteboard = @import("../../native/services/secure_pasteboard.zig");
const secret_vault_service = @import("../../native/services/secret_vault_service.zig");
const userspace_service_ipc = @import("../fixtures/userspace_service_ipc.zig");

test "service host tests import native service modules" {
    std.testing.refAllDecls(@import("../../native/services/identity_enrollment.zig"));
    std.testing.refAllDecls(@import("../../native/services/identity_provisioning.zig"));
    std.testing.refAllDecls(@import("../../native/services/identity_recovery_record.zig"));
    std.testing.refAllDecls(@import("../../native/services/identity_setup_worker.zig"));
    std.testing.refAllDecls(@import("../../native/services/identity_owner.zig"));
    std.testing.refAllDecls(@import("../../native/services/identity_policy.zig"));
    std.testing.refAllDecls(@import("../../native/services/identity_channel.zig"));
    _ = @import("../../native/services/identity_channel_test.zig");
    std.testing.refAllDecls(@import("../../userspace/identity_protocol.zig"));
    std.testing.refAllDecls(@import("../../userspace/identity_assertion.zig"));
    std.testing.refAllDecls(@import("../../native/platform/trusted_setup_entry.zig"));
    std.testing.refAllDecls(@import("../../native/services/identity_recovery.zig"));
    std.testing.refAllDecls(@import("../../native/services/identity_session.zig"));
    std.testing.refAllDecls(@import("../../native/services/identity_authenticator.zig"));
    _ = @import("../../native/services/peer_attestation_worker_test.zig");
    _ = @import("../../native/services/public_enrollment_test.zig");
    _ = @import("../../native/services/durable_enrollment_test.zig");
    std.testing.refAllDecls(durable_identity_service);
    std.testing.refAllDecls(component_abi_schema);
    std.testing.refAllDecls(indexing_service);
    std.testing.refAllDecls(media_print_service);
    std.testing.refAllDecls(notification_center);
    std.testing.refAllDecls(package_service);
    std.testing.refAllDecls(service_authority);
    std.testing.refAllDecls(service_registry);
    std.testing.refAllDecls(secure_pasteboard);
    std.testing.refAllDecls(secret_vault_service);
    std.testing.refAllDecls(userspace_service_ipc);
}
