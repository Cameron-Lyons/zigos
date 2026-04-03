const std = @import("std");
const accelerator_scheduler = @import("../../native/task/accelerator_scheduler.zig");
const attestation_service = @import("../../native/platform/attestation_service.zig");
const event_ledger = @import("../../native/platform/event_ledger.zig");
const immutable_base = @import("../../native/platform/immutable_base.zig");
const measured_boot = @import("../../native/platform/measured_boot.zig");
const native_ux = @import("../../native/platform/native_ux.zig");
const notification_center = @import("../../native/services/notification_center.zig");
const policy_object = @import("../../native/policy/policy_object.zig");
const recovery_environment = @import("../../native/platform/recovery_environment.zig");
const secure_secret_store = @import("../../native/platform/secure_secret_store.zig");
const session_manager = @import("../../native/session/session_manager.zig");

test "platform platform modules compile and expose their tests from the src root" {
    std.testing.refAllDecls(accelerator_scheduler);
    std.testing.refAllDecls(attestation_service);
    std.testing.refAllDecls(event_ledger);
    std.testing.refAllDecls(immutable_base);
    std.testing.refAllDecls(measured_boot);
    std.testing.refAllDecls(native_ux);
    std.testing.refAllDecls(notification_center);
    std.testing.refAllDecls(policy_object);
    std.testing.refAllDecls(recovery_environment);
    std.testing.refAllDecls(secure_secret_store);
    std.testing.refAllDecls(session_manager);
}
