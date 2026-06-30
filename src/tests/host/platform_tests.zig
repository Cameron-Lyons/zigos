const std = @import("std");

const attestation_service = @import("../../native/platform/attestation_service.zig");
const base_boot_selector = @import("../../native/platform/base_boot_selector.zig");
const compositor_display = @import("../../native/platform/compositor_display.zig");
const compositor_session = @import("../../native/platform/compositor_session.zig");
const event_ledger = @import("../../native/platform/event_ledger.zig");
const event_ledger_test = @import("../../native/platform/event_ledger_test.zig");
const immutable_base = @import("../../native/platform/immutable_base.zig");
const measured_boot = @import("../../native/platform/measured_boot.zig");
const native_ux = @import("../../native/platform/native_ux.zig");
const os_contract = @import("../../native/platform/os_contract.zig");
const os_identity = @import("../../native/platform/os_identity.zig");
const platform_policy_signals = @import("../../native/platform/platform_policy_signals.zig");
const recovery_environment = @import("../../native/platform/recovery_environment.zig");
const rendered_shell = @import("../../native/platform/rendered_shell.zig");
const secure_secret_store = @import("../../native/platform/secure_secret_store.zig");
const update_health = @import("../../native/platform/update_health.zig");

test "platform host tests import native platform modules" {
    std.testing.refAllDecls(attestation_service);
    std.testing.refAllDecls(base_boot_selector);
    std.testing.refAllDecls(compositor_display);
    std.testing.refAllDecls(compositor_session);
    std.testing.refAllDecls(event_ledger);
    std.testing.refAllDecls(event_ledger_test);
    std.testing.refAllDecls(immutable_base);
    std.testing.refAllDecls(measured_boot);
    std.testing.refAllDecls(native_ux);
    std.testing.refAllDecls(os_contract);
    std.testing.refAllDecls(os_identity);
    std.testing.refAllDecls(platform_policy_signals);
    std.testing.refAllDecls(recovery_environment);
    std.testing.refAllDecls(rendered_shell);
    std.testing.refAllDecls(secure_secret_store);
    std.testing.refAllDecls(update_health);
}
