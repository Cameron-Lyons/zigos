const std = @import("std");

const agent_delegation_service = @import("../../native/services/agent_delegation_service.zig");
const component_abi_schema = @import("../../native/services/component_abi_schema.zig");
const indexing_service = @import("../../native/services/indexing_service.zig");
const media_print_service = @import("../../native/services/media_print_service.zig");
const notification_center = @import("../../native/services/notification_center.zig");
const package_service = @import("../../native/services/package_service.zig");
const service_authority = @import("../../native/services/service_authority.zig");
const service_registry = @import("../../native/services/service_registry.zig");
const secure_pasteboard = @import("../../native/services/secure_pasteboard.zig");
const typed_component_abi = @import("../../native/services/typed_component_abi.zig");
const userspace_service_ipc = @import("../../native/services/userspace_service_ipc.zig");

test "service host tests import native service modules" {
    std.testing.refAllDecls(component_abi_schema);
    std.testing.refAllDecls(agent_delegation_service);
    std.testing.refAllDecls(indexing_service);
    std.testing.refAllDecls(media_print_service);
    std.testing.refAllDecls(notification_center);
    std.testing.refAllDecls(package_service);
    std.testing.refAllDecls(service_authority);
    std.testing.refAllDecls(service_registry);
    std.testing.refAllDecls(secure_pasteboard);
    std.testing.refAllDecls(typed_component_abi);
    std.testing.refAllDecls(userspace_service_ipc);
}
