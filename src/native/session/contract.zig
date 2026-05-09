const std = @import("std");
const driver_service = @import("../drivers/driver_service.zig");
const service_catalog = @import("service_catalog.zig");

pub const KernelTcbComponent = service_catalog.KernelTcbComponent;
pub const ServiceClass = service_catalog.ServiceClass;
pub const ServiceBoundary = service_catalog.ServiceBoundary;
pub const NetworkPrivilege = service_catalog.NetworkPrivilege;
pub const StoragePrivilege = service_catalog.StoragePrivilege;
pub const UiPrivilege = service_catalog.UiPrivilege;
pub const IsolationProfile = service_catalog.IsolationProfile;
pub const ServiceDescriptor = service_catalog.ServiceDescriptor;

pub const kernel_tcb = service_catalog.kernel_tcb;
pub const default_services = service_catalog.default_services;

pub const tcbName = service_catalog.tcbName;
pub const serviceName = service_catalog.serviceName;
pub const serviceDescriptor = service_catalog.serviceDescriptor;

pub fn allowsDriverClass(class: ServiceClass, device_class: driver_service.DeviceClass) bool {
    return service_catalog.allowsDriverClass(class, device_class);
}

test "kernel tcb contains the expected bootstrap surface" {
    try std.testing.expectEqual(@as(usize, 7), kernel_tcb.len);
    try std.testing.expectEqualStrings("ipc_transport", tcbName(.ipc_transport));
    try std.testing.expectEqualStrings("iommu_dma_isolation_hooks", tcbName(.iommu_dma_isolation_hooks));
}

test "native bootstrap and service bootstrap services sit behind restartable userspace contracts" {
    const runtime = serviceDescriptor(.task_runtime).?;
    const session = serviceDescriptor(.session_manager).?;
    const registry = serviceDescriptor(.service_registry).?;
    const compatibility_service = serviceDescriptor(.compatibility_portal).?;
    const network = serviceDescriptor(.network_stack).?;
    const storage = serviceDescriptor(.storage_object).?;
    const policy = serviceDescriptor(.policy_mediation).?;

    try std.testing.expectEqual(ServiceBoundary.userspace_service, runtime.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, session.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, registry.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, compatibility_service.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, network.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, storage.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, policy.boundary);
    try std.testing.expect(runtime.restartable);
    try std.testing.expect(compatibility_service.restartable);
    try std.testing.expect(runtime.isolation.namespace_isolated);
    try std.testing.expectEqual(NetworkPrivilege.unrestricted_brokered, network.isolation.network);
    try std.testing.expectEqual(StoragePrivilege.object_store_authority, storage.isolation.storage);
    try std.testing.expectEqual(UiPrivilege.review_surface, compatibility_service.isolation.ui);
    try std.testing.expect(allowsDriverClass(.network_stack, .network_adapter));
    try std.testing.expect(allowsDriverClass(.storage_object, .storage_controller));
    try std.testing.expect(allowsDriverClass(.compositor_ui_session, .graphics_adapter));
    try std.testing.expect(allowsDriverClass(.compositor_ui_session, .input_device));
    try std.testing.expect(allowsDriverClass(.media_print_helpers, .audio_print_io));
    try std.testing.expect(!allowsDriverClass(.policy_mediation, .network_adapter));
}
