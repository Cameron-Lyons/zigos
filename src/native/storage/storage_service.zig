const builtin = @import("builtin");
const service = @import("storage_service/service.zig");

pub const api = service;

pub const CheckpointStore = service.CheckpointStore;

pub const SharedPayloadTransfer = service.SharedPayloadTransfer;
pub const SharedPayloadReadTransfer = service.SharedPayloadReadTransfer;
pub const SharedPayloadError = service.SharedPayloadError;

pub const AuthorityContext = service.AuthorityContext;
pub const AuthorityError = service.AuthorityError;

pub const SharedWorkspaceGrant = service.SharedWorkspaceGrant;
pub const ShareCapabilityError = service.ShareCapabilityError;

pub const StorageCore = service.StorageCore;
pub const Service = service.Service;
pub const StoragePort = service.StoragePort;

comptime {
    if (builtin.is_test) _ = @import("storage_service/tests.zig");
}
