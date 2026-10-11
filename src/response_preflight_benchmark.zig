const dispatch = @import("native/kernel_api/syscall_dispatch.zig");

pub const UserMemoryContext = dispatch.UserMemoryContext;
pub const DispatchResult = dispatch.DispatchResult;
pub const AddressSpaceRecord = @import("native/task/task_runtime.zig").AddressSpaceRecord;
pub const preflightResponse = dispatch.preflightResponse;
pub const validateUserRange = dispatch.validateUserRange;
pub const prepareUserRange = dispatch.prepareUserRange;

comptime {
    if (@import("builtin").is_test) _ = dispatch;
}
