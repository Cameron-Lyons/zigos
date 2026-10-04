//! Live native publication authority. The owner and guard remain at stable
//! addresses until the operation and all device cleanup have returned.
pub const Error = error{ Cancelled, OperationExpired, OperationClockRollback, OperationAuthorityChanged, OperationPolicyDenied };

pub const Guard = struct {
    context: *anyopaque,
    // Read-only, non-yielding and non-destructive. In particular, this callback
    // must never unload a vault or erase buffers borrowed by an active command.
    check_fn: *const fn (*anyopaque) Error!u64,
};

pub fn currentTicks(guard: ?*const Guard, observed_ticks: u64) Error!u64 {
    const current = if (guard) |live| try live.check_fn(live.context) else observed_ticks;
    if (current < observed_ticks) return error.OperationClockRollback;
    return current;
}
