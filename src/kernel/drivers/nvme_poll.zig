//! One bounded completion inspection, shared by hardware and hosted fixtures.
const completion = @import("nvme_completion.zig");
const cooperative = @import("../../native/task/cooperative_worker.zig");

pub const Error = error{ CompletionOwnershipMismatch, CommandTimeout, ControllerFatal, DmaFault, CommandFailed };

pub fn poll(io: anytype, queue: anytype, outstanding: anytype, check_health: bool) Error!?u16 {
    if (outstanding.len == 0) return error.CompletionOwnershipMismatch;
    if (check_health) {
        for (outstanding) |command| if (io.expired(command.deadline)) return error.CommandTimeout;
        if (io.fatal()) return error.ControllerFatal;
        try io.checkDma();
    }
    if (completion.phase(io.status(queue.cq_head)) != queue.phase) return null;
    io.acquireCompletion();
    const value = completion.decode(io.submission(queue.cq_head), io.status(queue.cq_head));
    if (!value.belongsToQueue(queue.qid, queue.entries)) return error.CompletionOwnershipMismatch;
    var owned = false;
    for (outstanding) |command| if (command.cid == value.command_id) {
        owned = true;
        break;
    };
    if (!owned) return error.CompletionOwnershipMismatch;
    queue.cq_head = (queue.cq_head + 1) % queue.entries;
    if (queue.cq_head == 0) queue.phase ^= 1;
    io.acknowledge(queue.cq_head);
    try io.checkDma();
    if (!value.succeeded()) return error.CommandFailed;
    return value.command_id;
}

pub fn wait(io: anytype, queue: anytype, outstanding: anytype, interrupt_wait: bool, worker: ?*cooperative.Worker) Error!u16 {
    // Admin queues remain synchronous even if a native Worker invoked them.
    const active_worker = if (queue.qid != 0) worker else null;
    var spins: u64 = 0;
    while (true) : (spins +%= 1) {
        if (try poll(io, queue, outstanding, active_worker != null or interrupt_wait or (spins & 0x3ff) == 0)) |cid| return cid;
        if (active_worker) |active| active.yield() else if (interrupt_wait) io.idle(queue) else io.pause();
    }
}
