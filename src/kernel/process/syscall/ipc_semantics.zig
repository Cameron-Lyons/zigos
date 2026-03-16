const std = @import("std");
const abi = @import("abi.zig");

pub const MAX_SEMAPHORES = 32;

pub const Semaphore = struct {
    value: i16,
};

pub const SemSet = struct {
    key: i32,
    sems: [MAX_SEMAPHORES]Semaphore,
    nsems: u32,
    mode: u32,
    in_use: bool,
};

pub const Sembuf = extern struct {
    sem_num: u16,
    sem_op: i16,
    sem_flg: i16,
};

pub fn applySemOps(set: *SemSet, ops: []const Sembuf) i32 {
    for (ops) |op| {
        if (op.sem_num >= set.nsems) return abi.EINVAL;
    }

    for (ops) |op| {
        const sem = &set.sems[op.sem_num];
        if (op.sem_op > 0) {
            sem.value += op.sem_op;
        } else if (op.sem_op < 0) {
            if (sem.value < -op.sem_op) {
                return abi.EAGAIN;
            }
            sem.value += op.sem_op;
        } else {
            if (sem.value != 0) return abi.EAGAIN;
        }
    }

    return 0;
}

fn makeTestSemSet(nsems: u32) SemSet {
    return .{
        .key = 1,
        .sems = [_]Semaphore{.{ .value = 0 }} ** MAX_SEMAPHORES,
        .nsems = nsems,
        .mode = 0,
        .in_use = true,
    };
}

test "applySemOps updates semaphore values across add and subtract" {
    var set = makeTestSemSet(2);
    const ops = [_]Sembuf{
        .{ .sem_num = 0, .sem_op = 3, .sem_flg = 0 },
        .{ .sem_num = 0, .sem_op = -2, .sem_flg = 0 },
        .{ .sem_num = 1, .sem_op = 1, .sem_flg = 0 },
    };

    try std.testing.expectEqual(@as(i32, 0), applySemOps(&set, &ops));
    try std.testing.expectEqual(@as(i16, 1), set.sems[0].value);
    try std.testing.expectEqual(@as(i16, 1), set.sems[1].value);
}

test "applySemOps rejects underflow and zero waits on nonzero semaphores" {
    var set = makeTestSemSet(1);
    set.sems[0].value = 1;

    const underflow_ops = [_]Sembuf{
        .{ .sem_num = 0, .sem_op = -2, .sem_flg = 0 },
    };
    try std.testing.expectEqual(@as(i32, abi.EAGAIN), applySemOps(&set, &underflow_ops));

    const wait_for_zero_ops = [_]Sembuf{
        .{ .sem_num = 0, .sem_op = 0, .sem_flg = 0 },
    };
    try std.testing.expectEqual(@as(i32, abi.EAGAIN), applySemOps(&set, &wait_for_zero_ops));
}

test "applySemOps rejects operations beyond the configured semaphore count" {
    var set = makeTestSemSet(1);
    const ops = [_]Sembuf{
        .{ .sem_num = 1, .sem_op = 1, .sem_flg = 0 },
    };

    try std.testing.expectEqual(@as(i32, abi.EINVAL), applySemOps(&set, &ops));
}
