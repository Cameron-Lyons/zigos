const std = @import("std");
const abi = @import("abi.zig");
const semantics = @import("ipc_semantics.zig");
const memory = @import("../../memory/memory.zig");
const protection = @import("../../memory/protection.zig");

const MAX_SHM_SEGMENTS = 64;
const MAX_SEM_SETS = 64;
const MAX_SEMAPHORES = semantics.MAX_SEMAPHORES;

const ShmSegment = struct {
    key: i32,
    size: usize,
    addr: ?[*]u8,
    mode: u32,
    nattch: u32,
    in_use: bool,
    marked_for_deletion: bool,
};

var shm_segments: [MAX_SHM_SEGMENTS]ShmSegment = [_]ShmSegment{.{
    .key = 0,
    .size = 0,
    .addr = null,
    .mode = 0,
    .nattch = 0,
    .in_use = false,
    .marked_for_deletion = false,
}} ** MAX_SHM_SEGMENTS;

const ShmidDs = extern struct {
    shm_perm_mode: u32,
    shm_segsz: u32,
    shm_atime: u32,
    shm_dtime: u32,
    shm_ctime: u32,
    shm_cpid: u32,
    shm_lpid: u32,
    shm_nattch: u32,
};

pub fn sys_shmget(key: i32, size: usize, shmflg: u32) i32 {
    if (key != 0) {
        for (shm_segments, 0..) |seg, i| {
            if (seg.in_use and seg.key == key) {
                if (shmflg & abi.IPC_CREAT != 0 and shmflg & abi.IPC_EXCL != 0) {
                    return abi.EEXIST;
                }
                return @intCast(i);
            }
        }
    }

    if (shmflg & abi.IPC_CREAT == 0 and key != 0) return abi.ENOENT;

    for (&shm_segments, 0..) |*seg, i| {
        if (!seg.in_use) {
            const mem = memory.kmalloc(size) orelse return abi.ENOMEM;
            seg.in_use = true;
            seg.key = key;
            seg.size = size;
            seg.addr = @ptrCast(@alignCast(mem));
            seg.mode = shmflg & 0o777;
            seg.nattch = 0;
            seg.marked_for_deletion = false;
            return @intCast(i);
        }
    }
    return abi.ENOSPC;
}

pub fn sys_shmat(shmid: i32, shmaddr: usize, shmflg: u32) i32 {
    _ = shmaddr;
    _ = shmflg;

    if (shmid < 0 or shmid >= MAX_SHM_SEGMENTS) return abi.EINVAL;
    const seg = &shm_segments[@intCast(shmid)];
    if (!seg.in_use) return abi.EINVAL;
    if (seg.marked_for_deletion) return abi.EINVAL;

    seg.nattch += 1;
    if (seg.addr) |addr| {
        return @intCast(@intFromPtr(addr));
    }
    return abi.EINVAL;
}

pub fn sys_shmdt(addr: usize) i32 {
    for (&shm_segments) |*seg| {
        if (seg.in_use) {
            if (seg.addr) |segment_addr| {
                if (@intFromPtr(segment_addr) == addr) {
                    if (seg.nattch > 0) seg.nattch -= 1;
                    if (seg.marked_for_deletion and seg.nattch == 0) {
                        memory.kfree(@ptrCast(segment_addr));
                        seg.in_use = false;
                        seg.addr = null;
                        seg.marked_for_deletion = false;
                    }
                    return 0;
                }
            }
        }
    }
    return abi.EINVAL;
}

pub fn sys_shmctl(shmid: i32, cmd: u32, buf_addr: usize) i32 {
    if (shmid < 0 or shmid >= MAX_SHM_SEGMENTS) return abi.EINVAL;
    const seg = &shm_segments[@intCast(shmid)];
    if (!seg.in_use) return abi.EINVAL;

    switch (cmd) {
        abi.IPC_STAT => {
            if (!protection.verifyUserPointer(buf_addr, @sizeOf(ShmidDs))) return abi.EINVAL;
            const ds = ShmidDs{
                .shm_perm_mode = seg.mode,
                .shm_segsz = @intCast(seg.size),
                .shm_atime = 0,
                .shm_dtime = 0,
                .shm_ctime = 0,
                .shm_cpid = 0,
                .shm_lpid = 0,
                .shm_nattch = seg.nattch,
            };
            protection.copyToUser(buf_addr, std.mem.asBytes(&ds)) catch return abi.EINVAL;
            return 0;
        },
        abi.IPC_RMID => {
            if (seg.nattch == 0) {
                if (seg.addr) |addr| {
                    memory.kfree(@ptrCast(addr));
                }
                seg.in_use = false;
                seg.addr = null;
            } else {
                seg.marked_for_deletion = true;
            }
            return 0;
        },
        else => return abi.EINVAL,
    }
}

const Semaphore = semantics.Semaphore;
const SemSet = semantics.SemSet;

var sem_sets: [MAX_SEM_SETS]SemSet = [_]SemSet{.{
    .key = 0,
    .sems = [_]Semaphore{.{ .value = 0 }} ** MAX_SEMAPHORES,
    .nsems = 0,
    .mode = 0,
    .in_use = false,
}} ** MAX_SEM_SETS;

const Sembuf = semantics.Sembuf;

pub fn sys_semget(key: i32, nsems: u32, semflg: u32) i32 {
    if (nsems > MAX_SEMAPHORES) return abi.EINVAL;

    if (key != 0) {
        for (sem_sets, 0..) |set, i| {
            if (set.in_use and set.key == key) {
                if (semflg & abi.IPC_CREAT != 0 and semflg & abi.IPC_EXCL != 0) {
                    return abi.EEXIST;
                }
                return @intCast(i);
            }
        }
    }

    if (semflg & abi.IPC_CREAT == 0 and key != 0) return abi.ENOENT;

    for (&sem_sets, 0..) |*set, i| {
        if (!set.in_use) {
            set.in_use = true;
            set.key = key;
            set.nsems = nsems;
            set.mode = semflg & 0o777;
            for (&set.sems) |*sem| {
                sem.value = 0;
            }
            return @intCast(i);
        }
    }
    return abi.ENOSPC;
}

pub fn sys_semop(semid: i32, sops_addr: usize, nsops: u32) i32 {
    if (semid < 0 or semid >= MAX_SEM_SETS) return abi.EINVAL;
    const set = &sem_sets[@intCast(semid)];
    if (!set.in_use) return abi.EINVAL;
    if (nsops == 0 or nsops > MAX_SEMAPHORES) return abi.EINVAL;

    if (!protection.verifyUserPointer(sops_addr, nsops * @sizeOf(Sembuf))) return abi.EINVAL;

    var sops: [MAX_SEMAPHORES]Sembuf = undefined;
    protection.copyFromUser(std.mem.sliceAsBytes(sops[0..nsops]), sops_addr) catch return abi.EINVAL;
    return semantics.applySemOps(set, sops[0..nsops]);
}

pub fn sys_semctl(semid: i32, semnum: u32, cmd: u32, arg: usize) i32 {
    if (semid < 0 or semid >= MAX_SEM_SETS) return abi.EINVAL;
    const set = &sem_sets[@intCast(semid)];
    if (!set.in_use) return abi.EINVAL;

    switch (cmd) {
        abi.GETVAL => {
            if (semnum >= set.nsems) return abi.EINVAL;
            return set.sems[semnum].value;
        },
        abi.SETVAL => {
            if (semnum >= set.nsems) return abi.EINVAL;
            set.sems[semnum].value = @intCast(arg & 0xFFFF);
            return 0;
        },
        abi.IPC_RMID => {
            set.in_use = false;
            return 0;
        },
        else => return abi.EINVAL,
    }
}
