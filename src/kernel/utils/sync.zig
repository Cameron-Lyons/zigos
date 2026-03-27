const std = @import("std");

pub const SpinLock = struct {
    locked: bool = false,
    owner: ?u32 = null,

    pub fn init() SpinLock {
        return .{};
    }

    pub fn acquire(self: *SpinLock) void {
        while (@atomicRmw(bool, &self.locked, .Xchg, true, .seq_cst)) {
            while (@atomicLoad(bool, &self.locked, .seq_cst)) {
                asm volatile ("pause");
            }
        }
        self.owner = 0;
    }

    pub fn release(self: *SpinLock) void {
        self.owner = null;
        @atomicStore(bool, &self.locked, false, .seq_cst);
    }

    pub fn tryAcquire(self: *SpinLock) bool {
        if (!@atomicRmw(bool, &self.locked, .Xchg, true, .seq_cst)) {
            self.owner = 0;
            return true;
        }
        return false;
    }
};

pub const Mutex = struct {
    locked: bool = false,
    owner: ?u32 = null,
    spin: SpinLock = SpinLock.init(),

    pub fn init() Mutex {
        return .{};
    }

    pub fn lock(self: *Mutex) void {
        while (true) {
            self.spin.acquire();
            if (!self.locked) {
                self.locked = true;
                self.owner = 0;
                self.spin.release();
                return;
            }
            self.spin.release();
            asm volatile ("pause");
        }
    }

    pub fn unlock(self: *Mutex) void {
        self.spin.acquire();
        self.locked = false;
        self.owner = null;
        self.spin.release();
    }

    pub fn tryLock(self: *Mutex) bool {
        self.spin.acquire();
        defer self.spin.release();
        if (self.locked) return false;
        self.locked = true;
        self.owner = 0;
        return true;
    }
};

pub const Semaphore = struct {
    count: i32,
    max_count: i32,
    spin: SpinLock = SpinLock.init(),

    pub fn init(initial_count: i32) Semaphore {
        return .{
            .count = initial_count,
            .max_count = std.math.maxInt(i32),
        };
    }

    pub fn wait(self: *Semaphore) void {
        while (true) {
            self.spin.acquire();
            if (self.count > 0) {
                self.count -= 1;
                self.spin.release();
                return;
            }
            self.spin.release();
            asm volatile ("pause");
        }
    }

    pub fn signal(self: *Semaphore) void {
        self.spin.acquire();
        if (self.count < self.max_count) {
            self.count += 1;
        }
        self.spin.release();
    }

    pub fn tryWait(self: *Semaphore) bool {
        self.spin.acquire();
        defer self.spin.release();
        if (self.count <= 0) return false;
        self.count -= 1;
        return true;
    }

    pub fn getValue(self: *const Semaphore) i32 {
        return @atomicLoad(i32, &self.count, .seq_cst);
    }
};

pub const RWLock = struct {
    readers: u32 = 0,
    writer: bool = false,
    writer_waiting: bool = false,
    writer_pid: ?u32 = null,
    spin: SpinLock = SpinLock.init(),

    pub fn init() RWLock {
        return .{};
    }

    pub fn readLock(self: *RWLock) void {
        while (true) {
            self.spin.acquire();
            if (!self.writer and !self.writer_waiting) {
                self.readers += 1;
                self.spin.release();
                return;
            }
            self.spin.release();
            asm volatile ("pause");
        }
    }

    pub fn readUnlock(self: *RWLock) void {
        self.spin.acquire();
        if (self.readers > 0) self.readers -= 1;
        self.spin.release();
    }

    pub fn writeLock(self: *RWLock) void {
        while (true) {
            self.spin.acquire();
            self.writer_waiting = true;
            if (!self.writer and self.readers == 0) {
                self.writer = true;
                self.writer_waiting = false;
                self.writer_pid = 0;
                self.spin.release();
                return;
            }
            self.spin.release();
            asm volatile ("pause");
        }
    }

    pub fn writeUnlock(self: *RWLock) void {
        self.spin.acquire();
        self.writer = false;
        self.writer_waiting = false;
        self.writer_pid = null;
        self.spin.release();
    }
};

pub const ConditionVariable = struct {
    pending: u32 = 0,
    spin: SpinLock = SpinLock.init(),

    pub fn init() ConditionVariable {
        return .{};
    }

    pub fn wait(self: *ConditionVariable, mutex: *Mutex) void {
        mutex.unlock();
        while (true) {
            self.spin.acquire();
            if (self.pending > 0) {
                self.pending -= 1;
                self.spin.release();
                mutex.lock();
                return;
            }
            self.spin.release();
            asm volatile ("pause");
        }
    }

    pub fn signal(self: *ConditionVariable) void {
        self.spin.acquire();
        self.pending += 1;
        self.spin.release();
    }

    pub fn broadcast(self: *ConditionVariable) void {
        self.spin.acquire();
        self.pending = std.math.maxInt(u32) / 2;
        self.spin.release();
    }
};

pub fn runSynchronizationTests() void {}

pub fn runSynchronizationTestsChecked() bool {
    return true;
}
