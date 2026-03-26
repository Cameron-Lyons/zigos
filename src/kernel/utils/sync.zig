const vga = @import("../drivers/vga.zig");
const process = @import("../process/process.zig");
const scheduler = @import("../process/scheduler.zig");

fn enqueueWaiter(wait_queue: *?*process.Process, waiter: *process.Process) void {
    waiter.wait_next = null;

    if (wait_queue.* == null) {
        wait_queue.* = waiter;
        return;
    }

    var tail = wait_queue.*;
    while (tail.?.wait_next != null) {
        tail = tail.?.wait_next;
    }
    tail.?.wait_next = waiter;
}

fn dequeueWaiter(wait_queue: *?*process.Process) ?*process.Process {
    const waiter = wait_queue.* orelse return null;
    wait_queue.* = waiter.wait_next;
    waiter.wait_next = null;
    return waiter;
}

pub const SpinLock = struct {
    locked: bool,
    owner: ?u32,

    pub fn init() SpinLock {
        return SpinLock{
            .locked = false,
            .owner = null,
        };
    }

    pub fn acquire(self: *SpinLock) void {
        const pid = process.getCurrentPID();

        while (@atomicRmw(bool, &self.locked, .Xchg, true, .seq_cst)) {
            while (@atomicLoad(bool, &self.locked, .seq_cst)) {
                asm volatile ("pause");
            }
        }

        self.owner = pid;
    }

    pub fn release(self: *SpinLock) void {
        self.owner = null;
        @atomicStore(bool, &self.locked, false, .seq_cst);
    }

    pub fn tryAcquire(self: *SpinLock) bool {
        const pid = process.getCurrentPID();

        if (!@atomicRmw(bool, &self.locked, .Xchg, true, .seq_cst)) {
            self.owner = pid;
            return true;
        }

        return false;
    }
};

pub const Mutex = struct {
    locked: bool,
    owner: ?u32,
    wait_queue: ?*process.Process,
    spin: SpinLock,

    pub fn init() Mutex {
        return Mutex{
            .locked = false,
            .owner = null,
            .wait_queue = null,
            .spin = SpinLock.init(),
        };
    }

    pub fn lock(self: *Mutex) void {
        const pid = process.getCurrentPID();

        self.spin.acquire();
        defer self.spin.release();

        if (self.owner == pid) {
            return;
        }

        while (self.locked) {
            if (process.getEffectiveCurrent()) |current| {
                current.state = .Blocked;
                enqueueWaiter(&self.wait_queue, current);
                scheduler.blockProcess(current);
                self.spin.release();
                process.yield();
                self.spin.acquire();
            }
        }

        self.locked = true;
        self.owner = pid;
    }

    pub fn unlock(self: *Mutex) void {
        self.spin.acquire();
        defer self.spin.release();

        if (self.owner != process.getCurrentPID()) {
            return;
        }

        self.locked = false;
        self.owner = null;

        if (dequeueWaiter(&self.wait_queue)) |waiting| {
            waiting.state = .Ready;
            scheduler.unblockProcess(waiting);
        }
    }

    pub fn tryLock(self: *Mutex) bool {
        const pid = process.getCurrentPID();

        self.spin.acquire();
        defer self.spin.release();

        if (!self.locked) {
            self.locked = true;
            self.owner = pid;
            return true;
        }

        return false;
    }
};

pub const Semaphore = struct {
    count: i32,
    max_count: i32,
    wait_queue: ?*process.Process,
    spin: SpinLock,

    pub fn init(initial_count: i32) Semaphore {
        return Semaphore{
            .count = initial_count,
            .max_count = initial_count,
            .wait_queue = null,
            .spin = SpinLock.init(),
        };
    }

    pub fn wait(self: *Semaphore) void {
        self.spin.acquire();
        defer self.spin.release();

        self.count -= 1;

        if (self.count < 0) {
            if (process.getEffectiveCurrent()) |current| {
                current.state = .Blocked;
                enqueueWaiter(&self.wait_queue, current);
                scheduler.blockProcess(current);
                self.spin.release();
                process.yield();
                self.spin.acquire();
            }
        }
    }

    pub fn signal(self: *Semaphore) void {
        self.spin.acquire();
        defer self.spin.release();

        self.count += 1;

        if (self.count <= 0) {
            if (dequeueWaiter(&self.wait_queue)) |waiting| {
                waiting.state = .Ready;
                scheduler.unblockProcess(waiting);
            }
        }
    }

    pub fn tryWait(self: *Semaphore) bool {
        self.spin.acquire();
        defer self.spin.release();

        if (self.count > 0) {
            self.count -= 1;
            return true;
        }

        return false;
    }

    pub fn getValue(self: *const Semaphore) i32 {
        return @atomicLoad(i32, &self.count, .seq_cst);
    }
};

pub const RWLock = struct {
    readers: u32,
    writer: bool,
    writer_waiting: bool,
    writer_pid: ?u32,
    read_queue: ?*process.Process,
    write_queue: ?*process.Process,
    spin: SpinLock,

    pub fn init() RWLock {
        return RWLock{
            .readers = 0,
            .writer = false,
            .writer_waiting = false,
            .writer_pid = null,
            .read_queue = null,
            .write_queue = null,
            .spin = SpinLock.init(),
        };
    }

    pub fn readLock(self: *RWLock) void {
        self.spin.acquire();
        defer self.spin.release();

        while (self.writer or self.writer_waiting) {
            if (process.getEffectiveCurrent()) |current| {
                current.state = .Blocked;
                enqueueWaiter(&self.read_queue, current);
                scheduler.blockProcess(current);
                self.spin.release();
                process.yield();
                self.spin.acquire();
            }
        }

        self.readers += 1;
    }

    pub fn readUnlock(self: *RWLock) void {
        self.spin.acquire();
        defer self.spin.release();

        self.readers -= 1;

        if (self.readers == 0 and self.write_queue != null) {
            const waiting = dequeueWaiter(&self.write_queue).?;
            waiting.state = .Ready;
            scheduler.unblockProcess(waiting);
        }
    }

    pub fn writeLock(self: *RWLock) void {
        const pid = process.getCurrentPID();

        self.spin.acquire();
        defer self.spin.release();

        self.writer_waiting = true;

        while (self.writer or self.readers > 0) {
            if (process.getEffectiveCurrent()) |current| {
                current.state = .Blocked;
                enqueueWaiter(&self.write_queue, current);
                scheduler.blockProcess(current);
                self.spin.release();
                process.yield();
                self.spin.acquire();
            }
        }

        self.writer_waiting = false;
        self.writer = true;
        self.writer_pid = pid;
    }

    pub fn writeUnlock(self: *RWLock) void {
        self.spin.acquire();
        defer self.spin.release();

        if (self.writer_pid != process.getCurrentPID()) {
            return;
        }

        self.writer = false;
        self.writer_pid = null;

        while (self.read_queue != null) {
            const waiting = dequeueWaiter(&self.read_queue).?;
            waiting.state = .Ready;
            scheduler.unblockProcess(waiting);
        }

        if (self.read_queue == null and self.write_queue != null) {
            const waiting = dequeueWaiter(&self.write_queue).?;
            waiting.state = .Ready;
            scheduler.unblockProcess(waiting);
        }
    }
};

pub const ConditionVariable = struct {
    wait_queue: ?*process.Process,
    spin: SpinLock,

    pub fn init() ConditionVariable {
        return ConditionVariable{
            .wait_queue = null,
            .spin = SpinLock.init(),
        };
    }

    pub fn wait(self: *ConditionVariable, mutex: *Mutex) void {
        self.spin.acquire();

        if (process.getEffectiveCurrent()) |current| {
            current.state = .Blocked;
            enqueueWaiter(&self.wait_queue, current);
            scheduler.blockProcess(current);
            mutex.unlock();
            self.spin.release();
            process.yield();
            mutex.lock();
        } else {
            self.spin.release();
        }
    }

    pub fn signal(self: *ConditionVariable) void {
        self.spin.acquire();
        defer self.spin.release();

        if (dequeueWaiter(&self.wait_queue)) |waiting| {
            waiting.state = .Ready;
            scheduler.unblockProcess(waiting);
        }
    }

    pub fn broadcast(self: *ConditionVariable) void {
        self.spin.acquire();
        defer self.spin.release();

        while (self.wait_queue != null) {
            const waiting = dequeueWaiter(&self.wait_queue).?;
            waiting.state = .Ready;
            scheduler.unblockProcess(waiting);
        }
    }
};

// SAFETY: initialized via .init() in runTests before use
var test_mutex: Mutex = undefined;
// SAFETY: initialized via .init() in runTests before use
var test_semaphore: Semaphore = undefined;
// SAFETY: initialized via .init() in runTests before use
var test_rwlock: RWLock = undefined;
// SAFETY: initialized via .init() in runTests before use
var test_condvar: ConditionVariable = undefined;
var shared_counter: u32 = 0;

fn mutex_test_task1() void {
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        test_mutex.lock();
        shared_counter += 1;
        vga.print("M1");
        test_mutex.unlock();
        process.yield();
    }
}

fn mutex_test_task2() void {
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        test_mutex.lock();
        shared_counter += 1;
        vga.print("M2");
        test_mutex.unlock();
        process.yield();
    }
}

fn semaphore_producer() void {
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        test_semaphore.signal();
        vga.print("P+");

        var delay: u32 = 0;
        while (delay < 100000) : (delay += 1) {
            asm volatile ("nop");
        }
        process.yield();
    }
}

fn semaphore_consumer() void {
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        test_semaphore.wait();
        vga.print("C-");

        var delay: u32 = 0;
        while (delay < 150000) : (delay += 1) {
            asm volatile ("nop");
        }
        process.yield();
    }
}

fn reader_task() void {
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        test_rwlock.readLock();
        vga.print("R");

        var delay: u32 = 0;
        while (delay < 50000) : (delay += 1) {
            asm volatile ("nop");
        }

        test_rwlock.readUnlock();
        process.yield();
    }
}

fn writer_task() void {
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        test_rwlock.writeLock();
        vga.print("W");

        var delay: u32 = 0;
        while (delay < 100000) : (delay += 1) {
            asm volatile ("nop");
        }

        test_rwlock.writeUnlock();
        process.yield();
    }
}

pub fn runSynchronizationTests() void {
    vga.print("\n=== Synchronization Primitives Test ===\n");

    vga.print("\n1. Testing Mutex...\n");
    test_mutex = Mutex.init();
    shared_counter = 0;

    _ = process.create_kernel_process("mutex_test1", mutex_test_task1);
    _ = process.create_kernel_process("mutex_test2", mutex_test_task2);

    const timer = @import("../timer/timer.zig");
    timer.sleep(1000);

    vga.print("\nShared counter: ");
    print_number(shared_counter);
    vga.print(" (should be 200)\n");

    vga.print("\n2. Testing Semaphore (Producer-Consumer)...\n");
    test_semaphore = Semaphore.init(0);

    _ = process.create_kernel_process("producer", semaphore_producer);
    _ = process.create_kernel_process("consumer", semaphore_consumer);

    timer.sleep(1000);

    vga.print("\n3. Testing Read-Write Lock...\n");
    test_rwlock = RWLock.init();

    _ = process.create_kernel_process("reader1", reader_task);
    _ = process.create_kernel_process("reader2", reader_task);
    _ = process.create_kernel_process("writer", writer_task);

    timer.sleep(1000);

    vga.print("\n\nSynchronization tests completed!\n");
}

pub fn runSynchronizationTestsChecked() bool {
    var mutex = Mutex.init();
    if (!mutex.tryLock()) return false;
    if (mutex.tryLock()) return false;
    mutex.unlock();
    if (!mutex.tryLock()) return false;
    mutex.unlock();

    var semaphore = Semaphore.init(2);
    if (!semaphore.tryWait()) return false;
    if (!semaphore.tryWait()) return false;
    if (semaphore.tryWait()) return false;
    semaphore.signal();
    if (!semaphore.tryWait()) return false;
    if (semaphore.getValue() != 0) return false;

    var rwlock = RWLock.init();
    rwlock.readLock();
    if (rwlock.readers != 1 or rwlock.writer) return false;
    rwlock.readUnlock();
    if (rwlock.readers != 0 or rwlock.writer) return false;

    rwlock.writeLock();
    if (!rwlock.writer or rwlock.writer_pid != process.getCurrentPID()) return false;
    rwlock.writeUnlock();
    return !rwlock.writer and rwlock.writer_pid == null and rwlock.readers == 0;
}

fn print_number(num: u32) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }

    // SAFETY: filled by the following digit extraction loop
    var digits: [10]u8 = undefined;
    var i: usize = 0;
    var n = num;

    while (n > 0) : (n /= 10) {
        digits[i] = @as(u8, @truncate(n % 10)) + '0';
        i += 1;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(digits[i]);
    }
}
