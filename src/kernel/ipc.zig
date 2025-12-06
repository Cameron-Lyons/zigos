const std = @import("std");
const vga = @import("vga.zig");
const process = @import("process.zig");
const scheduler = @import("scheduler.zig");
const memory = @import("memory.zig");
const sync = @import("sync.zig");

pub const MessageType = enum {
    Data,
    Signal,
    Request,
    Response,
};

pub const Message = struct {
    sender_pid: u32,
    receiver_pid: u32,
    msg_type: MessageType,
    data: [256]u8,
    data_len: u32,
    timestamp: u64,
    next: ?*Message,
};

pub const MessageQueue = struct {
    pid: u32,
    messages: ?*Message,
    message_count: u32,
    max_messages: u32,
    mutex: sync.Mutex,
    not_empty: sync.Semaphore,
    not_full: sync.Semaphore,
    waiting_process: ?*process.Process,

    pub fn init(pid: u32, max_messages: u32) MessageQueue {
        return MessageQueue{
            .pid = pid,
            .messages = null,
            .message_count = 0,
            .max_messages = max_messages,
            .mutex = sync.Mutex.init(),
            .not_empty = sync.Semaphore.init(0),
            .not_full = sync.Semaphore.init(@intCast(max_messages)),
            .waiting_process = null,
        };
    }

    pub fn send(self: *MessageQueue, msg: *Message) !void {
        self.not_full.wait();
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.message_count >= self.max_messages) {
            self.not_full.signal();
            return error.QueueFull;
        }

        msg.next = null;

        if (self.messages == null) {
            self.messages = msg;
        } else {
            var tail = self.messages;
            while (tail.?.next != null) {
                tail = tail.?.next;
            }
            tail.?.next = msg;
        }

        self.message_count += 1;
        self.not_empty.signal();

        if (self.waiting_process) |waiting| {
            waiting.state = .Ready;
            scheduler.unblockProcess(waiting);
            self.waiting_process = null;
        }
    }

    pub fn receive(self: *MessageQueue) ?*Message {
        self.not_empty.wait();
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.messages == null) {
            self.not_empty.signal();
            return null;
        }

        const msg = self.messages.?;
        self.messages = msg.next;
        self.message_count -= 1;

        self.not_full.signal();

        return msg;
    }

    pub fn tryReceive(self: *MessageQueue) ?*Message {
        if (!self.not_empty.tryWait()) {
            return null;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.messages == null) {
            self.not_empty.signal();
            return null;
        }

        const msg = self.messages.?;
        self.messages = msg.next;
        self.message_count -= 1;

        self.not_full.signal();

        return msg;
    }

    pub fn peek(self: *MessageQueue) ?*Message {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.messages;
    }

    pub fn getCount(self: *MessageQueue) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.message_count;
    }
};

pub const SharedMemory = struct {
    id: u32,
    owner_pid: u32,
    data: [*]u8,
    size: usize,
    permissions: u8,
    attached_processes: u32,
    rwlock: sync.RWLock,
    next: ?*SharedMemory,

    pub const PERM_READ = 0x04;
    pub const PERM_WRITE = 0x02;
    pub const PERM_EXEC = 0x01;

    pub fn init(id: u32, owner_pid: u32, size: usize, permissions: u8) !SharedMemory {
        const pages_needed = (size + 4095) / 4096;
        const data = memory.allocPages(pages_needed) orelse return error.OutOfMemory;

        return SharedMemory{
            .id = id,
            .owner_pid = owner_pid,
            .data = data,
            .size = size,
            .permissions = permissions,
            .attached_processes = 1,
            .rwlock = sync.RWLock.init(),
            .next = null,
        };
    }

    pub fn attach(self: *SharedMemory) void {
        _ = @atomicRmw(u32, &self.attached_processes, .Add, 1, .seq_cst);
    }

    pub fn detach(self: *SharedMemory) void {
        _ = @atomicRmw(u32, &self.attached_processes, .Sub, 1, .seq_cst);
    }

    pub fn read(self: *SharedMemory, buffer: []u8, offset: usize) !usize {
        if ((self.permissions & PERM_READ) == 0) {
            return error.PermissionDenied;
        }

        if (offset >= self.size) {
            return error.InvalidOffset;
        }

        self.rwlock.readLock();
        defer self.rwlock.readUnlock();

        const read_size = @min(buffer.len, self.size - offset);
        @memcpy(buffer[0..read_size], self.data[offset..offset + read_size]);

        return read_size;
    }

    pub fn write(self: *SharedMemory, data: []const u8, offset: usize) !usize {
        if ((self.permissions & PERM_WRITE) == 0) {
            return error.PermissionDenied;
        }

        if (offset >= self.size) {
            return error.InvalidOffset;
        }

        self.rwlock.writeLock();
        defer self.rwlock.writeUnlock();

        const write_size = @min(data.len, self.size - offset);
        @memcpy(self.data[offset..offset + write_size], data[0..write_size]);

        return write_size;
    }
};

pub const Pipe = struct {
    read_end: u32,
    write_end: u32,
    buffer: [4096]u8,
    read_pos: usize,
    write_pos: usize,
    size: usize,
    closed: bool,
    mutex: sync.Mutex,
    not_empty: sync.Semaphore,
    not_full: sync.Semaphore,

    pub fn init() Pipe {
        return Pipe{
            .read_end = process.next_pid,
            .write_end = process.next_pid + 1,
            .buffer = undefined,
            .read_pos = 0,
            .write_pos = 0,
            .size = 0,
            .closed = false,
            .mutex = sync.Mutex.init(),
            .not_empty = sync.Semaphore.init(0),
            .not_full = sync.Semaphore.init(4096),
        };
    }

    pub fn write(self: *Pipe, data: []const u8) !usize {
        if (self.closed) {
            return error.PipeClosed;
        }

        var written: usize = 0;

        for (data) |byte| {
            self.not_full.wait();

            self.mutex.lock();

            if (self.closed) {
                self.mutex.unlock();
                self.not_full.signal();
                return error.PipeClosed;
            }

            self.buffer[self.write_pos] = byte;
            self.write_pos = (self.write_pos + 1) % self.buffer.len;
            self.size += 1;
            written += 1;

            self.mutex.unlock();
            self.not_empty.signal();
        }

        return written;
    }

    pub fn read(self: *Pipe, buffer: []u8) !usize {
        if (self.closed and self.size == 0) {
            return error.PipeClosed;
        }

        var read_count: usize = 0;

        for (buffer) |*byte| {
            if (!self.not_empty.tryWait()) {
                if (read_count > 0) {
                    return read_count;
                }

                if (self.closed) {
                    return error.PipeClosed;
                }

                self.not_empty.wait();
            }

            self.mutex.lock();

            if (self.size == 0) {
                self.mutex.unlock();
                self.not_empty.signal();
                return read_count;
            }

            byte.* = self.buffer[self.read_pos];
            self.read_pos = (self.read_pos + 1) % self.buffer.len;
            self.size -= 1;
            read_count += 1;

            self.mutex.unlock();
            self.not_full.signal();
        }

        return read_count;
    }

    pub fn close(self: *Pipe) void {
        self.mutex.lock();
        self.closed = true;
        self.mutex.unlock();

        self.not_empty.signal();
        self.not_full.signal();
    }
};

const MAX_MESSAGE_QUEUES = 64;
const MAX_SHARED_MEMORY = 32;
const MAX_PIPES = 128;

var message_queues: [MAX_MESSAGE_QUEUES]?MessageQueue = [_]?MessageQueue{null} ** MAX_MESSAGE_QUEUES;
var shared_memory_list: ?*SharedMemory = null;
var pipes: [MAX_PIPES]?Pipe = [_]?Pipe{null} ** MAX_PIPES;
var next_shm_id: u32 = 1;
var ipc_mutex: sync.Mutex = sync.Mutex.init();

pub fn createMessageQueue(pid: u32, max_messages: u32) !*MessageQueue {
    ipc_mutex.lock();
    defer ipc_mutex.unlock();

    for (&message_queues) |*queue| {
        if (queue.* == null) {
            queue.* = MessageQueue.init(pid, max_messages);
            return &queue.*.?;
        }
    }

    return error.NoFreeQueues;
}

pub fn getMessageQueue(pid: u32) ?*MessageQueue {
    ipc_mutex.lock();
    defer ipc_mutex.unlock();

    for (&message_queues) |*queue| {
        if (queue.* != null and queue.*.?.pid == pid) {
            return &queue.*.?;
        }
    }

    return null;
}

pub fn sendMessage(sender_pid: u32, receiver_pid: u32, msg_type: MessageType, data: []const u8) !void {
    const timer = @import("timer.zig");

    const msg = memory.alloc(Message) orelse return error.OutOfMemory;
    msg.sender_pid = sender_pid;
    msg.receiver_pid = receiver_pid;
    msg.msg_type = msg_type;
    msg.data_len = @min(data.len, msg.data.len);
    @memcpy(msg.data[0..msg.data_len], data[0..msg.data_len]);
    msg.timestamp = timer.getTicks();
    msg.next = null;

    const queue = getMessageQueue(receiver_pid) orelse return error.ReceiverNotFound;
    try queue.send(msg);
}

pub fn createSharedMemory(owner_pid: u32, size: usize, permissions: u8) !*SharedMemory {
    ipc_mutex.lock();
    defer ipc_mutex.unlock();

    const shm = memory.alloc(SharedMemory) orelse return error.OutOfMemory;
    shm.* = try SharedMemory.init(next_shm_id, owner_pid, size, permissions);
    next_shm_id += 1;

    shm.next = shared_memory_list;
    shared_memory_list = shm;

    return shm;
}

pub fn getSharedMemory(id: u32) ?*SharedMemory {
    ipc_mutex.lock();
    defer ipc_mutex.unlock();

    var current = shared_memory_list;
    while (current != null) {
        if (current.?.id == id) {
            return current;
        }
        current = current.?.next;
    }

    return null;
}

pub fn createPipe() !*Pipe {
    ipc_mutex.lock();
    defer ipc_mutex.unlock();

    for (&pipes) |*pipe| {
        if (pipe.* == null) {
            pipe.* = Pipe.init();
            return &pipe.*.?;
        }
    }

    return error.NoFreePipes;
}

fn ipc_test_sender() void {
    const pid = process.getCurrentPID();
    vga.print("\n[SENDER] Starting (PID: ");
    print_number(pid);
    vga.print(")\n");

    const target_pid = pid + 1;

    const timer = @import("timer.zig");
    timer.sleep(100);

    const test_data = "Hello from sender!";
    sendMessage(pid, target_pid, .Data, test_data) catch |err| {
        vga.print("[SENDER] Failed to send: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    vga.print("[SENDER] Message sent to PID ");
    print_number(target_pid);
    vga.print("\n");
}

fn ipc_test_receiver() void {
    const pid = process.getCurrentPID();
    vga.print("\n[RECEIVER] Starting (PID: ");
    print_number(pid);
    vga.print(")\n");

    const queue = createMessageQueue(pid, 10) catch |err| {
        vga.print("[RECEIVER] Failed to create queue: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    vga.print("[RECEIVER] Waiting for message...\n");

    if (queue.receive()) |msg| {
        vga.print("[RECEIVER] Got message from PID ");
        print_number(msg.sender_pid);
        vga.print(": ");

        var i: u32 = 0;
        while (i < msg.data_len) : (i += 1) {
            vga.put_char(msg.data[i]);
        }
        vga.print("\n");
    } else {
        vga.print("[RECEIVER] No message received\n");
    }
}

fn pipe_writer() void {
    vga.print("\n[PIPE WRITER] Starting\n");

    const pipe = createPipe() catch |err| {
        vga.print("[PIPE WRITER] Failed to create pipe: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    const data = "Data through pipe!";
    _ = pipe.write(data) catch |err| {
        vga.print("[PIPE WRITER] Write failed: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    vga.print("[PIPE WRITER] Wrote data to pipe\n");
}

fn pipe_reader() void {
    vga.print("\n[PIPE READER] Starting\n");

    const timer = @import("timer.zig");
    timer.sleep(100);

    if (pipes[0]) |*pipe| {
        var buffer: [64]u8 = undefined;
        const bytes_read = pipe.read(&buffer) catch |err| {
            vga.print("[PIPE READER] Read failed: ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        vga.print("[PIPE READER] Read ");
        print_number(@truncate(bytes_read));
        vga.print(" bytes: ");

        var i: usize = 0;
        while (i < bytes_read) : (i += 1) {
            vga.put_char(buffer[i]);
        }
        vga.print("\n");
    } else {
        vga.print("[PIPE READER] No pipe found\n");
    }
}

fn shm_writer() void {
    const pid = process.getCurrentPID();
    vga.print("\n[SHM WRITER] Starting (PID: ");
    print_number(pid);
    vga.print(")\n");

    const shm = createSharedMemory(pid, 256, SharedMemory.PERM_READ | SharedMemory.PERM_WRITE) catch |err| {
        vga.print("[SHM WRITER] Failed to create shared memory: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    vga.print("[SHM WRITER] Created shared memory ID: ");
    print_number(shm.id);
    vga.print("\n");

    const data = "Shared memory test data";
    _ = shm.write(data, 0) catch |err| {
        vga.print("[SHM WRITER] Write failed: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    vga.print("[SHM WRITER] Wrote data to shared memory\n");
}

fn shm_reader() void {
    vga.print("\n[SHM READER] Starting\n");

    const timer = @import("timer.zig");
    timer.sleep(100);

    if (getSharedMemory(1)) |shm| {
        shm.attach();
        defer shm.detach();

        var buffer: [64]u8 = undefined;
        const bytes_read = shm.read(&buffer, 0) catch |err| {
            vga.print("[SHM READER] Read failed: ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        vga.print("[SHM READER] Read ");
        print_number(@truncate(bytes_read));
        vga.print(" bytes: ");

        var i: usize = 0;
        while (i < bytes_read) : (i += 1) {
            vga.put_char(buffer[i]);
        }
        vga.print("\n");
    } else {
        vga.print("[SHM READER] Shared memory not found\n");
    }
}

pub fn runIPCTests() void {
    vga.print("\n=== Inter-Process Communication Test ===\n");

    vga.print("\n1. Testing Message Passing...\n");
    _ = process.create_kernel_process("receiver", ipc_test_receiver);
    _ = process.create_kernel_process("sender", ipc_test_sender);

    const timer = @import("timer.zig");
    timer.sleep(500);

    vga.print("\n2. Testing Pipes...\n");
    _ = process.create_kernel_process("pipe_writer", pipe_writer);
    _ = process.create_kernel_process("pipe_reader", pipe_reader);

    timer.sleep(500);

    vga.print("\n3. Testing Shared Memory...\n");
    _ = process.create_kernel_process("shm_writer", shm_writer);
    _ = process.create_kernel_process("shm_reader", shm_reader);

    timer.sleep(500);

    vga.print("\n\nIPC tests completed!\n");
}

fn print_number(num: u32) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }

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