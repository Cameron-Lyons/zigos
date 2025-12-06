const vga = @import("../drivers/vga.zig");
const memory = @import("../memory/memory.zig");

pub fn test_memory_allocator() void {
    vga.print("\n=== Testing Memory Allocator ===\n");

    vga.print("Test 1: Basic allocation and free\n");
    const ptr1 = memory.kmalloc(64);
    if (ptr1) |p| {
        vga.print("  Allocated 64 bytes at: 0x");
        printHex(@intFromPtr(p));
        vga.print("\n");

        const bytes = @as([*]u8, @ptrCast(p));
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            bytes[i] = @as(u8, @intCast(i & 0xFF));
        }

        memory.kfree(p);
        vga.print("  Freed successfully\n");
    } else {
        vga.print("  FAILED: Could not allocate\n");
    }

    vga.print("\nTest 2: Multiple allocations\n");
    const ptr2 = memory.kmalloc(128);
    const ptr3 = memory.kmalloc(256);
    const ptr4 = memory.kmalloc(512);

    if (ptr2 != null and ptr3 != null and ptr4 != null) {
        vga.print("  All allocations successful\n");
        memory.kfree(ptr3);
        vga.print("  Freed middle block\n");

        const ptr5 = memory.kmalloc(128);
        if (ptr5 != null) {
            vga.print("  Reused freed space successfully\n");
            memory.kfree(ptr5);
        }

        memory.kfree(ptr2);
        memory.kfree(ptr4);
    } else {
        vga.print("  FAILED: Some allocations failed\n");
    }

    vga.print("\nTest 3: Memory statistics\n");
    const stats = memory.getMemoryStats();
    vga.print("  Total: ");
    printDec(stats.total / 1024);
    vga.print(" KB\n  Used: ");
    printDec(stats.used / 1024);
    vga.print(" KB\n  Free: ");
    printDec(stats.free / 1024);
    vga.print(" KB\n");

    vga.print("\nTest 4: Realloc test\n");
    const ptr6 = memory.kmalloc(32);
    if (ptr6) |p| {
        vga.print("  Initial allocation: 32 bytes\n");
        const bytes = @as([*]u8, @ptrCast(p));
        bytes[0] = 0xAB;
        bytes[1] = 0xCD;

        const ptr7 = memory.krealloc(p, 128);
        if (ptr7) |new_p| {
            vga.print("  Reallocated to 128 bytes\n");
            const new_bytes = @as([*]u8, @ptrCast(new_p));
            if (new_bytes[0] == 0xAB and new_bytes[1] == 0xCD) {
                vga.print("  Data preserved correctly\n");
            } else {
                vga.print("  FAILED: Data not preserved\n");
            }
            memory.kfree(new_p);
        }
    }

    vga.print("\n=== Memory Tests Complete ===\n");
}

fn printHex(value: usize) void {
    const hex_chars = "0123456789ABCDEF";
    var buffer: [16]u8 = undefined;
    var i: usize = 0;
    var v = value;

    if (v == 0) {
        vga.print("0");
        return;
    }

    while (v > 0) : (i += 1) {
        buffer[i] = hex_chars[v & 0xF];
        v >>= 4;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}

fn printDec(value: usize) void {
    var buffer: [20]u8 = undefined;
    var i: usize = 0;
    var v = value;

    if (v == 0) {
        vga.print("0");
        return;
    }

    while (v > 0) : (i += 1) {
        buffer[i] = @as(u8, @intCast(v % 10)) + '0';
        v /= 10;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}