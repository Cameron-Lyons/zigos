const vga = @import("../drivers/vga.zig");
const memory = @import("../memory/memory.zig");
const numfmt = @import("../utils/numfmt.zig");

var fail_count: usize = 0;

pub fn runMemoryTestsChecked() bool {
    fail_count = 0;
    test_memory_allocator();
    return fail_count == 0;
}

pub fn test_memory_allocator() void {
    vga.print("\n=== Testing Memory Allocator ===\n");

    vga.print("Test 1: Basic allocation and free\n");
    const ptr1 = memory.kmalloc(64);
    if (ptr1) |p| {
        vga.print("  Allocated 64 bytes at: 0x");
        numfmt.printHex(@intFromPtr(p));
        vga.print("\n");

        const bytes: [*]u8 = @ptrCast(p);
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            bytes[i] = @as(u8, @intCast(i & 0xFF));
        }

        memory.kfree(p);
        vga.print("  Freed successfully\n");
    } else {
        vga.print("  FAILED: Could not allocate\n");
        fail_count += 1;
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
        fail_count += 1;
        if (ptr2) |p| memory.kfree(p);
        if (ptr3) |p| memory.kfree(p);
        if (ptr4) |p| memory.kfree(p);
    }

    vga.print("\nTest 3: Memory statistics\n");
    const stats = memory.getMemoryStats();
    vga.print("  Total: ");
    numfmt.printDec(stats.total / 1024);
    vga.print(" KB\n  Used: ");
    numfmt.printDec(stats.used / 1024);
    vga.print(" KB\n  Free: ");
    numfmt.printDec(stats.free / 1024);
    vga.print(" KB\n");

    vga.print("\nTest 4: Realloc test\n");
    const ptr6 = memory.kmalloc(32);
    if (ptr6) |p| {
        vga.print("  Initial allocation: 32 bytes\n");
        const bytes: [*]u8 = @ptrCast(p);
        bytes[0] = 0xAB;
        bytes[1] = 0xCD;

        const ptr7 = memory.krealloc(p, 128);
        if (ptr7) |new_p| {
            vga.print("  Reallocated to 128 bytes\n");
            const new_bytes: [*]u8 = @ptrCast(new_p);
            if (new_bytes[0] == 0xAB and new_bytes[1] == 0xCD) {
                vga.print("  Data preserved correctly\n");
            } else {
                vga.print("  FAILED: Data not preserved\n");
                fail_count += 1;
            }
            memory.kfree(new_p);
        } else {
            vga.print("  FAILED: Realloc returned null\n");
            fail_count += 1;
            memory.kfree(p);
        }
    } else {
        vga.print("  FAILED: Could not allocate initial block\n");
        fail_count += 1;
    }

    vga.print("\n=== Memory Tests Complete ===\n");
}
