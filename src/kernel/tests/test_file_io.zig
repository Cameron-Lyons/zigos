// zlint-disable suppressed-errors
const vga = @import("../drivers/vga.zig");
const vfs = @import("../fs/vfs.zig");

var pass_count: u32 = 0;
var fail_count: u32 = 0;

pub fn runFileIOTests() void {
    pass_count = 0;
    fail_count = 0;

    vga.print("\n=== File I/O Syscall Tests ===\n\n");

    testVFSOpen();
    testVFSWriteRead();
    testVFSSeek();
    testVFSClose();
    testVFSStat();
    testVFSOpenCreat();
    testVFSReadOnly();
    testVFSMultipleFDs();

    vga.print("\n--- Results: ");
    printDec(pass_count);
    vga.print(" passed, ");
    printDec(fail_count);
    vga.print(" failed ---\n");
    vga.print("=== File I/O Tests Complete ===\n");
}

fn testVFSOpen() void {
    vga.print("Test 1: VFS open existing path\n");
    const fd = vfs.open("/", vfs.O_RDONLY) catch |err| {
        vga.print("  [FAIL] Could not open /: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };
    vfs.close(fd) catch {};
    vga.print("  [OK] Opened / as fd ");
    printDec(fd);
    vga.print("\n");
    pass_count += 1;
}

fn testVFSWriteRead() void {
    vga.print("Test 2: VFS write then read\n");
    const test_path = "/test_io_file.txt";
    const test_data = "Hello from file I/O test";

    const wfd = vfs.open(test_path, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch |err| {
        vga.print("  [FAIL] Could not create file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    const written = vfs.write(wfd, test_data) catch |err| {
        vga.print("  [FAIL] Could not write: ");
        vga.print(@errorName(err));
        vga.print("\n");
        vfs.close(wfd) catch {};
        fail_count += 1;
        return;
    };
    vfs.close(wfd) catch {};

    if (written != test_data.len) {
        vga.print("  [FAIL] Wrote ");
        printDec(@intCast(written));
        vga.print(" bytes, expected ");
        printDec(@intCast(test_data.len));
        vga.print("\n");
        fail_count += 1;
        return;
    }
    vga.print("  [OK] Wrote ");
    printDec(@intCast(written));
    vga.print(" bytes\n");
    pass_count += 1;

    const rfd = vfs.open(test_path, vfs.O_RDONLY) catch |err| {
        vga.print("  [FAIL] Could not reopen for read: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    // SAFETY: filled by the subsequent vfs.read call
    var read_buf: [256]u8 = undefined;
    const bytes_read = vfs.read(rfd, &read_buf) catch |err| {
        vga.print("  [FAIL] Could not read: ");
        vga.print(@errorName(err));
        vga.print("\n");
        vfs.close(rfd) catch {};
        fail_count += 1;
        return;
    };
    vfs.close(rfd) catch {};

    if (bytes_read == test_data.len) {
        var match = true;
        for (0..bytes_read) |i| {
            if (read_buf[i] != test_data[i]) {
                match = false;
                break;
            }
        }
        if (match) {
            vga.print("  [OK] Read back matches written data (");
            printDec(@intCast(bytes_read));
            vga.print(" bytes)\n");
            pass_count += 1;
        } else {
            vga.print("  [FAIL] Data mismatch after read-back\n");
            fail_count += 1;
        }
    } else {
        vga.print("  [FAIL] Read ");
        printDec(@intCast(bytes_read));
        vga.print(" bytes, expected ");
        printDec(@intCast(test_data.len));
        vga.print("\n");
        fail_count += 1;
    }
}

fn testVFSSeek() void {
    vga.print("Test 3: VFS seek\n");
    const test_path = "/test_io_seek.txt";
    const data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    const wfd = vfs.open(test_path, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch {
        vga.print("  [FAIL] Could not create seek test file\n");
        fail_count += 1;
        return;
    };
    _ = vfs.write(wfd, data) catch {};
    vfs.close(wfd) catch {};

    const rfd = vfs.open(test_path, vfs.O_RDONLY) catch {
        vga.print("  [FAIL] Could not reopen seek test file\n");
        fail_count += 1;
        return;
    };

    _ = vfs.lseek(rfd, 10, vfs.SEEK_SET) catch |err| {
        vga.print("  [FAIL] Seek failed: ");
        vga.print(@errorName(err));
        vga.print("\n");
        vfs.close(rfd) catch {};
        fail_count += 1;
        return;
    };

    // SAFETY: filled by the subsequent vfs.read call
    var buf: [5]u8 = undefined;
    const n = vfs.read(rfd, &buf) catch {
        vga.print("  [FAIL] Read after seek failed\n");
        vfs.close(rfd) catch {};
        fail_count += 1;
        return;
    };
    vfs.close(rfd) catch {};

    if (n >= 1 and buf[0] == 'K') {
        vga.print("  [OK] Seek to offset 10 read 'K' as expected\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Expected 'K' at offset 10, got '");
        if (n > 0) vga.put_char(buf[0]);
        vga.print("'\n");
        fail_count += 1;
    }
}

fn testVFSClose() void {
    vga.print("Test 4: VFS close\n");

    const fd = vfs.open("/", vfs.O_RDONLY) catch {
        vga.print("  [FAIL] Could not open / for close test\n");
        fail_count += 1;
        return;
    };

    vfs.close(fd) catch |err| {
        vga.print("  [FAIL] Close failed: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    vga.print("  [OK] Close succeeded\n");
    pass_count += 1;

    vfs.close(fd) catch {
        vga.print("  [OK] Double-close correctly returned error\n");
        pass_count += 1;
        return;
    };
    vga.print("  [FAIL] Double-close did not return error\n");
    fail_count += 1;
}

fn testVFSStat() void {
    vga.print("Test 5: VFS stat\n");

    // SAFETY: filled by the subsequent vfs.stat call
    var stat_buf: vfs.FileStat = undefined;
    vfs.stat("/", &stat_buf) catch |err| {
        vga.print("  [FAIL] stat(/) failed: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    if (stat_buf.file_type == .Directory) {
        vga.print("  [OK] / is a directory\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] / is not reported as directory\n");
        fail_count += 1;
    }
}

fn testVFSOpenCreat() void {
    vga.print("Test 6: VFS open with O_CREAT\n");
    const test_path = "/test_io_creat.txt";

    const fd = vfs.open(test_path, vfs.O_WRONLY | vfs.O_CREAT) catch |err| {
        vga.print("  [FAIL] O_CREAT failed: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };
    vfs.close(fd) catch {};

    vga.print("  [OK] Created file with O_CREAT\n");
    pass_count += 1;

    const fd2 = vfs.open(test_path, vfs.O_RDONLY) catch |err| {
        vga.print("  [FAIL] Re-open after create failed: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };
    vfs.close(fd2) catch {};

    vga.print("  [OK] File exists after O_CREAT\n");
    pass_count += 1;
}

fn testVFSReadOnly() void {
    vga.print("Test 7: Write permission check\n");
    const test_path = "/test_io_creat.txt";

    const fd = vfs.open(test_path, vfs.O_RDONLY) catch {
        vga.print("  [FAIL] Could not open file as read-only\n");
        fail_count += 1;
        return;
    };

    _ = vfs.write(fd, "should fail") catch {
        vga.print("  [OK] Write on read-only fd correctly rejected\n");
        vfs.close(fd) catch {};
        pass_count += 1;
        return;
    };
    vfs.close(fd) catch {};
    vga.print("  [FAIL] Write on read-only fd did not error\n");
    fail_count += 1;
}

fn testVFSMultipleFDs() void {
    vga.print("Test 8: Multiple file descriptors\n");

    // SAFETY: each element assigned by vfs.open in the following loop
    var fds: [4]u32 = undefined;
    var opened: u32 = 0;

    for (0..4) |i| {
        fds[i] = vfs.open("/", vfs.O_RDONLY) catch {
            break;
        };
        opened += 1;
    }

    if (opened == 4) {
        vga.print("  [OK] Opened 4 file descriptors simultaneously\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Only opened ");
        printDec(opened);
        vga.print(" of 4 requested fds\n");
        fail_count += 1;
    }

    for (0..opened) |i| {
        vfs.close(fds[i]) catch {};
    }

    if (opened >= 2 and fds[0] != fds[1]) {
        vga.print("  [OK] Each fd is unique\n");
        pass_count += 1;
    } else if (opened >= 2) {
        vga.print("  [FAIL] Duplicate fd values returned\n");
        fail_count += 1;
    }
}

fn printDec(value: u32) void {
    // SAFETY: filled by the following digit extraction loop
    var buffer: [10]u8 = undefined;
    var i: usize = 0;
    var v = value;

    if (v == 0) {
        vga.put_char('0');
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
