// zlint-disable suppressed-errors
const vga = @import("../drivers/vga.zig");
const vfs = @import("../fs/vfs.zig");

var pass_count: u32 = 0;
var fail_count: u32 = 0;

pub fn runExt2WriteTests() void {
    pass_count = 0;
    fail_count = 0;

    vga.print("\n=== ext2 Write Operations Tests ===\n\n");

    testCreateFile();
    testWriteAndReadBack();
    testOverwrite();
    testCreateDirectory();
    testNestedDirectory();
    testUnlink();
    testRmdir();
    testRename();
    testTruncate();
    testChmod();
    testChown();
    testLargeWrite();

    vga.print("\n--- Results: ");
    printDec(pass_count);
    vga.print(" passed, ");
    printDec(fail_count);
    vga.print(" failed ---\n");
    vga.print("=== ext2 Write Tests Complete ===\n");
}

fn testCreateFile() void {
    vga.print("Test 1: Create file via VFS\n");
    const path = "/mnt/ext2_test_file.txt";

    const fd = vfs.open(path, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch |err| {
        vga.print("  [FAIL] Could not create file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };
    vfs.close(fd) catch {};

    vga.print("  [OK] File created\n");
    pass_count += 1;
}

fn testWriteAndReadBack() void {
    vga.print("Test 2: Write data and read back\n");
    const path = "/mnt/ext2_rw_test.txt";
    const data = "ext2 write test data 1234567890";

    const wfd = vfs.open(path, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch |err| {
        vga.print("  [FAIL] Create: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    const written = vfs.write(wfd, data) catch |err| {
        vga.print("  [FAIL] Write: ");
        vga.print(@errorName(err));
        vga.print("\n");
        vfs.close(wfd) catch {};
        fail_count += 1;
        return;
    };
    vfs.close(wfd) catch {};

    if (written != data.len) {
        vga.print("  [FAIL] Wrote ");
        printDec(@intCast(written));
        vga.print(" of ");
        printDec(@intCast(data.len));
        vga.print(" bytes\n");
        fail_count += 1;
        return;
    }

    vga.print("  [OK] Wrote ");
    printDec(@intCast(written));
    vga.print(" bytes\n");
    pass_count += 1;

    const rfd = vfs.open(path, vfs.O_RDONLY) catch |err| {
        vga.print("  [FAIL] Reopen: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    // SAFETY: filled by the subsequent vfs.read call
    var buf: [256]u8 = undefined;
    const n = vfs.read(rfd, &buf) catch |err| {
        vga.print("  [FAIL] Read: ");
        vga.print(@errorName(err));
        vga.print("\n");
        vfs.close(rfd) catch {};
        fail_count += 1;
        return;
    };
    vfs.close(rfd) catch {};

    if (n == data.len) {
        var match = true;
        for (0..n) |i| {
            if (buf[i] != data[i]) {
                match = false;
                break;
            }
        }
        if (match) {
            vga.print("  [OK] Data integrity verified\n");
            pass_count += 1;
        } else {
            vga.print("  [FAIL] Data corruption detected\n");
            fail_count += 1;
        }
    } else {
        vga.print("  [FAIL] Read ");
        printDec(@intCast(n));
        vga.print(" bytes, expected ");
        printDec(@intCast(data.len));
        vga.print("\n");
        fail_count += 1;
    }
}

fn testOverwrite() void {
    vga.print("Test 3: Overwrite existing file\n");
    const path = "/mnt/ext2_rw_test.txt";
    const new_data = "OVERWRITTEN";

    const wfd = vfs.open(path, vfs.O_WRONLY | vfs.O_TRUNC) catch |err| {
        vga.print("  [FAIL] Open for overwrite: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };
    _ = vfs.write(wfd, new_data) catch {};
    vfs.close(wfd) catch {};

    const rfd = vfs.open(path, vfs.O_RDONLY) catch {
        vga.print("  [FAIL] Reopen after overwrite\n");
        fail_count += 1;
        return;
    };
    // SAFETY: filled by the subsequent vfs.read call
    var buf: [256]u8 = undefined;
    const n = vfs.read(rfd, &buf) catch {
        vfs.close(rfd) catch {};
        vga.print("  [FAIL] Read after overwrite\n");
        fail_count += 1;
        return;
    };
    vfs.close(rfd) catch {};

    if (n == new_data.len) {
        vga.print("  [OK] Overwrite produced correct file size\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Size mismatch after overwrite\n");
        fail_count += 1;
    }
}

fn testCreateDirectory() void {
    vga.print("Test 4: Create directory\n");
    const path = "/mnt/ext2_test_dir";

    const mode = vfs.FileMode{
        .owner_read = true,
        .owner_write = true,
        .owner_exec = true,
        .group_read = true,
        .group_exec = true,
        .other_read = true,
        .other_exec = true,
    };

    vfs.mkdir(path, mode) catch |err| {
        vga.print("  [FAIL] mkdir: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    // SAFETY: filled by the subsequent vfs.stat call
    var stat_buf: vfs.FileStat = undefined;
    vfs.stat(path, &stat_buf) catch |err| {
        vga.print("  [FAIL] stat after mkdir: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    if (stat_buf.file_type == .Directory) {
        vga.print("  [OK] Directory created and verified\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Created path is not a directory\n");
        fail_count += 1;
    }
}

fn testNestedDirectory() void {
    vga.print("Test 5: Create file inside new directory\n");
    const path = "/mnt/ext2_test_dir/nested_file.txt";

    const fd = vfs.open(path, vfs.O_WRONLY | vfs.O_CREAT) catch |err| {
        vga.print("  [FAIL] Create in subdir: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };
    _ = vfs.write(fd, "nested content") catch {};
    vfs.close(fd) catch {};

    vga.print("  [OK] File created inside directory\n");
    pass_count += 1;
}

fn testUnlink() void {
    vga.print("Test 6: Unlink file\n");
    const path = "/mnt/ext2_test_file.txt";

    vfs.unlink(path) catch |err| {
        vga.print("  [FAIL] unlink: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    // SAFETY: filled by the subsequent vfs.stat call
    var stat_buf: vfs.FileStat = undefined;
    vfs.stat(path, &stat_buf) catch {
        vga.print("  [OK] File no longer exists after unlink\n");
        pass_count += 1;
        return;
    };
    vga.print("  [FAIL] File still exists after unlink\n");
    fail_count += 1;
}

fn testRmdir() void {
    vga.print("Test 7: Remove directory\n");

    vfs.unlink("/mnt/ext2_test_dir/nested_file.txt") catch {};

    vfs.rmdir("/mnt/ext2_test_dir") catch |err| {
        vga.print("  [FAIL] rmdir: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    // SAFETY: filled by the subsequent vfs.stat call
    var stat_buf: vfs.FileStat = undefined;
    vfs.stat("/mnt/ext2_test_dir", &stat_buf) catch {
        vga.print("  [OK] Directory removed\n");
        pass_count += 1;
        return;
    };
    vga.print("  [FAIL] Directory still exists after rmdir\n");
    fail_count += 1;
}

fn testRename() void {
    vga.print("Test 8: Rename file\n");
    const old_path = "/mnt/ext2_rw_test.txt";
    const new_path = "/mnt/ext2_renamed.txt";

    vfs.rename(old_path, new_path) catch |err| {
        vga.print("  [FAIL] rename: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    // SAFETY: filled by the subsequent vfs.stat call
    var stat_buf: vfs.FileStat = undefined;
    vfs.stat(new_path, &stat_buf) catch {
        vga.print("  [FAIL] New path does not exist after rename\n");
        fail_count += 1;
        return;
    };

    vga.print("  [OK] File renamed successfully\n");
    pass_count += 1;

    vfs.stat(old_path, &stat_buf) catch {
        vga.print("  [OK] Old path no longer exists\n");
        pass_count += 1;
        return;
    };
    vga.print("  [FAIL] Old path still exists after rename\n");
    fail_count += 1;
}

fn testTruncate() void {
    vga.print("Test 9: Truncate file\n");
    const path = "/mnt/ext2_renamed.txt";

    // SAFETY: filled by the subsequent vfs.stat call
    var stat_buf: vfs.FileStat = undefined;
    vfs.stat(path, &stat_buf) catch {
        vga.print("  [FAIL] Could not stat file for truncation\n");
        fail_count += 1;
        return;
    };
    const orig_size = stat_buf.size;

    vfs.truncate(path, 5) catch |err| {
        vga.print("  [FAIL] truncate: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    vfs.stat(path, &stat_buf) catch {
        vga.print("  [FAIL] Could not stat after truncation\n");
        fail_count += 1;
        return;
    };

    if (stat_buf.size == 5) {
        vga.print("  [OK] Truncated from ");
        printDec(@intCast(orig_size));
        vga.print(" to 5 bytes\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Size after truncate: ");
        printDec(@intCast(stat_buf.size));
        vga.print(", expected 5\n");
        fail_count += 1;
    }
}

fn testChmod() void {
    vga.print("Test 10: chmod\n");
    const path = "/mnt/ext2_renamed.txt";

    const new_mode = vfs.FileMode{
        .owner_read = true,
        .owner_write = false,
        .owner_exec = true,
        .group_read = true,
    };

    vfs.chmod(path, new_mode) catch |err| {
        vga.print("  [FAIL] chmod: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    vga.print("  [OK] chmod completed\n");
    pass_count += 1;
}

fn testChown() void {
    vga.print("Test 11: chown\n");
    const path = "/mnt/ext2_renamed.txt";

    vfs.chown(path, 1000, 1000) catch |err| {
        vga.print("  [FAIL] chown: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    vga.print("  [OK] chown completed\n");
    pass_count += 1;

    vfs.unlink(path) catch {};
}

fn testLargeWrite() void {
    vga.print("Test 12: Large write (multi-block)\n");
    const path = "/mnt/ext2_large_test.txt";

    const fd = vfs.open(path, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch |err| {
        vga.print("  [FAIL] Create: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    var total_written: usize = 0;
    const chunk = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz\n";
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        const n = vfs.write(fd, chunk) catch break;
        total_written += n;
    }
    vfs.close(fd) catch {};

    if (total_written > 512) {
        vga.print("  [OK] Wrote ");
        printDec(@intCast(total_written));
        vga.print(" bytes across multiple blocks\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Only wrote ");
        printDec(@intCast(total_written));
        vga.print(" bytes\n");
        fail_count += 1;
    }

    vfs.unlink(path) catch {};
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
