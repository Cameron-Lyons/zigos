const vfs = @import("vfs.zig");
const fs_utils = @import("fs_utils.zig");
const vga = @import("vga.zig");
const timer = @import("timer.zig");

pub fn testFileSystemOperations() void {
    vga.print("\n=== Testing Extended File System Operations ===\n\n");
    
    // Test 1: Create directory structure
    vga.print("Test 1: Creating directory structure...\n");
    testCreateDirectories();
    timer.sleep(1000);
    
    // Test 2: File creation and writing
    vga.print("\nTest 2: Creating and writing files...\n");
    testFileOperations();
    timer.sleep(1000);
    
    // Test 3: File truncation
    vga.print("\nTest 3: Testing file truncation...\n");
    testFileTruncate();
    timer.sleep(1000);
    
    // Test 4: File copying
    vga.print("\nTest 4: Testing file copy operations...\n");
    testFileCopy();
    timer.sleep(1000);
    
    // Test 5: File/Directory moving (rename)
    vga.print("\nTest 5: Testing rename operations...\n");
    testRename();
    timer.sleep(1000);
    
    // Test 6: Directory listing with options
    vga.print("\nTest 6: Testing directory listing...\n");
    testDirectoryListing();
    timer.sleep(1000);
    
    // Test 7: Recursive operations
    vga.print("\nTest 7: Testing recursive operations...\n");
    testRecursiveOperations();
    timer.sleep(1000);
    
    // Test 8: Permission operations
    vga.print("\nTest 8: Testing permission operations...\n");
    testPermissions();
    
    vga.print("\n=== All File System Tests Complete ===\n");
}

fn testCreateDirectories() void {
    // Create a test directory structure
    fs_utils.makeDirectory("/test", false) catch |err| {
        vga.print("Failed to create /test: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    vga.print("Created /test\n");
    
    fs_utils.makeDirectory("/test/docs", false) catch |err| {
        vga.print("Failed to create /test/docs: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
    vga.print("Created /test/docs\n");
    
    fs_utils.makeDirectory("/test/src", false) catch |err| {
        vga.print("Failed to create /test/src: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
    vga.print("Created /test/src\n");
    
    // Test creating directories with parents
    fs_utils.makeDirectory("/test/src/kernel/drivers", true) catch |err| {
        vga.print("Failed to create nested directories: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
    vga.print("Created /test/src/kernel/drivers (with parents)\n");
}

fn testFileOperations() void {
    // Create and write to a file
    const test_file = "/test/readme.txt";
    const test_content = "This is a test file for ZigOS file system.\nIt demonstrates extended file operations.\n";
    
    const fd = vfs.open(test_file, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch |err| {
        vga.print("Failed to create file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    
    _ = vfs.write(fd, test_content) catch |err| {
        vga.print("Failed to write file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        vfs.close(fd) catch {};
        return;
    };
    
    vfs.close(fd) catch {};
    vga.print("Created and wrote to ");
    vga.print(test_file);
    vga.print("\n");
    
    // Read back the file
    const read_fd = vfs.open(test_file, vfs.O_RDONLY) catch |err| {
        vga.print("Failed to open file for reading: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    
    var buffer: [256]u8 = undefined;
    const bytes_read = vfs.read(read_fd, &buffer) catch |err| {
        vga.print("Failed to read file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        vfs.close(read_fd) catch {};
        return;
    };
    
    vfs.close(read_fd) catch {};
    vga.print("Read ");
    printNumber(bytes_read);
    vga.print(" bytes from file\n");
}

fn testFileTruncate() void {
    const test_file = "/test/truncate_test.txt";
    
    // Create a file with some content
    const fd = vfs.open(test_file, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch |err| {
        vga.print("Failed to create file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    
    const content = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    _ = vfs.write(fd, content) catch {};
    vfs.close(fd) catch {};
    
    // Get original size
    const orig_size = fs_utils.getFileSize(test_file) catch 0;
    vga.print("Original file size: ");
    printNumber(orig_size);
    vga.print(" bytes\n");
    
    // Truncate to smaller size
    vfs.truncate(test_file, 10) catch |err| {
        vga.print("Failed to truncate file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    
    const new_size = fs_utils.getFileSize(test_file) catch 0;
    vga.print("Truncated file size: ");
    printNumber(new_size);
    vga.print(" bytes\n");
    
    // Extend file
    vfs.truncate(test_file, 20) catch |err| {
        vga.print("Failed to extend file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    
    const extended_size = fs_utils.getFileSize(test_file) catch 0;
    vga.print("Extended file size: ");
    printNumber(extended_size);
    vga.print(" bytes\n");
}

fn testFileCopy() void {
    const src_file = "/test/readme.txt";
    const dst_file = "/test/readme_copy.txt";
    
    fs_utils.copyFile(src_file, dst_file) catch |err| {
        vga.print("Failed to copy file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    
    vga.print("Copied ");
    vga.print(src_file);
    vga.print(" to ");
    vga.print(dst_file);
    vga.print("\n");
    
    // Verify copy
    const src_size = fs_utils.getFileSize(src_file) catch 0;
    const dst_size = fs_utils.getFileSize(dst_file) catch 0;
    
    if (src_size == dst_size) {
        vga.print("File copy verified (size match)\n");
    } else {
        vga.print("File copy size mismatch!\n");
    }
}

fn testRename() void {
    const old_name = "/test/readme_copy.txt";
    const new_name = "/test/readme_backup.txt";
    
    vfs.rename(old_name, new_name) catch |err| {
        vga.print("Failed to rename file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    
    vga.print("Renamed ");
    vga.print(old_name);
    vga.print(" to ");
    vga.print(new_name);
    vga.print("\n");
    
    // Test moving file to different directory
    const move_src = "/test/readme_backup.txt";
    const move_dst = "/test/docs/readme_backup.txt";
    
    fs_utils.moveFile(move_src, move_dst) catch |err| {
        vga.print("Failed to move file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    
    vga.print("Moved file to ");
    vga.print(move_dst);
    vga.print("\n");
}

fn testDirectoryListing() void {
    vga.print("\nListing /test (simple):\n");
    const simple_options = fs_utils.ListDirOptions{};
    fs_utils.listDirectory("/test", simple_options) catch |err| {
        vga.print("Failed to list directory: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
    
    vga.print("\n\nListing /test (detailed):\n");
    const detailed_options = fs_utils.ListDirOptions{
        .show_details = true,
        .show_hidden = true,
    };
    fs_utils.listDirectory("/test", detailed_options) catch |err| {
        vga.print("Failed to list directory: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
}

fn testRecursiveOperations() void {
    // Copy entire directory structure
    vga.print("Copying /test/src to /test/src_backup...\n");
    fs_utils.copyDirectory("/test/src", "/test/src_backup") catch |err| {
        vga.print("Failed to copy directory: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
    
    // List recursively
    vga.print("\nRecursive listing of /test:\n");
    const recursive_options = fs_utils.ListDirOptions{
        .recursive = true,
    };
    fs_utils.listDirectory("/test", recursive_options) catch |err| {
        vga.print("Failed to list directory recursively: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
    
    // Remove directory recursively
    vga.print("\nRemoving /test/src_backup recursively...\n");
    fs_utils.removeDirectory("/test/src_backup", true) catch |err| {
        vga.print("Failed to remove directory: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
    vga.print("Directory removed successfully\n");
}

fn testPermissions() void {
    const test_file = "/test/permission_test.txt";
    
    // Create a test file
    const fd = vfs.open(test_file, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch |err| {
        vga.print("Failed to create file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    _ = vfs.write(fd, "Permission test file") catch {};
    vfs.close(fd) catch {};
    
    // Change permissions to read-only
    const read_only = vfs.FileMode{
        .owner_read = true,
        .owner_write = false,
        .owner_exec = false,
        .group_read = true,
        .group_write = false,
        .group_exec = false,
        .other_read = true,
        .other_write = false,
        .other_exec = false,
    };
    
    vfs.chmod(test_file, read_only) catch |err| {
        vga.print("Failed to change permissions: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    vga.print("Changed file to read-only\n");
    
    // Change permissions to read-write
    const read_write = vfs.FileMode{
        .owner_read = true,
        .owner_write = true,
        .owner_exec = false,
        .group_read = true,
        .group_write = true,
        .group_exec = false,
        .other_read = true,
        .other_write = false,
        .other_exec = false,
    };
    
    vfs.chmod(test_file, read_write) catch |err| {
        vga.print("Failed to change permissions: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    vga.print("Changed file to read-write\n");
    
    // Test chown (will be ignored on FAT32 but shouldn't error)
    vfs.chown(test_file, 1000, 1000) catch |err| {
        vga.print("Failed to change ownership: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    vga.print("Changed ownership (FAT32 ignores this)\n");
}

fn printNumber(num: usize) void {
    var buffer: [20]u8 = undefined;
    var i: usize = 0;
    var n = num;

    if (n == 0) {
        vga.printChar('0');
        return;
    }

    while (n > 0) : (n /= 10) {
        buffer[i] = @as(u8, @intCast('0' + (n % 10)));
        i += 1;
    }

    while (i > 0) {
        i -= 1;
        vga.printChar(buffer[i]);
    }
}