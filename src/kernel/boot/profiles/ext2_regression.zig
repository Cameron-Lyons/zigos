const console = @import("../../utils/console.zig");
const process = @import("../../process/process.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const vfs = @import("../../fs/vfs.zig");
const common = @import("../common.zig");
const test_ext2 = @import("../../tests/test_ext2_write.zig");

const mount_dir_mode = vfs.FileMode{
    .owner_read = true,
    .owner_write = true,
    .owner_exec = true,
    .group_read = true,
    .group_exec = true,
    .other_read = true,
    .other_exec = true,
};

fn fail(marker: []const u8) noreturn {
    common.printBootMarker(marker);
    common.printBootMarker("EXT2:FAIL");
    qemu_exit.failure();
}

fn ensureMountDir() bool {
    vfs.mkdir("/mnt", mount_dir_mode) catch |err| switch (err) {
        error.AlreadyExists => {},
        else => return false,
    };
    return true;
}

pub fn run() noreturn {
    const runner = process.create_kernel_process("ext2_regression_runner", common.idleTaskPlaceholder);
    process.adoptAsCurrent(runner);

    console.print("Running ext2 regression suite...\n");
    common.printBootMarker("EXT2:START");

    if (!ensureMountDir()) {
        fail("EXT2:MOUNTPOINT:FAIL");
    }

    vfs.mount("ata1", "/mnt", "ext2", 0) catch {
        fail("EXT2:MOUNT:FAIL");
    };
    defer vfs.unmount("/mnt") catch {};
    common.printBootMarker("EXT2:MOUNT:PASS");

    if (!test_ext2.runExt2WriteTestsChecked()) {
        fail("EXT2:SUITE:FAIL");
    }

    common.printBootMarker("EXT2:PASS");
    qemu_exit.success();
}
