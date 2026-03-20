const console = @import("../../utils/console.zig");
const vfs = @import("../../fs/vfs.zig");
const fat32 = @import("../../fs/fat32.zig");
const ext2 = @import("../../fs/ext2.zig");
const embedfs = @import("../../fs/embedfs.zig");
const tmpfs = @import("../../fs/tmpfs.zig");
const devfs = @import("../../fs/devfs.zig");
const procfs = @import("../../fs/procfs.zig");
const sysfs = @import("../../fs/sysfs.zig");
const mmap = @import("../../memory/mmap.zig");

pub fn init() void {
    console.print("Initializing Virtual File System...\n");
    vfs.init();
    console.print("VFS ready!\n");

    console.print("Initializing FAT32 file system...\n");
    fat32.init();
    console.print("FAT32 ready!\n");

    console.print("Initializing ext2 file system...\n");
    ext2.init();

    console.print("Initializing embedded root filesystem...\n");
    embedfs.init();

    console.print("Mounting FAT32 disk as root...\n");
    const disk_root_ready = blk: {
        vfs.mount("ata0", "/", "fat32", 0) catch |err| {
            console.print("Disk root unavailable: ");
            console.print(@errorName(err));
            console.print("\n");
            break :blk false;
        };
        console.print("Disk root mounted at /\n");
        break :blk true;
    };

    if (!disk_root_ready) {
        console.print("Mounting embedded root filesystem fallback...\n");
        vfs.mount("none", "/", "embedfs", 0) catch |err| {
            console.print("Failed to mount embedded root filesystem: ");
            console.print(@errorName(err));
            console.print("\n");
        };
    }

    if (!disk_root_ready) {
        console.print("Mounting FAT32 disk on /mnt...\n");
        vfs.mount("ata0", "/mnt", "fat32", 0) catch |err| {
            console.print("Disk mount unavailable: ");
            console.print(@errorName(err));
            console.print("\n");
        };
    }

    console.print("Initializing tmpfs...\n");
    tmpfs.init();

    console.print("Mounting tmpfs on /tmp...\n");
    vfs.mount("none", "/tmp", "tmpfs", 0) catch |err| {
        console.print("Failed to mount tmpfs: ");
        console.print(@errorName(err));
        console.print("\n");
    };

    console.print("Initializing devfs...\n");
    devfs.init();

    console.print("Mounting devfs on /dev...\n");
    vfs.mount("none", "/dev", "devfs", 0) catch |err| {
        console.print("Failed to mount devfs: ");
        console.print(@errorName(err));
        console.print("\n");
    };

    console.print("Initializing procfs...\n");
    procfs.init();

    console.print("Mounting procfs on /proc...\n");
    vfs.mount("none", "/proc", "procfs", 0) catch |err| {
        console.print("Failed to mount procfs: ");
        console.print(@errorName(err));
        console.print("\n");
    };

    console.print("Initializing sysfs...\n");
    sysfs.init();

    console.print("Mounting sysfs on /sys...\n");
    vfs.mount("none", "/sys", "sysfs", 0) catch |err| {
        console.print("Failed to mount sysfs: ");
        console.print(@errorName(err));
        console.print("\n");
    };

    console.print("Initializing memory mapping...\n");
    mmap.init();
}
