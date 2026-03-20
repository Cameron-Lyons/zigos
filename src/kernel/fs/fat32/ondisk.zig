pub const BootSector = extern struct {
    jump: [3]u8,
    oem_name: [8]u8,
    bytes_per_sector: u16 align(1),
    sectors_per_cluster: u8,
    reserved_sectors: u16 align(1),
    fat_count: u8,
    root_entries: u16 align(1),
    total_sectors_16: u16 align(1),
    media_descriptor: u8,
    sectors_per_fat_16: u16 align(1),
    sectors_per_track: u16 align(1),
    heads: u16 align(1),
    hidden_sectors: u32 align(1),
    total_sectors_32: u32 align(1),

    sectors_per_fat_32: u32 align(1),
    ext_flags: u16 align(1),
    fs_version: u16 align(1),
    root_cluster: u32 align(1),
    fs_info_sector: u16 align(1),
    backup_boot_sector: u16 align(1),
    reserved: [12]u8,
    drive_number: u8,
    reserved1: u8,
    boot_signature: u8,
    volume_id: u32 align(1),
    volume_label: [11]u8,
    fs_type: [8]u8,
};

pub const FSInfo = extern struct {
    signature1: u32 align(1),
    reserved1: [480]u8,
    signature2: u32 align(1),
    free_clusters: u32 align(1),
    next_free_cluster: u32 align(1),
    reserved2: [12]u8,
    signature3: u32 align(1),
};

pub const DirEntry = extern struct {
    name: [8]u8,
    ext: [3]u8,
    attributes: u8,
    reserved: u8,
    create_time_tenth: u8,
    create_time: u16 align(1),
    create_date: u16 align(1),
    access_date: u16 align(1),
    cluster_high: u16 align(1),
    modify_time: u16 align(1),
    modify_date: u16 align(1),
    cluster_low: u16 align(1),
    size: u32 align(1),
};

pub const LfnEntry = extern struct {
    order: u8,
    name1: [5]u16 align(1),
    attributes: u8,
    entry_type: u8,
    checksum: u8,
    name2: [6]u16 align(1),
    first_cluster_low: u16 align(1),
    name3: [2]u16 align(1),
};

pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
pub const ATTR_ZIGOS_SYMLINK: u8 = ATTR_SYSTEM | ATTR_ARCHIVE;
pub const ATTR_LONG_NAME: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

pub const FAT32_EOC: u32 = 0x0FFFFFF8;
pub const FAT32_FREE: u32 = 0x00000000;
