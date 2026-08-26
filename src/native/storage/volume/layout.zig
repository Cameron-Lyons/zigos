pub const sector_size: usize = 512;
pub const slot_sectors: u32 = 768;
pub const slot_count: u32 = 2;
pub const header_sectors: u32 = 1;
pub const payload_sectors: u32 = slot_sectors - header_sectors;
pub const slot_bytes: usize = slot_sectors * sector_size;
pub const image_bytes: usize = slot_count * slot_bytes;
pub const max_payload_bytes: usize = payload_sectors * sector_size;
pub const required_device_sectors: u64 = slot_count * slot_sectors;
pub const max_signer_bytes: usize = 48;

pub const root_sector_count: u32 = 2;
pub const data_start_sector: u32 = root_sector_count;
pub const data_start_byte: usize = data_start_sector * sector_size;
pub const data_capacity_bytes: usize = image_bytes - data_start_byte;

pub const data_region_count: usize = 2;
pub const data_region_bytes: usize = data_capacity_bytes / data_region_count;
pub const alternate_data_region_offset: u32 = @intCast(data_region_bytes);

pub const root_magic = "ZG4LOG1";
pub const root_format_version: u16 = 4;
pub const max_replay_log_records: u16 = 512;
pub const max_log_segments: u16 = 64;
pub const compaction_threshold_bytes: u32 = @intCast((data_region_bytes * 3) / 4);

pub const log_record_kind_bytes: usize = 1;
pub const log_record_payload_len_bytes: usize = 4;
pub const log_record_checksum_bytes: usize = 8;
pub const log_record_payload_len_offset: usize = log_record_kind_bytes;
pub const log_record_checksum_offset: usize = log_record_payload_len_offset + log_record_payload_len_bytes;
pub const log_record_header_len: usize = log_record_checksum_offset + log_record_checksum_bytes;

pub const payload_magic = "ZG4STATE";
pub const format_version: u16 = 11;
