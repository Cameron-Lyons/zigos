pub const AtaBrokerGrant = struct {
    base_port: u16,
    ctrl_port: u16,
    is_master: bool,
    irq_line: u8,
    sector_count: u64,
};
