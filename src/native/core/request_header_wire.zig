pub const RequestHeader = extern struct {
    operation: u16,
    flags: u16 = 0,
    reserved: u32 = 0,
    subject_task_id: u64 = 0,

    // A header names its operation and carries no option or reserved bits.
    pub inline fn admits(self: RequestHeader, operation: u16) bool {
        return self.operation == operation and self.flags == 0 and self.reserved == 0;
    }
};
