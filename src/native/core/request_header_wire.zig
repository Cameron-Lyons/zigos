pub const RequestHeader = extern struct {
    operation: u16,
    flags: u16 = 0,
    reserved: u32 = 0,
    subject_task_id: u64 = 0,
};
