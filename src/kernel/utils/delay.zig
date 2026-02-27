pub fn busyWait(microseconds: u32) void {
    var i: u32 = 0;
    while (i < microseconds * 10) : (i += 1) {
        asm volatile ("pause");
    }
}
