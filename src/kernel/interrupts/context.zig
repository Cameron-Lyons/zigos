var depth: u32 = 0;

pub fn enter() void {
    _ = @atomicRmw(u32, &depth, .Add, 1, .seq_cst);
}

pub fn leave() void {
    const previous = @atomicRmw(u32, &depth, .Sub, 1, .seq_cst);
    if (previous == 0) unreachable;
}

pub fn active() bool {
    return @atomicLoad(u32, &depth, .seq_cst) != 0;
}
