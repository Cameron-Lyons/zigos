var local_depth: u32 = 0;

fn depthSlot() *volatile u32 {
    // The native runtime boots one logical processor, so interrupt nesting is
    // CPU-local. Volatile access models asynchronous entry without cross-CPU locks.
    return &local_depth;
}

pub fn enter() void {
    const depth = depthSlot();
    depth.* +%= 1;
}

pub fn leave() void {
    const depth = depthSlot();
    const previous = depth.*;
    if (previous == 0) unreachable;
    depth.* = previous - 1;
}

pub fn active() bool {
    return depthSlot().* != 0;
}
