const common = @import("../common.zig");
const session_manager = @import("../../process/native/session_manager.zig");

pub fn run() noreturn {
    session_manager.boot();
    common.enterIdleLoop();
}
