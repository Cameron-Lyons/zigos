const stdio = @import("stdio");

pub fn requireOperand(argc: usize, message: []const u8) bool {
    if (argc >= 2) return true;

    stdio.eputs(message);
    return false;
}

pub fn forEachOperand(argc: usize, argv: [*]const ?[*:0]const u8, handler: anytype) i32 {
    var exit_code: i32 = 0;
    var i: usize = 1;
    while (i < argc) : (i += 1) {
        const operand = argv[i] orelse continue;
        if (!handler(operand)) {
            exit_code = 1;
        }
    }

    return exit_code;
}
