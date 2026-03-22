const process = @import("../../process/process.zig");
const shell = @import("../../shell/repl.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");
const smoke_common = @import("smoke_common.zig");
const support = @import("support.zig");

fn userlandSmokeRunner() callconv(.c) void {
    var smoke_shell = shell.Shell.init();
    const commands = [_]struct {
        command: []const u8,
        marker: []const u8,
    }{
        .{ .command = "/bin/hello", .marker = "USERLAND:HELLO" },
        .{ .command = "/bin/echo USERLAND:ECHO", .marker = "USERLAND:ECHO" },
        .{ .command = "/bin/echo user:$USER home:${HOME}", .marker = "USERLAND:ENV" },
        .{ .command = "/bin/echo shell-$(/bin/uname)", .marker = "USERLAND:CMDSUB" },
        .{ .command = "/bin/echo \"USERLAND QUOTED\"", .marker = "USERLAND:QUOTED" },
        .{ .command = "/bin/echo USERLAND\\ ESCAPED", .marker = "USERLAND:ESCAPED" },
        .{ .command = "/bin/echo /bin/c* /bin/l?", .marker = "USERLAND:GLOB" },
        .{ .command = "/bin/uname", .marker = "USERLAND:UNAME" },
        .{ .command = "/bin/ls /bin", .marker = "USERLAND:LS" },
        .{ .command = "/bin/cat /etc/motd", .marker = "USERLAND:CAT" },
        .{ .command = "/bin/env", .marker = "USERLAND:ENV_STANDALONE" },
        .{ .command = "/bin/env | /bin/grep PATH=", .marker = "USERLAND:ENV_BIN" },
        .{ .command = "/bin/which ls", .marker = "USERLAND:WHICH" },
        .{ .command = "/bin/head /etc/motd", .marker = "USERLAND:HEAD" },
        .{ .command = "/bin/tail /etc/motd", .marker = "USERLAND:TAIL" },
        .{ .command = "/bin/wc /etc/motd", .marker = "USERLAND:WC" },
        .{ .command = "/bin/sort /etc/motd", .marker = "USERLAND:SORT" },
        .{ .command = "/bin/uniq /etc/motd", .marker = "USERLAND:UNIQ" },
        .{ .command = "/bin/hexdump /etc/motd", .marker = "USERLAND:HEXDUMP" },
        .{ .command = "/bin/test -e /etc/motd", .marker = "USERLAND:TEST" },
        .{ .command = "/bin/true", .marker = "USERLAND:TRUE" },
        .{ .command = "/bin/cp /etc/motd /tmp/motd.copy", .marker = "USERLAND:CP" },
        .{ .command = "/bin/mv /tmp/motd.copy /tmp/motd.moved", .marker = "USERLAND:MV" },
        .{ .command = "/bin/grep ZigOS /tmp/motd.moved", .marker = "USERLAND:GREP" },
        .{ .command = "/bin/chmod 600 /tmp/motd.moved", .marker = "USERLAND:CHMOD" },
        .{ .command = "/bin/chown user /tmp/motd.moved", .marker = "USERLAND:CHOWN" },
        .{ .command = "/bin/ln /etc/motd /motd-caf\xC3\xA9-r\xC3\xA9sum\xC3\xA9-hardlink.txt", .marker = "USERLAND:LN" },
        .{ .command = "/bin/cat /motd-caf\xC3\xA9-r\xC3\xA9sum\xC3\xA9-hardlink.txt", .marker = "USERLAND:CAT_HARD" },
        .{ .command = "/bin/cat /MOTD-CAFE\xCC\x81-RE\xCC\x81SUME\xCC\x81-HARDLINK.TXT", .marker = "USERLAND:CAT_HARD_CI" },
        .{ .command = "/bin/ln -s /etc/motd /motd-caf\xC3\xA9-stra\xC3\x9Fe-symbolic-link.txt", .marker = "USERLAND:LNS" },
        .{ .command = "/bin/cat /motd-caf\xC3\xA9-stra\xC3\x9Fe-symbolic-link.txt", .marker = "USERLAND:CAT_LINK" },
        .{ .command = "/bin/cat /MOTD-CAFE\xCC\x81-STRASSE-SYMBOLIC-LINK.TXT", .marker = "USERLAND:CAT_LINK_CI" },
        .{ .command = "/bin/ps", .marker = "USERLAND:PS" },
        .{ .command = "/bin/ping 1.1.1.1", .marker = "USERLAND:PING" },
        .{ .command = "/bin/whoami", .marker = "USERLAND:WHOAMI" },
        .{ .command = "/bin/id", .marker = "USERLAND:ID" },
        .{ .command = "/bin/date", .marker = "USERLAND:DATE" },
        .{ .command = "/bin/hostname", .marker = "USERLAND:HOSTNAME" },
        .{ .command = "/bin/cat /proc/version", .marker = "USERLAND:PROC_VERSION" },
        .{ .command = "/bin/cat /proc/mounts", .marker = "USERLAND:PROC_MOUNTS" },
        .{ .command = "/bin/cat /sys/kernel/hostname", .marker = "USERLAND:SYS_HOSTNAME" },
        .{ .command = "/bin/echo USERLAND:PIPE | /bin/cat", .marker = "USERLAND:PIPE_OK" },
        .{ .command = "/bin/cat /etc/motd | /bin/grep ZigOS | /bin/uniq > /tmp/pipe-chain.txt", .marker = "USERLAND:PIPE_CHAIN_WRITE" },
        .{ .command = "/bin/cat /tmp/pipe-chain.txt", .marker = "USERLAND:PIPE_CHAIN_READ" },
        .{ .command = "/bin/echo USERLAND:REDIRECT > /tmp/redir.txt", .marker = "USERLAND:REDIRECT_WRITE" },
        .{ .command = "/bin/cat < /tmp/redir.txt", .marker = "USERLAND:REDIRECT_READ" },
    };

    common.printBootMarker("USERLAND:START");

    for (commands) |step| {
        if (!smoke_common.runStep("USERLAND", &smoke_shell, step.command, step.marker)) {
            common.printBootMarker("USERLAND:FAIL");
            qemu_exit.failure();
        }
    }

    if (!smoke_shell.runCommandLine("/bin/sleep 3 &")) {
        common.printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    }
    common.printBootMarker("USERLAND:BG_START");

    if (!smoke_shell.runCommandLine("jobs")) {
        common.printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    }
    common.printBootMarker("USERLAND:JOBS_RUNNING");

    const bg_pid = smoke_shell.latestBackgroundPid() orelse {
        common.printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    };

    if (process.getProcessByPid(bg_pid)) |bg_proc| {
        bg_proc.state = .Stopped;
    } else {
        common.printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    }

    if (!smoke_shell.runCommandLine("jobs")) {
        common.printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    }
    common.printBootMarker("USERLAND:JOBS_STOPPED");

    if (!smoke_shell.runCommandLine("bg")) {
        common.printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    }
    common.printBootMarker("USERLAND:BG_RESUME");

    if (!smoke_shell.runCommandLine("jobs")) {
        common.printBootMarker("USERLAND:FAIL");
        qemu_exit.failure();
    }
    common.printBootMarker("USERLAND:JOBS_RESUMED");

    common.printBootMarker("USERLAND:PASS");
    qemu_exit.success();
}

pub fn run() noreturn {
    var shell_instance: shell.Shell = undefined;
    support.initializeShell(&shell_instance);

    const runner = process.create_kernel_process("userland_smoke_runner", common.idleTaskPlaceholder);
    process.adoptAsCurrent(runner);
    userlandSmokeRunner();
    unreachable;
}
