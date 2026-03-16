const http = @import("../net/http.zig");
const process = @import("../process/process.zig");
const vga = @import("../drivers/vga.zig");

const HttpServerRuntime = struct {
    server: http.HTTPServer = http.HTTPServer.init(80),
    pid: ?u32 = null,

    fn running(self: *const HttpServerRuntime) bool {
        return self.pid != null;
    }

    fn startedBy(self: *HttpServerRuntime, current_pid: u32) bool {
        return self.pid != null and self.pid.? == current_pid;
    }

    fn clearIfOwnedBy(self: *HttpServerRuntime, current_pid: u32) void {
        if (self.startedBy(current_pid)) {
            self.pid = null;
        }
    }
};

var runtime = HttpServerRuntime{};

fn httpServerEntry() void {
    const current_pid = if (process.getEffectiveCurrent()) |proc| proc.pid else 0;
    runtime.server.start() catch {
        vga.print("Failed to start HTTP server\n");
        runtime.clearIfOwnedBy(current_pid);
        return;
    };

    runtime.server.handleConnections();
    runtime.clearIfOwnedBy(current_pid);
}

pub fn running() bool {
    return runtime.running();
}

pub fn start(port: u16) u32 {
    runtime.server = http.HTTPServer.init(port);
    const server_process = process.create_process("httpd", httpServerEntry);
    runtime.pid = server_process.pid;
    return server_process.pid;
}

pub fn stop() ?u32 {
    const pid = runtime.pid orelse return null;
    runtime.server.stop();
    _ = process.terminateProcess(pid);
    runtime.clearIfOwnedBy(pid);
    return pid;
}
