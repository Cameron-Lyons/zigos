const gdt = @import("../interrupts/gdt.zig");
const process = @import("process.zig");
const vga = @import("../drivers/vga.zig");

pub const Ring3State = packed struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    ebp: u32,
    esp: u32,
    eip: u32,
    eflags: u32,
    cs: u32,
    ss: u32,
};

pub fn switchToRing3(entry_point: u32, user_stack: u32) void {
    const kernel_stack = @intFromPtr(process.current_process.?.kernel_stack) + process.current_process.?.stack_size;
    gdt.setKernelStack(kernel_stack);

    asm volatile (
        \\cli
        \\mov %[user_data_seg], %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%ax, %%fs
        \\mov %%ax, %%gs
        \\
        \\push %[user_data_seg]     # SS
        \\push %[user_stack]        # ESP
        \\push $0x202               # EFLAGS (interrupts enabled)
        \\push %[user_code_seg]     # CS
        \\push %[entry_point]       # EIP
        \\iret
        :
        : [user_data_seg] "i" (gdt.USER_DATA_SEG | 0x3),
          [user_stack] "r" (user_stack),
          [user_code_seg] "i" (gdt.USER_CODE_SEG | 0x3),
          [entry_point] "r" (entry_point),
    );
}

pub fn enterRing3(state: *const Ring3State) void {
    const kernel_stack = @intFromPtr(process.current_process.?.kernel_stack) + process.current_process.?.stack_size;
    gdt.setKernelStack(kernel_stack);

    asm volatile (
        \\cli
        \\mov %[eax], %%eax
        \\mov %[ebx], %%ebx
        \\mov %[ecx], %%ecx
        \\mov %[edx], %%edx
        \\mov %[esi], %%esi
        \\mov %[edi], %%edi
        \\mov %[ebp], %%ebp
        \\
        \\push %[ss]          # SS
        \\push %[esp]         # ESP
        \\push %[eflags]      # EFLAGS
        \\push %[cs]          # CS
        \\push %[eip]         # EIP
        \\
        \\iret
        :
        : [eax] "m" (state.eax),
          [ebx] "m" (state.ebx),
          [ecx] "m" (state.ecx),
          [edx] "m" (state.edx),
          [esi] "m" (state.esi),
          [edi] "m" (state.edi),
          [ebp] "m" (state.ebp),
          [ss] "m" (state.ss),
          [esp] "m" (state.esp),
          [eflags] "m" (state.eflags),
          [cs] "m" (state.cs),
          [eip] "m" (state.eip),
    );
}

fn ring3TestFunction() void {
    asm volatile (
        \\mov $1, %%eax
        \\mov $1, %%ebx
        \\lea %[msg], %%ecx
        \\mov $28, %%edx
        \\int $0x80
        :
        : [msg] "m" ("Hello from Ring 3 (user mode)!\n"),
        : .{ .eax = true, .ebx = true, .ecx = true, .edx = true, .memory = true }
    );

    asm volatile (
        \\mov $0, %%eax
        \\xor %%ebx, %%ebx
        \\int $0x80
        ::: .{ .eax = true, .ebx = true, .memory = true });
}

pub fn createRing3TestProcess() void {
    vga.print("Creating Ring 3 test process...\n");

    const proc = process.create_user_process("ring3_test", ring3TestFunction);

    vga.print("Ring 3 process created with PID: ");
    printNumber(proc.pid);
    vga.print("\n");
}

fn printNumber(num: u32) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }

    // SAFETY: filled by the following digit extraction loop
    var buffer: [20]u8 = undefined;
    var i: usize = 0;
    var n = num;

    while (n > 0) : (i += 1) {
        buffer[i] = @as(u8, @intCast((n % 10) + '0'));
        n /= 10;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}

pub fn validatePrivilegeLevels() bool {
    const cs = asm volatile ("mov %%cs, %[cs]"
        : [cs] "=r" (-> u16),
    );

    const current_ring = cs & 0x3;

    if (current_ring == 0) {
        vga.print("Currently in Ring 0 (kernel mode)\n");
        return true;
    } else if (current_ring == 3) {
        vga.print("Currently in Ring 3 (user mode)\n");
        return true;
    } else {
        vga.print("Invalid privilege level: ");
        printNumber(current_ring);
        vga.print("\n");
        return false;
    }
}
