const x86 = @import("../../arch/x86.zig");

const debug_exit_port: u16 = 0xF4;
const qemu_poweroff_port: u16 = 0x604;
const bochs_poweroff_port: u16 = 0xB004;
const acpi_poweroff_value: u16 = 0x2000;

const IdtPtr = packed struct {
    limit: u16 = 0,
    base: u32 = 0,
};

pub const success_status: u32 = 0x10;
pub const failure_status: u32 = 0x11;

fn exitWithStatus(status: u32) noreturn {
    x86.outl(debug_exit_port, status);
    x86.outw(qemu_poweroff_port, acpi_poweroff_value);
    x86.outw(bochs_poweroff_port, acpi_poweroff_value);
    forceTripleFault();

    while (true) {
        asm volatile ("hlt");
    }
}

fn forceTripleFault() noreturn {
    const idt = IdtPtr{};
    x86.cli();
    asm volatile ("lidt %[idt]"
        :
        : [idt] "m" (idt),
    );
    asm volatile ("ud2");

    while (true) {
        asm volatile ("hlt");
    }
}

pub fn success() noreturn {
    exitWithStatus(success_status);
}

pub fn failure() noreturn {
    exitWithStatus(failure_status);
}
