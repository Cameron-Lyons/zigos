ENTRY(_start)

SECTIONS
{
    . = 1M;
    __kernel_start = .;
    __kernel_measure_start = .;

    .text : ALIGN(4K)
    {
        *(.multiboot)
        *(.text)
    }

    .rodata : ALIGN(4K)
    {
        *(.rodata)
    }
    __kernel_measure_end = .;

    /* Userspace ELF bytes are covered by the signed build artifact manifest. */
    .zigos_userspace_archive : ALIGN(4K)
    {
        *(.zigos_userspace_archive)
        *(.zigos_userspace_archive.*)
    }

    .data : ALIGN(4K)
    {
        *(.data)
    }

    .bss : ALIGN(4K)
    {
        *(COMMON)
        *(.bss)
    }

    __kernel_end = .;
}
