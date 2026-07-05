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
        *(.text.*)
    }

    .rodata : ALIGN(4K)
    {
        *(.rodata)
        *(.rodata.*)
    }
    __kernel_measure_end = .;

    /* Userspace ELF bytes are covered by the signed build artifact manifest. */
    .zigos_userspace_archive : ALIGN(4K)
    {
        *(.zigos_userspace_archive)
        *(.zigos_userspace_archive.*)
    }
    __kernel_archive_end = .;

    .data : ALIGN(4K)
    {
        *(.data)
        *(.data.*)
    }

    .bss : ALIGN(4K)
    {
        *(COMMON)
        *(.bss)
        *(.bss.*)
    }

    __kernel_end = .;
}
