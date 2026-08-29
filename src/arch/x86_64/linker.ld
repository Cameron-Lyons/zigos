ENTRY(_start)

PHDRS
{
    kernel PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 1M;
    __kernel_start = .;
    __kernel_measure_start = .;

    .text : ALIGN(4K)
    {
        __kernel_text_start = .;
        KEEP(*(.multiboot2))
        *(.multiboot)
        *(.text.boot)
        *(.text)
        *(.text.*)
        . = ALIGN(4K);
        __kernel_text_end = .;
    } :kernel

    .rodata : ALIGN(4K)
    {
        __kernel_rodata_start = .;
        *(.rodata.boot)
        *(.rodata)
        *(.rodata.cst*)
        *(.rodata.str*)
        *(.rodata.*)
        *(.eh_frame)
        *(.eh_frame.*)
        *(.gcc_except_table)
        *(.gcc_except_table.*)
        . = ALIGN(4K);
        __kernel_rodata_end = .;
    } :kernel
    __kernel_measure_end = .;

    .zigos_userspace_archive : ALIGN(4K)
    {
        __kernel_archive_start = .;
        *(.zigos_userspace_archive)
        . = ALIGN(4K);
        __kernel_archive_end = .;
    } :kernel

    .relro : ALIGN(4K)
    {
        __kernel_relro_start = .;
        *(.data.rel.ro)
        *(.data.rel.ro.*)
        *(.got)
        *(.got.*)
        . = ALIGN(4K);
        __kernel_relro_end = .;
    } :kernel

    .data : ALIGN(4K)
    {
        __kernel_data_start = .;
        *(.data)
        *(.data.*)
        . = ALIGN(4K);
        __kernel_data_end = .;
    } :kernel

    .bss : ALIGN(4K)
    {
        __kernel_bss_start = .;
        *(COMMON)
        *(.bss)
        *(.bss.*)
        . = ALIGN(4K);
        __kernel_bss_end = .;
    } :kernel

    __kernel_end = .;
    /* Keep synchronized with PRECISE_IDENTITY_BYTES in paging64.zig. */
    __kernel_precise_identity_end = 16M;

    ASSERT(__kernel_start == __kernel_text_start,
           "unexpected loadable section before kernel text")
    ASSERT(__kernel_text_end == __kernel_rodata_start,
           "unexpected loadable section between kernel text and rodata")
    ASSERT(__kernel_rodata_end == __kernel_archive_start,
           "unexpected loadable section between kernel rodata and userspace archive")
    ASSERT(__kernel_archive_end == __kernel_relro_start,
           "unexpected loadable section between userspace archive and kernel RELRO")
    ASSERT(__kernel_relro_end == __kernel_data_start,
           "unexpected loadable section between kernel RELRO and data")
    ASSERT(__kernel_data_end == __kernel_bss_start,
           "unexpected loadable section between kernel data and bss")
    ASSERT(__kernel_bss_end == __kernel_end,
           "unexpected loadable section after kernel bss")
    ASSERT(__kernel_relro_end <= __kernel_precise_identity_end,
           "immutable kernel image exceeds the precise identity-mapping region")
    ASSERT(__kernel_end <= 0x40000000,
           "kernel exceeds the low identity-mapping region")
}
