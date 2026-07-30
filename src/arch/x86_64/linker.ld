ENTRY(_start)

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
    }

    .rodata : ALIGN(4K)
    {
        __kernel_rodata_start = .;
        *(.rodata.boot)
        *(.rodata)
        *(.rodata.cst*)
        *(.rodata.str*)
        *(.eh_frame)
        *(.eh_frame.*)
        *(.gcc_except_table)
        *(.gcc_except_table.*)
        . = ALIGN(4K);
        __kernel_rodata_end = .;
    }
    __kernel_measure_end = .;

    .zigos_userspace_archive : ALIGN(4K)
    {
        __kernel_archive_start = .;
        *(.rodata.zigos_userspace_archive)
        . = ALIGN(4K);
        __kernel_archive_end = .;
    }

    .relro : ALIGN(4K)
    {
        __kernel_relro_start = .;
        *(.data.rel.ro)
        *(.data.rel.ro.*)
        *(.got)
        *(.got.*)
        . = ALIGN(4K);
        __kernel_relro_end = .;
    }

    .data : ALIGN(4K)
    {
        __kernel_data_start = .;
        *(.data)
        *(.data.*)
        . = ALIGN(4K);
        __kernel_data_end = .;
    }

    .bss : ALIGN(4K)
    {
        __kernel_bss_start = .;
        *(COMMON)
        *(.bss)
        *(.bss.*)
        . = ALIGN(4K);
        __kernel_bss_end = .;
    }

    __kernel_end = .;

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
}
