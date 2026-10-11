ENTRY(zigos_efi_entry)

PHDRS
{
    text PT_LOAD FLAGS(5);
    readonly PT_LOAD FLAGS(4);
    writable PT_LOAD FLAGS(6);
}

SECTIONS
{
    /* Keep synchronized with arch/kernel_address.zig. Physical allocations
       remain above firmware's low ACPI NVS and runtime allocations. */
    __kernel_image_bias = 0xffffffff80000000;
    . = __kernel_image_bias + 32M;
    __kernel_start = .;
    __kernel_measure_start = .;

    .text ALIGN(4K) : AT(ADDR(.text) - __kernel_image_bias)
    {
        __kernel_text_start = .;
        KEEP(*(.text.boot))
        *(.text)
        *(.text.*)
        . = ALIGN(4K);
        __kernel_text_end = .;
    } :text

    .rodata ALIGN(4K) : AT(ADDR(.rodata) - __kernel_image_bias)
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
    } :readonly
    __kernel_measure_end = .;

    .zigos_userspace_archive ALIGN(4K) : AT(ADDR(.zigos_userspace_archive) - __kernel_image_bias)
    {
        __kernel_archive_start = .;
        *(.zigos_userspace_archive)
        . = ALIGN(4K);
        __kernel_archive_end = .;
    } :readonly

    .relro ALIGN(4K) : AT(ADDR(.relro) - __kernel_image_bias)
    {
        __kernel_relro_start = .;
        *(.data.rel.ro)
        *(.data.rel.ro.*)
        *(.got)
        *(.got.*)
        . = ALIGN(4K);
        __kernel_relro_end = .;
    } :readonly

    .data ALIGN(4K) : AT(ADDR(.data) - __kernel_image_bias)
    {
        __kernel_data_start = .;
        *(.data)
        *(.data.*)
        . = ALIGN(4K);
        __kernel_data_end = .;
    } :writable

    .bss ALIGN(4K) : AT(ADDR(.bss) - __kernel_image_bias)
    {
        __kernel_bss_start = .;
        *(COMMON)
        *(.bss)
        *(.bss.*)
        . = ALIGN(4K);
        __kernel_bss_end = .;
    } :writable

    __kernel_end = .;
    /* Keep synchronized with PRECISE_IDENTITY_BYTES in paging64.zig. */
    __kernel_precise_image_physical_end = 64M;

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
    ASSERT(__kernel_relro_end - __kernel_image_bias <= __kernel_precise_image_physical_end,
           "immutable kernel image exceeds the precise mapping region")
    ASSERT(__kernel_start - __kernel_image_bias == 32M,
           "kernel physical load must start at 32 MiB")
    ASSERT(__kernel_end - __kernel_image_bias <= 0x40000000,
           "kernel exceeds the initial physical mapping region")
    ASSERT(zigos_efi_entry >= __kernel_text_start && zigos_efi_entry < __kernel_text_end,
           "kernel entry must use the upper-half text mapping")
}
