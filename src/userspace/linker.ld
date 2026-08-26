ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x40000000;

    . = ALIGN(4K);
    .text :
    {
        *(.text)
        *(.text.*)
    } :text

    . = ALIGN(4K);
    .rodata :
    {
        KEEP(*(.zigos_userspace_role_identity))
        *(.rodata)
        *(.rodata.*)
        *(.eh_frame_hdr)
        *(.eh_frame_hdr.*)
        *(.eh_frame)
        *(.eh_frame.*)
    } :rodata

    . = ALIGN(4K);
    . = ALIGN(4K);
    .zigos_userspace_bootstrap :
    {
        KEEP(*(.zigos_userspace_bootstrap))
    } :data

    . = ALIGN(4K);
    .data :
    {
        *(.data)
        *(.data.*)
    } :data

    . = ALIGN(4K);
    .bss :
    {
        *(COMMON)
        *(.bss)
        *(.bss.*)
    } :data

    /DISCARD/ :
    {
        *(.comment)
        *(.note.GNU-stack)
    }
}
