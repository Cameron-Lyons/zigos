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

    .text : ALIGN(4K)
    {
        *(.text)
        *(.text.*)
    } :text

    .rodata : ALIGN(4K)
    {
        *(.rodata)
        *(.rodata.*)
        *(.eh_frame_hdr)
        *(.eh_frame_hdr.*)
        *(.eh_frame)
        *(.eh_frame.*)
    } :rodata

    .zigos_userspace_descriptor : ALIGN(4K)
    {
        KEEP(*(.zigos_userspace_descriptor))
    } :rodata

    .data : ALIGN(4K)
    {
        *(.data)
        *(.data.*)
    } :data

    .bss : ALIGN(4K)
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
