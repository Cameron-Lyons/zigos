/* The isolated native-instruction proof deliberately keeps a low entry. Its
   EFI loader mode cannot be used by a production kernel. */
ENTRY(zigos_efi_entry)

PHDRS
{
    text PT_LOAD FLAGS(5);
    readonly PT_LOAD FLAGS(4);
    writable PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 32M;

    .text : ALIGN(4K)
    {
        KEEP(*(.text.boot))
        *(.text)
        *(.text.*)
    } :text

    .rodata : ALIGN(4K)
    {
        *(.rodata)
        *(.rodata.*)
        *(.eh_frame)
        *(.eh_frame.*)
        *(.gcc_except_table)
        *(.gcc_except_table.*)
        *(.data.rel.ro)
        *(.data.rel.ro.*)
        *(.got)
        *(.got.*)
    } :readonly

    .data : ALIGN(4K)
    {
        *(.data)
        *(.data.*)
    } :writable

    .bss : ALIGN(4K)
    {
        *(COMMON)
        *(.bss)
        *(.bss.*)
    } :writable
}
