"""Prepare firmware-authenticated and tampered images for a disposable VM."""

import pathlib
import struct
import sys

import pefile
from virt.peutils.pesign import pe_authenticode_hash


def main():
    image_path, kernel_path, cmdline_path, output_path = map(pathlib.Path, sys.argv[1:])
    image = image_path.read_bytes()
    kernel = kernel_path.read_bytes()
    cmdline = cmdline_path.read_bytes()
    pe = pefile.PE(data=image)
    output_path.mkdir(parents=True, exist_ok=True)
    (output_path / "image.sha256").write_text(pe_authenticode_hash(pe).hex() + "\n")
    (output_path / "original.efi").write_bytes(image)
    for name, payload in (("kernel", kernel), ("cmdline", cmdline)):
        if not payload or image.count(payload) != 1:
            raise ValueError(f"expected one complete embedded {name}")
        start = image.index(payload)
        if not any(
            section.PointerToRawData <= start
            and start + len(payload) <= section.PointerToRawData + section.SizeOfRawData
            and not section.Characteristics & 0x02000000  # Not discardable.
            for section in pe.sections
        ):
            raise ValueError(f"embedded {name} is not in a retained PE section")
        offset = start
        if name == "kernel":
            entry, phoff = struct.unpack_from("<QQ", kernel, 24)
            phsize, phnum = struct.unpack_from("<HH", kernel, 54)
            for index in range(phnum):
                kind, _, file_offset, vaddr, _, file_size, _, _ = struct.unpack_from(
                    "<IIQQQQQQ", kernel, phoff + index * phsize
                )
                if kind == 1 and vaddr <= entry < vaddr + file_size:
                    offset += file_offset + entry - vaddr
                    break
            else:
                raise ValueError("kernel entry is not file-backed")
        tampered = bytearray(image)
        tampered[offset] ^= 1
        if pe_authenticode_hash(pefile.PE(data=tampered)) == pe_authenticode_hash(pe):
            raise ValueError(f"{name} mutation escaped firmware hash coverage")
        (output_path / f"tampered-{name}.efi").write_bytes(tampered)


if __name__ == "__main__":
    main()
