#!/usr/bin/env python3
"""
mklipo-linux.py <out> <thin_binary> [<thin_binary> ...]

Creates a Mach-O universal ("fat") binary from thin slices, replacing Apple's
`lipo -create` so macOS packages can be built on Linux CI.

The fat container is a small big-endian header followed by the slices, each
aligned to a page boundary:

    uint32  magic        0xCAFEBABE
    uint32  nfat_arch
    repeated fat_arch:
        uint32  cputype
        uint32  cpusubtype
        uint32  offset
        uint32  size
        uint32  align       (as a power of two)

cputype/cpusubtype are read from each slice's own Mach-O header, so the fat
entries always describe what is actually inside rather than a guess.
"""

import struct
import sys

FAT_MAGIC = 0xCAFEBABE
MH_MAGIC_64 = 0xFEEDFACF   # little-endian 64-bit Mach-O
MH_CIGAM_64 = 0xCFFAEDFE   # byte-swapped
ALIGN_BITS = 14            # 16 KB, what lipo uses for arm64
ALIGN = 1 << ALIGN_BITS


def read_arch(path):
    """Return (cputype, cpusubtype, data) for one thin Mach-O file."""
    with open(path, "rb") as fh:
        data = fh.read()

    if len(data) < 16:
        sys.exit(f"mklipo: {path} is too small to be a Mach-O file")

    magic = struct.unpack("<I", data[0:4])[0]
    if magic == MH_MAGIC_64:
        cputype, cpusubtype = struct.unpack("<ii", data[4:12])
    elif magic == MH_CIGAM_64:
        cputype, cpusubtype = struct.unpack(">ii", data[4:12])
    else:
        sys.exit(f"mklipo: {path} is not a 64-bit Mach-O (magic {magic:#x})")

    # Mask off the ABI64 / capability bits that must not appear in fat entries.
    return cputype, cpusubtype & 0x00FFFFFF, data


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: mklipo-linux.py <out> <thin> [<thin> ...]")

    out = sys.argv[1]
    slices = [read_arch(p) for p in sys.argv[2:]]

    header_size = 8 + 20 * len(slices)
    offset = (header_size + ALIGN - 1) // ALIGN * ALIGN

    entries, blobs = [], []
    for cputype, cpusubtype, data in slices:
        entries.append((cputype, cpusubtype, offset, len(data), ALIGN_BITS))
        blobs.append((offset, data))
        offset = (offset + len(data) + ALIGN - 1) // ALIGN * ALIGN

    with open(out, "wb") as fh:
        fh.write(struct.pack(">II", FAT_MAGIC, len(slices)))
        for cputype, cpusubtype, off, size, align in entries:
            fh.write(struct.pack(">iiIII", cputype, cpusubtype, off, size, align))
        for off, data in blobs:
            fh.write(b"\0" * (off - fh.tell()))
            fh.write(data)

    names = {0x01000007: "x86_64", 0x0100000C: "arm64"}
    described = ", ".join(names.get(e[0], hex(e[0])) for e in entries)
    print(f"    universal binary written: {described}")


if __name__ == "__main__":
    main()
