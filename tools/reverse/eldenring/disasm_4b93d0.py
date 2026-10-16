#!/usr/bin/env python3
"""
Disassemble 0x1404B93A0 - 0x1404B9750.
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from disasm_buddy_spawner import print_instructions, EXE_PATH, rva_to_file_offset, read_pe_sections

def main():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        raw_off = rva_to_file_offset(sections, 0x4B93B0)
        f.seek(raw_off)
        data = f.read(0x100)
        insns = list(md.disasm(data, 0x140000000 + 0x4B93B0))
        print_instructions(insns, "0x1404B93B0")
    return 0

if __name__ == "__main__":
    sys.exit(main())
