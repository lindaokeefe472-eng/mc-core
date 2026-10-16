#!/usr/bin/env python3
"""
Disassemble around 0x140509640.
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from disasm_buddy_spawner import print_instructions, EXE_PATH, rva_to_file_offset, read_pe_sections

def main():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        raw_off = rva_to_file_offset(sections, 0x509620)
        f.seek(raw_off)
        data = f.read(0x80)
        insns = list(md.disasm(data, 0x140000000 + 0x509620))
        print_instructions(insns, "0x140509620")
    return 0

if __name__ == "__main__":
    sys.exit(main())
