#!/usr/bin/env python3
"""
Inspect function 0x14031BCA0 and callers to find what object is being destroyed.
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from disasm_buddy_spawner import print_instructions, EXE_PATH, rva_to_file_offset, read_pe_sections
from pdata_func import get_function

def main():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        begin, end, unwind = get_function(0x31BCA0)
        raw_off = rva_to_file_offset(sections, begin)
        f.seek(raw_off)
        data = f.read(end - begin)
        insns = list(md.disasm(data, 0x140000000 + begin))
        print_instructions(insns, f"Function 0x14{begin:X} - 0x14{end:X}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
