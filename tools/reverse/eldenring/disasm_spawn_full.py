#!/usr/bin/env python3
"""
Disassemble CSBuddyMan::Spawn (0x1404BBDD0) and follow how it allocates buddy nodes.
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from verify_reverse_results import read_pe_sections, disasm_range
from disasm_buddy_spawner import print_instructions, EXE_PATH

def main():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        insns = disasm_range(md, f, sections, 0x4BC4B0, 0x200)
        print_instructions(insns, "CSBuddyMan::Spawn main body (0x1404BC4B0)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
