#!/usr/bin/env python3
"""
Disassemble CSBuddyMan Pre-Dismissal Routine (0x1404BB9A0) and Single Dismissal (0x1404BBAA0).
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from verify_reverse_results import read_pe_sections, disasm_range
from disasm_buddy_spawner import print_instructions, EXE_PATH

def main():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        insns = disasm_range(md, f, sections, 0x4BB9A0, 0x100)
        print_instructions(insns, "CSBuddyMan::DismissAll (0x1404BB9A0)")
        
        insns2 = disasm_range(md, f, sections, 0x4BBAA0, 0x200)
        print_instructions(insns2, "CSBuddyMan::DismissSingle (0x1404BBAA0)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
