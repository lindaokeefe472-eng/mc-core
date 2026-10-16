#!/usr/bin/env python3
"""
Disassemble CSBuddyMan::Spawn (RVA 0x4BBDD0) completely.
"""
import os
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from verify_reverse_results import read_pe_sections, disasm_range
from disasm_buddy_spawner import print_instructions

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\ELDEN RING\Game\eldenring.exe"

def main():
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        
        insns = disasm_range(md, f, sections, 0x4BB93F, 0x60)
        print_instructions(insns, "CSBuddyMan::Spawn Exit / Failure (RVA 0x4BB93F - 0x4BB9A0)")

        insns_dismiss = disasm_range(md, f, sections, 0x4BBAA0, 0x90)
        print_instructions(insns_dismiss, "Single Entity Dismissal (RVA 0x4BBAA0 - 0x4BBB30)")

    return 0

if __name__ == "__main__":
    sys.exit(main())
