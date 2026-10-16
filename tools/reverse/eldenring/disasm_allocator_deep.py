#!/usr/bin/env python3
"""
Deep disassembly of CSBuddyMan entity allocator and slot selection logic.
1. 0x1404BAEA0 (Alloc helper)
2. 0x1404BB450 - 0x1404BB4F0 (Slot query and ChrSpawner call)
3. How slot index is chosen (al from 0xCAF260 or r9d).
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
        
        insns_sp = disasm_range(md, f, sections, 0x493410, 0x70)
        print_instructions(insns_sp, "ChrSpawner::Spawn Success Path (RVA 0x493410 - 0x493480)")

        # 2. 0x1404BB450 - 0x1404BB500
        insns_slot = disasm_range(md, f, sections, 0x4BB450, 0xB0)
        print_instructions(insns_slot, "Slot Selection & Spawner Call (RVA 0x4BB450 - 0x4BB500)")

    return 0

if __name__ == "__main__":
    sys.exit(main())
