#!/usr/bin/env python3
"""
Search for modifications to [rdi + 0x30] or [r12/r15 + 0x30] or [rax + 0x30] in CSBuddyMan::Spawn.
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from disasm_buddy_spawner import print_instructions, EXE_PATH, rva_to_file_offset, read_pe_sections

def main():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        raw_off = rva_to_file_offset(sections, 0x4BAEA0)
        f.seek(raw_off)
        data = f.read(0x4BB900 - 0x4BAEA0)
        insns = list(md.disasm(data, 0x140000000 + 0x4BAEA0))
        for ins in insns:
            if any(k in ins.op_str for k in ["0x30", "0x38", "0x28"]):
                print(f"0x{ins.address:016X} | {ins.mnemonic:8s} {ins.op_str}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
