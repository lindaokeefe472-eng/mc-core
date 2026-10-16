#!/usr/bin/env python3
"""
Search for 'inc qword ptr [... + 0x38]' or list push_back in CSBuddyMan (RVA 0x4B8000 - 0x4C0000).
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from disasm_buddy_spawner import print_instructions, EXE_PATH, rva_to_file_offset, read_pe_sections

def main():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        raw_off = rva_to_file_offset(sections, 0x4B8000)
        f.seek(raw_off)
        data = f.read(0x8000) # 32KB
        insns = list(md.disasm(data, 0x140000000 + 0x4B8000))
        for ins in insns:
            if "0x38" in ins.op_str:
                print(f"0x{ins.address:016X} | {ins.mnemonic:8s} {ins.op_str}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
