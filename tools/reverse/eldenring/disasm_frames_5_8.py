#!/usr/bin/env python3
"""
Disassemble frames 5, 6, 7, 8 of the crash callstack.
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from disasm_buddy_spawner import print_instructions, EXE_PATH, rva_to_file_offset, read_pe_sections
from pdata_func import get_function

FRAMES = [
    (5, 0x1538F8),
    (6, 0x31BCF9),
    (7, 0x317F07),
    (8, 0x2CB59E),
]

def main():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        for frame_idx, rva in FRAMES:
            print("=" * 80)
            func_info = get_function(rva)
            if func_info:
                begin, end, unwind = func_info
                print(f"FRAME {frame_idx}: RVA 0x{rva:X} in function [0x{begin:X} - 0x{end:X}]")
            else:
                print(f"FRAME {frame_idx}: RVA 0x{rva:X}")
            print("=" * 80)
            
            raw_off = rva_to_file_offset(sections, rva - 0x30)
            if raw_off:
                f.seek(raw_off)
                data = f.read(0x60)
                insns = list(md.disasm(data, 0x140000000 + rva - 0x30))
                for ins in insns:
                    marker = "==>" if ins.address == 0x140000000 + rva else "   "
                    print(f"{marker} 0x{ins.address:016X} | {ins.mnemonic:8s} {ins.op_str}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
