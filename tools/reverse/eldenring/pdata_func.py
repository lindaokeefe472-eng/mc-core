#!/usr/bin/env python3
import struct
import sys
from verify_reverse_results import read_pe_sections, rva_to_file_offset
from disasm_buddy_spawner import EXE_PATH, print_instructions
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def get_function(rva):
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        pdata_sec = next(s for s in sections if s["name"] == ".pdata")
        f.seek(pdata_sec["raw_offset"])
        pdata = f.read(pdata_sec["raw_size"])
        
        for i in range(0, len(pdata), 12):
            begin, end, unwind = struct.unpack("<III", pdata[i:i+12])
            if begin <= rva < end:
                return begin, end, unwind
    return None

def main():
    target = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x4B93D0
    res = get_function(target)
    if not res:
        print(f"No function for RVA 0x{target:X}")
        return 1
    begin, end, unwind = res
    print(f"Function: Begin=0x14{begin:X}, End=0x14{end:X}, Unwind=0x{unwind:X}")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        raw_off = rva_to_file_offset(sections, begin)
        f.seek(raw_off)
        data = f.read(end - begin)
        insns = list(md.disasm(data, 0x140000000 + begin))
        print_instructions(insns, f"Function 0x14{begin:X}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
