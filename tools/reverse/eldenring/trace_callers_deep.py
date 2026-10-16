#!/usr/bin/env python3
"""
Find functions containing callers of 0x141F10AD0.
"""
import struct
import sys
from verify_reverse_results import read_pe_sections, rva_to_file_offset
from disasm_buddy_spawner import EXE_PATH

def main():
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        pdata_sec = next(s for s in sections if s["name"] == ".pdata")
        f.seek(pdata_sec["raw_offset"])
        pdata = f.read(pdata_sec["raw_size"])
        
        callers = [0x1B44764, 0x1B4480A, 0x1B4482C, 0x1F38781, 0x1F388B1, 0x1F38C62, 0x1F38DD2]
        
        for c in callers:
            # Find function in pdata
            for i in range(0, len(pdata), 12):
                begin, end, unwind = struct.unpack("<III", pdata[i:i+12])
                if begin <= c < end:
                    print(f"Caller 0x14{c:X} is in function 0x14{begin:X} - 0x14{end:X}")
                    break

    return 0

if __name__ == "__main__":
    sys.exit(main())
