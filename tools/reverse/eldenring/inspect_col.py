#!/usr/bin/env python3
"""
Inspect Complete Object Locator for vtable at 0x2A2CD90.
"""
import struct
import sys
from verify_reverse_results import read_pe_sections, rva_to_file_offset
from disasm_buddy_spawner import EXE_PATH

def main():
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        # Scan backward from 0x2A2CD90 to find the start of the vtable
        # Vtable starts right after the COL pointer.
        # COL pointer is an address in .rdata pointing to a valid COL structure (sig=1)
        target_rva = 0x2A2CD90
        for off in range(0, 0x200, 8):
            cand_col_rva = target_rva - off - 8
            raw_off = rva_to_file_offset(sections, cand_col_rva)
            if not raw_off:
                continue
            f.seek(raw_off)
            col_ptr = struct.unpack("<Q", f.read(8))[0]
            if 0x140000000 <= col_ptr < 0x145000000:
                col_rva = col_ptr - 0x140000000
                col_raw = rva_to_file_offset(sections, col_rva)
                if col_raw:
                    f.seek(col_raw)
                    sig = struct.unpack("<I", f.read(4))[0]
                    if sig == 1: # x64 COL signature!
                        f.seek(col_raw + 0xC)
                        td_rva = struct.unpack("<I", f.read(4))[0]
                        name_raw = rva_to_file_offset(sections, td_rva + 0x10)
                        f.seek(name_raw)
                        cls_name = f.read(128).split(b"\x00")[0].decode('latin1', errors='ignore')
                        print(f"Found vtable start at RVA 0x{cand_col_rva + 8:X} (offset +0x{off:X})")
                        print(f"Class Name: {cls_name}")
                        return 0

    print("COL not found")
    return 1

if __name__ == "__main__":
    sys.exit(main())
