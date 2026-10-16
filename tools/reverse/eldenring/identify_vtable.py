#!/usr/bin/env python3
"""
Find vtables containing 0x1403CE410 to identify the class name.
"""
import struct
import sys
from verify_reverse_results import read_pe_sections, rva_to_file_offset
from disasm_buddy_spawner import EXE_PATH

def main():
    target_addr = 0x1403CE410
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        # Search .rdata and .data for pointers to target_addr
        rdata_sec = next(s for s in sections if s["name"] in [".rdata", ".data"])
        f.seek(rdata_sec["raw_offset"])
        data = f.read(rdata_sec["raw_size"])
        
        target_bytes = struct.pack("<Q", target_addr)
        idx = 0
        hits = []
        while True:
            idx = data.find(target_bytes, idx)
            if idx == -1:
                break
            vtable_entry_rva = rdata_sec["vrva"] + idx
            hits.append(vtable_entry_rva)
            idx += 8
            
        print(f"Found {len(hits)} vtable entries pointing to 0x{target_addr:X}:")
        for v in hits:
            print(f"  Entry at RVA 0x{v:X}")
            # The vtable entry is at index 0x58 / 8 = 11 (offset 0x58 in vtable)
            # So vtable start is at v - 0x58
            vtable_rva = v - 0x58
            # In MSVC x64 RTTI, vtable[-1] (at vtable_rva - 8) is COL
            col_off = rva_to_file_offset(sections, vtable_rva - 8)
            if col_off:
                f.seek(col_off)
                col_ptr = struct.unpack("<Q", f.read(8))[0]
                if 0x140000000 <= col_ptr < 0x145000000:
                    col_rva = col_ptr - 0x140000000
                    col_raw = rva_to_file_offset(sections, col_rva)
                    if col_raw:
                        f.seek(col_raw)
                        sig, td_off = struct.unpack("<II", f.read(8))
                        # td_rva is at offset 0xC in COL
                        f.seek(col_raw + 0xC)
                        td_rva = struct.unpack("<I", f.read(4))[0]
                        name_raw = rva_to_file_offset(sections, td_rva + 0x10)
                        if name_raw:
                            f.seek(name_raw)
                            raw_name = f.read(128).split(b"\x00")[0]
                            print(f"    Vtable RVA: 0x{vtable_rva:X} -> Class: {raw_name.decode('latin1', errors='ignore')}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
