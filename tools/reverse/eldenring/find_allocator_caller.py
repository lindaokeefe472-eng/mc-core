#!/usr/bin/env python3
"""
Find exact function boundaries and all callers for the memory tree allocator around 0x1F10BC0.
"""
import os
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from verify_reverse_results import read_pe_sections, rva_to_file_offset

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\ELDEN RING\Game\eldenring.exe"
IMAGE_BASE = 0x140000000

def main():
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        text_sec = next(s for s in sections if s["name"] == ".text")
        pdata_sec = next(s for s in sections if s["name"] == ".pdata")
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        f.seek(pdata_sec["raw_offset"])
        pdata = f.read(pdata_sec["raw_size"])
        
        target_rva = 0x1F10BDF
        matching_func = None
        # Each entry is 12 bytes: BeginAddress (uint32), EndAddress (uint32), UnwindData (uint32)
        for i in range(0, len(pdata), 12):
            begin, end, unwind = struct.unpack("<III", pdata[i:i+12])
            if begin <= target_rva < end:
                matching_func = (begin, end, unwind)
                break
        
        print(f"Target RVA 0x{target_rva:X} belongs to function: Begin=0x{matching_func[0]:X}, End=0x{matching_func[1]:X}, Unwind=0x{matching_func[2]:X}")
        func_begin, func_end, _ = matching_func
        
        f.seek(text_sec["raw_offset"])
        data = f.read(text_sec["raw_size"])
        
        func_idx = func_begin - text_sec["vrva"]
        func_len = func_end - func_begin
        insns = list(md.disasm(data[func_idx : func_idx + func_len], IMAGE_BASE + func_begin))
        print(f"\n--- Function 0x{func_begin:X} - 0x{func_end:X} ({len(insns)} instructions) ---")
        for ins in insns:
            marker = "==> CRASH" if ins.address == IMAGE_BASE + target_rva else "         "
            print(f"{marker} 0x{ins.address:016X} | {ins.mnemonic:8} {ins.op_str}")

        print(f"\n--- Searching callers of 0x{func_begin:X} in .text ---")
        callers = []
        for i in range(len(data) - 5):
            if data[i] == 0xE8:
                rel32 = struct.unpack("<i", data[i+1:i+5])[0]
                site_rva = text_sec["vrva"] + i
                dest_rva = site_rva + 5 + rel32
                if dest_rva == func_begin:
                    callers.append(site_rva)
        
        print(f"Found {len(callers)} direct callers to 0x{func_begin:X}: {[hex(c) for c in callers]}")
        for c in callers:
            c_idx = c - text_sec["vrva"]
            surround = list(md.disasm(data[max(0, c_idx - 0x20) : c_idx + 0x20], IMAGE_BASE + text_sec["vrva"] + max(0, c_idx - 0x20)))
            print(f"\nCaller at RVA 0x{c:X}:")
            for ins in surround:
                marker = "==>" if ins.address == IMAGE_BASE + c else "   "
                print(f"{marker} 0x{ins.address:016X} | {ins.mnemonic:8} {ins.op_str}")
        return 0
        # Entry of our function is right after prev_ret (skipping 0xCC or 0x90)
        entry_idx = prev_ret + 1
        while entry_idx < target_idx and data[entry_idx] in (0xCC, 0x90):
            entry_idx += 1
        
        func_rva = text_sec["vrva"] + entry_idx
        print(f"Function entry RVA: 0x{func_rva:X}")
        
        # Disassemble from func_rva to 0x1F10C67
        func_len = target_rva - func_rva + 1
        insns = list(md.disasm(data[entry_idx : entry_idx + func_len + 10], IMAGE_BASE + func_rva))
        print(f"\n--- Disassembly of Function 0x{func_rva:X} ({len(insns)} instructions) ---")
        for ins in insns:
            print(f"0x{ins.address:016X} | {ins.mnemonic:8} {ins.op_str}")

        # Search callers across the entire .text section!
        print(f"\n--- Searching callers of 0x{func_rva:X} in .text ---")
        callers = []
        for i in range(len(data) - 5):
            if data[i] == 0xE8:
                rel32 = struct.unpack("<i", data[i+1:i+5])[0]
                site_rva = text_sec["vrva"] + i
                dest_rva = site_rva + 5 + rel32
                if dest_rva == func_rva:
                    callers.append(site_rva)
        
        print(f"Found {len(callers)} direct callers: {[hex(c) for c in callers]}")
        for c in callers:
            c_idx = c - text_sec["vrva"]
            surround = list(md.disasm(data[max(0, c_idx - 0x20) : c_idx + 0x20], IMAGE_BASE + text_sec["vrva"] + max(0, c_idx - 0x20)))
            print(f"\nCaller at RVA 0x{c:X}:")
            for ins in surround:
                marker = "==>" if ins.address == IMAGE_BASE + c else "   "
                print(f"{marker} 0x{ins.address:016X} | {ins.mnemonic:8} {ins.op_str}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
