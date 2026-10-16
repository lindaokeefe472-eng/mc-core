#!/usr/bin/env python3
"""
Trace callers and callers of caller for RVA 0x1F10BDF.
"""
import os
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from verify_reverse_results import read_pe_sections, disasm_range, rva_to_file_offset

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\ELDEN RING\Game\eldenring.exe"
IMAGE_BASE = 0x140000000

def find_function_prologue(f, sections, crash_rva):
    # Scan backwards from crash_rva to find function prologue (e.g., push rbp / sub rsp / mov [rsp...])
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for start_rva in range(crash_rva - 0x200, crash_rva, 0x10):
        insns = disasm_range(md, f, sections, start_rva, crash_rva - start_rva + 0x20)
        for ins in insns:
            # Check for typical prologue signatures:
            # 48 89 5c 24 (mov [rsp+...], rbx) or 40 53 (push rbx) or 48 83 ec (sub rsp, ...)
            if ins.mnemonic in ["push", "sub"] and "rsp" in ins.op_str:
                # Potential start
                pass
    return None

def find_callers(f, sections, target_rva):
    # Search all text sections for 'E8 xx xx xx xx' or indirect calls to target_rva
    text_sec = next(s for s in sections if s["name"] == ".text")
    f.seek(text_sec["raw_offset"])
    data = f.read(text_sec["raw_size"])
    
    callers = []
    # E8 rel32: rel32 = target_rva - (call_site_rva + 5)
    # => rel32 = target_rva - call_site_rva - 5
    for i in range(len(data) - 5):
        if data[i] == 0xE8:
            rel32 = struct.unpack("<i", data[i+1:i+5])[0]
            call_site_rva = text_sec["vrva"] + i
            dest_rva = call_site_rva + 5 + rel32
            if dest_rva == target_rva:
                callers.append(call_site_rva)
    return callers

def main():
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        
        # Let's disassemble around 0x1F10B90 to 0x1F10C10
        from disasm_buddy_spawner import print_instructions
        # Let's find instruction alignment
        raw_off = rva_to_file_offset(sections, 0x1F10B90)
        f.seek(raw_off)
        data = f.read(0x100)
        insns = list(md.disasm(data, IMAGE_BASE + 0x1F10B90))
        print_instructions(insns, "Instructions around 0x1F10BDF")

        # Let's find the function start: scan backwards from 0x1F10BDF
        # In x86_64 MSVC, functions usually start with 'sub rsp' or 'push ...' following a 'ret' or 'int 3' (0xCC)
        raw_start = rva_to_file_offset(sections, 0x1F10000)
        f.seek(raw_start)
        data_block = f.read(0xC00)
        # Find 0xCC padding or ret before 0x1F10BDF
        target_offset = 0xBDF
        # Scan backwards for CC padding
        func_entry_rva = None
        for i in range(target_offset, 0, -1):
            if data_block[i] == 0xCC and data_block[i+1] != 0xCC:
                func_entry_rva = 0x1F10000 + i + 1
                break
            elif data_block[i] == 0xC3: # ret
                # Next instruction might be entry
                func_entry_rva = 0x1F10000 + i + 1
                break
        
        print(f"\nFunction entry detected at RVA: 0x{func_entry_rva:X}")
        if func_entry_rva:
            entry_off = rva_to_file_offset(sections, func_entry_rva)
            f.seek(entry_off)
            func_code = f.read(0x1F10BDF - func_entry_rva + 0x40)
            func_insns = list(md.disasm(func_code, IMAGE_BASE + func_entry_rva))
            print_instructions(func_insns[:25], f"Prologue of function 0x{func_entry_rva:X}")

            print(f"\nSearching callers of function 0x{func_entry_rva:X}...")
            callers = find_callers(f, sections, func_entry_rva)
            print(f"Found {len(callers)} direct callers: {[hex(c) for c in callers[:10]]}")
            for c in callers[:5]:
                c_off = rva_to_file_offset(sections, c - 0x20)
                f.seek(c_off)
                c_code = f.read(0x40)
                c_insns = list(md.disasm(c_code, IMAGE_BASE + c - 0x20))
                print_instructions(c_insns, f"Caller site at 0x{c:X}")

if __name__ == "__main__":
    sys.exit(main())
