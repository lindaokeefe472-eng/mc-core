#!/usr/bin/env python3
"""
Parse x64 UNWIND_INFO at 0x39E83A8 to find primary function.
"""
import struct
import sys
from verify_reverse_results import read_pe_sections, rva_to_file_offset
from disasm_buddy_spawner import EXE_PATH

def main():
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        unwind_rva = 0x39E83A8
        raw_off = rva_to_file_offset(sections, unwind_rva)
        f.seek(raw_off)
        data = f.read(32)
        # UNWIND_INFO:
        # Version : 3 bits, Flags : 5 bits (byte 0)
        # SizeOfProlog : byte 1
        # CountOfCodes : byte 2
        # FrameRegister : 4 bits, FrameOffset : 4 bits (byte 3)
        # UnwindCode : CountOfCodes * 2 bytes
        # Alignment if odd
        # If UNW_FLAG_CHAININFO (0x4):
        #   RUNTIME_FUNCTION (12 bytes): FunctionEntry of primary function!
        b0, prolog_size, code_count, frame = struct.unpack("<BBBB", data[:4])
        version = b0 & 7
        flags = b0 >> 3
        print(f"UNWIND_INFO at 0x{unwind_rva:X}: version={version}, flags=0x{flags:X}, prolog_size={prolog_size}, code_count={code_count}")
        
        # Check UNW_FLAG_CHAININFO = 4
        is_chain = (flags & 4) != 0
        print(f"Is Chained Unwind Info: {is_chain}")
        if is_chain:
            # Chained info follows the unwind codes
            aligned_count = (code_count + 1) & ~1
            chain_offset = 4 + aligned_count * 2
            f.seek(raw_off + chain_offset)
            primary_begin, primary_end, primary_unwind = struct.unpack("<III", f.read(12))
            print(f"Primary Function: Begin=0x14{primary_begin:X}, End=0x14{primary_end:X}, Unwind=0x{primary_unwind:X}")
            
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            from disasm_buddy_spawner import print_instructions
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            text_sec = next(s for s in sections if s["name"] == ".text")
            f.seek(text_sec["raw_offset"])
            text_data = f.read(text_sec["raw_size"])
            
            p_off = rva_to_file_offset(sections, primary_begin)
            f.seek(p_off)
            code = f.read(primary_end - primary_begin + 0x40)
            insns = list(md.disasm(code, 0x140000000 + primary_begin))
            print_instructions(insns, f"Primary function at 0x14{primary_begin:X}")
            
            # Search callers of primary_begin
            callers = []
            for i in range(len(text_data) - 5):
                if text_data[i] == 0xE8:
                    rel32 = struct.unpack("<i", text_data[i+1:i+5])[0]
                    site_rva = text_sec["vrva"] + i
                    dest_rva = site_rva + 5 + rel32
                    if dest_rva == primary_begin:
                        callers.append(site_rva)
            print(f"Callers of primary function 0x14{primary_begin:X}: {[hex(c) for c in callers]}")
            for c in callers:
                c_off = rva_to_file_offset(sections, c - 0x20)
                f.seek(c_off)
                c_code = f.read(0x40)
                c_insns = list(md.disasm(c_code, 0x140000000 + c - 0x20))
                print_instructions(c_insns, f"Caller site at 0x{c:X}")
            return 0
    return 0

if __name__ == "__main__":
    sys.exit(main())
