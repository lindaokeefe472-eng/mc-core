#!/usr/bin/env python3
"""
Search for all references to [WorldChrMan + 0x1E630] and 0x1E638 in eldenring.exe.
"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from disasm_buddy_spawner import print_instructions, EXE_PATH, rva_to_file_offset, read_pe_sections

def main():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        text_sec = next(s for s in sections if s["name"] == ".text")
        f.seek(text_sec["raw_offset"])
        data = f.read(text_sec["raw_size"])
        
        # 0x1E630 in hex is 30 E6 01 00
        # 0x1E638 in hex is 38 E6 01 00
        matches = []
        for pat in [b"\x30\xE6\x01\x00", b"\x38\xE6\x01\x00"]:
            idx = 0
            while True:
                idx = data.find(pat, idx)
                if idx == -1:
                    break
                rva = text_sec["vrva"] + idx
                matches.append(rva)
                idx += 1
                
        matches = sorted(list(set(matches)))
        print(f"Found {len(matches)} pattern hits in .text:")
        for rva in matches[:20]:
            # Disassemble around rva
            offset = rva_to_file_offset(sections, max(0, rva - 10))
            f.seek(offset)
            code = f.read(30)
            insns = list(md.disasm(code, 0x140000000 + max(0, rva - 10)))
            for ins in insns:
                if "1e63" in ins.op_str:
                    print(f"0x{ins.address:016X} | {ins.mnemonic:8s} {ins.op_str}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
