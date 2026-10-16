#!/usr/bin/env python3
"""
Verify signature uniqueness of 0x1404BB9A0 (CSBuddyDismissAll) across eldenring.exe.
"""
import os
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from verify_reverse_results import read_pe_sections, disasm_range, rva_to_file_offset

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\ELDEN RING\Game\eldenring.exe"
IMAGE_BASE = 0x140000000

def main():
    with open(EXE_PATH, "rb") as f:
        raw = f.read()
        sections = read_pe_sections(f)
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        insns = disasm_range(md, f, sections, 0x4BB9A0, 0x40)
        bytes_list = []
        for ins in insns:
            bytes_list.extend(ins.bytes)
            if len(bytes_list) >= 32:
                break

        sig_bytes = bytes(bytes_list[:32])
        sig_hex = " ".join(f"{b:02X}" for b in sig_bytes)
        print(f"Extracted Signature for 0x1404BB9A0 ({len(sig_bytes)} bytes):")
        print(f"  {sig_hex}")

        matches = []
        idx = 0
        while True:
            idx = raw.find(sig_bytes, idx)
            if idx == -1:
                break
            matches.append(idx)
            idx += 1

        print(f"Total matches in entire eldenring.exe: {len(matches)}")
        for m in matches:
            print(f"  Match at file offset 0x{m:X}")

        assert len(matches) == 1, "Signature not unique!"
        print("[SUCCESS] Signature for 0x1404BB9A0 (DismissAll) is 100% UNIQUE across eldenring.exe!")

    return 0

if __name__ == "__main__":
    sys.exit(main())
