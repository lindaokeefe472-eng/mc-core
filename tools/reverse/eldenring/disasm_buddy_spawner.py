#!/usr/bin/env python3
"""
Reverse-engineer CSBuddyMan dispatch and entity spawning routines in eldenring.exe (2.7.1.0).
Disassembles:
1. CSBuddyMan tick/request check (around RVA 0x4B8900)
2. CSBuddyMan spawn logic (around RVA 0x4BBDD0)
3. Traces entity creation and ChrIns instantiation callees.
"""

import os
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_PATH = r"C:\Program Files (x86)\Steam\steamapps\common\ELDEN RING\Game\eldenring.exe"
IMAGE_BASE = 0x140000000

def read_pe_sections(f):
    f.seek(0x3C)
    e_lfanew = struct.unpack("<I", f.read(4))[0]
    f.seek(e_lfanew)
    sig = f.read(4)
    if sig != b"PE\x00\x00":
        raise ValueError("Invalid PE signature")
    
    machine, num_sections = struct.unpack("<HH", f.read(4))
    f.seek(e_lfanew + 0x14)
    size_of_opt = struct.unpack("<H", f.read(2))[0]
    
    opt_header_offset = e_lfanew + 0x18
    section_headers_offset = opt_header_offset + size_of_opt
    
    sections = []
    f.seek(section_headers_offset)
    for _ in range(num_sections):
        sec_data = f.read(40)
        name = sec_data[:8].rstrip(b"\x00").decode("latin-1", errors="ignore")
        vsize, vrva, raw_size, raw_offset = struct.unpack("<IIII", sec_data[8:24])
        sections.append({
            "name": name,
            "vsize": vsize,
            "vrva": vrva,
            "raw_size": raw_size,
            "raw_offset": raw_offset,
        })
    return sections

def rva_to_file_offset(sections, rva):
    for sec in sections:
        if sec["vrva"] <= rva < sec["vrva"] + max(sec["vsize"], sec["raw_size"]):
            return sec["raw_offset"] + (rva - sec["vrva"])
    return None

def disasm_range(md, f, sections, start_rva, length):
    offset = rva_to_file_offset(sections, start_rva)
    if offset is None:
        print(f"Error: RVA 0x{start_rva:X} not in any section")
        return []
    f.seek(offset)
    code = f.read(length)
    instructions = list(md.disasm(code, IMAGE_BASE + start_rva))
    return instructions

def print_instructions(instructions, title):
    print("=" * 80)
    print(f" {title}")
    print("=" * 80)
    for ins in instructions:
        bytes_hex = " ".join(f"{b:02X}" for b in ins.bytes)
        print(f"0x{ins.address:016X} | {bytes_hex:24s} | {ins.mnemonic:8s} {ins.op_str}")

def main():
    if not os.path.exists(EXE_PATH):
        print(f"Error: {EXE_PATH} does not exist")
        return 1

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    targets = [
        ("1. CSBuddyMan Update / Request Dispatch", 0x4B8940, 0xA0),
        ("2. CSBuddyMan Pre-Dismissal Routine (0x1404BB9A0)", 0x4BB9A0, 0x100),
        ("3. CSBuddyMan Single-Entity Dismissal (0x1404BBAA0)", 0x4BBAA0, 0x80),
        ("4. CSBuddyMan Spawn Entry (0x1404BBDD0)", 0x4BBDD0, 0x60),
        ("5. CSBuddyMan Spawn Callee / Dispatch (0x1404BC4B0)", 0x4BC4B0, 0x30),
        ("6. CSBuddyMan Entity Allocator Helper (0x1404BAEA0)", 0x4BAEA0, 0x50),
        ("7. Group Slot Check (0x1404BB490 - 0x1404BB4D0)", 0x4BB490, 0x40),
        ("8. ChrSpawner::Spawn & Slot Loop (0x140493380 - 0x140493410)", 0x493380, 0x90),
    ]

    with open(EXE_PATH, "rb") as f:
        sections = read_pe_sections(f)
        for title, rva, length in targets:
            insns = disasm_range(md, f, sections, rva, length)
            print_instructions(insns, f"{title} (RVA 0x{rva:X})")

    return 0

if __name__ == "__main__":
    sys.exit(main())

