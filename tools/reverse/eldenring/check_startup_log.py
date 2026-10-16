#!/usr/bin/env python3
"""
Inspect mc_er.log startup lines and thread/module info.
"""
import os
import sys

GAME_DIR = r"C:\Program Files (x86)\Steam\steamapps\common\ELDEN RING\Game"

def main():
    log_file = os.path.join(GAME_DIR, "mc_er.log")
    if not os.path.exists(log_file):
        print("Log not found")
        return 1

    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    print(f"Total lines in mc_er.log: {len(lines)}")
    print("--- First 50 lines ---")
    for l in lines[:50]:
        print(l.rstrip())

    print("\n--- Any mentions of thread / hook / dinput8 ---")
    for l in lines:
        if any(k in l.lower() for k in ["dinput8", "thread", "base", "module", "veh"]):
            print(l.rstrip())

    return 0

if __name__ == "__main__":
    sys.exit(main())
