#!/usr/bin/env python3
"""
Inspect crash logs and mc_er.log in Elden Ring game directory.
"""
import os
import sys

GAME_DIR = r"C:\Program Files (x86)\Steam\steamapps\common\ELDEN RING\Game"

def main():
    log_file = os.path.join(GAME_DIR, "mc_er.log")
    if not os.path.exists(log_file):
        print(f"No mc_er.log found at {log_file}")
        return 0

    print(f"Reading {log_file} (size {os.path.getsize(log_file)} bytes):")
    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    
    print("\n--- Absolute LAST 100 lines of mc_er.log ---")
    for l in lines[-100:]:
        print(l.rstrip())
    return 0

if __name__ == "__main__":
    sys.exit(main())
