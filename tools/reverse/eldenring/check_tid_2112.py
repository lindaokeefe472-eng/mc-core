#!/usr/bin/env python3
"""
Inspect all lines for summon / F2 / spawn egg / main thread in mc_er.log before crash.
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

    # Search backwards for the last session
    session_start = 0
    for idx in range(len(lines) - 1, -1, -1):
        if "key: KeyThread started" in lines[idx]:
            session_start = idx
            break

    session_lines = lines[session_start:]
    print(f"Total session lines: {len(session_lines)}")

    keywords = ["summon", "f2", "egg", "spawn", "buddy", "refusal", "dismiss", "infinite", "error"]
    for l in session_lines:
        lower = l.lower()
        if any(k in lower for k in keywords) and "crash-veh" not in lower and "phys:" not in lower:
            print(l.rstrip())

    return 0

if __name__ == "__main__":
    sys.exit(main())
