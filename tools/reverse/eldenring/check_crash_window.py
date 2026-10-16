#!/usr/bin/env python3
"""
Inspect mc_er.log between seconds 30 and 45.
"""
import os
import re
import sys

GAME_DIR = r"C:\Program Files (x86)\Steam\steamapps\common\ELDEN RING\Game"

def main():
    log_file = os.path.join(GAME_DIR, "mc_er.log")
    if not os.path.exists(log_file):
        print("Log not found")
        return 1

    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    # Find the crash session (last session)
    # Search backwards for "[   0.000]" or "key: KeyThread started"
    session_start = 0
    for idx in range(len(lines) - 1, -1, -1):
        if "key: KeyThread started" in lines[idx]:
            session_start = idx
            break

    print(f"Session starts at line {session_start + 1}")
    session_lines = lines[session_start:]

    time_re = re.compile(r"^\[\s*([0-9]+\.[0-9]+)\]")
    for l in session_lines:
        m = time_re.match(l)
        if not m:
            continue
        t = float(m.group(1))
        if 30.0 <= t <= 45.0:
            # Skip high frequency phys lines
            if "phys:" in l or "world=" in l:
                continue
            print(l.rstrip())

    return 0

if __name__ == "__main__":
    sys.exit(main())
