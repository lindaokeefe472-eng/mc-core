#!/usr/bin/env python3
"""
Read the last 64KB of mc_er.log efficiently.
"""
import os
import sys

GAME_DIR = r"C:\Program Files (x86)\Steam\steamapps\common\ELDEN RING\Game"

def main():
    log_file = os.path.join(GAME_DIR, "mc_er.log")
    if not os.path.exists(log_file):
        print("Log not found")
        return 1

    size = os.path.getsize(log_file)
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    print(f"Log size: {size} bytes")
    read_size = min(size, 524288) # 512KB
    with open(log_file, "rb") as f:
        f.seek(size - read_size)
        raw = f.read(read_size)
    
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    print(f"Total lines in last 512KB: {len(lines)}")
    
    # Filter out noisy lines like "phys: " and "world="
    filtered = [l for l in lines if not l.strip().startswith("[") or not any(k in l for k in ["phys:", "world=", "menu[", "fade="])]
    print(f"Non-phys lines in last 512KB: {len(filtered)}")
    print("--- LAST 60 Non-phys lines ---")
    for l in filtered[-60:]:
        print(l)
    return 0
    for l in lines:
        if any(k in l.lower() for k in ["tid 2112", "game_tid", "main thread", "render thread", "thread"]):
            print(l)
    return 0
    
    print("\n--- Absolute LAST 40 lines of mc_er.log ---")
    for l in lines[-40:]:
        print(l)

    return 0

if __name__ == "__main__":
    sys.exit(main())
