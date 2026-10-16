#!/usr/bin/env python3
"""
Deploy built dinput8.dll to Elden Ring game directory.
"""
import os
import shutil
import sys

GAME_DIR = r"C:\Program Files (x86)\Steam\steamapps\common\ELDEN RING\Game"
BUILD_DLL = r"D:\code\universal-modder\mc-core\build\bin\eldenring\dinput8.dll"

def main():
    target = os.path.join(GAME_DIR, "dinput8.dll")
    if not os.path.exists(BUILD_DLL):
        print(f"Error: {BUILD_DLL} does not exist")
        return 1
    
    shutil.copy2(BUILD_DLL, target)
    print(f"Successfully deployed {BUILD_DLL} -> {target} ({os.path.getsize(target)} bytes)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
