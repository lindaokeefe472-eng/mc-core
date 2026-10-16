#!/usr/bin/env python3
"""
Check if Elden Ring processes are running.
"""
import subprocess
import sys

def main():
    res = subprocess.run(["tasklist", "/FI", "IMAGENAME eq eldenring.exe"], capture_output=True, text=True)
    res2 = subprocess.run(["tasklist", "/FI", "IMAGENAME eq start_protected_game.exe"], capture_output=True, text=True)
    print("--- Tasklist eldenring.exe ---")
    print(res.stdout)
    print("--- Tasklist start_protected_game.exe ---")
    print(res2.stdout)
    return 0

if __name__ == "__main__":
    sys.exit(main())
