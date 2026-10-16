#!/usr/bin/env python3
import sys

def main():
    with open("adapters/eldenring/src/loader.cpp", "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if "Dismiss" in line or "CSBuddy" in line or "infinite_summon" in line:
                print(f"{idx+1}: {line.rstrip()}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
