#!/usr/bin/env python3
"""
Command Bridge v5 — launch entry point.

All application logic lives in the command_bridge/ package.
Run with:  python3 command_bridge_v5.py
"""

import sys
import os

# Ensure the script's own directory is on sys.path so the package resolves
# correctly regardless of the current working directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from command_bridge.main import main

if __name__ == "__main__":
    main()
