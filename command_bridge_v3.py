#!/usr/bin/env python3
"""Compatibility shim — the entry point is now command_bridge_v5.py."""

import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from command_bridge.main import main

if __name__ == "__main__":
    main()
