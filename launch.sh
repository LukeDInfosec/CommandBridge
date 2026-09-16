#!/usr/bin/env bash
# Command Bridge launcher — path-independent and logs startup errors so a failed
# launch is never silent. Run this from the file manager or a terminal.
#
# It cd's into its own directory (so the command_bridge package resolves), runs
# the app, and on any non-zero exit prints + logs the Python traceback to
# launch_error.log next to this script.

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || { echo "Cannot cd to $HERE"; exit 1; }

LOG="$HERE/launch_error.log"

# Pick an interpreter: prefer a local venv if present, else system python3.
if [ -x "$HERE/.venv/bin/python" ]; then
    PY="$HERE/.venv/bin/python"
else
    PY="python3"
fi

# Fail fast with a clear message if PyQt6 is missing for this interpreter.
if ! "$PY" -c "import PyQt6" 2>/dev/null; then
    echo "[!] PyQt6 is not installed for: $PY" | tee "$LOG"
    echo "    Install it with:  $PY -m pip install PyQt6" | tee -a "$LOG"
    echo "    (or: sudo apt install python3-pyqt6)" | tee -a "$LOG"
    read -r -p "Press Enter to close..." _ 2>/dev/null || true
    exit 1
fi

# Run the app, tee-ing stderr to the log so GUI clicks still leave a trace.
"$PY" command_bridge_v5.py "$@" 2> >(tee "$LOG" >&2)
status=${PIPESTATUS[0]}

if [ "$status" -ne 0 ]; then
    echo "" >&2
    echo "[!] Command Bridge exited with status $status. Details in: $LOG" >&2
    # Keep the window open if launched from a GUI so the error is readable.
    read -r -p "Press Enter to close..." _ 2>/dev/null || true
fi
exit "$status"
