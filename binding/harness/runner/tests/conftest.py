import os, sys
# Put the harness root on sys.path so rawhttp/mutator/runner/oracle import as top-level.
HARNESS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if HARNESS not in sys.path:
    sys.path.insert(0, HARNESS)
