import sys
from pathlib import Path

# Ensure mock-adr-api is first on sys.path so 'app' resolves to mock-adr-api/app
_root = str(Path(__file__).parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)
