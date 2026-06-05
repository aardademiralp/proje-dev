from __future__ import annotations
import sys
from pathlib import Path

_project_root = Path(__file__).resolve().parent
_src_path = _project_root / "src"

for p in [str(_project_root), str(_src_path)]:
    if p not in sys.path:
        sys.path.insert(0, p)
