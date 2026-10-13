"""Paths for a source checkout (the supported installation method)."""

import os
from pathlib import Path

ROOT = Path(os.environ.get("TENCENT_CARTOGRAPHY_ROOT", Path(__file__).resolve().parents[1]))
ICONS = ROOT / "landscape/web/public/icons/tencent"
DIST = ROOT / "landscape/web/dist"
