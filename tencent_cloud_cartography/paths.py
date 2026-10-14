"""Resolve packaged UI assets or the development checkout independently of cwd."""

import os
from pathlib import Path

ROOT = Path(os.environ.get("TENCENT_CARTOGRAPHY_ROOT", Path(__file__).resolve().parents[1]))
PACKAGED = Path(__file__).resolve().parent / "_web"
DIST = (
    PACKAGED
    if not os.environ.get("TENCENT_CARTOGRAPHY_ROOT") and (PACKAGED / "index.html").is_file()
    else ROOT / "landscape/web/dist"
)
ICONS = DIST / "icons/tencent" if DIST == PACKAGED else ROOT / "landscape/web/public/icons/tencent"
