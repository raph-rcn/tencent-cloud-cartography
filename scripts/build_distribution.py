"""Build a portable wheel and source archive with the compiled UI and official assets."""

import argparse
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-web", action="store_true", help="Use an already built web UI")
    args = parser.parse_args()
    web = ROOT / "landscape/web"
    if not args.skip_web:
        subprocess.run(["npm", "ci"], cwd=web, check=True)
        subprocess.run(["npm", "run", "build"], cwd=web, check=True)
    subprocess.run(
        ["uv", "run", "python", "scripts/update_tencent_icons.py", "--check"], cwd=ROOT, check=True
    )
    dist = web / "dist"
    if not (dist / "index.html").is_file() or not (dist / "icons/tencent/manifest.json").is_file():
        raise SystemExit("Build the frontend before packaging")
    staged = ROOT / "tencent_cloud_cartography/_web"
    if staged.exists():
        raise SystemExit("Remove stale packaging staging directory before rebuilding")
    try:
        shutil.copytree(dist, staged)
        subprocess.run(["uv", "build"], cwd=ROOT, check=True)
    finally:
        if staged.exists():
            shutil.rmtree(staged)


if __name__ == "__main__":
    main()
