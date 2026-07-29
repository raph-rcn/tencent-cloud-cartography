#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import urllib.request
import zipfile
from pathlib import Path

AWS_ARCHITECTURE_ICONS_RELEASE = "04302026"
AWS_ARCHITECTURE_ICONS_URL = (
    "https://d1.awsstatic.com/onedam/marketing-channels/website/aws/en_US/"
    "architecture/approved/architecture-icons/"
    "Icon-package_04302026.4705b90f5aa45b019271a2699e9ce9b97b941ee1.zip"
)


def _slug(filename: str) -> str:
    name = re.sub(r"^Arch_", "", filename)
    name = re.sub(r"_64\.svg$", "", name)
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _load_archive(archive: Path | None) -> bytes:
    if archive:
        return archive.read_bytes()
    with urllib.request.urlopen(AWS_ARCHITECTURE_ICONS_URL) as response:
        return response.read()


def update_icons(destination: Path, archive: Path | None = None) -> dict[str, str]:
    payload = _load_archive(archive)
    icons: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(payload)) as package:
        for member in sorted(package.infolist(), key=lambda item: item.filename):
            path = Path(member.filename)
            if (
                member.is_dir()
                or path.suffix.lower() != ".svg"
                or "__MACOSX" in path.parts
                or path.name.startswith("._")
                or path.parent.name != "64"
                or "Architecture-Service-Icons_" not in member.filename
            ):
                continue
            icon_name = _slug(path.name)
            content = package.read(member)
            previous = icons.get(icon_name)
            if previous is not None and previous != content:
                category = _slug(path.parents[1].name.removeprefix("Arch_"))
                icon_name = f"{icon_name}-{category}"
                if icon_name in icons and icons[icon_name] != content:
                    raise ValueError(
                        f"Conflicting official icon assets for {icon_name}",
                    )
            icons[icon_name] = content

    destination.mkdir(parents=True, exist_ok=True)
    for old_icon in destination.glob("*.svg"):
        old_icon.unlink()
    for icon_name, content in sorted(icons.items()):
        (destination / f"{icon_name}.svg").write_bytes(content)

    manifest = {
        "release": AWS_ARCHITECTURE_ICONS_RELEASE,
        "source": AWS_ARCHITECTURE_ICONS_URL,
        "archive_sha256": hashlib.sha256(payload).hexdigest(),
        "icon_count": len(icons),
        "icons": sorted(icons),
    }
    (destination / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
    )
    return {
        name: hashlib.sha256(content).hexdigest() for name, content in icons.items()
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path("landscape/web/public/icons/aws"),
    )
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    hashes = update_icons(args.destination, args.archive)
    print(
        f"Installed {len(hashes)} saturated AWS service icons "
        f"from release {AWS_ARCHITECTURE_ICONS_RELEASE}",
    )


if __name__ == "__main__":
    main()
