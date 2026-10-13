"""Import every SVG from Tencent's official archive; preserve bytes and provenance."""

import argparse
import hashlib
import io
import json
import re
import unicodedata
import urllib.request
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "landscape/web/public/icons/tencent"
SOURCE = "https://dscache.tencent-cloud.cn/upload/uploader/tencent_cloud_product_icons_svg-cabb63b49a754a7417b973bec8724623f0414854.zip"
SHA256 = "030aa75c7c111beb5bb7b25806c8c4ec648f74934f128522586a4ceda83eaddd"


def validate_svg(data):
    root = ET.fromstring(data)
    assert root.tag.endswith("svg")
    for node in root.iter():
        assert node.tag.split("}")[-1].lower() not in {"script", "foreignobject"}
        for key, value in node.attrib.items():
            assert not key.lower().startswith("on")
            if key.split("}")[-1] == "href":
                assert value.startswith("#"), "External SVG reference"


def check():
    manifest = json.loads((DEST / "manifest.json").read_text())
    assert manifest["archive_sha256"] == SHA256
    assert len(manifest["icons"]) == 896
    for item in manifest["icons"]:
        data = (DEST / item["file"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item["sha256"], item["file"]
        validate_svg(data)
    assert len(list(DEST.glob("*.svg"))) == len(manifest["icons"])
    print(f"Verified {len(manifest['icons'])} official Tencent SVG assets")


def update(archive=None):
    data = (
        Path(archive).read_bytes() if archive else urllib.request.urlopen(SOURCE, timeout=60).read()
    )
    assert hashlib.sha256(data).hexdigest() == SHA256, (
        "Archive checksum changed; review before updating"
    )
    DEST.mkdir(parents=True, exist_ok=True)
    icons, used = [], set()
    with zipfile.ZipFile(io.BytesIO(data)) as package:
        for name in sorted(package.namelist()):
            if not name.endswith(".svg") or not name.startswith("tencent_cloud_product_icons_"):
                continue
            locale = name.split("/")[0].rsplit("_", 1)[-1]
            title = Path(name).stem
            base = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode().lower()
            slug = re.sub("[^a-z0-9]+", "-", base).strip("-")
            if locale == "zh" or not slug:
                slug = hashlib.sha256(name.encode()).hexdigest()[:16]
            key = locale + "-" + slug
            if key in used:
                key += "-" + hashlib.sha256(name.encode()).hexdigest()[:8]
            used.add(key)
            content = package.read(name)
            validate_svg(content)
            (DEST / (key + ".svg")).write_bytes(content)
            icons.append(
                dict(
                    id=key,
                    name=title,
                    locale=locale,
                    file=key + ".svg",
                    source_path=name,
                    sha256=hashlib.sha256(content).hexdigest(),
                )
            )
    (DEST / "manifest.json").write_text(
        json.dumps(
            dict(
                source_page="https://cloud.tencent.com/act/event/icons",
                source_archive=SOURCE,
                archive_sha256=SHA256,
                retrieved="2026-10-13",
                attribution="Tencent Cloud official architecture icon library; Tencent retains rights in these assets.",
                icons=icons,
            ),
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )
    check()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--archive")
    args = parser.parse_args()
    check() if args.check else update(args.archive)
