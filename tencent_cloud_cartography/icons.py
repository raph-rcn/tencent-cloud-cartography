import json
from functools import lru_cache

from .catalog import KIND_ICONS, SERVICE_ICONS
from .paths import ICONS


@lru_cache
def manifest():
    return json.loads((ICONS / "manifest.json").read_text())


@lru_cache
def names():
    return {item["name"]: item["file"] for item in manifest()["icons"]}


def service_title(kind):
    service = kind.split(".")[0]
    return SERVICE_ICONS.get(service, (service.upper(), ""))[0]


def icon_for(kind):
    title = KIND_ICONS.get(kind) or SERVICE_ICONS.get(kind.split(".")[0], ("", ""))[1]
    return names().get(title, "unmapped.svg")


def icon_bytes(filename):
    allowed = {item["file"] for item in manifest()["icons"]}
    if filename not in allowed:
        return (ICONS.parent / "unmapped.svg").read_bytes()
    return (ICONS / filename).read_bytes()
