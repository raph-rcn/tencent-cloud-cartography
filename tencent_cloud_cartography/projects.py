"""Isolated project settings and snapshots; settings never contain credentials."""

import json
import re
from pathlib import Path

from .catalog import SERVICE_ICONS
from .model import Graph
from .repository import FileRepository, SourceError
from .storage import save


def project_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value):
        raise ValueError("Project name must contain lowercase letters, digits, - or _")
    return value


def settings(raw):
    if not isinstance(raw, dict) or set(raw) != {"id", "profiles", "regions", "services"}:
        raise ValueError("Invalid project settings; credentials are not accepted")
    project_id(raw["id"])
    if len(json.dumps(raw).encode()) > 16_384:
        raise ValueError("Project configuration too large")
    if (
        not isinstance(raw["profiles"], list)
        or not raw["profiles"]
        or not all(
            isinstance(p, str) and p not in {".", ".."} and re.fullmatch(r"[A-Za-z0-9_.-]+", p)
            for p in raw["profiles"]
        )
    ):
        raise ValueError("Invalid project profiles")
    if (
        not isinstance(raw["regions"], list)
        or not raw["regions"]
        or not all(
            isinstance(r, str) and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", r)
            for r in raw["regions"]
        )
    ):
        raise ValueError("Invalid project regions")
    services = raw["services"]
    if services is not None and (
        not isinstance(services, list)
        or not services
        or not all(isinstance(s, str) and s in SERVICE_ICONS for s in services)
    ):
        raise ValueError("Invalid project services")
    if any(
        len(values) != len(set(values))
        for values in (raw["profiles"], raw["regions"], services or [])
    ):
        raise ValueError("Duplicate project settings")
    return raw


class ProjectStore:
    def __init__(self, root=Path(".local/projects")):
        self.root = Path(root).resolve()

    def directory(self, name):
        path = (self.root / project_id(name)).resolve()
        if path.parent != self.root:
            raise ValueError("Invalid project directory")
        return path

    def snapshot_path(self, name):
        path = self.directory(name) / "inventory.json"
        if path.is_symlink():
            raise ValueError("Project snapshot must not be a symlink")
        return path

    def create(self, name, profiles, regions, services=None):
        config = settings(
            dict(id=project_id(name), profiles=profiles, regions=regions, services=services)
        )
        path = self.directory(name) / "project.json"
        if path.exists() or path.is_symlink():
            raise ValueError("Project already exists; choose another name")
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=False)
        save(config, path)
        return config

    def read(self, name):
        path = self.directory(name) / "project.json"
        if path.is_symlink() or path.stat().st_size > 16_384:
            raise ValueError("Invalid project configuration file")
        from .cam import _unique_object

        config = settings(json.loads(path.read_text(), object_pairs_hook=_unique_object))
        if config["id"] != name:
            raise ValueError("Project identity mismatch")
        return config

    def list(self):
        result = []
        for directory in sorted(self.root.glob("*")):
            if not directory.is_dir():
                continue
            try:
                config = self.read(directory.name)
                result.append(
                    dict(**config, snapshot_available=self.snapshot_path(directory.name).exists())
                )
            except (ValueError, OSError):
                continue  # Never expose malformed config fields or raw errors.
        return result


class ProjectRepository:
    backend = "project"

    def __init__(self, store=None, selected=None, default_path=Path(".local/inventory.json")):
        self.store = store or ProjectStore()
        self.selected = selected
        self.default_path = Path(default_path)
        if selected:
            self.store.read(selected)

    def projects(self):
        return self.store.list()

    def read_project(self, name=None):
        selected = name if name is not None else self.selected
        if selected:
            try:
                config = self.store.read(selected)
                path = self.store.snapshot_path(selected)
            except (ValueError, OSError):
                raise SourceError("Project unavailable; check its saved settings.") from None
        else:
            config, path = None, self.default_path
        if path.exists():
            snapshot = FileRepository(path).read_snapshot()
            if snapshot["mode"] != "live":
                raise SourceError(
                    "Normal project viewing requires collected inventory. Open examples explicitly with --input."
                )
        else:
            snapshot = Graph(mode="setup").snapshot()
            snapshot["status"] = "partial"
        return {**snapshot, "project": config}

    def read_snapshot(self):
        return self.read_project()

    def close(self):
        pass
