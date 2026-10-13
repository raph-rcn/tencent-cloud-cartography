"""Sources used by the viewer. No source exposes a cloud mutation operation."""

from pathlib import Path

from .storage import load, validate


class SourceError(RuntimeError):
    """A safe, user-facing source failure without raw database/credential details."""


class SnapshotRepository:
    backend = "snapshot"

    def __init__(self, snapshot):
        self.snapshot = validate(snapshot)

    def read_snapshot(self):
        return self.snapshot

    def close(self):
        pass


class FileRepository:
    backend = "file"

    def __init__(self, path):
        self.path = Path(path)

    def read_snapshot(self):
        try:
            return load(self.path)
        except (ValueError, OSError, KeyError, TypeError) as exc:
            raise SourceError("Snapshot unavailable or invalid; check the selected file.") from exc

    def close(self):
        pass
