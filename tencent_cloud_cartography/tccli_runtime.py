"""Private, bounded IPC with TCCLI's isolated Python installation.

Credentials travel only through anonymous pipes, never command arguments. The
bridge deliberately avoids tccli.main, which installs an on-disk request logger.
"""

import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from .errors import AuthenticationError, CollectionError


def runtime_python(executable="tccli", override=None):
    if override:
        value = shutil.which(str(override))
        if value:
            return value
        raise AuthenticationError("TccliRuntimeNotFound")
    located = shutil.which(str(executable))
    if not located:
        raise AuthenticationError("TccliNotFound")
    path = Path(located).resolve()
    try:
        with path.open("rb") as stream:
            header = stream.readline(4096).decode("utf-8")
        if header.startswith("#!"):
            parts = shlex.split(header[2:].strip())
            if parts and Path(parts[0]).name == "env":
                parts = parts[1:]
                if parts and parts[0] == "-S":
                    parts = parts[1:]
            if len(parts) == 1 and re.fullmatch(
                r"python(?:[0-9]+(?:\.[0-9]+)*)?(?:\.exe)?", Path(parts[0]).name
            ):
                python = shutil.which(parts[0])
                if python:
                    return python
    except (OSError, UnicodeError, ValueError):
        pass
    # Standard Windows pip console-script layout.
    if os.name == "nt" and path.parent.name.lower() == "scripts":
        python = path.parent.parent / "python.exe"
        if python.is_file():
            return str(python)
    raise AuthenticationError("TccliRuntimeNotFound")


class TccliRuntime:
    def __init__(self, executable="tccli", python=None, timeout=90):
        self.executable, self.python, self.timeout = executable, python, timeout
        self._resolved = None

    def invoke(self, operation, **payload):
        if self._resolved is None:
            self._resolved = runtime_python(self.executable, self.python)
        bridge = Path(__file__).with_name("_tccli_bridge.py")
        try:
            result = subprocess.run(
                [self._resolved, "-I", str(bridge)],
                input=json.dumps(dict(operation=operation, timeout=self.timeout, **payload)),
                capture_output=True,
                text=True,
                timeout=self.timeout + 30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise CollectionError(
                "TccliRuntimeTimeout" if operation == "resolve" else "Timeout"
            ) from None
        try:
            response = json.loads(result.stdout)
            if result.returncode or not isinstance(response, dict):
                raise ValueError
            if set(response) == {"error"}:
                code = response["error"]
                if not isinstance(code, str) or not re.fullmatch(
                    r"[A-Za-z][A-Za-z0-9.]{0,100}", code
                ):
                    raise ValueError
                raise CollectionError(code)
            if set(response) != {"result"} or not isinstance(response["result"], dict):
                raise ValueError
            return response["result"]
        except (ValueError, TypeError):
            # Never propagate the child stdout/stderr, even on malformed IPC.
            raise CollectionError("InvalidTccliRuntimeResponse") from None
