"""Smoke-test the built wheel away from the checkout, without cloud calls."""

import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECK = r"""
import hashlib
import http.client
import json
import threading
from pathlib import Path
import tencent_cloud_cartography as package
from tencent_cloud_cartography.cli import main
from tencent_cloud_cartography.icons import icon_bytes, icon_for
from tencent_cloud_cartography.paths import DIST, ICONS
from tencent_cloud_cartography.projects import ProjectRepository, ProjectStore
from tencent_cloud_cartography.server import create_server
assert Path(package.__file__).resolve().is_relative_to(Path("environment").resolve())
assert DIST.name == "_web" and (DIST / "index.html").is_file()
manifest = json.loads((ICONS / "manifest.json").read_text())
assert len(manifest["icons"]) == 896
for icon in manifest["icons"]:
    assert hashlib.sha256((ICONS / icon["file"]).read_bytes()).hexdigest() == icon["sha256"]
assert b"<svg" in icon_bytes(icon_for("cos.bucket"))
brand = json.loads((DIST / "brand/manifest.json").read_text())
assert hashlib.sha256((DIST / "brand" / brand["file"]).read_bytes()).hexdigest() == brand["sha256"]
assert main(["projects", "init", "alpha", "--profile", "prod", "--regions", "eu-frankfurt"]) == 0
assert main(["projects", "init", "beta", "--profile", "dev", "--regions", "ap-singapore"]) == 0
store = ProjectStore()
server = create_server(port=0, repository=ProjectRepository(store))
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    for path in ["/", "/icons.html", "/brand/tencent-cloud.svg", "/api/health?project=alpha", "/api/health?project=beta"]:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
        conn.request("GET", path)
        response = conn.getresponse()
        body = response.read()
        assert response.status == 200, (path, response.status)
        if path.startswith("/api"):
            health = json.loads(body)
            assert health["mode"] == "setup" and health["resources"] == 0
            assert health["project"]["id"] == path.rsplit("=", 1)[1]
        conn.close()
finally:
    server.shutdown()
    server.server_close()
    thread.join()
print("Portable wheel: 896 icons, official logo, UI and isolated projects verified without cloud access")
"""


def main():
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    wheels = list((ROOT / "dist").glob(f"tencent_cloud_cartography-{version}-*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Expected one current wheel in dist; archive old builds before checking")
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        venv = directory / "environment"
        subprocess.run(["uv", "venv", "--python", sys.executable, str(venv)], check=True)
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        subprocess.run(
            ["uv", "pip", "install", "--python", str(python), str(wheels[0])], check=True
        )
        environment = dict(os.environ)
        environment.pop("TENCENT_CARTOGRAPHY_ROOT", None)
        environment.pop("PYTHONPATH", None)
        subprocess.run([str(python), "-I", "-c", CHECK], cwd=directory, env=environment, check=True)


if __name__ == "__main__":
    main()
