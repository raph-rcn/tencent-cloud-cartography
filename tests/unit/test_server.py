import http.client
import json
import threading

import pytest

from tencent_cloud_cartography.demo import demo
from tencent_cloud_cartography.server import create_server


@pytest.fixture
def server():
    server = create_server(demo(), 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join()


def request(server, path, method="GET", body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
    conn.request(method, path, body, headers or {})
    res = conn.getresponse()
    data = res.read()
    conn.close()
    return res.status, data


def test_server_health_topology_coverage(server):
    status, data = request(server, "/api/health")
    assert status == 200 and json.loads(data)["mode"] == "demo"
    status, data = request(server, "/api/topology?view=full")
    assert status == 200 and json.loads(data)["elements"]
    status, data = request(server, "/api/coverage")
    assert status == 200 and json.loads(data)["status"] == "partial"
    assert request(server, "/api/topology?limit=abc")[0] == 400


def test_server_rejects_other_origins_and_hosts(server):
    assert request(server, "/api/health", headers={"Host": "evil.example"})[0] == 403
    assert request(server, "/api/health", headers={"Origin": "https://evil.example"})[0] == 403
    assert (
        request(server, "/api/export/drawio", "POST", "{}", {"Origin": "https://evil.example"})[0]
        == 403
    )


def test_export_api_validation(server):
    assert request(server, "/api/export/drawio", "POST", '{"nodes":[],"edges":[]}')[0] == 200
    assert request(server, "/api/export/drawio", "POST", "{}")[0] == 400
    assert request(server, "/api/sync", "POST", "{}")[0] == 404


def test_http_repository_refresh_and_outage_are_visible(tmp_path):
    from tencent_cloud_cartography.repository import FileRepository
    from tencent_cloud_cartography.storage import save

    path = tmp_path / "data.json"
    data = demo()
    save(data, path)
    server = create_server(port=0, repository=FileRepository(path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, body = request(server, "/api/health")
        assert status == 200 and json.loads(body)["backend"] == "file"
        data["accounts"][0]["display"] = "Updated account"
        save(data, path)
        status, body = request(server, "/api/accounts")
        assert status == 200 and json.loads(body)["accounts"][0]["display"] == "Updated account"
        path.unlink()
        status, body = request(server, "/api/topology")
        assert status == 503 and "unavailable" in json.loads(body)["message"]
        assert request(server, "/api/sync", "POST", "{}")[0] == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
