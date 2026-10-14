import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS
from tencent_cloud_cartography.exclusions import EXCLUSIONS, record
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError, TccliTransport


@pytest.mark.parametrize("service,action,field", EXCLUSIONS)
def test_known_mixed_responses_blocked_without_launching_cli(service, action, field, monkeypatch):
    assert (service, action) not in ALLOWED_ACTIONS and field
    monkeypatch.setattr(
        "subprocess.run", lambda *a, **k: pytest.fail("Excluded API must not execute")
    )
    with pytest.raises(CollectionError) as error:
        TccliTransport()._run(service, action, "eu-frankfurt", {})
    assert error.value.code == "BlockedAction"


def test_exclusion_scopes_selected_and_idempotent_with_no_request_ids():
    g = Graph()
    record(g, "100", ["eu-frankfurt"], {"tcr"})
    record(g, "100", ["eu-frankfurt"], {"tcr"})
    assert len(g.coverage) == 1 and g.coverage[0]["action"] == "DescribeImageManifests"
    assert g.coverage[0]["status"] == "unsupported" and not g.coverage[0]["request_ids"]
