from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.auth_source import Material


@pytest.fixture
def frozen_session():
    """Explicit already-verified fixture for offline SDK contract tests."""
    material = Material("fixture-id", "fixture-key", "fixture-token")
    return SimpleNamespace(execute=lambda operation: operation(material), material=lambda: material)
