from __future__ import annotations

from collections.abc import Iterator

import pytest

from tests.integrations.bitbucket.common import Tracker


@pytest.fixture
def tracker() -> Iterator[Tracker]:
    """Servers and fakes a test starts, checked and closed at the end."""
    t = Tracker()
    yield t
    t.finish()
