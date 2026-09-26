from __future__ import annotations

import os
import sys
from collections.abc import Iterator

import pytest

# Tests import the harness as tests.harness; make the project root importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import harness  # noqa: E402

if os.environ.get("HALLPASS_REQUIRE_INSTALLED"):
    # CI tests the built wheel from outside the checkout: the package under
    # test must be the installed one, not the source tree.
    import hallpass

    _src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
    assert not os.path.abspath(hallpass.__file__).startswith(_src), f"testing the source tree, not the wheel: {hallpass.__file__}"


@pytest.fixture(autouse=True)
def _canary() -> Iterator[None]:
    """Fail any test whose captured logs contain a test secret."""
    harness._OPEN.clear()
    yield
    for logs in harness._OPEN:
        harness.assert_no_canary(logs.text())
    harness._OPEN.clear()


@pytest.fixture
def srv() -> Iterator[harness.Server]:
    s = harness.Server()
    yield s
    s.close()
    assert not s.spec_errors, "requests did not match the API description:\n" + "\n".join(s.spec_errors)
