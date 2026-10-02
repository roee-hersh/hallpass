from __future__ import annotations

import os
import sys
from collections.abc import Iterator

import pytest

# Tests import the harness as tests.harness; make the project root importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import harness

if os.environ.get("TOOLPASS_REQUIRE_INSTALLED"):
    # CI tests the built wheel from outside the checkout: the package under
    # test must be the installed one, not the source tree.
    import toolpass

    _src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
    assert not os.path.abspath(toolpass.__file__).startswith(_src), f"testing the source tree, not the wheel: {toolpass.__file__}"


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


# Property tests stand in for the original Go fuzz targets. CI runs them at
# Hypothesis's default size; the nightly job selects HYPOTHESIS_PROFILE=nightly
# for long runs. The profile's 20,000 examples are not multiplied by
# TOOLPASS_FUZZ_SCALE: that scale is for tests that set their own smaller count
# with harness.examples(n), and multiplying both would put the slowest parser
# tests at close to an hour each.
try:
    from hypothesis import HealthCheck, settings

    settings.register_profile("nightly", max_examples=20_000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))
except ImportError:  # pragma: no cover - hypothesis is a test dependency
    pass
