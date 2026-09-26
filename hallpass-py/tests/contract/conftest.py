"""The contract tests' marker (Go gates them behind the `contract` build
tag): deselect them with ``-m "not contract"``."""

from __future__ import annotations

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "contract: runs integrations against Prism mock servers (needs HALLPASS_SPECS_DIR and npx on PATH)")
