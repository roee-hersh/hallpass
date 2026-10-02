from __future__ import annotations

from collections.abc import Iterator

import pytest

from toolpass import AuditEvent, Session


class Events(list[AuditEvent]):
    """An audit sink that keeps every event."""

    def __call__(self, event: AuditEvent) -> None:
        self.append(event)

    @property
    def last(self) -> AuditEvent:
        return self[-1]


@pytest.fixture
def events() -> Events:
    return Events()


@pytest.fixture
def dana() -> Iterator[Session]:
    session = Session("dana@example.com")
    with session.active():
        yield session


@pytest.fixture(autouse=True)
def _fresh_default_toolkit() -> Iterator[None]:
    """Each test starts with the module-level secured_tool unconfigured."""
    import toolpass

    toolpass.configure(audit=None)
    yield
    toolpass.configure(audit=None)
