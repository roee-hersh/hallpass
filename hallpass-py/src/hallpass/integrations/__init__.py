"""Every integration, registered in one place, so a build without an
integration is one deleted line."""

from __future__ import annotations

from hallpass.core.integration import Registry

__all__ = ["registry"]


def registry() -> Registry:
    """A registry with every integration."""
    from hallpass.integrations.fake import Fake

    r = Registry()
    r.register(Fake())
    return r
