"""hallpass-client is now part of ``hallpass``. This package re-exports it.

    pip install hallpass          # new projects
    from hallpass import Hallpass, guarded

Existing code keeps working unchanged: ``hallpass_client.Hallpass()`` is a
client for a running hallpass server, as it always was (``HALLPASS_URL`` and
``HALLPASS_API_KEY`` from the environment), and ``guarded``, ``current``,
``Decision`` and ``PermissionDenied`` are hallpass's own. With ``hallpass``
you can also run the engine in-process, with no server:
``Hallpass.from_config("hallpass.yaml")``.
"""

from __future__ import annotations

from hallpass import (
    ALLOW,
    DENY,
    UNKNOWN,
    Decision,
    GroupsSource,
    PermissionDenied,
    UserSource,
    current,
    guarded,
)
from hallpass import Hallpass as _Hallpass
from hallpass._api import _Remote

__all__ = [
    "ALLOW",
    "DENY",
    "UNKNOWN",
    "Decision",
    "GroupsSource",
    "Hallpass",
    "PermissionDenied",
    "UserSource",
    "current",
    "guarded",
]


class Hallpass(_Hallpass):
    """A client for one hallpass server: ``hallpass.Hallpass.remote``.

    ``url`` defaults to ``$HALLPASS_URL`` or ``http://localhost:8080``,
    ``api_key`` to ``$HALLPASS_API_KEY``.
    """

    def __init__(self, url: str | None = None, api_key: str | None = None, timeout: float = 10.0) -> None:
        self._backend = _Remote(url, api_key, timeout)
