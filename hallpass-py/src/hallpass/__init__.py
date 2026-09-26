"""hallpass: permission checks for AI agents and bots, answered live by the
system they act in.

    from hallpass import Hallpass, guarded

    hp = Hallpass.from_config("hallpass.yaml")
    hp.require("dana@example.com", "jira-main", "DELETE_ISSUES", "issue:PAY-123", fresh=True)

See ``Hallpass`` for the in-process, in-code and remote forms, and
``guarded`` for tools an agent framework exposes to a model.
"""

from hallpass._api import (
    ALLOW,
    DENY,
    UNKNOWN,
    Decision,
    GroupsSource,
    Hallpass,
    PermissionDenied,
    UserSource,
    current,
    guarded,
)
from hallpass._version import __version__
from hallpass.core.secret import env, file, literal

__all__ = [
    "ALLOW",
    "DENY",
    "UNKNOWN",
    "Decision",
    "GroupsSource",
    "Hallpass",
    "PermissionDenied",
    "UserSource",
    "__version__",
    "current",
    "env",
    "file",
    "guarded",
    "literal",
]
