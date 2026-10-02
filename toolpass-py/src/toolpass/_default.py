"""The module-level ``secured_tool``, on a default toolkit set up by ``configure``.

    import toolpass
    from toolpass import ApprovalQueue, secured_tool

    toolpass.configure(approver=ApprovalQueue(), credentials={"github-bot": token})

    @secured_tool(effect="write", scope={"repo": "acme/gitops-*"}, approve=True)
    def open_pr(repo: str, title: str) -> str: ...

Tools declared before ``configure`` use its settings too: they read them at
call time. A program that needs two sets of settings makes its own
``Toolkit`` objects and uses their ``secured_tool``.
"""

from __future__ import annotations

from typing import Any

from toolpass._toolkit import Toolkit

_DEFAULT = Toolkit()
_DEFAULT._lenient = True


def configure(**settings: Any) -> Toolkit:
    """Set up the default toolkit behind ``secured_tool``, with the same
    settings as ``Toolkit(...)``. Settings left out return to their defaults.
    Returns the default toolkit."""
    _DEFAULT._configure(**settings)
    return _DEFAULT


def default_toolkit() -> Toolkit:
    """The toolkit behind the module-level ``secured_tool``."""
    return _DEFAULT


secured_tool = _DEFAULT.secured_tool
