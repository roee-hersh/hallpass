"""securetools: secure-by-default tools for AI agents, under any framework.

    from securetools import Toolkit, Session, ApprovalQueue

    tools = Toolkit(approver=ApprovalQueue(), credentials={"github-bot": token}, limits={"destructive": 3})

    @tools.tool(effect="write", scope={"repo": "acme/gitops-*"}, approve=True, credential="github-bot")
    def open_pr(repo: str, title: str, *, credential: str) -> str: ...

    with Session("dana@example.com").active():
        agent.run(prompt)

See ``Toolkit`` for the order of checks around every call.
"""

from securetools._approval import ApprovalQueue, ApprovalRequest, Approver, approve_all
from securetools._audit import AuditEvent, AuditSink, log_audit
from securetools._checks import ScopeRule, Validator
from securetools._hallpass import hallpass_check
from securetools._session import Session, current_session
from securetools._toolkit import (
    EFFECTS,
    ApprovalPending,
    AuthDecision,
    Authorizer,
    Call,
    CredentialSource,
    Effect,
    Toolkit,
    ToolRefused,
    ToolSpec,
    fence,
    spec_of,
)

__version__ = "0.1.0.dev0"

__all__ = [
    "EFFECTS",
    "ApprovalPending",
    "ApprovalQueue",
    "ApprovalRequest",
    "Approver",
    "AuditEvent",
    "AuditSink",
    "AuthDecision",
    "Authorizer",
    "Call",
    "CredentialSource",
    "Effect",
    "ScopeRule",
    "Session",
    "ToolRefused",
    "ToolSpec",
    "Toolkit",
    "Validator",
    "__version__",
    "approve_all",
    "current_session",
    "fence",
    "hallpass_check",
    "log_audit",
    "spec_of",
]
