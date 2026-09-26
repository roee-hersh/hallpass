"""The zendesk integration: what a team member may do in one Zendesk Support account."""

from __future__ import annotations

from hallpass.integrations.zendesk.zendesk import Zendesk, ZendeskConnection

__all__ = ["INTEGRATION", "Zendesk", "ZendeskConnection"]

INTEGRATION = Zendesk()
