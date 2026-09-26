"""The confluence integration: Confluence Cloud page, blog post and space
permissions, with users resolved by email through a jira connection on the
same Atlassian site."""

from __future__ import annotations

from hallpass.integrations.confluence.confluence import Confluence, ConfluenceConnection

__all__ = ["INTEGRATION", "Confluence", "ConfluenceConnection"]

INTEGRATION = Confluence()
