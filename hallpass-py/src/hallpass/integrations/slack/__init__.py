"""Slack: users, channels and user groups, read through the Web API with a
bot token (Go: internal/integrations/slack)."""

from __future__ import annotations

from hallpass.integrations.slack.slack import DEFAULT_URL, Slack, SlackConnection

__all__ = ["DEFAULT_URL", "INTEGRATION", "Slack", "SlackConnection"]

INTEGRATION = Slack()
