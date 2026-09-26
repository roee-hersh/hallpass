"""The pagerduty integration: what a user may do in one PagerDuty account."""

from __future__ import annotations

from hallpass.integrations.pagerduty.pagerduty import PagerDuty, PagerDutyConnection

__all__ = ["INTEGRATION", "PagerDuty", "PagerDutyConnection"]

INTEGRATION = PagerDuty()
