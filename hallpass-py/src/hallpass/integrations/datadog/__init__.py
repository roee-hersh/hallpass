"""The datadog integration: what a user may do in one Datadog organization."""

from __future__ import annotations

from hallpass.integrations.datadog.datadog import Datadog, DatadogConnection

__all__ = ["INTEGRATION", "Datadog", "DatadogConnection"]

INTEGRATION = Datadog()
