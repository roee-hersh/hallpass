"""Linear: team, issue and project visibility and workspace roles, read
through the GraphQL API (Go: v0.5.0:internal/integrations/linear)."""

from __future__ import annotations

from toolpass.integrations.linear.linear import DEFAULT_URL, Linear, LinearConnection

__all__ = ["DEFAULT_URL", "INTEGRATION", "Linear", "LinearConnection"]

INTEGRATION = Linear()
