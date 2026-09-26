"""The databricks integration: permissions in one Databricks workspace."""

from __future__ import annotations

from hallpass.integrations.databricks.databricks import Databricks, DatabricksConnection

__all__ = ["INTEGRATION", "Databricks", "DatabricksConnection"]

INTEGRATION = Databricks()
