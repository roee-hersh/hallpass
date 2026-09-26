"""The snowflake integration: what a user may do in a Snowflake account."""

from __future__ import annotations

from hallpass.integrations.snowflake.snowflake import Snowflake, SnowflakeConnection

__all__ = ["INTEGRATION", "Integration", "Snowflake", "SnowflakeConnection"]

# Go: snowflake.Integration.
Integration = Snowflake

INTEGRATION = Snowflake()
