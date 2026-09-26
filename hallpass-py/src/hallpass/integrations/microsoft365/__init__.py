"""The microsoft365 integration: Entra ID, Teams, OneDrive/SharePoint and
Exchange facts through Microsoft Graph."""

from __future__ import annotations

from hallpass.integrations.microsoft365.microsoft365 import Microsoft365, Microsoft365Connection

__all__ = ["INTEGRATION", "Microsoft365", "Microsoft365Connection"]

INTEGRATION = Microsoft365()
