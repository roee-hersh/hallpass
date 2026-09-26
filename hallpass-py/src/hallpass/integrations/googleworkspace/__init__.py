"""The googleworkspace integration: Directory, Drive, Calendar, Gmail and
Groups facts through the Google Workspace APIs."""

from __future__ import annotations

from hallpass.integrations.googleworkspace.googleworkspace import GoogleWorkspace, GoogleWorkspaceConnection

__all__ = ["INTEGRATION", "GoogleWorkspace", "GoogleWorkspaceConnection"]

INTEGRATION = GoogleWorkspace()
