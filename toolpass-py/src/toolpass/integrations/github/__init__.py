"""The github integration: repository, organization and team permissions
in one GitHub organization, read as a GitHub App."""

from __future__ import annotations

from toolpass.integrations.github.github import GitHub, GitHubConnection

__all__ = ["INTEGRATION", "GitHub", "GitHubConnection"]

INTEGRATION = GitHub()
