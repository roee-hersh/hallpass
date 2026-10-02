"""The googlecloud integration: Google Cloud IAM permissions through the
Policy Troubleshooter API."""

from __future__ import annotations

from toolpass.integrations.googlecloud.googlecloud import GoogleCloud, GoogleCloudConnection

__all__ = ["INTEGRATION", "GoogleCloud", "GoogleCloudConnection"]

INTEGRATION = GoogleCloud()
