"""Every integration, registered in one place, so a build without an
integration is one deleted line."""

from __future__ import annotations

import importlib

from hallpass.core.integration import Registry

__all__ = ["NAMES", "registry"]

# Registration order. Each name is a package (or module) under
# hallpass.integrations exposing INTEGRATION.
NAMES = (
    "fake",
    "kubernetes",
    "argocd",
    "aws",
    "github",
    "gitlab",
    "bitbucket",
    "jira",
    "confluence",
    "slack",
    "salesforce",
    "microsoft365",
    "googleworkspace",
    "snowflake",
    "vault",
    "azure",
    "linear",
    "zendesk",
    "datadog",
    "pagerduty",
    "databricks",
    "googlecloud",
)

def registry() -> Registry:
    """A registry with every integration."""
    r = Registry()
    for name in NAMES:
        mod_name = f"hallpass.integrations.{name}"
        r.register(importlib.import_module(mod_name).INTEGRATION)
    return r
