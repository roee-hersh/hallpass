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

# While the port from Go is in progress, a name whose package does not
# exist yet is skipped. Removed once every integration is ported.
_PORT_IN_PROGRESS = True


def registry() -> Registry:
    """A registry with every integration."""
    r = Registry()
    for name in NAMES:
        mod_name = f"hallpass.integrations.{name}"
        try:
            mod = importlib.import_module(mod_name)
        except ModuleNotFoundError as e:
            if _PORT_IN_PROGRESS and e.name == mod_name:
                continue
            raise
        r.register(mod.INTEGRATION)
    return r
