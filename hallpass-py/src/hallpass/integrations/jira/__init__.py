"""The jira integration: Jira Cloud permissions through the permissions/check
API. The package also holds the Atlassian Cloud transport (site.Site) that
the confluence integration shares.

The API gateway and token endpoint are the module attributes
hallpass.integrations.jira.site.GATEWAY and TOKEN_URL, read when a
connection is built.
"""

from __future__ import annotations

from hallpass.integrations.jira.jira import Jira, JiraConnection
from hallpass.integrations.jira.site import MODE_BASIC, MODE_OAUTH_CLIENT, MODE_SCOPED_TOKEN, Site, new_site, site_fields

__all__ = [
    "INTEGRATION",
    "MODE_BASIC",
    "MODE_OAUTH_CLIENT",
    "MODE_SCOPED_TOKEN",
    "Jira",
    "JiraConnection",
    "Site",
    "new_site",
    "site_fields",
]

INTEGRATION = Jira()
