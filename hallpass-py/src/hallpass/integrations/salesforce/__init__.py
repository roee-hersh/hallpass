"""The salesforce integration: record, object, field and system permissions
through the Salesforce REST API."""

from __future__ import annotations

from hallpass.integrations.salesforce.salesforce import Salesforce, SalesforceConnection

__all__ = ["INTEGRATION", "Integration", "Salesforce", "SalesforceConnection"]

# Go: salesforce.Integration.
Integration = Salesforce

INTEGRATION = Salesforce()
