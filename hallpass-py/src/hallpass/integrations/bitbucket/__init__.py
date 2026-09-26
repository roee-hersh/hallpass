"""Checks repository, project and workspace permissions in Bitbucket Cloud
and Bitbucket Data Center.

Cloud: hallpass finds the user among the workspace's members by email,
reads the user's effective repository permission (the highest of direct,
group and project grants, as Bitbucket computes it), the explicit project
permission, the workspace role, and for @branch questions the branch
restrictions. Data Center: hallpass finds the user by email, lists the
groups the user belongs to, and combines the direct, group, project,
project-default, public and global grants into the effective level, then
the ref restrictions for @branch questions. Every call is a read with
hallpass's own token; nothing is written.

A port of internal/integrations/bitbucket.
"""

from __future__ import annotations

from hallpass.core.catalog import Action
from hallpass.core.context import Context
from hallpass.core.decision import Code, Decision, denied, errorf, wrap_error
from hallpass.core.errors import go_lower, go_quote, go_trim_space
from hallpass.core.integration import (
    CheckRequest,
    Connection,
    Deps,
    Field,
    Identity,
    Integration,
    ProbeResult,
    Settings,
    User,
    credential_field,
    url_field,
)
from hallpass.core.template import is_email
from hallpass.integrations.bitbucket.actions import catalog_actions, parse_target, valid_slug
from hallpass.integrations.bitbucket.cloud import CloudMixin
from hallpass.integrations.bitbucket.common import EDITION_CLOUD, EDITION_DATA_CENTER, classify
from hallpass.integrations.bitbucket.datacenter import DataCenterMixin
from hallpass.net import httpx

__all__ = ["INTEGRATION", "Bitbucket", "BitbucketConnection", "classify"]

AUTH_BEARER = "bearer"
AUTH_BASIC = "basic"

DEFAULT_CLOUD_URL = "https://api.bitbucket.org"


def validate_slug(v: str) -> None:
    if v == "" or valid_slug(v):
        return
    raise ValueError("must be a workspace slug")


class Bitbucket(Integration):
    """The bitbucket product."""

    def name(self) -> str:
        return "bitbucket"

    def fields(self) -> list[Field]:
        return [
            Field(
                name="edition",
                default=EDITION_CLOUD,
                enum=(EDITION_CLOUD, EDITION_DATA_CENTER),
                description="cloud: bitbucket.org; datacenter: a self-hosted Bitbucket Data Center or Server",
            ),
            url_field(False, "Data Center base URL (required there); Cloud default https://api.bitbucket.org"),
            Field(
                name="workspace",
                validate=validate_slug,
                description="cloud: the workspace slug every resource belongs to; identities are resolved among its members",
            ),
            Field(
                name="auth_mode",
                default=AUTH_BEARER,
                enum=(AUTH_BEARER, AUTH_BASIC),
                description="bearer: a workspace access token (Cloud) or HTTP access token (Data Center); basic: an Atlassian API token with username (Cloud)",
            ),
            Field(name="username", description="auth_mode basic: the Atlassian account email the API token belongs to"),
            credential_field(True, "the token"),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network."""
        hc = d.http_client(s)
        if s.secret("credential").is_zero():
            raise ValueError("credential is required")
        edition = s.get("edition") or EDITION_CLOUD
        base = s.get("url").rstrip("/")
        workspace = s.get("workspace")
        if edition == EDITION_CLOUD:
            if base == "":
                base = DEFAULT_CLOUD_URL
            if not valid_slug(workspace):
                raise ValueError("workspace is required for edition cloud and must be a workspace slug")
        elif edition == EDITION_DATA_CENTER:
            if base == "":
                raise ValueError("url is required for edition datacenter")
            if workspace != "":
                raise ValueError("workspace applies to edition cloud only")
        else:
            raise ValueError(f"edition {go_quote(edition)} must be cloud or datacenter")
        cred = s.secret("credential")

        def token(_ctx: Context) -> str:
            try:
                t = cred.get_string()
            except Exception as e:  # noqa: BLE001 - Go: any error reading the secret
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the token could not be read")
            return go_trim_space(t)

        client = httpx.Client(http=hc, base=base, logger=d.logger)
        mode = s.get("auth_mode")
        if mode in ("", AUTH_BEARER):
            client.auth = httpx.bearer_auth(token)
        elif mode == AUTH_BASIC:
            user = s.get("username")
            if user == "":
                raise ValueError("username is required in auth_mode basic")
            client.auth = httpx.basic_auth(user, token)
        else:
            raise ValueError(f"auth_mode {go_quote(mode)} must be bearer or basic")
        return BitbucketConnection(s, edition, workspace, client)


class BitbucketConnection(CloudMixin, DataCenterMixin, Connection):
    """One Cloud workspace or one Data Center instance."""

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Map the email to an account: a workspace member's Atlassian
        account id on Cloud, a user name on Data Center."""
        email = go_lower(go_trim_space(u.email))
        if not is_email(email):
            raise errorf(Code.INVALID_REQUEST, f"user email {go_quote(email)} is not an address")
        if self.data_center():
            return self.dc_identity(ctx, email)
        return self.cloud_identity(ctx, email)

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Answer one question."""
        t = parse_target(r.action_name, r.resource, self.data_center())
        if r.identity.attr("active") == "false":
            return denied(f"{r.identity.display} is deactivated")
        if self.data_center():
            return self.dc_check(ctx, t, r.identity)
        return self.cloud_check(ctx, t, r.identity)

    def probe(self, ctx: Context) -> ProbeResult:
        """Verify the token."""
        if self.data_center():
            return self.dc_probe(ctx)
        return self.cloud_probe(ctx)


INTEGRATION = Bitbucket()
