"""Slack users, channels and user groups, read with a bot token through the
Slack Web API (Go: slack/slack.go).

hallpass resolves the caller's email with users.lookupByEmail, reads the
channel with conversations.info, checks membership with users.conversations
(falling back to conversations.members for users in very many channels) and
reads #general's posting rule with team.preferences.list and user group
membership with usergroups.list. The probe also lists public channels with
conversations.list to find #general. Every call is a read; nothing is
posted, joined or changed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from hallpass.core import jsonx
from hallpass.core.catalog import Action
from hallpass.core.context import Context
from hallpass.core.decision import (
    Code,
    Decision,
    HallpassError,
    allowed,
    denied,
    errorf,
    unknown_decision,
    unsupported,
    user_not_found,
    wrap_error,
)
from hallpass.core.errors import as_error, go_lower, go_quote, go_trim_space
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
    validate_https_url,
)
from hallpass.core.secret import Secret, SecretError
from hallpass.integrations.slack.actions import catalog_actions, validate_resource
from hallpass.net import httpx

# The Slack Web API base.
DEFAULT_URL = "https://slack.com/api"

# What a bot token starts with. hallpass refuses user (xoxp) and app-level
# (xapp) tokens so a check never runs as a person.
TOKEN_PREFIX = "xoxb-"

# Scopes the bot token needs.
REQUIRED_SCOPES = ("users:read", "users:read.email", "channels:read", "groups:read")
OPTIONAL_SCOPES = {
    "team.preferences:read": "message.post in #general answers unknown",
    "usergroups:read": "usergroup.member answers unknown",
}

TEAM_ID_RE = re.compile(r"[TE][A-Z0-9]{6,}")


class Slack(Integration):
    """The slack product."""

    def name(self) -> str:
        return "slack"

    def fields(self) -> list[Field]:
        return [
            credential_field(True, "bot token (xoxb-...) of an internal app with the read scopes listed in the docs"),
            Field(
                name="url",
                default=DEFAULT_URL,
                validate=validate_https_url,
                description="Slack Web API base URL, default " + DEFAULT_URL,
            ),
            Field(
                name="team_id",
                validate=validate_team_id,
                description="workspace id (T...) to address with an Enterprise Grid org-level install; sent as team_id on every call",
            ),
            Field(
                name="assume_default_prefs",
                default="false",
                enum=("true", "false"),
                description="treat workspace preferences the bot cannot read as Slack's defaults instead of answering unknown",
            ),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It does not touch the network."""
        hc = d.http_client(s)
        cred = s.secret("credential")
        if cred.is_zero():
            raise ValueError("credential is required")
        base = s.get("url")
        if base == "":
            base = DEFAULT_URL
        c = SlackConnection(team_id=s.get("team_id"), assume_defaults=s.bool("assume_default_prefs", False))
        c.client = httpx.Client(http=hc, base=base, logger=d.logger, retries=1, auth=httpx.bearer_auth(bot_token(cred)))
        return c


def validate_team_id(v: str) -> None:
    if v == "":
        return
    if not TEAM_ID_RE.fullmatch(v):
        raise ValueError(f"team_id {go_quote(v)} must be a Slack workspace id such as T0123456789")


def bot_token(cred: Secret) -> Callable[[Context], str]:
    """Read the credential at call time and refuse anything that is not a
    bot token. The error names neither the token nor its prefix."""

    def token(ctx: Context) -> str:
        try:
            tok = cred.get_string()
        except SecretError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the connection's credential could not be read") from e
        if not tok.startswith(TOKEN_PREFIX):
            raise errorf(Code.CREDENTIAL_REJECTED, f"the connection's credential is not a Slack bot token (it must start with {TOKEN_PREFIX})")
        return tok

    return token


class APIError(Exception):
    """An HTTP 200 response with ok:false."""

    def __init__(self, method: str, code: str, needed: str = "") -> None:
        self.method = method
        self.code = code
        self.needed = needed  # the scope named by missing_scope
        super().__init__(str(self))

    def __str__(self) -> str:
        return "slack " + self.method + ": " + self.code


def api_code(err: BaseException | None) -> str:
    """The Slack error code carried by err, or ""."""
    ae = as_error(err, APIError)
    return ae.code if ae is not None else ""


@dataclass
class Result:
    """What call returns besides the decoded body."""

    header: httpx.Headers
    next_cursor: str


def classify(err: BaseException | None) -> HallpassError | None:
    """An ok:false error or a transport error as a HallpassError."""
    if err is None:
        return None
    ae = as_error(err, APIError)
    if ae is None:
        return httpx.classify(err)
    code = ae.code
    if code in ("invalid_auth", "not_authed", "account_inactive", "token_revoked", "token_expired"):
        return wrap_error(Code.CREDENTIAL_REJECTED, err, f"Slack rejected the connection's bot token ({code})")
    if code == "missing_scope":
        scope = ae.needed or "a required"
        return wrap_error(Code.CREDENTIAL_REJECTED, err, f"the bot token lacks the {scope} scope that {ae.method} needs")
    if code == "ratelimited":
        return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, "rate limited by Slack")
    if code in ("users_not_found", "user_not_found"):
        return wrap_error(Code.USER_NOT_FOUND, err, "no Slack account matches the user")
    if code == "channel_not_found":
        return wrap_error(
            Code.RESOURCE_NOT_VISIBLE,
            err,
            "the channel does not exist or is a private channel the bot is not in; invite the bot to the channel",
        )
    if code == "not_in_channel":
        return wrap_error(Code.RESOURCE_NOT_VISIBLE, err, "the bot is not a member of the channel; invite the bot to the channel")
    return wrap_error(Code.UPSTREAM_ERROR, err, f"Slack {ae.method} returned error {code}")


# -- decoding (Go decodes into typed structs: a wrong type is an error) -------


# The member for a key the way Go's decoder finds a struct field: an exact
# match, else a case-insensitive one. None for a missing key or null.
member = jsonx._get


def raw(d: dict[str, Any], key: str) -> str:
    """A json.RawMessage field: the value's JSON text, "" when absent. (Go
    holds "null" for a null value; both parse to no posting rule.)"""
    v = member(d, key)
    if v is None:
        return ""
    return json.dumps(v)


@dataclass(frozen=True)
class Profile:
    email: str = ""
    display_name: str = ""
    real_name: str = ""


@dataclass(frozen=True)
class EnterpriseUser:
    # UNVERIFIED: the enterprise_user field names is_admin / is_owner on
    # Enterprise Grid; hallpass has not seen a Grid user object.
    id: str = ""
    enterprise_id: str = ""
    is_admin: bool = False
    is_owner: bool = False


@dataclass(frozen=True)
class SlackUser:
    """The Web API user object, as far as hallpass reads it."""

    id: str = ""
    team_id: str = ""
    name: str = ""
    real_name: str = ""
    deleted: bool = False
    is_admin: bool = False
    is_owner: bool = False
    is_primary_owner: bool = False
    is_restricted: bool = False
    is_ultra_restricted: bool = False
    is_bot: bool = False
    is_app_user: bool = False
    is_invited_user: bool = False
    is_stranger: bool = False
    profile: Profile = field(default_factory=Profile)
    enterprise_user: EnterpriseUser | None = None


def decode_user(v: Any) -> SlackUser:
    d = jsonx.obj(v, "user")
    p = jsonx.o(d, "profile")
    eu_raw = member(d, "enterprise_user")
    eu = None
    if eu_raw is not None:
        e = jsonx.obj(eu_raw, "enterprise_user")
        eu = EnterpriseUser(jsonx.s(e, "id"), jsonx.s(e, "enterprise_id"), jsonx.b(e, "is_admin"), jsonx.b(e, "is_owner"))
    return SlackUser(
        id=jsonx.s(d, "id"),
        team_id=jsonx.s(d, "team_id"),
        name=jsonx.s(d, "name"),
        real_name=jsonx.s(d, "real_name"),
        deleted=jsonx.b(d, "deleted"),
        is_admin=jsonx.b(d, "is_admin"),
        is_owner=jsonx.b(d, "is_owner"),
        is_primary_owner=jsonx.b(d, "is_primary_owner"),
        is_restricted=jsonx.b(d, "is_restricted"),
        is_ultra_restricted=jsonx.b(d, "is_ultra_restricted"),
        is_bot=jsonx.b(d, "is_bot"),
        is_app_user=jsonx.b(d, "is_app_user"),
        is_invited_user=jsonx.b(d, "is_invited_user"),
        is_stranger=jsonx.b(d, "is_stranger"),
        profile=Profile(jsonx.s(p, "email"), jsonx.s(p, "display_name"), jsonx.s(p, "real_name")),
        enterprise_user=eu,
    )


# Attribute keys on the resolved identity.
ATTR_DELETED = "deleted"
ATTR_BOT = "is_bot"
ATTR_INVITED = "is_invited_user"
ATTR_ADMIN = "is_admin"
ATTR_OWNER = "is_owner"
ATTR_PRIMARY_OWNER = "is_primary_owner"
ATTR_RESTRICTED = "is_restricted"
ATTR_ULTRA_RESTRICTED = "is_ultra_restricted"
ATTR_STRANGER = "is_stranger"
ATTR_TEAM_ID = "team_id"
ATTR_ENTERPRISE_ID = "enterprise_id"
ATTR_ENTERPRISE_ADMIN = "enterprise_admin"
ATTR_ENTERPRISE_OWNER = "enterprise_owner"


def bool_attr(b: bool) -> str:
    return "true" if b else "false"


def inactive(ident: Identity) -> str | None:
    """Why the account cannot act at all, if so."""
    if ident.attr(ATTR_DELETED) == "true":
        return "account deactivated"
    if ident.attr(ATTR_BOT) == "true":
        return "bot account"
    if ident.attr(ATTR_INVITED) == "true":
        return "invited, not yet joined"
    return None


def is_admin(ident: Identity) -> bool:
    return ident.attr(ATTR_ADMIN) == "true" or ident.attr(ATTR_OWNER) == "true" or ident.attr(ATTR_PRIMARY_OWNER) == "true"


def is_owner(ident: Identity) -> bool:
    return ident.attr(ATTR_OWNER) == "true" or ident.attr(ATTR_PRIMARY_OWNER) == "true"


def is_guest(ident: Identity) -> bool:
    return ident.attr(ATTR_RESTRICTED) == "true" or ident.attr(ATTR_ULTRA_RESTRICTED) == "true"


def role(ident: Identity) -> str:
    if ident.attr(ATTR_PRIMARY_OWNER) == "true":
        return "primary owner"
    if ident.attr(ATTR_OWNER) == "true":
        return "owner"
    if ident.attr(ATTR_ADMIN) == "true":
        return "admin"
    if ident.attr(ATTR_ULTRA_RESTRICTED) == "true":
        return "single-channel guest"
    if ident.attr(ATTR_RESTRICTED) == "true":
        return "multi-channel guest"
    return "full member"


@dataclass
class Posters:
    """Slack's "who may post" shape: {"type":["admin"],"user":["U.."]}.

    UNVERIFIED: the shape of who_can_post_general (team.preferences.list) and
    whether conversations.info exposes properties.posting_restricted_to to a
    bot token. Both are read in this shape; a string form is accepted too.
    """

    type: list[str] = field(default_factory=list)
    user: list[str] = field(default_factory=list)

    def allows(self, ident: Identity) -> tuple[bool, str]:
        """Whether the identity is among the posters. An empty rule means
        everyone. When the identity matches nothing and the rule names a type
        hallpass does not model, unknown carries that type: the rule could not
        be evaluated, so the caller answers unsupported rather than deny."""
        return posters_allows(self, ident)

    def __str__(self) -> str:
        return posters_string(self)


def posters_allows(p: Posters | None, ident: Identity) -> tuple[bool, str]:
    if p is None or (not p.type and not p.user):
        return True, ""
    unknown = ""
    for t in p.type:
        if t in ("everyone", "regular", "ra"):
            return True, ""
        if t == "admin":
            if is_admin(ident):
                return True, ""
        elif t == "owner":
            if is_owner(ident):
                return True, ""
        elif unknown == "":
            unknown = t
    for u in p.user:
        if u == ident.id:
            return True, ""
    return False, unknown


def posters_string(p: Posters | None) -> str:
    if p is None or (not p.type and not p.user):
        return "everyone"
    parts = []
    for t in p.type:
        if t == "admin":
            parts.append("admins and owners")
        elif t == "owner":
            parts.append("owners")
        else:
            parts.append(t)
    if p.user:
        parts.append(f"{len(p.user)} named users")
    return " and ".join(parts)


def parse_posters(raw_msg: str | bytes) -> Posters | None:
    """The object form, or a string such as "everyone", "admin" or "owner".
    None for an absent or null value; ValueError for anything else."""
    if isinstance(raw_msg, bytes):
        raw_msg = raw_msg.decode("utf-8", "replace")
    raw_msg = go_trim_space(raw_msg)
    if raw_msg == "" or raw_msg == "null":
        return None
    v = json.loads(raw_msg)
    if raw_msg[0] == '"':
        if not isinstance(v, str):
            raise ValueError("json: cannot unmarshal into string")
        if v in ("", "everyone", "regular", "ra"):  # UNVERIFIED: string values of who_can_post_general
            return Posters()
        if v in ("admin", "owner"):
            return Posters(type=[v])
        raise ValueError(f"unrecognised value {go_quote(v)}")
    d = jsonx.obj(v, "posters")
    return Posters(type=jsonx.strs(d, "type"), user=jsonx.strs(d, "user"))


@dataclass
class Channel:
    """The conversations.info object, as far as hallpass reads it."""

    id: str = ""
    name: str = ""
    is_archived: bool = False
    is_private: bool = False
    is_general: bool = False
    is_member: bool = False  # the bot
    is_ext_shared: bool = False
    is_shared: bool = False
    # None when conversations.info returned no properties object; otherwise
    # the raw posting_restricted_to ("" when the key is absent).
    properties: str | None = None

    def posting_restricted_to(self) -> str:
        """The raw posting_restricted_to property, or "" when the channel
        object carries no properties at all."""
        if self.properties is None:
            return ""
        return self.properties

    def label(self) -> str:
        if self.name != "":
            return "#" + self.name + " (" + self.id + ")"
        return self.id


def decode_channel(v: Any) -> Channel:
    d = jsonx.obj(v, "channel")
    props: str | None = None
    if member(d, "properties") is not None:
        props = raw(jsonx.o(d, "properties"), "posting_restricted_to")
    return Channel(
        id=jsonx.s(d, "id"),
        name=jsonx.s(d, "name"),
        is_archived=jsonx.b(d, "is_archived"),
        is_private=jsonx.b(d, "is_private"),
        is_general=jsonx.b(d, "is_general"),
        is_member=jsonx.b(d, "is_member"),
        is_ext_shared=jsonx.b(d, "is_ext_shared"),
        is_shared=jsonx.b(d, "is_shared"),
        properties=props,
    )


# How many users.conversations pages are read before switching to
# conversations.members.
MEMBERSHIP_PAGES = 5

# Bounds the conversations.list pages the probe reads to find #general,
# which is the workspace's oldest channel and listed early.
GENERAL_LIST_PAGES = 5


class SlackConnection(Connection):
    """One Slack workspace (or one workspace of an Enterprise Grid org-level
    install, selected by team_id)."""

    def __init__(self, team_id: str = "", assume_defaults: bool = False) -> None:
        self.client: httpx.Client = httpx.Client()
        self.team_id = team_id
        self.assume_defaults = assume_defaults

    def call(self, ctx: Context, method: str, q: Mapping[str, str] | None, decode: Callable[[dict[str, Any]], Any] | None = None) -> tuple[Result, Any]:
        """Perform one Web API method as a GET with query parameters (so
        httpx retries apply; every method used here is a read) and decode the
        body with decode when ok is true. team_id is added when configured."""
        query: dict[str, str] = dict(q or {})
        if self.team_id != "":
            query["team_id"] = self.team_id
        resp, _ = self.client.get_json(ctx, method, query, decode=False)
        try:
            body = jsonx.obj(resp.json(), "envelope")
            ok = jsonx.b(body, "ok")
            code = jsonx.s(body, "error")
            needed = jsonx.s(body, "needed")
            next_cursor = jsonx.s(jsonx.o(body, "response_metadata"), "next_cursor")
        except ValueError as e:
            raise ValueError(f"decode {method}: {e}") from e
        if not ok:
            raise APIError(method, code or "unknown_error", needed)
        out = None
        if decode is not None:
            try:
                out = decode(body)
            except ValueError as e:
                raise ValueError(f"decode {method}: {e}") from e
        return Result(resp.header, next_cursor), out

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Look the email up with users.lookupByEmail."""
        try:
            _, usr = self.call(ctx, "users.lookupByEmail", {"email": u.email}, lambda b: decode_user(jsonx.o(b, "user")))
        except Exception as err:  # noqa: BLE001 - Go's error return: every error is classified
            if api_code(err) in ("users_not_found", "user_not_found"):
                raise user_not_found(f"no Slack account for {u.email}") from None
            raise _classified(err)
        if usr.id == "":
            raise wrap_error(Code.UPSTREAM_ERROR, ValueError("users.lookupByEmail returned no user id"), "Slack returned an incomplete user object")
        display = usr.real_name or usr.profile.real_name or usr.name or u.email
        attrs = {
            ATTR_DELETED: bool_attr(usr.deleted),
            ATTR_BOT: bool_attr(usr.is_bot or usr.id == "USLACKBOT"),
            ATTR_INVITED: bool_attr(usr.is_invited_user),
            ATTR_ADMIN: bool_attr(usr.is_admin),
            ATTR_OWNER: bool_attr(usr.is_owner),
            ATTR_PRIMARY_OWNER: bool_attr(usr.is_primary_owner),
            ATTR_RESTRICTED: bool_attr(usr.is_restricted),
            ATTR_ULTRA_RESTRICTED: bool_attr(usr.is_ultra_restricted),
            ATTR_STRANGER: bool_attr(usr.is_stranger),
            ATTR_TEAM_ID: usr.team_id,
        }
        if usr.enterprise_user is not None:
            attrs[ATTR_ENTERPRISE_ID] = usr.enterprise_user.enterprise_id
            attrs[ATTR_ENTERPRISE_ADMIN] = bool_attr(usr.enterprise_user.is_admin)
            attrs[ATTR_ENTERPRISE_OWNER] = bool_attr(usr.enterprise_user.is_owner)
        return Identity(id=usr.id, display=display, attrs=attrs, native=usr)

    def other_workspace(self, ident: Identity) -> bool:
        """Whether, on an Enterprise Grid org-level install addressed with
        team_id, the user object belongs to a different workspace. Slack then
        says nothing about the user's membership of the addressed workspace,
        so rules that rest on "any full member of this workspace" are not
        evaluated.

        UNVERIFIED: on a Grid org-level install, the team_id of the user
        object users.lookupByEmail returns names the user's workspace; a user
        of the addressed workspace is taken to carry the configured team_id.
        """
        return self.team_id != "" and ident.attr(ATTR_TEAM_ID) != "" and ident.attr(ATTR_TEAM_ID) != self.team_id

    # -- reads --

    def channel(self, ctx: Context, id: str) -> Channel:
        try:
            _, ch = self.call(ctx, "conversations.info", {"channel": id}, lambda b: decode_channel(jsonx.o(b, "channel")))
        except Exception as err:
            code = api_code(err)
            if code == "channel_not_found":
                # A private channel the bot is not in answers
                # channel_not_found too, for both C and G ids, so this is
                # never a deny.
                raise wrap_error(
                    Code.RESOURCE_NOT_VISIBLE,
                    err,
                    f"channel {id} does not exist or is a private channel the bot is not in; invite the bot to the channel",
                ) from err
            if code == "not_in_channel":
                raise wrap_error(Code.RESOURCE_NOT_VISIBLE, err, f"the bot is not a member of channel {id}; invite the bot to the channel") from err
            raise _classified(err)
        if ch.id == "":
            ch.id = id
        return ch

    def is_member(self, ctx: Context, user_id: str, channel_id: str) -> bool:
        """Whether the user is in the channel. users.conversations lists the
        user's channels (cost grows with how many the user is in); after
        MEMBERSHIP_PAGES pages without a hit the channel's member list is
        read instead."""
        cursor = ""
        for _ in range(MEMBERSHIP_PAGES):
            q = {"user": user_id, "types": "public_channel,private_channel", "limit": "1000"}
            if cursor != "":
                q["cursor"] = cursor
            try:
                res, ids = self.call(ctx, "users.conversations", q, _decode_channel_ids)
            except Exception as err:  # noqa: BLE001 - Go's error return: every error is classified
                raise _classified(err)
            if channel_id in ids:
                return True
            cursor = res.next_cursor
            if cursor == "":
                return False
        cursor = ""
        for _ in range(httpx.MAX_PAGES):
            q = {"channel": channel_id, "limit": "1000"}
            if cursor != "":
                q["cursor"] = cursor
            try:
                res, members = self.call(ctx, "conversations.members", q, lambda b: jsonx.strs(b, "members"))
            except Exception as err:  # noqa: BLE001 - Go's error return: every error is classified
                raise _classified(err)
            if user_id in members:
                return True
            cursor = res.next_cursor
            if cursor == "":
                return False
        raise errorf(Code.UNSUPPORTED, f"channel {channel_id} has more members than hallpass will list")

    def general_posters(self, ctx: Context) -> Posters:
        """Who may post in #general."""
        try:
            _, raw_msg = self.call(ctx, "team.preferences.list", None, lambda b: raw(b, "who_can_post_general"))
        except Exception as err:  # noqa: BLE001 - Go's error return: every error is classified
            if api_code(err) == "missing_scope" and self.assume_defaults:
                return Posters()
            raise _classified(err)
        try:
            p = parse_posters(raw_msg)
        except ValueError:
            raise errorf(Code.UNSUPPORTED, "who_can_post_general has a shape hallpass does not understand") from None
        if p is None:
            if self.assume_defaults:
                return Posters()
            raise errorf(
                Code.UNSUPPORTED,
                "team.preferences.list did not report who_can_post_general; set assume_default_prefs: true to assume everyone may post",
            )
        return p

    def usergroup_members(self, ctx: Context, id: str) -> tuple[list[str], str, bool]:
        """The member ids and handle of one user group, found=False when the
        group is not listed (unknown id, or a disabled group)."""
        try:
            _, groups = self.call(ctx, "usergroups.list", {"include_users": "true"}, _decode_usergroups)
        except Exception as err:  # noqa: BLE001 - Go's error return: every error is classified
            raise _classified(err)
        for gid, handle, users in groups:
            if gid == id:
                return users, handle, True
        return [], "", False

    # -- checks --

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Answer one action."""
        try:
            a = validate_resource(r.action_name, r.resource)
        except ValueError as e:
            raise errorf(Code.INVALID_REQUEST, str(e)) from None
        ident = r.identity
        reason = inactive(ident)
        if reason is not None:
            return denied(f"{ident.display} ({ident.id}): {reason}")
        name = a.name
        if name == "user.active":
            return allowed(f"{ident.display} ({ident.id}) is an active {role(ident)}")
        if name == "workspace.admin":
            if is_admin(ident):
                return allowed(f"{ident.display} is a workspace {role(ident)}")
            return denied(f"{ident.display} is a {role(ident)}, not a workspace admin or owner")
        if name == "org.admin":
            if ident.attr(ATTR_ENTERPRISE_ADMIN) == "":
                return unsupported("the user object has no enterprise_user field; this is not an Enterprise Grid workspace, or the bot cannot see org roles")
            if ident.attr(ATTR_ENTERPRISE_ADMIN) == "true" or ident.attr(ATTR_ENTERPRISE_OWNER) == "true":
                return allowed(f"{ident.display} is an org admin or owner")
            return denied(f"{ident.display} is not an org admin or owner")
        if name == "channel.create":
            return self.pref_gate(ident, "create channels")
        if name == "usergroup.member":
            return self.check_usergroup(ctx, ident, r.resource.id)

        # Channel actions.
        if ident.attr(ATTR_STRANGER) == "true":
            return unsupported(
                f"{ident.display} is an external (Slack Connect) user; channel permissions in this workspace are not evaluated for external users"
            )
        ch = self.channel(ctx, r.resource.id)
        if name == "channel.read":
            return self.check_read(ctx, ident, ch)
        if name == "channel.join":
            return self.check_join(ctx, ident, ch)
        if name in ("message.post", "file.upload"):
            return self.check_post(ctx, ident, ch, False)
        if name == "message.post_thread":
            return self.check_post(ctx, ident, ch, True)
        if name == "channel.invite":
            if ch.is_archived:
                return denied(f"{ch.label()} is archived; nobody can be invited")
            return self.member_pref_gate(ctx, ident, ch, "invite members to channels")
        if name == "channel.rename":
            if ch.is_archived:
                return denied(f"{ch.label()} is archived and cannot be renamed")
            return self.member_pref_gate(ctx, ident, ch, "rename channels")
        if name == "channel.archive":
            if ch.is_archived:
                return denied(f"{ch.label()} is already archived")
            if ch.is_general:
                return denied(f"{ch.label()} is the workspace's general channel and cannot be archived")
            return self.member_pref_gate(ctx, ident, ch, "archive channels")
        raise RuntimeError("unreachable: unknown action")

    def member_pref_gate(self, ctx: Context, ident: Identity, ch: Channel, verb: str) -> Decision:
        """The channel-scoped actions a workspace preference governs (invite,
        rename, archive). They all act from inside the channel, so membership
        is checked first: a non-member of a private channel is refused
        outright, a guest cannot join on their own, and anyone else could join
        a public channel first, which hallpass does not assume. Members go
        through pref_gate."""
        if not self.is_member(ctx, ident.id, ch.id):
            if ch.is_private:
                return denied(f"{ch.label()} is private and {ident.display} is not a member")
            if is_guest(ident):
                return denied(f"{ident.display} is a {role(ident)} and not a member of {ch.label()}")
            return unsupported(f"{ident.display} is not a member of {ch.label()}; joining first is possible, but the action needs membership")
        return self.pref_gate(ident, verb)

    def check_usergroup(self, ctx: Context, ident: Identity, group_id: str) -> Decision:
        members, handle, found = self.usergroup_members(ctx, group_id)
        if not found:
            return unknown_decision(
                Code.RESOURCE_NOT_VISIBLE,
                f"user group {group_id} is not listed for this workspace; it does not exist or is disabled",
            )
        label = group_id
        if handle != "":
            label = "@" + handle + " (" + group_id + ")"
        if ident.id in members:
            return allowed(f"{ident.display} is a member of user group {label}")
        return denied(f"{ident.display} is not a member of user group {label}")

    def check_read(self, ctx: Context, ident: Identity, ch: Channel) -> Decision:
        archived = " (archived; still readable)" if ch.is_archived else ""
        if ch.is_private or is_guest(ident):
            if self.is_member(ctx, ident.id, ch.id):
                return allowed(f"{ident.display} is a member of {ch.label()}{archived}")
            if ch.is_private:
                return denied(f"{ch.label()} is private and {ident.display} is not a member")
            return denied(f"{ident.display} is a {role(ident)} and not a member of {ch.label()}")
        if self.other_workspace(ident):
            return unsupported(
                f"{ident.display} belongs to another workspace of the organization; "
                f"whether they are a member of the workspace that owns {ch.label()} is not visible"
            )
        return allowed(f"{ch.label()} is public{archived}; any full member may read it")

    def check_join(self, ctx: Context, ident: Identity, ch: Channel) -> Decision:
        if ch.is_archived:
            return denied(f"{ch.label()} is archived and cannot be joined")
        if ch.is_private or is_guest(ident):
            if self.is_member(ctx, ident.id, ch.id):
                return allowed(f"{ident.display} is already a member of {ch.label()}")
            if ch.is_private:
                return denied(f"{ch.label()} is private; {ident.display} must be invited")
            return denied(f"{ident.display} is a {role(ident)} and cannot join channels on their own")
        if self.other_workspace(ident):
            return unsupported(
                f"{ident.display} belongs to another workspace of the organization; "
                f"whether they are a member of the workspace that owns {ch.label()} is not visible"
            )
        return allowed(f"{ch.label()} is public; any full member may join it")

    def check_post(self, ctx: Context, ident: Identity, ch: Channel, thread: bool) -> Decision:
        if ch.is_archived:
            return denied(f"{ch.label()} is archived")
        if not self.is_member(ctx, ident.id, ch.id):
            if ch.is_private:
                return denied(f"{ch.label()} is private and {ident.display} is not a member")
            if is_guest(ident):
                return denied(f"{ident.display} is a {role(ident)} and not a member of {ch.label()}")
            return denied(f"{ident.display} is not a member of {ch.label()}; joining is possible for a full member, but posting needs membership first")
        if ch.is_general:
            p = self.general_posters(ctx)
            ok, unknown = p.allows(ident)
            if not ok:
                if unknown != "":
                    return unsupported(f"who_can_post_general names a poster type {go_quote(unknown)} hallpass does not understand")
                return denied(f"posting in {ch.label()} is restricted to {p} and {ident.display} is a {role(ident)}")
        try:
            restricted = parse_posters(ch.posting_restricted_to())
        except ValueError:
            return unsupported(f"{ch.label()} has a posting restriction in a shape hallpass does not understand")
        if restricted is None:
            # UNVERIFIED: whether a bot token sees properties.posting_restricted_to,
            # and whether Slack omits it for an unrestricted channel. An absent
            # property is therefore not taken as "unrestricted" unless the
            # connection opts in with assume_default_prefs.
            if self.assume_defaults:
                return allowed(
                    f"{ident.display} is a member of {ch.label()}; no posting restriction is visible to the bot "
                    "and assume_default_prefs treats the channel as unrestricted"
                )
            return unsupported(
                f"posting restrictions of {ch.label()} are not visible to the bot (no posting_restricted_to property); "
                "set assume_default_prefs: true to treat the channel as unrestricted"
            )
        if is_admin(ident):
            return allowed(f"{ident.display} is a member of {ch.label()}")
        ok, unknown = restricted.allows(ident)
        if ok:
            return allowed(f"{ident.display} is a member of {ch.label()}")
        if thread:
            # UNVERIFIED: posting_restricted_to is taken to limit top-level
            # posts only, not thread replies.
            return allowed(f"{ident.display} is a member of {ch.label()}; top-level posting is restricted to {restricted} but thread replies are not")
        if unknown != "":
            return unsupported(f"the posting restriction of {ch.label()} names a poster type {go_quote(unknown)} hallpass does not understand")
        return denied(f"posting in {ch.label()} is restricted to {restricted} and {ident.display} is a {role(ident)}")

    def pref_gate(self, ident: Identity, verb: str) -> Decision:
        """The actions governed by a workspace preference a bot token cannot
        read: guests may not, admins and owners may, and for everyone else the
        answer is unknown unless assume_default_prefs is set."""
        if is_guest(ident):
            return denied(f"{ident.display} is a {role(ident)}; guests may not {verb}")
        if is_admin(ident):
            return allowed(f"{ident.display} is a workspace {role(ident)}")
        if self.assume_defaults:
            # UNVERIFIED: Slack's default for each of these preferences is "everyone".
            return allowed(
                f"{ident.display} is a full member and assume_default_prefs treats the workspace preference 'who can {verb}' as Slack's default (everyone)"
            )
        return unsupported(f"the workspace preference 'who can {verb}' is not readable by a bot token; {ident.display} is a full member")

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Verify the token with auth.test and the users:read.email scope with
        a lookup that cannot match, and warn about missing optional scopes and
        any write scope the token carries."""
        try:
            res, auth = self.call(ctx, "auth.test", None, _decode_auth)
        except Exception as err:  # noqa: BLE001 - Go's error return: every error is classified
            raise _classified(err)
        user_id, bot_id, team, _team_id, enterprise = auth
        summary = f"authenticated as bot user {user_id} in workspace {team}"
        warnings: list[str] = []
        if bot_id != "":
            summary += " (bot " + bot_id + ")"
        if enterprise and self.team_id == "":
            warnings.append("the token is an Enterprise Grid org-level install but team_id is not set; set it to the workspace to check")
        # UNVERIFIED: whether Slack sends X-OAuth-Scopes on Web API responses.
        scopes = res.header.get("X-OAuth-Scopes")
        if scopes != "":
            warnings.extend(scope_warnings(scopes))

        try:
            self.call(ctx, "users.lookupByEmail", {"email": "hallpass-probe-does-not-exist@example.invalid"})
        except Exception as err:  # noqa: BLE001 - Go's error return: every error is classified
            code = api_code(err)
            if code in ("users_not_found", "user_not_found"):
                pass
            elif code == "missing_scope":
                warnings.append("the token lacks users:read.email; every check will answer credential_rejected")
            else:
                raise _classified(err)

        for method, scope in (("team.preferences.list", "team.preferences:read"), ("usergroups.list", "usergroups:read")):
            try:
                self.call(ctx, method, None)
            except Exception as err:  # noqa: BLE001 - Go's error return: every error is classified
                if api_code(err) == "missing_scope":
                    warnings.append(f"the token lacks the optional scope {scope}; {OPTIONAL_SCOPES[scope]}")
                    continue
                raise _classified(err)

        # Whether the bot sees channel properties at all, read off #general.
        gen_id = self.general_channel_id(ctx)
        if gen_id == "":
            warnings.append(
                f"#general was not found among the first {GENERAL_LIST_PAGES} pages of public channels; "
                "whether channel properties are visible to the bot was not checked"
            )
            return ProbeResult(summary=summary, warnings=tuple(warnings))
        gen = self.channel(ctx, gen_id)
        if gen.properties is not None:
            summary += "; channel properties visible"
        else:
            warnings.append(
                f"conversations.info on #general ({gen_id}) returned no properties object; message.post answers unknown "
                "for channels without a visible posting_restricted_to unless assume_default_prefs is set"
            )
        return ProbeResult(summary=summary, warnings=tuple(warnings))

    def general_channel_id(self, ctx: Context) -> str:
        """The workspace's general channel from conversations.list; "" when
        it is not among the first pages."""
        cursor = ""
        for _ in range(GENERAL_LIST_PAGES):
            q = {"types": "public_channel", "exclude_archived": "true", "limit": "200"}
            if cursor != "":
                q["cursor"] = cursor
            try:
                res, chans = self.call(ctx, "conversations.list", q, _decode_general_list)
            except Exception as err:  # noqa: BLE001 - Go's error return: every error is classified
                raise _classified(err)
            for cid, general in chans:
                if general and cid != "":
                    return cid
            cursor = res.next_cursor
            if cursor == "":
                return ""
        return ""


def _classified(err: BaseException) -> HallpassError:
    he = classify(err)
    assert he is not None
    return he


def _decode_channel_ids(b: dict[str, Any]) -> list[str]:
    return [jsonx.s(jsonx.obj(c, "channel"), "id") for c in jsonx.arr(b, "channels")]


def _decode_usergroups(b: dict[str, Any]) -> list[tuple[str, str, list[str]]]:
    out = []
    for g in jsonx.arr(b, "usergroups"):
        g = jsonx.obj(g, "usergroup")
        out.append((jsonx.s(g, "id"), jsonx.s(g, "handle"), jsonx.strs(g, "users")))
    return out


def _decode_general_list(b: dict[str, Any]) -> list[tuple[str, bool]]:
    out = []
    for c in jsonx.arr(b, "channels"):
        c = jsonx.obj(c, "channel")
        out.append((jsonx.s(c, "id"), jsonx.b(c, "is_general")))
    return out


def _decode_auth(b: dict[str, Any]) -> tuple[str, str, str, str, bool]:
    return (jsonx.s(b, "user_id"), jsonx.s(b, "bot_id"), jsonx.s(b, "team"), jsonx.s(b, "team_id"), jsonx.b(b, "is_enterprise_install"))


def scope_warnings(header: str) -> list[str]:
    """Warnings from a comma-separated scope list."""
    have: set[str] = set()
    writes: list[str] = []
    for s in header.split(","):
        s = go_trim_space(s)
        if s == "":
            continue
        have.add(s)
        if is_write_scope(s):
            writes.append(s)
    out: list[str] = []
    if writes:
        out.append("the token carries write scopes it does not need: " + ", ".join(writes))
    missing = [s for s in REQUIRED_SCOPES if s not in have]
    if missing:
        out.append("the token lacks required scopes: " + ", ".join(missing))
    return out


def is_write_scope(s: str) -> bool:
    s = go_lower(s)
    if s.startswith("admin"):
        return True
    if ":write" in s or ":manage" in s:
        return True
    return s in ("incoming-webhook", "commands")
