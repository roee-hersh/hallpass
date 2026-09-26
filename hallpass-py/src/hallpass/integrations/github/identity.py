"""Mapping an email to a GitHub login: organization SAML identities, a
login template or a mapping file."""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from hallpass.core import jsonx
from hallpass.core.catalog import go_bytes
from hallpass.core.context import Context
from hallpass.core.decision import Code, HallpassError, errorf, user_ambiguous, user_not_found, wrap_error
from hallpass.core.errors import as_error, go_lower, go_quote, go_trim_space, path_error_text
from hallpass.core.integration import Identity, User
from hallpass.core.template import email_domain
from hallpass.integrations.github.actions import equal_fold, valid_login
from hallpass.net import httpx

if TYPE_CHECKING:
    from hallpass.core.cache import TTL
    from hallpass.core.log import Logger
    from hallpass.core.template import Template

__all__ = [
    "MAP_FILE_TTL",
    "MODE_MAP_FILE",
    "MODE_SAML",
    "MODE_TEMPLATE",
    "SAML_CACHE_TTL",
    "SAML_FETCH_HOOK",
    "SAML_MAX_IDENTITIES",
    "IdentityMixin",
    "SamlData",
    "SamlEntry",
    "SamlIndex",
    "api_status",
    "decode_saml_data",
    "member",
    "read_user_map",
    "valid_email",
]

# Identity modes.
MODE_SAML = "saml"
MODE_TEMPLATE = "template"
MODE_MAP_FILE = "map_file"

# How long the full external-identity map is reused. A fresh check uses
# the map for as long as anyone: it is an organization's whole identity
# listing, paged, and a link between an address and a login is not what a
# fresh check is about; the permission read that follows is always live.
SAML_CACHE_TTL = 10 * 60.0
# The shortest interval between two reads of user_map_file.
MAP_FILE_TTL = 60.0

# Caps the map built by the paginated fallback. Module-level so tests can
# exercise the truncated path; read at every listing.
SAML_MAX_IDENTITIES = 5000

# Runs at the start of every identity listing. Tests set it to inject
# failures such as a crash; None in production.
SAML_FETCH_HOOK: Callable[[], None] | None = None


def valid_email(s: str) -> bool:
    """A shape check only. The email goes into a GraphQL variable (JSON, so
    no injection) or a file lookup; this keeps garbage out of both."""
    n = len(go_bytes(s))
    if n == 0 or n > 254:
        return False
    local, at, domain = s.partition("@")
    if not at or local == "" or domain == "" or "@" in domain:
        return False
    return all(not (ord(c) <= 0x20 or c in "\x7f\"'\\/") for c in s)


def member(d: dict[str, Any] | None, key: str) -> Any:
    """The member a Go struct field named key decodes from: an exact match,
    else a case-insensitive one; None when absent or null."""
    if not d:
        return None
    if key in d:
        return d[key]
    lk = key.lower()
    for k, v in d.items():
        if len(k) == len(key) and "".join("k" if c == "K" else "s" if c == "ſ" else c.lower() if c.isascii() else c for c in k) == lk:
            return v
    return None


def api_status(err: BaseException) -> int:
    """The HTTP status of a failed API call, or 0 when the failure was
    already classified (for example a 404 from the token exchange, which
    must not read as "user not found")."""
    if as_error(err, HallpassError) is not None:
        return 0
    return httpx.status(err)


# -- saml ----------------------------------------------------------------------

SAML_LOOKUP_QUERY = (
    "query($org:String!,$email:String!){ organization(login:$org){ samlIdentityProvider { externalIdentities(first:5, userName:$email)"
    "{ nodes { user { login } samlIdentity { nameId username } scimIdentity { username } } } } } }"
)

SAML_PAGE_QUERY = (
    "query($org:String!,$cursor:String){ organization(login:$org){ samlIdentityProvider { externalIdentities(first:100, after:$cursor)"
    "{ pageInfo { hasNextPage endCursor } nodes { user { login } samlIdentity { nameId username } scimIdentity { username } } } } } }"
)


@dataclass(frozen=True)
class ExternalIdentity:
    """One node; None for an object GitHub reported as null."""

    user_login: str | None
    saml_name_id: str | None
    saml_username: str | None
    scim_username: str | None


@dataclass
class SamlData:
    has_org: bool = False
    has_provider: bool = False
    has_next_page: bool = False
    end_cursor: str = ""
    nodes: list[ExternalIdentity] = field(default_factory=list)


def _decode_identity(v: Any) -> ExternalIdentity:
    n = jsonx.obj(v)
    u, saml, scim = member(n, "user"), member(n, "samlIdentity"), member(n, "scimIdentity")
    login = jsonx.s(jsonx.obj(u, "user"), "login") if u is not None else None
    name_id = username = scim_user = None
    if saml is not None:
        saml = jsonx.obj(saml, "samlIdentity")
        name_id, username = jsonx.s(saml, "nameId"), jsonx.s(saml, "username")
    if scim is not None:
        scim_user = jsonx.s(jsonx.obj(scim, "scimIdentity"), "username")
    return ExternalIdentity(login, name_id, username, scim_user)


def decode_saml_data(v: Any) -> SamlData:
    """The GraphQL data object, decoded as Go decodes samlData."""
    out = SamlData()
    org = member(jsonx.obj(v), "organization")
    if org is None:
        return out
    out.has_org = True
    prov = member(jsonx.obj(org, "organization"), "samlIdentityProvider")
    if prov is None:
        return out
    out.has_provider = True
    ext = jsonx.o(jsonx.obj(prov, "samlIdentityProvider"), "externalIdentities")
    page = jsonx.o(ext, "pageInfo")
    out.has_next_page, out.end_cursor = jsonx.b(page, "hasNextPage"), jsonx.s(page, "endCursor")
    out.nodes = [_decode_identity(n) for n in jsonx.arr(ext, "nodes")]
    return out


@dataclass(frozen=True)
class SamlEntry:
    """One cached identity: login "" means the identity is not linked to a
    GitHub account; conflict means the address belongs to identities linked
    to different accounts."""

    login: str = ""
    conflict: bool = False


@dataclass
class SamlIndex:
    """The address -> entry map of every external identity, with whether
    the listing stopped before the end (a miss is then not a deny)."""

    entries: dict[str, SamlEntry] = field(default_factory=dict)
    truncated: bool = False
    total: int = 0


def _no_saml() -> Exception:
    """The error for an organization without a SAML identity provider."""
    return errorf(Code.UNSUPPORTED, "organization has no SAML identity provider; use identity_mode template or map_file")


def identity_matches(n: ExternalIdentity, email: str) -> bool:
    """Whether the node's SAML nameId, SAML username or SCIM username equals
    the email case-insensitively. GitHub's userName filter is not trusted
    to have matched exactly."""
    if n.saml_name_id is not None and (equal_fold(n.saml_name_id, email) or equal_fold(n.saml_username or "", email)):
        return True
    return n.scim_username is not None and equal_fold(n.scim_username, email)


def pick_identity(nodes: list[ExternalIdentity], email: str) -> str:
    """Choose among the identities that match the email: the linked login
    when there is exactly one; several different logins is ambiguous; only
    unlinked ones is unsupported."""
    logins: list[str] = [n.user_login for n in nodes if n.user_login is not None and n.user_login != ""]
    if not logins:
        raise errorf(Code.UNSUPPORTED, f"SAML identity for {email} is not linked to a GitHub account")
    for lg in logins[1:]:
        if not equal_fold(lg, logins[0]):
            raise user_ambiguous(f"SAML identity {email} is linked to several GitHub accounts")
    return logins[0]


def identity_emails(n: ExternalIdentity) -> list[str]:
    """The address-shaped values of an identity, lowercased."""
    return [go_lower(v) for v in (n.saml_name_id, n.saml_username, n.scim_username) if v is not None and "@" in v]


# -- map_file ------------------------------------------------------------------

# Go's unicode.IsSpace, which strings.Fields splits on.
_GO_SPACE = "\t\n\v\f\r \x85\xa0                　"
_FIELDS_RE = re.compile("[" + re.escape(_GO_SPACE) + "]+")

# bufio.Scanner's limit here: a line (with its newline) must fit in 1 MiB.
_MAX_LINE = 1 << 20


def _go_fields(s: str) -> list[str]:
    return [f for f in _FIELDS_RE.split(s) if f != ""]


def read_user_map(path: str) -> dict[str, str]:
    """Parse lines of "email login" or "email=login"; "#" starts a comment.
    Emails are lowercased; a login that is not a GitHub login is an error so
    a typo is caught rather than silently denying one user. Raises
    ValueError."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except IsADirectoryError as e:
        # Go opens a directory and fails on the first read.
        raise ValueError(f"{path}: {path_error_text('read', path, e)}") from e
    except (OSError, ValueError) as e:
        raise ValueError(path_error_text("open", path, e)) from e
    m: dict[str, str] = {}
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    for n, raw in enumerate(lines, start=1):
        if len(raw) >= _MAX_LINE:
            raise ValueError(f"{path}: bufio.Scanner: token too long")
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        line = raw.decode("utf-8", "surrogateescape")
        i = line.find("#")
        if i >= 0:
            line = line[:i]
        line = go_trim_space(line)
        if line == "":
            continue
        ep, sep, lg = line.partition("=")
        if sep:
            email, login = go_trim_space(ep), go_trim_space(lg)
        else:
            fields = _go_fields(line)
            if len(fields) != 2:
                raise ValueError(f'{path}:{n}: expected "email login" or "email=login"')
            email, login = fields
        if not valid_email(email):
            raise ValueError(f"{path}:{n}: {go_quote(email)} is not an email address")
        if not valid_login(login):
            raise ValueError(f"{path}:{n}: {go_quote(login)} is not a GitHub login")
        m[go_lower(email)] = login
    return m


class IdentityMixin:
    """resolve_identity for GitHubConnection."""

    # Provided by GitHubConnection.
    org: str
    mode: str
    template: Template
    email_domains: frozenset[str]
    map_file: str
    logger: Logger
    now: Callable[[], float]
    saml: TTL[tuple[()], SamlIndex]
    _map_lock: threading.Lock
    _map_entries: dict[str, str] | None
    _map_read: float

    if TYPE_CHECKING:

        def graphql_saml(self, ctx: Context, query: str, variables: dict[str, Any]) -> SamlData: ...
        def _get(self, ctx: Context, path: str, decode: bool = True) -> Any: ...
        def classify(self, err: BaseException, what: str) -> Exception: ...

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Map an email to a GitHub login by the configured mode."""
        email = go_trim_space(u.email)
        if not valid_email(email):
            raise errorf(Code.INVALID_REQUEST, f"email {go_quote(u.email)} is not a valid address")
        if self.mode == MODE_SAML:
            login = self._resolve_saml(ctx, email)
        elif self.mode == MODE_TEMPLATE:
            login = self._resolve_template(ctx, email)
        elif self.mode == MODE_MAP_FILE:
            login = self._resolve_map_file(email)
        else:
            raise errorf(Code.UNSUPPORTED, f"identity_mode {go_quote(self.mode)} is not supported")
        if not valid_login(login):
            raise errorf(Code.UNSUPPORTED, f"identity mode {self.mode} produced {go_quote(login)}, which is not a GitHub login")
        return Identity(id=login, display=login, attrs={"identity_mode": self.mode})

    # -- saml --

    def _resolve_saml(self, ctx: Context, email: str) -> str:
        data = self.graphql_saml(ctx, SAML_LOOKUP_QUERY, {"org": self.org, "email": email})
        if not data.has_org:
            raise errorf(Code.CREDENTIAL_REJECTED, f"organization {self.org} is not visible to the app")
        if not data.has_provider:
            raise _no_saml()
        nodes = [n for n in data.nodes if identity_matches(n, email)]
        if nodes:
            return pick_identity(nodes, email)
        # userName did not match: the IdP may send an email only as nameId.
        # Build (or reuse) the full map and look the address up there.
        idx = self._saml_map(ctx)
        e = idx.entries.get(go_lower(email))
        if e is None:
            if idx.truncated:
                raise errorf(Code.UNSUPPORTED, f"no SAML identity in {self.org} for {email} in the first {idx.total} identities; identity list truncated")
            raise user_not_found(f"no SAML identity in {self.org} for {email}")
        if e.conflict:
            raise user_ambiguous(f"SAML identity {email} is linked to several GitHub accounts")
        if e.login == "":
            raise errorf(Code.UNSUPPORTED, f"SAML identity for {email} is not linked to a GitHub account")
        return e.login

    def _saml_map(self, ctx: Context) -> SamlIndex:
        """The index of every external identity, loaded at most every
        SAML_CACHE_TTL. Concurrent callers share one fetch (TTL.do runs it
        on a context detached from the first caller's cancellation, so a
        waiter is never failed by the leader going away). A crash in the
        listing becomes an unknown decision for everyone waiting on it."""
        return self.saml.do(ctx, (), lambda fctx: (self._fetch_saml_map(fctx), SAML_CACHE_TTL))

    def _fetch_saml_map(self, ctx: Context) -> SamlIndex:
        """List every external identity. Two linked identities that carry
        the same address for different logins mark the address as
        conflicting, so a lookup is ambiguous rather than whichever came
        last."""
        from hallpass.integrations.github import identity as _self

        hook = _self.SAML_FETCH_HOOK
        if hook is not None:
            hook()
        limit = _self.SAML_MAX_IDENTITIES
        idx = SamlIndex()
        m = idx.entries
        cursor: str | None = None
        total = 0
        for _ in range(httpx.MAX_PAGES):
            variables: dict[str, Any] = {"org": self.org}
            if cursor is not None:
                variables["cursor"] = cursor
            data = self.graphql_saml(ctx, SAML_PAGE_QUERY, variables)
            if not data.has_org or not data.has_provider:
                raise _no_saml()
            for n in data.nodes:
                total += 1
                e = SamlEntry(login=n.user_login or "")
                for v in identity_emails(n):
                    prev = m.get(v)
                    if prev is None:
                        m[v] = e
                    elif prev.conflict or e.login == "":
                        # Keep the conflict, or the linked entry over an unlinked one.
                        pass
                    elif prev.login == "":
                        m[v] = e
                    elif not equal_fold(prev.login, e.login):
                        m[v] = SamlEntry(conflict=True)
            idx.total = total
            if not data.has_next_page:
                return idx
            if total >= limit:
                self.logger.warn("github: SAML identity listing stopped at the identity limit", "organization", self.org, "identities", total)
                idx.truncated = True
                return idx
            if data.end_cursor == "":
                self.logger.warn("github: SAML identity listing reported a next page without a cursor", "organization", self.org)
                idx.truncated = True
                return idx
            cursor = data.end_cursor
        self.logger.warn("github: SAML identity listing stopped at the page limit", "organization", self.org, "identities", total)
        idx.truncated = True
        return idx

    # -- template --

    def _resolve_template(self, ctx: Context, email: str) -> str:
        domain = email_domain(email)
        if domain == "" or domain not in self.email_domains:
            raise errorf(Code.UNSUPPORTED, f"email domain {domain} is not in email_domains; login_template is not applied to it")
        login = self.template.render(email)
        if not valid_login(login):
            raise user_not_found(f"login_template renders {email} to {go_quote(login)}, which is not a GitHub login")
        try:
            d = jsonx.obj(self._get(ctx, "/users/" + httpx.path_escape(login)))
            u_login, u_type = jsonx.s(d, "login"), jsonx.s(d, "type")
        except Exception as e:  # noqa: BLE001 - classified below
            if api_status(e) == 404:
                raise user_not_found(f"no GitHub user {login} (from login_template) for {email}")
            raise self.classify(e, "look up user " + login)
        if u_type != "" and u_type != "User":
            raise user_not_found(f"{login} (from login_template) is a GitHub {go_lower(u_type)}, not a user")
        if u_login != "":
            login = u_login
        return login

    # -- map_file --

    def _resolve_map_file(self, email: str) -> str:
        m = self._user_map()
        login = m.get(go_lower(email))
        if login is None:
            raise user_not_found(f"{email} is not in user_map_file")
        return login

    def _user_map(self) -> dict[str, str]:
        """The parsed user_map_file, re-read at most every MAP_FILE_TTL. A
        failed re-read keeps the previous map."""
        with self._map_lock:
            now = self.now()
            if self._map_entries is not None and now - self._map_read < MAP_FILE_TTL:
                return self._map_entries
            try:
                m = read_user_map(self.map_file)
            except ValueError as e:
                if self._map_entries is not None:
                    self.logger.warn("github: user_map_file could not be re-read; keeping the previous map", "error", str(e))
                    self._map_read = now
                    return self._map_entries
                raise wrap_error(Code.UPSTREAM_ERROR, e, "user_map_file could not be read")
            self._map_entries, self._map_read = m, now
            return m
