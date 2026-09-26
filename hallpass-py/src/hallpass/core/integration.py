"""What every integration implements and what the framework gives it.

Vocabulary: an Integration is the product (kubernetes, jira). A Connection
is one configured system of that product (one cluster, one Jira site).
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from hallpass.core.catalog import Action, Resource, validate_action_name
from hallpass.core.context import Context
from hallpass.core.decision import Decision
from hallpass.core.errors import go_quote
from hallpass.core.log import Logger
from hallpass.core.secret import Secret

if TYPE_CHECKING:
    from hallpass.net.httpx import Transport

__all__ = [
    "COMMON_FIELDS",
    "DEFAULT_TIMEOUT",
    "CheckRequest",
    "Connection",
    "Deps",
    "Field",
    "Identity",
    "Integration",
    "ProbeResult",
    "Registry",
    "Settings",
    "User",
    "connection_ref_field",
    "credential_field",
    "find_action",
    "is_loopback_host",
    "url_field",
    "validate_fields",
    "validate_https_url",
]

# The per-check budget when a connection sets none.
DEFAULT_TIMEOUT = 8.0


@dataclass(frozen=True)
class User:
    """What the caller sent."""

    email: str
    groups: tuple[str, ...] = ()


@dataclass(frozen=True)
class Identity:
    """The resolved account in the third-party system."""

    # The system's identifier (accountId, login, user id, username).
    id: str = ""
    # A short human-readable label for logs and reasons.
    display: str = ""
    # Small string facts (for example "is_admin" -> "true").
    attrs: Mapping[str, str] = field(default_factory=dict)
    # Group identifiers the system reported, if any.
    groups: tuple[str, ...] = ()
    # Optionally the integration's own decoded record. It is cached, so it
    # must be treated as read-only.
    native: Any = field(default=None, compare=False)

    def attr(self, k: str) -> str:
        return self.attrs.get(k, "") if self.attrs else ""


@dataclass(frozen=True)
class CheckRequest:
    """One question for a Connection."""

    user: User
    identity: Identity
    action: Action
    # The caller's exact action string (matters for patterns).
    action_name: str
    resource: Resource


@dataclass(frozen=True)
class ProbeResult:
    # One line, for example "authenticated as bot@acme.com".
    summary: str = ""
    # Non-fatal findings such as an over-privileged credential.
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class Field:
    """One config key an integration accepts."""

    name: str
    required: bool = False
    # Secret fields must be env: or file: references.
    secret: bool = False
    # Names another integration; the value must be the id of a connection
    # of that integration. Used for keys ending in _connection.
    ref: str = ""
    # Applies when the key is absent.
    default: str = ""
    # Restricts the accepted values.
    enum: tuple[str, ...] = ()
    # One line for `hallpass catalog`.
    description: str = ""
    # Optionally checks the value (raise ValueError). Runs after enum.
    validate: Callable[[str], None] | None = field(default=None, compare=False)


def url_field(required: bool, desc: str) -> Field:
    """The base URL of the system."""
    return Field(name="url", required=required, description=desc, validate=validate_https_url)


def credential_field(required: bool, desc: str) -> Field:
    """The bot credential."""
    return Field(name="credential", required=required, secret=True, description=desc)


def connection_ref_field(name: str, integration: str, required: bool, desc: str) -> Field:
    """A reference to a connection of another integration."""
    return Field(name=name, ref=integration, required=required, description=desc)


_FIELD_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")

# Accepted on every connection and handled by the framework.
COMMON_FIELDS = frozenset({"id", "integration", "ca_file", "tls_server_name", "proxy_url", "timeout"})


def validate_fields(fields: list[Field] | tuple[Field, ...]) -> None:
    """Check an integration's field declarations at registration."""
    seen: set[str] = set()
    for f in fields:
        if not _FIELD_NAME_RE.fullmatch(f.name):
            raise ValueError(f'field "{f.name}": name must match ^[a-z][a-z0-9_]*$')
        if f.name in seen:
            raise ValueError(f'field "{f.name}" declared twice')
        seen.add(f.name)
        if f.name in COMMON_FIELDS:
            raise ValueError(f'field "{f.name}" is a common field and may not be redeclared')
        if f.ref and not f.name.endswith("_connection"):
            raise ValueError(f'field "{f.name}" references a connection so its name must end in _connection')
        if f.secret and f.default:
            raise ValueError(f'field "{f.name}": secret fields cannot have defaults')


def validate_https_url(v: str) -> None:
    """Accept https:// URLs with no query, fragment or userinfo.

    Plain http:// is allowed only when the host is exactly "localhost" or a
    loopback IP address, for local testing; a name that merely starts with
    "localhost" or "127.0.0.1" resolves wherever DNS says and would carry
    the credential in clear text, so it is rejected. The URL is parsed as
    Go's url.Parse does, so the same values pass and fail with the same text.
    """
    if v == "":
        return
    if any(c in v for c in " \t\r\n#?"):
        raise ValueError(f"url {go_quote(v)} must not contain whitespace, '?' or '#'")
    try:
        scheme, has_user, host = _go_url_parse(v)
    except _URLError as e:
        raise ValueError(f"url {go_quote(v)}: parse {go_quote(v)}: {e}") from None
    if has_user:
        raise ValueError(f"url {go_quote(v)} must not contain userinfo")
    if scheme == "https":
        return
    if scheme == "http" and is_loopback_host(_hostname(host)):
        return
    raise ValueError(f"url {go_quote(v)} must start with https://")


class _URLError(ValueError):
    pass


_HEXDIGITS = frozenset(b"0123456789abcdefABCDEF")
_HOST_OK = frozenset(b"!$&'()*+,;=:[]<>\"-_.~")
_USERINFO_OK = frozenset("-._:~!$&'()*+,;=%@")


def _quote_bytes(b: bytes) -> str:
    return go_quote(b.decode("utf-8", "surrogateescape"))


def _host_should_escape(c: int) -> bool:
    """Go's shouldEscape(c, encodeHost) for an ASCII byte."""
    if 0x30 <= c <= 0x39 or 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A:
        return False
    return c not in _HOST_OK


def _unescape(s: bytes, mode: str) -> bytes:
    """Go's url unescape for the modes url.Parse uses: "host", "zone",
    "path" and "userinfo"."""
    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == 0x25:  # %
            if i + 2 >= n or s[i + 1] not in _HEXDIGITS or s[i + 2] not in _HEXDIGITS:
                raise _URLError("invalid URL escape " + _quote_bytes(s[i : i + 3]))
            v = int(s[i + 1 : i + 3], 16)
            if mode == "host" and (v >> 4) < 8 and s[i : i + 3] != b"%25":
                raise _URLError("invalid URL escape " + _quote_bytes(s[i : i + 3]))
            if mode == "zone" and s[i : i + 3] != b"%25" and v != 0x20 and (v >= 0x80 or _host_should_escape(v)):
                raise _URLError("invalid URL escape " + _quote_bytes(s[i : i + 3]))
            out.append(v)
            i += 3
            continue
        if mode in ("host", "zone") and c < 0x80 and _host_should_escape(c):
            raise _URLError("invalid character " + _quote_bytes(s[i : i + 1]) + " in host name")
        out.append(c)
        i += 1
    return bytes(out)


def _valid_optional_port(port: bytes) -> bool:
    if port == b"":
        return True
    return port[:1] == b":" and all(0x30 <= b <= 0x39 for b in port[1:])


def _parse_host(host: bytes) -> bytes:
    if host.startswith(b"["):
        i = host.rfind(b"]")
        if i < 0:
            raise _URLError("missing ']' in host")
        colon_port = host[i + 1 :]
        if not _valid_optional_port(colon_port):
            raise _URLError(f"invalid port {_quote_bytes(colon_port)} after host")
        zone = host[:i].find(b"%25")
        if zone >= 0:
            return _unescape(host[:zone], "host") + _unescape(host[zone:i], "zone") + _unescape(host[i:], "host")
    else:
        i = host.rfind(b":")
        if i != -1 and not _valid_optional_port(host[i:]):
            raise _URLError(f"invalid port {_quote_bytes(host[i:])} after host")
    return _unescape(host, "host")


def _go_url_parse(raw: str) -> tuple[str, bool, bytes]:
    """The parts of Go's url.Parse the validation reads: the lowercased
    scheme, whether userinfo is present, and the host (with port)."""
    b = raw.encode("utf-8", "surrogatepass")
    if any(c < 0x20 or c == 0x7F for c in b):
        raise _URLError("net/url: invalid control character in URL")
    if b == b"*":
        return "", False, b""
    scheme, rest = b"", b
    for i, c in enumerate(b):
        if 0x61 <= c <= 0x7A or 0x41 <= c <= 0x5A:
            continue
        if 0x30 <= c <= 0x39 or c in b"+-.":
            if i == 0:
                break
            continue
        if c == 0x3A:  # :
            if i == 0:
                raise _URLError("missing protocol scheme")
            scheme, rest = b[:i], b[i + 1 :]
        break
    sch = scheme.decode("ascii").lower()
    if not rest.startswith(b"/"):
        if sch:
            return sch, False, b""  # opaque
        if b":" in rest.split(b"/", 1)[0]:
            raise _URLError("first path segment in URL cannot contain colon")
    has_user, host = False, b""
    if (sch or not rest.startswith(b"///")) and rest.startswith(b"//"):
        authority, sep, path = rest[2:].partition(b"/")
        rest = sep + path
        at = authority.rfind(b"@")
        host = _parse_host(authority[at + 1 :] if at >= 0 else authority)
        if at >= 0:
            userinfo = authority[:at].decode("utf-8", "surrogateescape")
            if not all(c.isascii() and (c.isalnum() or c in _USERINFO_OK) for c in userinfo):
                raise _URLError("net/url: invalid userinfo")
            name, colon, password = authority[:at].partition(b":")
            _unescape(name, "userinfo")
            if colon:
                _unescape(password, "userinfo")
            has_user = True
    _unescape(rest, "path")
    return sch, has_user, host


def _hostname(host: bytes) -> str:
    """Go's URL.Hostname: the host without port and IPv6 brackets."""
    colon = host.rfind(b":")
    if colon != -1 and _valid_optional_port(host[colon:]):
        host = host[:colon]
    if host.startswith(b"[") and host.endswith(b"]"):
        host = host[1:-1]
    return host.decode("utf-8", "surrogateescape")


def is_loopback_host(host: str) -> bool:
    """host is "localhost" or a loopback IP address, as Go's net.ParseIP
    and IP.IsLoopback read it: 127.0.0.0/8 (also IPv4-mapped) or ::1, and
    no zone. A bracketed IPv6 literal is accepted too."""
    if host == "localhost":
        return True
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if "%" in host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv4Address):
        return ip.packed[0] == 127
    return ip == ipaddress.IPv6Address("::1")


class Settings:
    """The validated config values of one connection."""

    def __init__(
        self,
        id: str,
        integration: str,
        values: Mapping[str, str] | None = None,
        secrets: Mapping[str, Secret] | None = None,
        *,
        ca_file: str = "",
        tls_server_name: str = "",
        proxy_url: str = "",
        timeout: float = 0.0,
    ) -> None:
        self.id = id
        self.integration = integration
        self.ca_file = ca_file
        self.tls_server_name = tls_server_name
        self.proxy_url = proxy_url
        self.timeout = timeout
        self._values: dict[str, str] = dict(values or {})
        self._secrets: dict[str, Secret] = dict(secrets or {})

    def get(self, key: str) -> str:
        """A non-secret value (defaults already applied) or ""."""
        return self._values.get(key, "")

    def has(self, key: str) -> bool:
        """Whether a non-secret key was set (or defaulted)."""
        return key in self._values

    def bool(self, key: str, default: bool) -> bool:
        v = self._values.get(key, "").lower()
        if v in ("true", "yes", "1"):
            return True
        if v in ("false", "no", "0"):
            return False
        return default

    def secret(self, key: str) -> Secret:
        """A secret reference; the empty Secret when absent."""
        return self._secrets.get(key, Secret())

    def keys(self) -> list[str]:
        return sorted(self._values)

    def effective_timeout(self) -> float:
        return self.timeout if self.timeout > 0 else DEFAULT_TIMEOUT

    def __repr__(self) -> str:
        return f"Settings(id={self.id!r}, integration={self.integration!r})"


@dataclass
class Deps:
    """What the framework hands to Integration.new."""

    logger: Logger
    # Another built connection by id. Only ids named in a ref field of this
    # integration are resolvable.
    connection: Callable[[str], Connection]
    # A transport built from the connection's transport settings.
    http_client: Callable[[Settings], Transport]
    # The clock (epoch seconds). Tests replace it.
    now: Callable[[], float] = time.time


class Connection(ABC):
    """One configured system."""

    @abstractmethod
    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Map the caller's user to the system's own account.

        Raise HallpassError with USER_NOT_FOUND or USER_AMBIGUOUS when the
        mapping fails; any other exception means the lookup itself failed.
        """

    @abstractmethod
    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Answer one question. Return deny only when the system positively
        says no. A raised exception is turned into an unknown decision."""

    @abstractmethod
    def probe(self, ctx: Context) -> ProbeResult:
        """Verify the credential and permissions without a user."""


class Integration(ABC):
    """The product."""

    @abstractmethod
    def name(self) -> str:
        """The value of the "integration" config key, lowercase."""

    @abstractmethod
    def fields(self) -> list[Field]:
        """Every config key this integration accepts besides the common ones."""

    @abstractmethod
    def actions(self) -> list[Action]:
        """What callers may ask about."""

    @abstractmethod
    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build one connection from validated settings."""

    def match_action(self, name: str) -> Action | None:
        """For integrations whose action names are patterns; consulted only
        when an exact match in actions() fails."""
        return None


def find_action(i: Integration, name: str) -> Action | None:
    """Exact match in actions() first, then match_action."""
    for a in i.actions():
        if not a.pattern and a.name == name:
            return a
    return i.match_action(name)


_NAME_RE = re.compile(r"[a-z][a-z0-9]*")


class Registry:
    """The known integrations by name."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, Integration] = {}

    def register(self, i: Integration) -> None:
        """Add an integration after validating its name, fields and actions.
        A programming error raises: registration happens at import time."""
        name = i.name()
        if not _NAME_RE.fullmatch(name):
            raise ValueError(f'integration name "{name}" must match ^[a-z][a-z0-9]*$')
        try:
            validate_fields(i.fields())
        except ValueError as e:
            raise ValueError(f"integration {name}: {e}") from None
        seen: set[str] = set()
        for a in i.actions():
            if not a.pattern:
                try:
                    validate_action_name(a.name)
                except ValueError as e:
                    raise ValueError(f'integration {name}: action "{a.name}": {e}') from None
            if a.name in seen:
                raise ValueError(f'integration {name}: action "{a.name}" declared twice')
            seen.add(a.name)
        with self._lock:
            if name in self._items:
                raise ValueError(f"integration {name} registered twice")
            self._items[name] = i

    def lookup(self, name: str) -> Integration | None:
        with self._lock:
            return self._items.get(name)

    def names(self) -> list[str]:
        with self._lock:
            return sorted(self._items)
