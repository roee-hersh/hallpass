"""What every integration implements and what the framework gives it.

Vocabulary: an Integration is the product (kubernetes, jira). A Connection
is one configured system of that product (one cluster, one Jira site).
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
import urllib.parse
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from hallpass.core.catalog import Action, Resource, validate_action_name
from hallpass.core.context import Context
from hallpass.core.decision import Decision
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
    the credential in clear text, so it is rejected.
    """
    if v == "":
        return
    if any(c in v for c in " \t\r\n#?"):
        raise ValueError(f"url \"{v}\" must not contain whitespace, '?' or '#'")
    try:
        u = urllib.parse.urlsplit(v)
        host = u.hostname or ""
        _ = u.port  # a malformed port raises
    except ValueError as e:
        raise ValueError(f'url "{v}": {e}') from None
    if "@" in u.netloc:
        raise ValueError(f'url "{v}" must not contain userinfo')
    if u.scheme == "https":
        return
    if u.scheme == "http" and is_loopback_host(host):
        return
    raise ValueError(f'url "{v}" must start with https://')


def is_loopback_host(host: str) -> bool:
    """host is "localhost" or a loopback IP address."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


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
