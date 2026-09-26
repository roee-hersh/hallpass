"""Validators and escaping for everything that ends up inside a SOQL
statement.

Everything that ends up inside a SOQL statement passes through one of the
validators in this module first. Identifiers (record ids, API names,
permission names) are matched against strict regexes that leave no room for
quotes, whitespace or operators; free text (an email) is validated and then
escaped with soql_string. Nothing else is ever interpolated.
"""

from __future__ import annotations

import ipaddress
import re

from hallpass.core.errors import go_quote

__all__ = [
    "API_NAME_RE",
    "ID_RE",
    "PERM_NAME_RE",
    "parse_bare_address",
    "soql_id_list",
    "soql_string",
    "validate_api_name",
    "validate_email",
    "validate_id",
    "validate_permission_name",
    "validate_text",
]

# A Salesforce record Id: 15 case-sensitive characters, or the 18-character
# case-insensitive form the API returns. (Patterns are used with fullmatch:
# Go's $ does not match before a trailing newline, Python's does.)
ID_RE = re.compile(r"[a-zA-Z0-9]{15}([a-zA-Z0-9]{3})?")
# An sObject or field API name (Account, Invoice__c; Parent.Name is not one:
# relationship paths are built by hallpass).
API_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,79}")
# The shape of a PermissionSet permission field (PermissionsApiEnabled). The
# describe check narrows it to fields that exist.
PERM_NAME_RE = re.compile(r"Permissions[A-Za-z0-9]+")


def validate_id(s: str) -> None:
    """Check a Salesforce record Id."""
    if not ID_RE.fullmatch(s):
        raise ValueError(f"{go_quote(s)} is not a Salesforce Id (15 or 18 alphanumeric characters)")


def validate_api_name(s: str) -> None:
    """Check an sObject or field API name."""
    if not API_NAME_RE.fullmatch(s):
        raise ValueError(f"{go_quote(s)} is not an API name (letters, digits and underscores, starting with a letter, at most 80 characters)")


def validate_permission_name(s: str) -> None:
    """Check the shape of a PermissionsXxx field name. Whether the field
    exists is checked against the PermissionSet describe."""
    if not PERM_NAME_RE.fullmatch(s):
        raise ValueError(f"{go_quote(s)} is not a permission field name (PermissionsXxx)")


# -- net/mail ------------------------------------------------------------------

# RFC 5322 specials, which are not atext.
_SPECIALS = frozenset('()<>[]:;@\\,"')


def _is_vchar(c: str) -> bool:
    """Go's isVchar: printable US-ASCII or any multi-byte rune (RFC 6532)."""
    return "!" <= c <= "~" or ord(c) >= 0x80


def _is_atext(c: str) -> bool:
    """Go's isAtext(r, dot=true)."""
    if c == ".":
        return True
    if c in _SPECIALS:
        return False
    return _is_vchar(c)


def _is_dtext(c: str) -> bool:
    return c not in "[]\\" and _is_vchar(c)


def _dot_atom(s: str) -> bool:
    """A non-empty run of atext with no leading, trailing or double dot."""
    return s != "" and all(_is_atext(c) for c in s) and not s.startswith(".") and not s.endswith(".") and ".." not in s


def _go_parse_ip(s: str) -> bool:
    """Whether Go's net.ParseIP accepts s: dotted-decimal IPv4 without
    leading zeros, or IPv6 (with an embedded IPv4 tail) without a zone."""
    if s == "" or "%" in s or not s.isascii():
        return False
    try:
        ipaddress.ip_address(s)
    except ValueError:
        return False
    return True


def parse_bare_address(s: str) -> bool:
    """Whether Go's mail.ParseAddress(s) succeeds with Address == s and
    Name == "".

    Only an addr-spec made of a dot-atom local part, "@" and a dot-atom or
    domain-literal domain, with nothing around it, parses back to itself:
    ParseAddress drops the quotes of a quoted local part, the spaces and
    comments around an address, and a name-addr or group carries '<' or ':'
    that never appears in the parsed Address.
    """
    local, at, domain = s.partition("@")
    if not at or not _dot_atom(local):
        return False
    if domain.startswith("["):
        if not domain.endswith("]") or len(domain) < 2:
            return False
        inner = domain[1:-1]
        return all(_is_dtext(c) for c in inner) and _go_parse_ip(inner)
    return _dot_atom(domain)


def validate_email(s: str) -> None:
    """Parse s as a bare address: it must round-trip through net/mail
    unchanged, so display names, comments and angle brackets are rejected,
    and it must carry no control characters."""
    if s == "":
        raise ValueError("email is empty")
    validate_text(s)
    if not parse_bare_address(s):
        # Go distinguishes an unparseable address from one that parses to
        # something else; the latter always carries a display name, angle
        # brackets, quotes or spaces around an otherwise valid addr-spec.
        if _parses_to_other(s):
            raise ValueError(f"{go_quote(s)} is not a bare email address")
        raise ValueError(f"{go_quote(s)} is not an email address")


def _parses_to_other(s: str) -> bool:
    """A rough test of whether mail.ParseAddress would succeed on s with a
    different Address or a Name: only the error text depends on it."""
    t = s.strip(" \t")
    if t.endswith(">") and "<" in t:
        inner = t[t.rindex("<") + 1 : -1]
        return parse_bare_address(inner) or _quoted_addr(inner)
    if t != s and parse_bare_address(t):
        return True
    return _quoted_addr(t)


def _quoted_addr(s: str) -> bool:
    if not s.startswith('"'):
        return False
    i = 1
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            rest = s[i + 1 :]
            return rest.startswith("@") and parse_bare_address("x" + rest)
        i += 1
    return False


def validate_text(s: str) -> None:
    """Reject control characters and over-long values in free text that
    will be escaped into a string literal."""
    if len(s.encode("utf-8", "surrogatepass")) > 255:
        raise ValueError("value is longer than 255 bytes")
    for c in s:
        if c < "\x20" or c == "\x7f":
            raise ValueError("value contains a control character")


_SOQL_ESCAPES = {"\\": "\\\\", "'": "\\'", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def soql_string(s: str) -> str:
    """Escape s for use inside a single-quoted SOQL string literal.

    Backslashes are doubled first, then single quotes are escaped, so an
    input of \\' becomes \\\\\\' and cannot terminate the literal. Newlines,
    carriage returns and tabs become their SOQL escape sequences. The caller
    still validates the value: this function only makes it inert.
    """
    return "".join(_SOQL_ESCAPES.get(c, c) for c in s)


def soql_id_list(ids: list[str]) -> str:
    """Render validated ids as a SOQL IN list: 'a','b'. It fails loudly
    (Go: panics) on an id that does not match ID_RE, because callers
    validate first and an unvalidated id here would be a programming error,
    not a runtime condition."""
    parts = []
    for i in ids:
        if not ID_RE.fullmatch(i):
            raise AssertionError("salesforce: unvalidated id in soqlIDList")
        parts.append("'" + i + "'")
    return ",".join(parts)
