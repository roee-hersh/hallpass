"""Validators and escaping for everything that ends up inside a SOQL
statement.

Everything that ends up inside a SOQL statement passes through one of the
validators in this module first. Identifiers (record ids, API names,
permission names) are matched against strict regexes that leave no room for
quotes, whitespace or operators; free text (an email) is validated and then
escaped with soql_string. Nothing else is ever interpolated.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re

from hallpass.core.errors import go_quote

__all__ = [
    "API_NAME_RE",
    "ID_RE",
    "PERM_NAME_RE",
    "parse_address",
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


class _MailError(ValueError):
    """mail.ParseAddress failed."""


class _InvalidWord(ValueError):
    """Not an RFC 2047 encoded-word, or one that does not decode: the text
    is kept as it is."""


class _CharsetError(ValueError):
    """An encoded-word in a charset Go's net/mail cannot convert."""


# RFC 5322 specials, which are not atext.
_SPECIALS = frozenset('()<>[]:;@\\,"')


def _is_vchar(c: str) -> bool:
    """Go's isVchar: printable US-ASCII or any multi-byte rune (RFC 6532)."""
    return "!" <= c <= "~" or ord(c) >= 0x80


def _is_atext(c: str, dot: bool) -> bool:
    if c == ".":
        return dot
    if c in _SPECIALS:
        return False
    return _is_vchar(c)


def _is_qtext(c: str) -> bool:
    return c not in '\\"' and _is_vchar(c)


def _is_wsp(c: str) -> bool:
    return c in " \t"


def _is_dtext(c: str) -> bool:
    return c not in "[]\\" and _is_vchar(c)


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


def _fold(c: str) -> str:
    f = c.casefold()
    if len(f) == 1:
        return f
    lo = c.lower()
    return lo if len(lo) == 1 else c


def _equal_fold(a: str, b: str) -> bool:
    """Go's strings.EqualFold."""
    return len(a) == len(b) and all(x == y or _fold(x) == _fold(y) for x, y in zip(a, b, strict=True))


def _from_hex(c: int) -> int:
    if 0x30 <= c <= 0x39:
        return c - 0x30
    if 0x41 <= c <= 0x46:
        return c - 0x41 + 10
    if 0x61 <= c <= 0x66:
        return c - 0x61 + 10
    raise _InvalidWord("mime: invalid hex byte")


def _q_decode(s: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == 0x5F:  # _
            out.append(0x20)
        elif c == 0x3D:  # =
            if i + 2 >= len(s):
                raise _InvalidWord("mime: invalid RFC 2047 encoded-word")
            out.append(_from_hex(s[i + 1]) << 4 | _from_hex(s[i + 2]))
            i += 2
        elif 0x20 <= c <= 0x7E or c in (0x0A, 0x0D, 0x09):
            out.append(c)
        else:
            raise _InvalidWord("mime: invalid RFC 2047 encoded-word")
        i += 1
    return bytes(out)


def _mime_decode(word: str) -> str:
    """mime.WordDecoder.Decode with no CharsetReader of its own: utf-8,
    iso-8859-1 and us-ascii convert, any other charset is _CharsetError."""
    if len(word.encode("utf-8", "surrogatepass")) < 8 or not word.startswith("=?") or not word.endswith("?=") or word.count("?") != 4:
        raise _InvalidWord("mime: invalid RFC 2047 encoded-word")
    w = word[2:-2]
    charset, _, text = w.partition("?")
    if charset == "":
        raise _InvalidWord("mime: invalid RFC 2047 encoded-word")
    encoding, _, text = text.partition("?")
    if len(encoding.encode("utf-8", "surrogatepass")) != 1:
        raise _InvalidWord("mime: invalid RFC 2047 encoded-word")
    raw = text.encode("utf-8", "surrogatepass")
    if encoding in "Bb":
        try:
            if not re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", raw) or len(raw) % 4:
                raise binascii.Error("illegal base64 data")
            content = base64.b64decode(raw, validate=True)
        except binascii.Error:
            raise _InvalidWord("illegal base64 data") from None
    elif encoding in "Qq":
        content = _q_decode(raw)
    else:
        raise _InvalidWord("mime: invalid RFC 2047 encoded-word")
    if _equal_fold("utf-8", charset):
        return content.decode("utf-8", "replace")
    if _equal_fold("iso-8859-1", charset):
        return content.decode("latin-1")
    if _equal_fold("us-ascii", charset):
        return "".join(chr(b) if b < 0x80 else "\ufffd" for b in content)
    raise _CharsetError(f"charset not supported: {go_quote(charset.lower())}")


class _AddrParser:
    """A port of Go's net/mail addrParser, enough for ParseAddress."""

    def __init__(self, s: str) -> None:
        self.s = s

    def parse_single_address(self) -> tuple[str, str]:
        addrs = self.parse_address(True)
        if not self.skip_cfws():
            raise _MailError("mail: misformatted parenthetical comment")
        if self.s:
            raise _MailError("mail: expected single address")
        if len(addrs) == 0:
            raise _MailError("mail: empty group")
        if len(addrs) > 1:
            raise _MailError("mail: group with multiple addresses")
        return addrs[0]

    def parse_address(self, handle_group: bool) -> list[tuple[str, str]]:
        self.skip_space()
        if not self.s:
            raise _MailError("mail: no address")
        # addr-spec has a more restricted grammar than name-addr, so it is
        # tried first.
        try:
            spec = self.consume_addr_spec()
        except _MailError:
            spec = None
        if spec is not None:
            display = ""
            self.skip_space()
            if self.s and self.s[0] == "(":
                display = self.consume_display_name_comment()
            return [(display, spec)]
        display = ""
        if self.s[0] != "<":
            display = self.consume_phrase()
        self.skip_space()
        if handle_group and self.consume(":"):
            return self.consume_group_list()
        if not self.consume("<"):
            raise _MailError("mail: no angle-addr")
        spec = self.consume_addr_spec()
        if not self.consume(">"):
            raise _MailError("mail: unclosed angle-addr")
        return [(display, spec)]

    def consume_group_list(self) -> list[tuple[str, str]]:
        group: list[tuple[str, str]] = []
        self.skip_space()
        if self.consume(";"):
            if not self.skip_cfws():
                raise _MailError("mail: misformatted parenthetical comment")
            return group
        while True:
            self.skip_space()
            group.extend(self.parse_address(False))
            if not self.skip_cfws():
                raise _MailError("mail: misformatted parenthetical comment")
            if self.consume(";"):
                if not self.skip_cfws():
                    raise _MailError("mail: misformatted parenthetical comment")
                break
            if not self.consume(","):
                raise _MailError("mail: expected comma")
        return group

    def consume_addr_spec(self) -> str:
        orig = self.s
        try:
            self.skip_space()
            if not self.s:
                raise _MailError("mail: no addr-spec")
            if self.s[0] == '"':
                local = self.consume_quoted_string()
                if local == "":
                    raise _MailError("mail: empty quoted string in addr-spec")
            else:
                local = self.consume_atom(True, False)
            if not self.consume("@"):
                raise _MailError("mail: missing @ in addr-spec")
            self.skip_space()
            if not self.s:
                raise _MailError("mail: no domain in addr-spec")
            domain = self.consume_domain_literal() if self.s[0] == "[" else self.consume_atom(True, False)
            return local + "@" + domain
        except _MailError:
            self.s = orig
            raise

    def consume_phrase(self) -> str:
        words: list[str] = []
        prev_encoded = False
        err: ValueError | None = None
        while True:
            # obs-phrase allows CFWS after one word
            if words and not self.skip_cfws():
                raise _MailError("mail: misformatted parenthetical comment")
            self.skip_space()
            if not self.s:
                break
            encoded = False
            try:
                if self.s[0] == '"':
                    word = self.consume_quoted_string()
                else:
                    # dot-atom, more permissive than RFC 5322's atom
                    word = self.consume_atom(True, True)
                    word, encoded = self.decode_rfc2047_word(word)
            except (_MailError, _CharsetError) as e:
                err = e
                break
            if prev_encoded and encoded:
                words[-1] += word
            else:
                words.append(word)
            prev_encoded = encoded
        if err is not None and not words:
            raise _MailError(f"mail: missing word in phrase: {err}")
        return " ".join(words)

    def consume_quoted_string(self) -> str:
        i = 1
        out: list[str] = []
        escaped = False
        s = self.s
        while True:
            if i >= len(s):
                raise _MailError("mail: unclosed quoted-string")
            r = s[i]
            if escaped:
                if not _is_vchar(r) and not _is_wsp(r):
                    raise _MailError("mail: bad character in quoted-string")
                out.append(r)
                escaped = False
            elif _is_qtext(r) or _is_wsp(r):
                out.append(r)
            elif r == '"':
                break
            elif r == "\\":
                escaped = True
            else:
                raise _MailError("mail: bad character in quoted-string")
            i += 1
        self.s = s[i + 1 :]
        return "".join(out)

    def consume_atom(self, dot: bool, permissive: bool) -> str:
        i = 0
        while i < len(self.s) and _is_atext(self.s[i], dot):
            i += 1
        if i == 0:
            raise _MailError("mail: invalid string")
        atom, self.s = self.s[:i], self.s[i:]
        if not permissive:
            if atom.startswith("."):
                raise _MailError("mail: leading dot in atom")
            if ".." in atom:
                raise _MailError("mail: double dot in atom")
            if atom.endswith("."):
                raise _MailError("mail: trailing dot in atom")
        return atom

    def consume_domain_literal(self) -> str:
        if not self.consume("["):
            raise _MailError('mail: missing "[" in domain-literal')
        dtext = ""
        while True:
            if not self.s:
                raise _MailError("mail: unclosed domain-literal")
            if self.s[0] == "]":
                break
            if not _is_dtext(self.s[0]):
                raise _MailError("mail: bad character in domain-literal")
            dtext += self.s[0]
            self.s = self.s[1:]
        if not self.consume("]"):
            raise _MailError("mail: unclosed domain-literal")
        if not _go_parse_ip(dtext):
            raise _MailError("mail: invalid IP address in domain-literal")
        return "[" + dtext + "]"

    def consume_display_name_comment(self) -> str:
        if not self.consume("("):
            raise _MailError("mail: comment does not start with (")
        comment, ok = self.consume_comment()
        if not ok:
            raise _MailError("mail: misformatted parenthetical comment")
        words = [w for w in re.split("[ \t]+", comment) if w]
        for n, w in enumerate(words):
            try:
                decoded, encoded = self.decode_rfc2047_word(w)
            except _CharsetError as e:
                raise _MailError(str(e)) from None
            if encoded:
                words[n] = decoded
        return " ".join(words)

    def decode_rfc2047_word(self, s: str) -> tuple[str, bool]:
        """(decoded, True) for an encoded-word, (s, False) for anything
        that is not one; a charset Go cannot convert raises."""
        try:
            return _mime_decode(s), True
        except _InvalidWord:
            return s, False

    def consume(self, c: str) -> bool:
        if not self.s or self.s[0] != c:
            return False
        self.s = self.s[1:]
        return True

    def skip_space(self) -> None:
        self.s = self.s.lstrip(" \t")

    def skip_cfws(self) -> bool:
        self.skip_space()
        while self.consume("("):
            _, ok = self.consume_comment()
            if not ok:
                return False
            self.skip_space()
        return True

    def consume_comment(self) -> tuple[str, bool]:
        # '(' already consumed.
        depth = 1
        comment = []
        while self.s and depth != 0:
            if self.s[0] == "\\" and len(self.s) > 1:
                self.s = self.s[1:]
            elif self.s[0] == "(":
                depth += 1
            elif self.s[0] == ")":
                depth -= 1
            if depth > 0:
                comment.append(self.s[0])
            self.s = self.s[1:]
        return "".join(comment), depth == 0


def parse_address(s: str) -> tuple[str, str]:
    """Go's mail.ParseAddress: (Name, Address); raises ValueError."""
    return _AddrParser(s).parse_single_address()


def validate_email(s: str) -> None:
    """Parse s as a bare address: it must round-trip through net/mail
    unchanged, so display names, comments and angle brackets are rejected,
    and it must carry no control characters."""
    if s == "":
        raise ValueError("email is empty")
    validate_text(s)
    try:
        name, address = parse_address(s)
    except ValueError:
        raise ValueError(f"{go_quote(s)} is not an email address") from None
    if address != s or name != "":
        raise ValueError(f"{go_quote(s)} is not a bare email address")


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
