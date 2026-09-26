"""Per-user name templates and email helpers."""

from __future__ import annotations

import re

__all__ = [
    "Template",
    "email_domain",
    "is_email",
    "parse_email_domains",
    "parse_template",
    "validate_email_domains",
    "validate_template",
]

_PLACEHOLDERS = "placeholders are {email}, {local} and {domain}"


class Template(str):
    """Renders a per-user name (a Kubernetes username, a GitLab username)
    from the caller's email. Placeholders: {email} (the whole address),
    {local} (before @) and {domain} (after @)."""

    def render(self, email: str) -> str:
        local, _, domain = email.partition("@")
        # One pass, like strings.NewReplacer: a substituted value is never
        # scanned for placeholders again.
        return re.sub(r"\{(email|local|domain)\}", lambda m: {"email": email, "local": local, "domain": domain}[m.group(1)], str(self))


def validate_template(s: str) -> None:
    """Every "{...}" must name a placeholder, braces must balance, and
    {email} or {local} must occur, otherwise every user gets the same name."""
    if s.strip() == "":
        raise ValueError("must not be empty")
    rest = s
    while True:
        i = _index_any(rest, "{}")
        if i < 0:
            break
        if rest[i] == "}":
            raise ValueError("unbalanced '}': " + _PLACEHOLDERS)
        j = _index_any(rest[i + 1 :], "{}")
        if j < 0 or rest[i + 1 + j] != "}":
            raise ValueError("unclosed '{': " + _PLACEHOLDERS)
        ph = rest[i + 1 : i + 1 + j]
        if ph not in ("email", "local", "domain"):
            raise ValueError(f"unknown placeholder {{{ph}}}; use {{email}}, {{local}} or {{domain}}")
        rest = rest[i + 1 + j + 1 :]
    if "{email}" not in s and "{local}" not in s:
        raise ValueError("must contain {email} or {local}, otherwise every user gets the same name")


def parse_template(s: str) -> Template:
    validate_template(s)
    return Template(s)


def _index_any(s: str, chars: str) -> int:
    for i, c in enumerate(s):
        if c in chars:
            return i
    return -1


# A local part of RFC 5322 atom characters and a domain of letters, digits,
# dots and hyphens. No double quote, backslash, space or control character,
# but it does admit the apostrophe (o'brien@example.com), so a validated
# address still needs the escaping of whatever query syntax it is placed in.
_EMAIL_RE = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@[A-Za-z0-9.-]{1,255}")


def is_email(s: str) -> bool:
    return _EMAIL_RE.fullmatch(s) is not None


def email_domain(email: str) -> str:
    """The lowercased domain of an address, or "" when there is none."""
    _, at, domain = email.partition("@")
    if not at:
        return ""
    return domain.lower()


def parse_email_domains(v: str) -> list[str]:
    """A comma-separated email_domains value: trimmed, lowercased DNS names,
    no empty entries, repeats kept once. Matching is by whole domain."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in v.split(","):
        d = raw.strip().lower()
        if d == "":
            raise ValueError("must be a comma-separated list of domains with no empty entries (acme.com,acme.io)")
        err = _check_domain(d)
        if err:
            raise ValueError(f'"{raw.strip()}" {err}')
        if d in seen:
            continue
        seen.add(d)
        out.append(d)
    if not out:
        raise ValueError("must list at least one domain")
    return out


def validate_email_domains(v: str) -> None:
    parse_email_domains(v)


def _check_domain(d: str) -> str:
    if len(d.encode()) > 253:
        return "is longer than 253 characters"
    for label in d.split("."):
        if label == "":
            return "is not a domain name (empty label)"
        if len(label.encode()) > 63:
            return "is not a domain name (label longer than 63 characters)"
        if label[0] == "-" or label[-1] == "-":
            return "is not a domain name (label starts or ends with a hyphen)"
        for c in label:
            if not ("a" <= c <= "z" or "0" <= c <= "9" or c == "-"):
                return "is not a domain name (letters, digits, hyphens and dots only)"
    return ""
