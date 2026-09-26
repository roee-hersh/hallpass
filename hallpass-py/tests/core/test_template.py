"""Port of internal/integration/template_test.go."""

from __future__ import annotations

import pytest

from hallpass.core.template import (
    email_domain,
    is_email,
    parse_email_domains,
    parse_template,
    validate_email_domains,
    validate_template,
)


@pytest.mark.parametrize("tpl", ["{email}", "{local}", "oidc:{email}", "{local}-acme", "{domain}/{local}", "{local}.{domain}", "x{email}y"])
def test_template_validation_good(tpl: str) -> None:
    parse_template(tpl)


BAD_TEMPLATES = {
    "": "empty",
    "  ": "empty",
    "static": "must contain",
    "{domain}": "must contain",
    "{user}": "unknown placeholder {user}",
    "{email}{name}": "unknown placeholder {name}",
    "{email": "unclosed",
    "{local}{": "unclosed",
    "{local}{email": "unclosed",
    "{local}}": "unbalanced",
    "{local}{{email}}": "unclosed",
    "{Email}": "unknown placeholder {Email}",
    "{ email }": "unknown placeholder { email }",
}


@pytest.mark.parametrize(("tpl", "want"), BAD_TEMPLATES.items())
def test_template_validation_bad(tpl: str, want: str) -> None:
    with pytest.raises(ValueError) as ei:
        validate_template(tpl)
    assert want in str(ei.value), f"ValidateTemplate({tpl!r}) = {ei.value}, want {want!r}"
    with pytest.raises(ValueError):
        parse_template(tpl)


@pytest.mark.parametrize(
    ("tpl", "email", "want"),
    [
        ("{email}", "dana@example.com", "dana@example.com"),
        ("{local}", "dana@example.com", "dana"),
        ("{domain}-{local}", "dana@example.com", "example.com-dana"),
        ("oidc:{email}", "Dana@Example.com", "oidc:Dana@Example.com"),
        ("{local}@corp", "dana@example.com", "dana@corp"),
        # No @: the whole value is the local part, the domain is empty.
        ("{local}/{domain}", "dana", "dana/"),
        # Only the first @ splits the address.
        ("{local}|{domain}", "a@b@c", "a|b@c"),
        # The rendered value is not re-scanned for placeholders.
        ("{local}", "{domain}@example.com", "{domain}"),
    ],
)
def test_template_render(tpl: str, email: str, want: str) -> None:
    assert parse_template(tpl).render(email) == want


@pytest.mark.parametrize(("addr", "want"), {"dana@Example.COM": "example.com", "dana": "", "dana@": "", "a@b@c": "b@c"}.items())
def test_email_domain(addr: str, want: str) -> None:
    assert email_domain(addr) == want


GOOD_DOMAINS = {
    "acme.com": ["acme.com"],
    "acme.com,acme.io": ["acme.com", "acme.io"],
    "acme.com, acme.io": ["acme.com", "acme.io"],
    " acme.com ,\tacme.io ": ["acme.com", "acme.io"],
    "Acme.com,ACME.IO": ["acme.com", "acme.io"],
    "acme.com,acme.com,Acme.com": ["acme.com"],
    "corp.example": ["corp.example"],
    "localhost": ["localhost"],
    "xn--bcher-kva.example": ["xn--bcher-kva.example"],
    "a-b.c1.example, 1.2.3.4": ["a-b.c1.example", "1.2.3.4"],
}


@pytest.mark.parametrize(("v", "want"), GOOD_DOMAINS.items())
def test_parse_email_domains_good(v: str, want: list[str]) -> None:
    assert parse_email_domains(v) == want
    validate_email_domains(v)


BAD_DOMAINS = [
    "",
    " ",
    ",",
    "acme.com,",
    ",acme.com",
    "acme.com,,acme.io",
    "acme.com, ,acme.io",
    "acme.com;acme.io",
    "a b.com",
    "a/b",
    "exa_mple.com",
    "acme.com.",
    ".acme.com",
    "acme..com",
    "-acme.com",
    "acme-.com",
    "acme.com:443",
    "@acme.com",
    "*.acme.com",
    "acmé.com",
    "a" * 64 + ".com",
    "ab." * 90 + "com",
]


@pytest.mark.parametrize("v", BAD_DOMAINS)
def test_parse_email_domains_bad(v: str) -> None:
    with pytest.raises(ValueError):
        parse_email_domains(v)
    with pytest.raises(ValueError):
        validate_email_domains(v)


def test_parse_email_domains_names_bad_entry() -> None:
    """The error names the offending entry, not the whole list."""
    with pytest.raises(ValueError) as ei:
        parse_email_domains("acme.com, bad_domain.io")
    assert '"bad_domain.io"' in str(ei.value)


# -- Behaviour pinned against the Go implementation ------------------------------
# Expected values are what the Go functions return for the same input.


def test_go_string_semantics() -> None:
    # strings.TrimSpace does not trim U+001C..U+001F (str.strip does) but
    # trims U+0085 and U+3000.
    with pytest.raises(ValueError, match=r"^must contain"):
        validate_template("\x1c")
    with pytest.raises(ValueError, match=r"^must not be empty$"):
        validate_template("\x85　")
    assert parse_email_domains("　acme.com\x85") == ["acme.com"]
    with pytest.raises(ValueError) as ei:
        parse_email_domains("\x1cacme.com")
    assert str(ei.value) == '"\\x1cacme.com" is not a domain name (letters, digits, hyphens and dots only)'
    # strings.ToLower maps U+0130 to a plain i, one rune for one.
    assert parse_email_domains("İbm.com") == ["ibm.com"]
    assert email_domain("x@İBM.COM") == "ibm.com"
    assert email_domain("x@ΣΣ") == "σσ"


@pytest.mark.parametrize(
    ("v", "want"),
    [
        ("acme.com, bad_domain.io", '"bad_domain.io" is not a domain name (letters, digits, hyphens and dots only)'),
        ("a" * 64 + ".com", '"' + "a" * 64 + '.com" is not a domain name (label longer than 63 characters)'),
        ("ab." * 84 + "co", '"' + "ab." * 84 + 'co" is longer than 253 characters'),
        ("acme..com", '"acme..com" is not a domain name (empty label)'),
        ("-acme.com", '"-acme.com" is not a domain name (label starts or ends with a hyphen)'),
        ("acmé.com", '"acmé.com" is not a domain name (letters, digits, hyphens and dots only)'),
        (" , ", "must be a comma-separated list of domains with no empty entries (acme.com,acme.io)"),
    ],
)
def test_parse_email_domains_error_text(v: str, want: str) -> None:
    with pytest.raises(ValueError) as ei:
        parse_email_domains(v)
    assert str(ei.value) == want


def test_parse_email_domains_limits() -> None:
    assert parse_email_domains("ab." * 83 + "com") == ["ab." * 83 + "com"]  # 252 bytes
    assert parse_email_domains("a" * 63 + ".com") == ["a" * 63 + ".com"]


@pytest.mark.parametrize(
    ("s", "want"),
    [
        ("dana@example.com", True),
        ("o'brien@example.com", True),
        ("a" * 64 + "@x", True),
        ("a" * 65 + "@x", False),
        ("a@" + "x" * 255, True),
        ("a@" + "x" * 256, False),
        ("a@x\n", False),
        ('"a"@x', False),
        ("a b@x", False),
        ("a@x_y", False),
        ("é@x", False),
        ("@x", False),
        ("a@", False),
    ],
)
def test_is_email(s: str, want: bool) -> None:
    assert is_email(s) is want
