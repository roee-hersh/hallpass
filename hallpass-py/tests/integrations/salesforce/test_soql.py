"""Port of internal/integrations/salesforce/soql_test.go."""

from __future__ import annotations

import pytest

from hallpass.integrations.salesforce.soql import soql_id_list, soql_string, validate_api_name, validate_email, validate_id, validate_permission_name


@pytest.mark.parametrize(
    ("inp", "want"),
    [
        ("plain@example.com", "plain@example.com"),
        ("o'neil@example.com", r"o\'neil@example.com"),
        ("x' OR 1=1--", r"x\' OR 1=1--"),
        ("\\'", r"\\\'"),
        ("a\\b", r"a\\b"),
        ("line1\nline2", r"line1\nline2"),
        ("cr\rlf\n", r"cr\rlf\n"),
        ("tab\there", r"tab\there"),
        ('say "hi"', r"say \"hi\""),
        ("' OR Username != '", r"\' OR Username != \'"),
        ("", ""),
        ("ünïcödé", "ünïcödé"),
    ],
)
def test_soql_string(inp: str, want: str) -> None:
    got = soql_string(inp)
    assert got == want, f"soql_string({inp!r}) = {got!r}, want {want!r}"


@pytest.mark.parametrize("inp", ["'", "''", "\\", "\\\\'", "'\\", "a'b\\c'd"])
def test_soql_string_no_bare_quote(inp: str) -> None:
    """Go: TestSoqlString, second half. An escaped literal never contains a
    bare quote or backslash: every quote is preceded by an odd run of
    backslashes."""
    out = soql_string(inp)
    for i, ch in enumerate(out):
        if ch != "'":
            continue
        n = 0
        j = i - 1
        while j >= 0 and out[j] == "\\":
            n += 1
            j -= 1
        assert n % 2 == 1, f"soql_string({inp!r}) = {out!r} leaves an unescaped quote at {i}"


def _ok(fn, v: str) -> bool:  # type: ignore[no-untyped-def]
    try:
        fn(v)
    except ValueError:
        return False
    return True


def test_validators() -> None:
    for ok in ("001000000000001", "001000000000001AAA", "0055g00000AbCdEfGH"):
        assert _ok(validate_id, ok), f"id {ok!r}"
    for bad in ("", "001", "001000000000001'", "001000000000001AA", "0010000000000010000", "001-00000000001", "001000000000001AAAA"):
        assert not _ok(validate_id, bad), f"id {bad!r} accepted"
    for ok in ("Account", "Invoice__c", "Custom_Metadata__mdt", "Order_Event__e", "npsp__Household__c", "a"):
        assert _ok(validate_api_name, ok), f"api name {ok!r}"
    for bad in ("", "_x", "1abc", "Account'", "Account Name", "Parent.Name", "Account;", "a" * 81):
        assert not _ok(validate_api_name, bad), f"api name {bad!r} accepted"
    for ok in ("PermissionsApiEnabled", "PermissionsViewSetup", "PermissionsModifyAllData"):
        assert _ok(validate_permission_name, ok), f"perm {ok!r}"
    for bad in ("", "Permissions", "ApiEnabled", "PermissionsApi_Enabled", "PermissionsApiEnabled = true OR Id != null", "permissionsApiEnabled", "PermissionsApiEnabled'"):
        assert not _ok(validate_permission_name, bad), f"perm {bad!r} accepted"
    for ok in ("dana@example.com", "o'neil@example.com", "first.last+tag@sub.example.co"):
        assert _ok(validate_email, ok), f"email {ok!r}"
    for bad in (
        "",
        "dana",
        "Dana <dana@example.com>",
        "<dana@example.com>",
        "dana@example.com\n",
        "dana@exa\x00mple.com",
        "a@b.c' OR 1=1--",
        "x' OR 1=1--@example.com",
        "(comment)dana@example.com",
        " dana@example.com",
    ):
        assert not _ok(validate_email, bad), f"email {bad!r} accepted"
    got = soql_id_list(["001000000000001", "001000000000002AAA"])
    assert got == "'001000000000001','001000000000002AAA'", got
    # Go: a panic; here a "bug" exception type.
    with pytest.raises(AssertionError):
        soql_id_list(["x') OR (1=1"])


@pytest.mark.parametrize(
    ("inp", "want"),
    [
        # Not in the Go test: the messages Go's validateEmail gives, which
        # reach decision texts, for inputs that exercise the net/mail port.
        ("Dana <dana@example.com>", '"Dana <dana@example.com>" is not a bare email address'),
        ("<dana@example.com>", '"<dana@example.com>" is not a bare email address'),
        ('"dana"@example.com', '"\\"dana\\"@example.com" is not a bare email address'),
        (" dana@example.com", '" dana@example.com" is not a bare email address'),
        ("dana@example.com (x)", '"dana@example.com (x)" is not a bare email address'),
        ("dana", '"dana" is not an email address'),
        ("a@b.c' OR 1=1--", "\"a@b.c' OR 1=1--\" is not an email address"),
        ("=?x-unknown?q?a?= <a@b.c>", '"=?x-unknown?q?a?= <a@b.c>" is not an email address'),
        ("=?utf-8?q?a?= <a@b.c>", '"=?utf-8?q?a?= <a@b.c>" is not a bare email address'),
        ("g: a@b.c;", '"g: a@b.c;" is not a bare email address'),
        ("g: ;", '"g: ;" is not an email address'),
        ("a@[1.2.3.4]", None),
        ("a@[01.2.3.4]", '"a@[01.2.3.4]" is not an email address'),
        ("a@[::1]", None),
        ("a@[fe80::1%eth0]", '"a@[fe80::1%eth0]" is not an email address'),
        ("a..b@c", '"a..b@c" is not an email address'),
        ("ü@ex.com", None),
    ],
)
def test_validate_email_messages(inp: str, want: str | None) -> None:
    try:
        validate_email(inp)
    except ValueError as e:
        assert str(e) == want
        return
    assert want is None, f"{inp!r} accepted"
