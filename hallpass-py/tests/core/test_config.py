"""Port of internal/config/config_test.go.

Go's Parse returns *Error (a YAML syntax error, or an empty file) or Errors
(every validation problem); here parse raises ConfigError or ConfigErrors,
and a test reads the message the way the Go test reads err.Error().
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from hallpass.core import config
from hallpass.core.catalog import Action
from hallpass.core.config import DEFAULT_IDENTITY_CACHE, Config, ConfigError, ConfigErrors
from hallpass.core.context import Context
from hallpass.core.integration import (
    Connection,
    Deps,
    Field,
    Integration,
    Registry,
    Settings,
    connection_ref_field,
    credential_field,
    url_field,
)


class StubIntegration(Integration):
    def __init__(self, name: str, fields: list[Field]) -> None:
        self._name = name
        self._fields = fields

    def name(self) -> str:
        return self._name

    def fields(self) -> list[Field]:
        return self._fields

    def actions(self) -> list[Action]:
        return []

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        raise NotImplementedError


def reg() -> Registry:
    r = Registry()
    r.register(
        StubIntegration(
            "kubernetes",
            [url_field(True, ""), credential_field(True, ""), Field(name="username_template", default="{email}")],
        )
    )
    r.register(
        StubIntegration(
            "argocd",
            [
                connection_ref_field("kubernetes_connection", "kubernetes", True, ""),
                Field(name="namespace", default="argocd"),
                Field(name="user_subject", default="none", enum=("none", "email")),
            ],
        )
    )
    r.register(StubIntegration("loop", [connection_ref_field("loop_connection", "loop", False, "")]))
    return r


def parse(yml: str) -> Config:
    return config.parse("test.yaml", yml.encode(), reg())


def parse_err(yml: str) -> ConfigError | ConfigErrors:
    with pytest.raises((ConfigError, ConfigErrors)) as ei:
        parse(yml)
    assert isinstance(ei.value, (ConfigError, ConfigErrors))
    return ei.value


def ids(c: Config) -> list[str]:
    return [s.id for s in c.connections]


def test_valid_config(tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    cfg = parse(
        f"""
api_key: env:HALLPASS_API_KEY
listen: ":9090"
decision_cache_seconds: 0
connections:
  - id: argocd-prod
    integration: argocd
    kubernetes_connection: k8s-prod
  - id: k8s-prod
    integration: kubernetes
    url: https://10.0.0.1:6443
    ca_file: {ca}
    credential: file:/secrets/token
    timeout: 10s
    tls_server_name: kubernetes
"""
    )
    assert cfg.listen == ":9090" and cfg.decision_cache == 0 and cfg.identity_cache == DEFAULT_IDENTITY_CACHE, cfg
    assert ids(cfg) == ["k8s-prod", "argocd-prod"], "order"
    k8s = cfg.connections[0]
    assert k8s.get("url") == "https://10.0.0.1:6443"
    assert k8s.get("username_template") == "{email}"
    assert k8s.ca_file == str(ca)
    assert k8s.tls_server_name == "kubernetes"
    assert k8s.timeout == 10
    assert k8s.secret("credential").ref() == "file:/secrets/token", "secret"
    argo = cfg.connections[1]
    assert argo.get("namespace") == "argocd"
    assert argo.get("user_subject") == "none"
    assert argo.get("kubernetes_connection") == "k8s-prod"
    assert cfg.integrations["argocd-prod"].name() == "argocd", "integrations map"


ERROR_CASES = [
    ("no api key", "connections: []\n", "api_key is required"),
    ("inline api key", "api_key: hunter2\nconnections: []\n", "inline secret"),
    ("unknown top key", "api_key: env:K\nconnections: []\nfoo: 1\n", 'unknown key "foo"'),
    ("no connections", "api_key: env:K\n", "connections is required"),
    ("unknown integration", "api_key: env:K\nconnections:\n  - id: a\n    integration: nope\n", 'unknown integration "nope"'),
    (
        "unknown key",
        "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    server: https://x\n",
        'does not accept key "server"',
    ),
    ("missing required", "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n", "requires credential"),
    (
        "inline secret",
        "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: abc123\n",
        "inline secret",
    ),
    (
        "bad url",
        "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: http://x\n    credential: env:T\n",
        "must start with https://",
    ),
    (
        "bad id",
        "api_key: env:K\nconnections:\n  - id: Bad_ID\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n",
        "must match",
    ),
    (
        "dup id",
        "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n"
        "  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n",
        "already used at line 3",
    ),
    (
        "bad enum",
        "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n"
        "  - id: b\n    integration: argocd\n    kubernetes_connection: a\n    user_subject: sub\n",
        "must be one of none, email",
    ),
    (
        "dangling ref",
        "api_key: env:K\nconnections:\n  - id: b\n    integration: argocd\n    kubernetes_connection: zzz\n",
        'refers to unknown connection "zzz"',
    ),
    (
        "wrong ref type",
        "api_key: env:K\nconnections:\n  - id: b\n    integration: argocd\n    kubernetes_connection: c\n"
        "  - id: c\n    integration: argocd\n    kubernetes_connection: b\n",
        "must name a kubernetes connection",
    ),
    ("self ref", "api_key: env:K\nconnections:\n  - id: b\n    integration: loop\n    loop_connection: b\n", "refers to itself"),
    (
        "cycle",
        "api_key: env:K\nconnections:\n  - id: b\n    integration: loop\n    loop_connection: c\n  - id: c\n    integration: loop\n    loop_connection: b\n",
        "reference cycle",
    ),
    (
        "nested",
        "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url:\n      host: x\n    credential: env:T\n",
        "must be a single value",
    ),
    (
        "bad timeout",
        "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    timeout: fast\n",
        "timeout must be a duration",
    ),
    (
        "missing ca",
        "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    ca_file: /nope/ca.pem\n",
        "ca_file",
    ),
    ("bad cache", "api_key: env:K\ndecision_cache_seconds: -1\nconnections: []\n", "whole number of seconds"),
    (
        "dup connections",
        "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n"
        "connections:\n  - id: b\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n",
        'test.yaml:7: key "connections" repeated (first set at line 2)',
    ),
    ("dup api_key", "api_key: env:K\napi_key: env:K2\nconnections: []\n", 'test.yaml:2: key "api_key" repeated (first set at line 1)'),
    ("dup listen", 'api_key: env:K\nlisten: ":1"\nconnections: []\nlisten: ":2"\n', 'test.yaml:4: key "listen" repeated'),
    ("not yaml", "api_key: [\n", "test.yaml"),
]


@pytest.mark.parametrize(("name", "yml", "want"), ERROR_CASES, ids=[c[0] for c in ERROR_CASES])
def test_errors(name: str, yml: str, want: str) -> None:
    err = parse_err(yml)
    assert want in str(err), f"{name}: got {str(err)!r}, want substring {want!r}"
    assert str(err).startswith("test.yaml"), f"{name}: error lacks file: {str(err)!r}"


def test_errors_report_all() -> None:
    err = parse_err("api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: http://x\n    credential: abc\n    bogus: 1\n")
    assert isinstance(err, ConfigErrors)
    assert len(err.errors) == 3, str(err)
    assert "test.yaml:5" in str(err), "line numbers"


def test_load_file(tmp_path: Path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("api_key: env:K\nconnections: []\n")
    cfg = config.load(str(p), reg())
    assert len(cfg.connections) == 0
    with pytest.raises(OSError):
        config.load(str(tmp_path / "missing"), reg())


# -- Behaviour pinned against the Go implementation ------------------------------
# Every expected message below is what config.Parse (on gopkg.in/yaml.v3)
# returns for the same file. Go reports the problems of one connection in
# map order; only single-problem cases are pinned exactly.


@pytest.mark.parametrize(
    ("yml", "want"),
    [
        # Empty documents and non-mappings.
        ("", "test.yaml: file is empty"),
        ("# only a comment\n", "test.yaml: file is empty"),
        ("---\n", "test.yaml:2: top level must be a mapping"),
        ("~\n", "test.yaml:1: top level must be a mapping"),
        ("[]\n", "test.yaml:1: top level must be a mapping"),
        # Only the first document counts, but yaml.v3 reads two tokens past it.
        ("api_key: env:K\nconnections: []\nlisten: x\n---\nfoo: [\n", None),
        ("api_key: env:K\nconnections: []\n---\n'x", "test.yaml: yaml: line 4: found unexpected end of stream"),
        # Syntax errors carry libyaml's text and yaml.v3's choice of line.
        ("api_key: [\n", "test.yaml: yaml: line 1: did not find expected node content"),
        ("a: b\n\tc: d\n", "test.yaml: yaml: line 2: found a tab character that violates indentation"),
        ("a: b: c\n", "test.yaml: yaml: mapping values are not allowed in this context"),
        ("- a\nb: c\n", "test.yaml: yaml: line 1: did not find expected '-' indicator"),
        ("a:\n  - b\n c: d\n", "test.yaml: yaml: line 2: did not find expected key"),
        ("a:\n  - b\n  ? x\n    c: d\n", "test.yaml: yaml: line 4: mapping values are not allowed in this context"),
        ("api_key: env:K\nconnections: []\n\x01\n", "test.yaml: yaml: control characters are not allowed"),
        ("%YAML 1.2\n---\napi_key: env:K\nconnections: []\n", "test.yaml: yaml: found incompatible YAML document"),
        # Aliases: not a single value, never expanded; an unknown one fails the
        # file; an anchor may be redefined; an alias key reads as the anchor name.
        ("a: &x b\nc: *y\n", "test.yaml: yaml: unknown anchor 'y' referenced"),
        ("api_key: &k env:K\nconnections: []\nlisten: *k\n", "test.yaml:3: listen must be a single value, not a list or mapping"),
        (
            "api_key: &k env:K\n*k : x\nconnections: []\n",
            'test.yaml:2: unknown key "k" (known: api_key, listen, decision_log, decision_cache_seconds, identity_cache_seconds, connections)',
        ),
        (
            "api_key: env:K\nconnections: []\n<<: {listen: x}\n",
            'test.yaml:3: unknown key "<<" (known: api_key, listen, decision_log, decision_cache_seconds, identity_cache_seconds, connections)',
        ),
        (
            "api_key: env:K\nconnections: []\n[1]: x\n",
            'test.yaml:3: unknown key "" (known: api_key, listen, decision_log, decision_cache_seconds, identity_cache_seconds, connections)',
        ),
        # Nulls: plain empty/~ and an explicit !!null tag; a quoted "~" is a string.
        ("api_key:\nconnections: []\n", "test.yaml:1: api_key is empty\ntest.yaml:1: api_key is required (env:NAME or file:/path)"),
        ("api_key: !!null env:K\nconnections: []\n", "test.yaml:1: api_key is empty\ntest.yaml:1: api_key is required (env:NAME or file:/path)"),
        ("api_key: ! ~\nconnections: []\n", "test.yaml:1: api_key is empty\ntest.yaml:1: api_key is required (env:NAME or file:/path)"),
        (
            'api_key: ! "~"\nconnections: []\n',
            "test.yaml:1: api_key: secret: value must be a reference of the form env:NAME or file:/path, not an inline secret\n"
            "test.yaml:1: api_key is required (env:NAME or file:/path)",
        ),
        ("api_key: ''\nconnections: []\n", "test.yaml:1: api_key: secret: empty reference\ntest.yaml:1: api_key is required (env:NAME or file:/path)"),
        ("api_key: env:K\nconnections:\n", "test.yaml:2: connections must be a list"),
        (
            "api_key: env:K\nconnections: [1, [2], {id: a}]\n",
            'test.yaml:2: each connection must be a mapping\ntest.yaml:2: each connection must be a mapping\ntest.yaml:2: connection "a" has no integration',
        ),
        ("api_key: env:K\nconnections:\n  - id: c\n    integration: ~\n", "test.yaml:4: integration is empty"),
        # Keys are quoted as Go's %q quotes them.
        (
            'api_key: env:K\nconnections: []\n"f\\to": 1\n',
            'test.yaml:3: unknown key "f\\to" (known: api_key, listen, decision_log, decision_cache_seconds, identity_cache_seconds, connections)',
        ),
        (
            'api_key: env:K\nconnections: []\n"\\x01": 2\n',
            'test.yaml:3: unknown key "\\x01" (known: api_key, listen, decision_log, decision_cache_seconds, identity_cache_seconds, connections)',
        ),
        # Whole numbers are strconv.Atoi.
        ("api_key: env:K\ndecision_cache_seconds: 0x10\nconnections: []\n", "test.yaml:2: must be a whole number of seconds between 0 and 3600"),
        ("api_key: env:K\ndecision_cache_seconds: 1_0\nconnections: []\n", "test.yaml:2: must be a whole number of seconds between 0 and 3600"),
        ("api_key: env:K\nidentity_cache_seconds: 86401\nconnections: []\n", "test.yaml:2: must be a whole number of seconds between 0 and 86400"),
        # Transport keys.
        (
            "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    ca_file: /nope/ca.pem\n",
            'test.yaml:7: connection "a": ca_file: stat /nope/ca.pem: no such file or directory',
        ),
        (
            "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    ca_file: ''\n",
            'test.yaml:7: connection "a": ca_file: stat : no such file or directory',
        ),
        (
            "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    timeout: 5m0.000000001s\n",
            'test.yaml:7: connection "a": timeout must be a duration such as 10s, up to 5m',
        ),
        (
            "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    proxy_url: socks5://x\n",
            'test.yaml:7: connection "a": proxy_url must start with http:// or https://',
        ),
        (
            'api_key: env:K\nconnections:\n- {id: a, integration: kubernetes, url: "https://x\\ty", credential: env:T}\n',
            "test.yaml:3: connection \"a\": url: url \"https://x\\ty\" must not contain whitespace, '?' or '#'",
        ),
        (
            "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    username_template: ''\n",
            'test.yaml:7: connection "a": username_template is empty',
        ),
        (
            "api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    url: https://y\n",
            'test.yaml:7: key "url" repeated',
        ),
    ],
)
def test_go_behaviour(yml: str, want: str | None) -> None:
    if want is None:
        parse(yml)
        return
    assert str(parse_err(yml)) == want


def test_ca_file_not_a_directory(tmp_path: Path) -> None:
    f = tmp_path / "file"
    f.write_text("x")
    err = parse_err(
        f"api_key: env:K\nconnections:\n  - id: a\n    integration: kubernetes\n    url: https://x\n    credential: env:T\n    ca_file: {f}/ca.pem\n"
    )
    prefix = f'test.yaml:7: connection "a": ca_file: stat {f}/ca.pem: '
    # Windows reports a file used as a directory as a missing path.
    tail = "no such file or directory" if sys.platform == "win32" else "not a directory"
    assert str(err) == prefix + tail


def test_go_values() -> None:
    cfg = parse(
        "api_key: env:K\nlisten: 8080\ndecision_cache_seconds: +5\nidentity_cache_seconds: 007\nconnections:\n"
        "- id: a\n  integration: kubernetes\n  url: 'https://x'\n  credential: |\n    env:T\n  timeout: 5m\n"
    )
    assert cfg.listen == "8080"
    assert cfg.decision_cache == 5 and cfg.identity_cache == 7
    (a,) = cfg.connections
    assert a.get("url") == "https://x"
    # A literal block keeps its trailing newline, as yaml.v3's Node.Value does.
    assert a.secret("credential").ref() == "env:T\n"
    assert a.timeout == 300


def test_from_mapping_secret_only_for_secret_fields() -> None:
    # A Secret given for a field that is not a secret field is an error, not
    # the placeholder reference validated as the value.
    from hallpass.core import config as cfgmod
    from hallpass.core.secret import literal
    from hallpass.integrations import registry

    with pytest.raises(cfgmod.ConfigError, match='connection "f": users is not a secret field; pass a plain string'):
        cfgmod.from_mapping({"connections": [{"id": "f", "integration": "fake", "users": literal("a@x.com")}]}, registry(), require_api_key=False)
