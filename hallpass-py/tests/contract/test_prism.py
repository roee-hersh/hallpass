"""Port of test/contract/prism_test.go: runs integrations against Prism
(@stoplight/prism-cli), a mock server that answers from the vendor's OpenAPI
description: every response is built from the description's examples and
schemas, and Prism rejects requests that violate the description. The tests
prove that the integration's requests are accepted and that its decoders
understand schema-conformant responses. Decisions themselves are not
asserted beyond "hallpass produced a decision, not a decode failure".

    HALLPASS_SPECS_DIR=$PWD/.specs python -m pytest tests/contract

Needs node (npx) on the PATH; the Prism CLI is fetched by npx. Go gates the
file behind the `contract` build tag; here the tests carry the `contract`
marker (deselect with ``-m "not contract"``) and skip, as Go's do, unless
HALLPASS_SPECS_DIR names the descriptions and npx is on the PATH."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import socket
import subprocess
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from hallpass.core.config import parse as parse_config
from hallpass.core.context import background, with_timeout
from hallpass.core.decision import Code
from hallpass.core.engine import Engine, Options, Request, build
from hallpass.integrations import registry
from tests.contract.key import rsa_test_key
from tests.harness import spec as itest_spec

pytestmark = [pytest.mark.contract, pytest.mark.timeout(900)]

# patch edits a description before Prism loads it.
Patch = Callable[[dict[str, Any]], None]


class Errors:
    """Go's t.Errorf: failures are collected and reported together, so every
    case runs and Prism's log is still read."""

    def __init__(self) -> None:
        self.errors: list[str] = []

    def errorf(self, msg: str) -> None:
        self.errors.append(msg)

    def check(self) -> None:
        if self.errors:
            pytest.fail("\n".join(self.errors), pytrace=False)


def spec_path(name: str) -> str:
    d = os.environ.get("HALLPASS_SPECS_DIR", "")
    if d == "":
        pytest.skip("HALLPASS_SPECS_DIR not set")
    p = os.path.join(d, name + ".spec")
    if not os.path.exists(p):
        pytest.skip(f"no {p}")
    return p


def drop_required_param(name: str) -> Patch:
    """Makes every parameter with the name optional: Slack's legacy
    description requires "token" in the query although the token travels
    in the Authorization header."""

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            if v.get("name") == name and v.get("in") is not None:
                v.pop("required", None)
            for c in v.values():
                walk(c)
        elif isinstance(v, list):
            for c in v:
                walk(c)

    return walk


def _sprint(k: Any) -> str:
    """fmt.Sprint of a YAML map key."""
    if isinstance(k, str):
        return k
    if isinstance(k, bool):
        return "true" if k else "false"
    if k is None:
        return "<nil>"
    return str(k)


def normalise(v: Any) -> Any:
    """Converts YAML maps with non-string keys into string-keyed maps."""
    if isinstance(v, dict):
        return {_sprint(k): normalise(val) for k, val in v.items()}
    if isinstance(v, list):
        return [normalise(x) for x in v]
    return v


def prefix_paths(prefix: str) -> Patch:
    """Moves every path under a prefix: the github integration talks to a
    configured url the way it talks to GitHub Enterprise Server, under
    /api/v3, while the api.github.com description has no prefix."""

    def apply(doc: dict[str, Any]) -> None:
        paths = doc.get("paths")
        if not isinstance(paths, dict):
            paths = {}
        doc["paths"] = {prefix + p: v for p, v in paths.items()}

    return apply


def add_media_type(media_type: str) -> Patch:
    """Makes every application/json response also available as media_type
    (GitHub answers requests that Accept application/vnd.github+json with
    JSON; the description lists only application/json)."""

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            c = v.get("content")
            if isinstance(c, dict) and "application/json" in c and media_type not in c:
                c[media_type] = c["application/json"]
            for child in list(v.values()):
                walk(child)
        elif isinstance(v, list):
            for child in v:
                walk(child)

    def apply(doc: dict[str, Any]) -> None:
        walk(doc.get("paths"))
        walk(doc.get("components"))

    return apply


def add_gitlab_users() -> Patch:
    """Adds the users endpoints GitLab's description omits, with the user
    entity the description itself defines, so identity lookups can be
    exercised."""

    def apply(doc: dict[str, Any]) -> None:
        defs = doc.get("definitions")
        if not isinstance(defs, dict):
            defs = {}
        entity = ""
        for name in ("API_Entities_UserPublic", "API_Entities_UserWithAdmin", "API_Entities_UserBasic", "API_Entities_UserSafe"):
            if name in defs:
                entity = name
                break
        if entity == "":
            return
        ref = {"$ref": "#/definitions/" + entity}
        paths = doc["paths"]  # Go writes into the map and panics on a nil one
        paths["/api/v4/users"] = {
            "get": {
                "parameters": [
                    {"name": "username", "in": "query", "type": "string"},
                    {"name": "search", "in": "query", "type": "string"},
                    {"name": "page", "in": "query", "type": "integer"},
                    {"name": "per_page", "in": "query", "type": "integer"},
                ],
                "responses": {"200": {"description": "users", "schema": {"type": "array", "items": ref}}},
            }
        }
        paths["/api/v4/user"] = {"get": {"responses": {"200": {"description": "the current user", "schema": ref}}}}

    return apply


def ext_for(path: str) -> str:
    with open(path, "rb") as f:
        b = f.read()
    return ".json" if b.strip().startswith(b"{") else ".yaml"


def _load_doc(data: bytes) -> dict[str, Any]:
    """json.Unmarshal into map[string]any, falling back to YAML."""
    try:
        doc = itest_spec.go_json(data)
        if doc is None:
            return {}
        if isinstance(doc, dict):
            return doc
    except ValueError:
        pass
    try:
        # A SafeLoader matching gopkg.in/yaml.v3 decoding into any
        # (timestamps stay strings, only true/false are booleans).
        doc = yaml.load(data, Loader=itest_spec._Loader)
    except yaml.YAMLError as e:
        pytest.fail(f"description is neither JSON nor YAML: {e}")
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        pytest.fail(f"description is neither JSON nor YAML: a {type(doc).__name__}, not a mapping")
    out: dict[str, Any] = normalise(doc)
    return out


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


@contextlib.contextmanager
def start_prism(t: Errors, tmp: Path, spec: str, *patches: Patch, dynamic: bool = False) -> Iterator[str]:
    """Runs `prism mock` on the description and yields its base URL; with
    dynamic, in Prism's dynamic mode (responses generated from schemas
    rather than examples). On exit Prism is stopped and its log is checked
    for request violations."""
    if shutil.which("npx") is None:
        pytest.skip("npx not on PATH")
    port = _free_port()
    # Prism wants a file extension it recognises.
    target = tmp / ("spec" + ext_for(spec))
    with open(spec, "rb") as f:
        data = f.read()
    if patches:
        doc = _load_doc(data)
        for p in patches:
            p(doc)
        data = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
        target = target.with_suffix(".json")
    target.write_bytes(data)
    os.chmod(target, 0o600)
    # Without --errors Prism still validates requests (logged) but answers
    # even when its own example violates the response schema; request
    # violations are enforced below by reading the log.
    args = ["npx", "--yes", "@stoplight/prism-cli@5", "mock", "-p", str(port), "-h", "127.0.0.1"]
    if dynamic:
        args.append("-d")
    args.append(str(target))
    log_path = tmp / "prism.log"
    logf = open(log_path, "wb")  # noqa: SIM115 - closed in the finally below
    # Its own process group, so stopping it also stops the node process npx starts.
    proc = subprocess.Popen(args, stdout=logf, stderr=logf, stdin=subprocess.DEVNULL, start_new_session=True)

    def stop() -> bytes:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        logf.close()
        return log_path.read_bytes()

    base = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 3 * 60
    started = False
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            started = True
            break
        except OSError:
            if proc.poll() is not None:
                break
            time.sleep(0.5)
    if not started:
        b = stop()
        pytest.fail(f"prism did not start:\n{b.decode(errors='replace')}")
    try:
        yield base
    finally:
        b = stop()
        for line in b.decode(errors="replace").split("\n"):
            if "Violation: request" in line:
                t.errorf(f"prism: {line.strip()}")
            if "NO_PATH_MATCHED_ERROR" in line:
                print(f"prism: {line.strip()} (not in the description)")
        if t.errors:
            tail = b[-6000:] if len(b) > 6000 else b
            print(f"prism log tail:\n{tail.decode(errors='replace')}")


def build_engine(monkeypatch: pytest.MonkeyPatch, yml: str) -> Engine:
    """Makes an engine from a config snippet."""
    monkeypatch.setenv("HALLPASS_API_KEY", "contract")
    cfg = parse_config("contract.yaml", "api_key: env:HALLPASS_API_KEY\ndecision_log: none\nconnections:\n" + yml, registry())
    return build(background(), cfg, Options())


def run(t: Errors, eng: Engine, conn: str, cases: list[tuple[str, str, str]]) -> None:
    """Performs a probe and a set of checks and fails only on decode-level
    failures: an upstream_error means hallpass could not understand a
    schema-conformant response (or Prism rejected the request as invalid)."""
    ctx, cancel = with_timeout(background(), 2 * 60)
    try:
        for p in eng.probe(ctx, conn):
            print(f"probe {p.id}: summary={p.result.summary!r} warnings={list(p.result.warnings)} err={p.err}")
        for action, resource, want in cases:
            res = eng.check(ctx, Request(user="dana@example.com", groups=["team"], connection=conn, action=action, resource=resource))
            d = res.decision
            print(f"{action} on {resource} -> {d.outcome.value} ({d.reason()})")
            if d.code == Code.UPSTREAM_ERROR and "HTTP 404" not in d.reason():
                t.errorf(f"{action} on {resource}: {d.reason()}")
            code = "" if d.code is None else d.code.value
            if want != "" and code != want:
                t.errorf(f"{action} on {resource}: code {code}, want {want}")
    finally:
        cancel()


def test_github_against_prism(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    t = Errors()
    with start_prism(t, tmp_path, spec_path("github"), prefix_paths("/api/v3"), add_media_type("application/vnd.github+json")) as base:
        key = tmp_path / "app.pem"
        key.write_text(rsa_test_key())
        os.chmod(key, 0o600)
        eng = build_engine(
            monkeypatch,
            f"""  - id: gh
    integration: github
    url: {base}
    organization: octo-org
    app_id: "12345"
    identity_mode: template
    email_domains: example.com
    credential: file:{key}
""",
        )
        run(
            t,
            eng,
            "gh",
            [
                ("repo.read", "repo:octo-org/hello-world", ""),
                ("repo.push", "repo:octo-org/hello-world", ""),
                ("org.member", "org:octo-org", ""),
                ("team.member", "team:octo-org/justice-league", ""),
            ],
        )
    t.check()


def test_jira_against_prism(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    t = Errors()
    # Jira's description has few examples; dynamic mode generates bodies
    # from the schemas instead.
    with start_prism(t, tmp_path, spec_path("jira"), dynamic=True) as base:
        monkeypatch.setenv("JIRA_TOKEN", "contract-token")
        eng = build_engine(
            monkeypatch,
            f"""  - id: jira
    integration: jira
    url: {base}
    username: bot@example.com
    credential: env:JIRA_TOKEN
""",
        )
        run(
            t,
            eng,
            "jira",
            [
                ("BROWSE_PROJECTS", "project:EX", ""),
                ("CREATE_ISSUES", "project:EX", ""),
                ("EDIT_ISSUES", "issue:EX-1", ""),
                ("ADMINISTER", "global", ""),
            ],
        )
    t.check()


def test_slack_against_prism(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    t = Errors()
    with start_prism(t, tmp_path, spec_path("slack"), drop_required_param("token")) as base:
        monkeypatch.setenv("SLACK_TOKEN", "xoxb-contract")
        eng = build_engine(
            monkeypatch,
            f"""  - id: slack
    integration: slack
    url: {base}
    credential: env:SLACK_TOKEN
    assume_default_prefs: "true"
""",
        )
        run(
            t,
            eng,
            "slack",
            [
                ("user.active", "workspace", ""),
                ("channel.read", "channel:C012AB3CD", ""),
                ("message.post", "channel:C012AB3CD", ""),
                ("usergroup.member", "usergroup:S0604QSJC", ""),
            ],
        )
    t.check()


def test_gitlab_against_prism(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    t = Errors()
    with start_prism(t, tmp_path, spec_path("gitlab"), add_gitlab_users(), dynamic=True) as base:
        monkeypatch.setenv("GITLAB_TOKEN", "contract-token")
        eng = build_engine(
            monkeypatch,
            f"""  - id: gl
    integration: gitlab
    url: {base}
    credential: env:GITLAB_TOKEN
    identity_mode: template
    email_domains: example.com
""",
        )
        run(
            t,
            eng,
            "gl",
            [
                ("project.read", "project:5", ""),
                ("repo.push", "project:5@main", ""),
                ("group.member", "group:7", ""),
            ],
        )
    t.check()
