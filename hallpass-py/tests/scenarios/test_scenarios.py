"""Recorded decision scenarios: each engine decision's outcome, code and
reason against the expected ones.

Each file in scenarios/ describes connections, the fake upstream's routes
and a list of checks with the expected code and reason; every check runs
through the engine against that upstream. The reasons are the Go
implementation's (v0.5.0) answers to the same checks, recorded when it was
retired, so the text of every decision stays what operators saw before.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from hallpass.core.config import parse as parse_config
from hallpass.core.context import background
from hallpass.core.engine import Options, Request, build
from hallpass.core.log import discard
from hallpass.integrations import registry
from tests import harness as itest

SCENARIOS = sorted((Path(__file__).parent / "scenarios").glob("*.yaml"))


def _cases() -> list[Any]:
    out = []
    for f in SCENARIOS:
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        for i, c in enumerate(doc["checks"]):
            out.append(pytest.param(f, i, id=f"{f.stem}-{i}-{c['user']}-{c['action']}-{c['resource']}"))
    return out


def _render(v: Any, subst: dict[str, str]) -> Any:
    if isinstance(v, str):
        for k, x in subst.items():
            v = v.replace("{{" + k + "}}", x)
        return v
    if isinstance(v, list):
        return [_render(x, subst) for x in v]
    if isinstance(v, dict):
        return {k: _render(x, subst) for k, x in v.items()}
    return v


def _route(srv: itest.Server, r: dict[str, Any]) -> None:
    body = r.get("json")
    data = json.dumps(body).encode() if body is not None else str(r.get("body", "")).encode()
    headers = dict(r.get("headers") or {})
    if body is not None:
        headers.setdefault("Content-Type", "application/json")
    status = int(r.get("status", 200))

    def h(w: itest.ResponseWriter, req: itest.Request) -> None:
        if "when_body_contains" in r and r["when_body_contains"] not in req.body.decode("utf-8", "replace"):
            w.write_header(404)
            return
        for k, v in headers.items():
            w.header().set(k, v)
        w.write_header(status)
        w.write(data)

    srv.handle(r.get("method", ""), r["path"], h)


@pytest.mark.parametrize(("path", "index"), _cases())
def test_scenario(path: Path, index: int) -> None:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    check = doc["checks"][index]
    with itest.Server() as srv:
        for r in doc.get("upstream") or []:
            _route(srv, r)
        subst = {"url": srv.url, "ca_file": itest.test_ca().ca_file}
        cfg_doc = {"api_key": "env:HALLPASS_SCENARIO_KEY", "decision_log": "none", "connections": _render(doc["connections"], subst)}
        text = yaml.safe_dump(cfg_doc, sort_keys=False)
        env = {**os.environ, **{k: str(v) for k, v in (doc.get("env") or {}).items()}, "HALLPASS_SCENARIO_KEY": "k"}
        old = dict(os.environ)
        os.environ.update(env)
        try:
            cfg = parse_config(str(path), text, registry())
            eng = build(background(), cfg, Options(logger=discard()))
            d = eng.check(
                background(),
                Request(
                    user=check["user"],
                    groups=check.get("groups"),
                    connection=check.get("connection", doc["connections"][0]["id"]),
                    action=check["action"],
                    resource=check["resource"],
                ),
            ).decision
        finally:
            os.environ.clear()
            os.environ.update(old)
        got = {"decision": d.outcome.value, "reason": d.reason()}
        assert got["reason"].split(":", 1)[0] == check["want"], f"got {got}, want code {check['want']}"
        # The reason as the Go implementation (v0.5.0) gave it for this check.
        assert got["reason"] == check["reason"], f"got {got}, want reason {check['reason']!r}"
        want_decision = {"allowed": "allow", "denied": "deny", "user_not_found": "deny"}.get(check["want"], "unknown")
        assert got["decision"] == want_decision, f"got {got}"
