"""The ops-agent example runs and every protection does its part."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def test_ops_agent_example():
    path = Path(__file__).parents[2] / "examples" / "ops_agent.py"
    spec = importlib.util.spec_from_file_location("ops_agent", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    outcomes = [outcome for _, outcome in module.main(say=lambda _: None)]
    assert outcomes == [
        "ran",  # service health
        "ran",  # the injected email, fenced
        "out_of_scope",  # delete main
        "untrusted_input",  # delete with the email's words
        "ran",  # private tickets
        "out_of_scope",  # #random
        "approval_pending",  # the trifecta
        "not_authorized",  # dana's PR, denied by toolpass (or the stand-in)
        "approval_pending",  # admin's PR waits
        "ran",  # approved, runs once
        "approval_pending",  # the approval was used up
    ]
