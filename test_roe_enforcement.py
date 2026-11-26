"""RoE machine-enforcement: loading the scope allowlist from plan/roe.json.

Covers the step that activates plan/roe.json — the orchestrator guard rail now
reads the machine RoE (Decepticon pattern) instead of a single hardcoded target.
(The Exec API's execution-chokepoint enforcement is exercised live in the lab,
since it depends on the running daemon and the roe.json mount.)
"""
from pathlib import Path

import pytest

from graduation_project.core.roe import RoEViolation, RulesOfEngagement

ROE_FILE = Path(__file__).resolve().parents[1] / "plan" / "roe.json"


def test_from_roe_file_loads_in_scope_hosts():
    roe = RulesOfEngagement.from_roe_file(ROE_FILE)
    assert "dvwa" in roe.allowed_hosts


def test_in_scope_target_is_allowed():
    roe = RulesOfEngagement.from_roe_file(ROE_FILE)
    assert roe.is_in_scope("http://dvwa/vulnerabilities/sqli/?id=1")
    roe.enforce("http://dvwa/")  # must not raise


@pytest.mark.parametrize("target", [
    "http://metasploitable2/",
    "http://infra/",
    "http://sandbox:9999/",
])
def test_out_of_scope_target_is_blocked(target):
    roe = RulesOfEngagement.from_roe_file(ROE_FILE)
    assert not roe.is_in_scope(target)
    with pytest.raises(RoEViolation):
        roe.enforce(target)


def test_missing_in_scope_raises():
    import json
    import tempfile

    bad = Path(tempfile.mkdtemp()) / "roe.json"
    bad.write_text(json.dumps({"machine_enforcement": {"in_scope": []}}))
    with pytest.raises(ValueError):
        RulesOfEngagement.from_roe_file(bad)
