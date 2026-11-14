import pytest

from erp_agent_guard.errors import PolicyError
from erp_agent_guard.policy import load_policy, load_policy_dict


def base(**agent):
    return {"agents": {"a": {"models": {"res.partner": {"read": ["name"]}}, **agent}}}


def test_example_policy_loads(policy_path):
    pol = load_policy(policy_path)
    assert set(pol.agents) == {"support-bot", "sales-ops"}
    assert pol.audit_path.endswith("audit.jsonl")


def test_default_mode_is_read_only():
    pol = load_policy_dict(base())
    assert pol.effective_mode("a", "res.partner") == "read-only"


def test_model_cannot_be_less_strict_than_agent():
    d = base()
    d["agents"]["a"]["models"]["res.partner"]["mode"] = "read-write"
    pol = load_policy_dict(d)
    assert pol.effective_mode("a", "res.partner") == "read-only"


def test_unknown_agent_and_model_denied():
    pol = load_policy_dict(base())
    with pytest.raises(PolicyError):
        pol.agent("nobody")
    with pytest.raises(PolicyError):
        pol.model_rule("a", "sale.order")


@pytest.mark.parametrize("model", ["ir.config_parameter", "res.users.apikeys", "base.module.upgrade"])
def test_builtin_denied_models_cannot_be_allowed(model):
    d = {"agents": {"a": {"models": {model: {"read": ["id"]}}}}}
    with pytest.raises(PolicyError, match="deny list"):
        load_policy_dict(d)


def test_user_deny_glob():
    d = {"deny": {"models": ["hr.*"]}, "agents": {"a": {"models": {"hr.employee": {"read": ["name"]}}}}}
    with pytest.raises(PolicyError, match="deny list"):
        load_policy_dict(d)


def test_denied_field_rejected():
    d = {"agents": {"a": {"models": {"res.partner": {"read": ["name", "password"]}}}}}
    with pytest.raises(PolicyError, match="password"):
        load_policy_dict(d)


def test_writable_must_be_readable():
    d = {"agents": {"a": {"mode": "read-write", "models": {"res.partner": {"read": ["name"], "write": ["phone"]}}}}}
    with pytest.raises(PolicyError, match="readable"):
        load_policy_dict(d)


def test_masked_field_cannot_be_writable():
    d = {"agents": {"a": {"mode": "read-write", "models": {"res.partner": {
        "read": ["email"], "write": ["email"], "mask": {"email": "email"}}}}}}
    with pytest.raises(PolicyError, match="masked"):
        load_policy_dict(d)


@pytest.mark.parametrize("bad", [
    {"agents": {}},
    {"agents": {"a": {"mode": "admin"}}},
    {"agents": {"a": {"bogus": 1}}},
    {"agents": {"a": {"models": {"res.partner": {"mask": {"name": "rot13"}}}}}},
    {"agents": {"a": {"quota": {"calls_per_minute": 0}}}},
    {"version": 2, "agents": {"a": {}}},
])
def test_invalid_policies(bad):
    with pytest.raises(PolicyError):
        load_policy_dict(bad)
