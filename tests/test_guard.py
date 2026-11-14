import json

import pytest

from erp_agent_guard.approval import issue_token
from erp_agent_guard.audit import verify_audit
from erp_agent_guard.errors import ApprovalError, ConflictError, PolicyError, QuotaExceeded, UpstreamError

from conftest import SECRET


def token_for(guard, proposal):
    return issue_token(SECRET.encode(), proposal["proposal_id"], proposal["digest"], 300, now=guard.clock())


# ---- reads -------------------------------------------------------------

def test_read_returns_only_allowlisted_fields_and_masks_pii(guard):
    res = guard.search_read("support-bot", "res.partner", [["country_code", "=", "EC"]])
    assert res["count"] == 2
    lucia = next(r for r in res["records"] if r["id"] == 2)
    assert lucia["email"] == "l***@mail.example"
    assert lucia["phone"] == "***0199"
    assert "vat" not in lucia and "credit_limit" not in lucia


def test_read_hidden_field_refused(guard, fake):
    with pytest.raises(PolicyError, match="not allowed"):
        guard.search_read("support-bot", "res.partner", fields=["vat"])
    assert ("res.partner", "search_read") not in fake.calls  # never reached the ERP


def test_unlisted_and_denied_models(guard):
    with pytest.raises(PolicyError, match="not allowed"):
        guard.search_read("support-bot", "account.move")
    with pytest.raises(PolicyError, match="deny list"):
        guard.search_read("support-bot", "res.users")
    with pytest.raises(PolicyError, match="deny list"):
        guard.search_read("support-bot", "ir.config_parameter")


def test_unknown_agent(guard):
    with pytest.raises(PolicyError, match="not declared"):
        guard.search_read("intruder", "res.partner")


@pytest.mark.parametrize("domain,match", [
    ([["vat", "=", "1712345678"]], "not readable"),            # search oracle on hidden field
    ([["email", "=ilike", "l%"]], "masked"),                    # oracle on masked field
    ([["partner_id.email", "ilike", "x"]], "paths"),            # traversal to other model
    ([["name", "child_of", {"x": 1}]], "scalars"),
    ([["name", "regex", "x"]], "operator"),
    ([["name", "="]], "malformed"),
    (["&&"], "logical"),
    ("name = x", "list"),
])
def test_domain_validation(guard, domain, match):
    with pytest.raises(PolicyError, match=match):
        guard.search_read("support-bot", "res.partner", domain)


def test_domain_logic_operators_allowed(guard):
    res = guard.search_read("support-bot", "res.partner",
                            ["|", ["country_code", "=", "US"], ["customer_rank", ">", 2]])
    assert sorted(r["id"] for r in res["records"]) == [1, 3]


def test_order_validation(guard):
    assert guard.search_read("support-bot", "res.partner", order="name desc")["records"][0]["id"] == 3
    with pytest.raises(PolicyError):
        guard.search_read("support-bot", "res.partner", order="email asc")  # masked
    with pytest.raises(PolicyError):
        guard.search_read("support-bot", "res.partner", order="name; drop table")


def test_limit_is_capped(guard):
    res = guard.search_read("support-bot", "res.partner", limit=10_000)
    assert res["limit"] == 50


def test_many2one_display(guard):
    res = guard.search_read("support-bot", "sale.order", [["state", "=", "sale"]])
    assert res["records"][0]["partner_id"] == [1, "Andes Hardware S.A."]


def test_upstream_error_is_sanitized(guard, fake):
    fake.data["res.partner"][1].pop("customer_rank")
    with pytest.raises(UpstreamError) as ei:
        guard.search_read("support-bot", "res.partner")
    assert "Traceback" not in str(ei.value)


# ---- writes ------------------------------------------------------------

def test_read_only_agent_cannot_propose(guard):
    with pytest.raises(PolicyError, match="read-only"):
        guard.propose_write("support-bot", "res.partner", [1], {"phone": "x"})


def test_model_level_read_only(guard):
    with pytest.raises(PolicyError, match="read-only"):
        guard.propose_write("sales-ops", "sale.order", [10], {"state": "cancel"})


def test_write_field_not_allowlisted(guard):
    with pytest.raises(PolicyError, match="not allowed"):
        guard.propose_write("sales-ops", "res.partner", [1], {"credit_limit": 1e9})


def test_relational_commands_refused(guard):
    with pytest.raises(PolicyError, match="scalar"):
        guard.propose_write("sales-ops", "res.partner", [1], {"comment": [[6, 0, [1, 2]]]})


def test_dry_run_does_not_write_and_returns_diff(guard, fake):
    p = guard.propose_write("sales-ops", "res.partner", [1, 2], {"comment": "VIP"})
    assert fake.data["res.partner"][1]["comment"] == "Pays on time"
    assert ("res.partner", "write") not in fake.calls
    assert p["diff"] == [
        {"id": 1, "changes": {"comment": {"from": "Pays on time", "to": "VIP"}}},
        {"id": 2, "changes": {"comment": {"from": "", "to": "VIP"}}},
    ]
    assert p["approval_required"] is True


def test_noop_and_missing_records(guard):
    with pytest.raises(PolicyError, match="no-op"):
        guard.propose_write("sales-ops", "res.partner", [1], {"comment": "Pays on time"})
    with pytest.raises(PolicyError, match="not found"):
        guard.propose_write("sales-ops", "res.partner", [999], {"comment": "x"})


def test_commit_requires_valid_token(guard, fake):
    p = guard.propose_write("sales-ops", "res.partner", [2], {"phone": "+593 99 000 0000"})
    with pytest.raises(ApprovalError, match="needs a human"):
        guard.commit("sales-ops", p["proposal_id"])
    other = guard.propose_write("sales-ops", "res.partner", [1], {"phone": "+593 2 000 0000"})
    with pytest.raises(ApprovalError):
        guard.commit("sales-ops", p["proposal_id"], token_for(guard, other))
    assert fake.data["res.partner"][2]["phone"] == "+593 99 555 0199"

    res = guard.commit("sales-ops", p["proposal_id"], token_for(guard, p))
    assert res == {"proposal_id": p["proposal_id"], "status": "committed", "written": [2]}
    assert fake.data["res.partner"][2]["phone"] == "+593 99 000 0000"
    with pytest.raises(ApprovalError, match="already committed"):  # no replay
        guard.commit("sales-ops", p["proposal_id"], token_for(guard, p))


def test_other_agent_cannot_commit(guard):
    p = guard.propose_write("sales-ops", "res.partner", [2], {"comment": "x"})
    with pytest.raises(ApprovalError, match="unknown proposal"):
        guard.commit("support-bot", p["proposal_id"], token_for(guard, p))


def test_stale_proposal_rejected(guard, fake):
    p = guard.propose_write("sales-ops", "res.partner", [1], {"comment": "VIP"})
    fake.data["res.partner"][1]["comment"] = "edited by a human meanwhile"
    with pytest.raises(ConflictError):
        guard.commit("sales-ops", p["proposal_id"], token_for(guard, p))
    assert fake.data["res.partner"][1]["comment"] == "edited by a human meanwhile"


def test_proposal_expires(guard):
    p = guard.propose_write("sales-ops", "res.partner", [1], {"comment": "VIP"})
    tok = token_for(guard, p)
    guard.clock.t += 901
    with pytest.raises(ApprovalError, match="expired"):
        guard.commit("sales-ops", p["proposal_id"], tok)


def test_policy_tightened_after_dry_run(guard):
    p = guard.propose_write("sales-ops", "res.partner", [1], {"comment": "VIP"})
    from dataclasses import replace
    a = guard.policy.agents["sales-ops"]
    guard.policy.agents["sales-ops"] = replace(a, mode="read-only")
    with pytest.raises(PolicyError, match="read-only"):
        guard.commit("sales-ops", p["proposal_id"], token_for(guard, p))


def test_create_flow(guard, fake):
    p = guard.propose_create("sales-ops", "res.partner", {"name": "Nueva Tienda", "country_code": "EC"})
    assert p["diff"][0]["changes"]["name"] == {"from": None, "to": "Nueva Tienda"}
    res = guard.commit("sales-ops", p["proposal_id"], token_for(guard, p))
    assert fake.data["res.partner"][res["created"]]["name"] == "Nueva Tienda"
    with pytest.raises(PolicyError, match="not allowed"):
        guard.propose_create("sales-ops", "res.partner", {"name": "X", "credit_limit": 1})


def test_write_quota_enforced(guard):
    for i in range(10):
        p = guard.propose_write("sales-ops", "res.partner", [1], {"comment": f"c{i}"})
        guard.commit("sales-ops", p["proposal_id"], token_for(guard, p))
        guard.clock.t += 10  # stay under the per-minute call limit
    p = guard.propose_write("sales-ops", "res.partner", [1], {"comment": "one too many"})
    with pytest.raises(QuotaExceeded, match="write quota"):
        guard.commit("sales-ops", p["proposal_id"], token_for(guard, p))


def test_call_rate_limit(guard):
    for _ in range(30):
        guard.describe("support-bot")
    with pytest.raises(QuotaExceeded):
        guard.describe("support-bot")
    guard.clock.t += 61
    guard.describe("support-bot")


def test_approval_not_required_mode(guard, fake):
    from dataclasses import replace
    guard.policy = replace(guard.policy, approval=replace(guard.policy.approval, required=False))
    p = guard.propose_write("sales-ops", "res.partner", [1], {"comment": "auto"})
    assert p["approval_required"] is False
    guard.commit("sales-ops", p["proposal_id"])
    assert fake.data["res.partner"][1]["comment"] == "auto"


# ---- audit -------------------------------------------------------------

def test_everything_is_audited(guard, policy_path):
    guard.search_read("support-bot", "res.partner", [["country_code", "=", "EC"]])
    with pytest.raises(PolicyError):
        guard.search_read("support-bot", "res.users")
    p = guard.propose_write("sales-ops", "res.partner", [1], {"comment": "VIP"})
    guard.commit("sales-ops", p["proposal_id"], token_for(guard, p))
    path = policy_path.parent / "audit.jsonl"
    events = [json.loads(l) for l in path.read_text().splitlines()]
    assert [e["event"] for e in events] == ["read", "denied", "propose", "commit"]
    assert events[1]["code"] == "policy_denied"
    assert events[0]["returned"] == 2 and "records" not in events[0]  # no data copied into the log
    assert verify_audit(path)[0]
