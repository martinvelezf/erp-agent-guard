import shutil
from pathlib import Path

import pytest

from erp_agent_guard.adapters.odoo import OdooJsonRpcAdapter
from erp_agent_guard.audit import AuditLog
from erp_agent_guard.fake_odoo import DEMO_DB, DEMO_KEY, DEMO_USER, FakeOdoo
from erp_agent_guard.guard import Guard
from erp_agent_guard.policy import load_policy
from erp_agent_guard.proposals import ProposalStore
from erp_agent_guard.quota import QuotaTracker

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "policy.yaml"
SECRET = "test-approval-secret-0123456789"


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def fake():
    f = FakeOdoo()
    url = f.start()
    f.url = url
    yield f
    f.stop()


@pytest.fixture
def adapter(fake):
    return OdooJsonRpcAdapter(fake.url, DEMO_DB, DEMO_USER, DEMO_KEY)


@pytest.fixture
def policy_path(tmp_path):
    p = tmp_path / "policy.yaml"
    shutil.copy(EXAMPLE, p)
    return p


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def guard(policy_path, adapter, clock, monkeypatch):
    monkeypatch.setenv("EAG_APPROVAL_SECRET", SECRET)
    pol = load_policy(policy_path)
    return Guard(pol, adapter, audit=AuditLog(pol.audit_path, clock=clock),
                 quotas=QuotaTracker(clock=clock), store=ProposalStore(pol.proposals_path), clock=clock)
