"""End to end: a real `erp-agent-guard serve` subprocess speaking MCP over
stdio, in front of the fake Odoo JSON-RPC server, plus the approve CLI."""

import json
import os
import subprocess
import sys

import pytest

from erp_agent_guard.fake_odoo import DEMO_DB, DEMO_KEY, DEMO_USER
from erp_agent_guard.mcp_server import MCPServer

from conftest import SECRET


class StdioClient:
    def __init__(self, args, env):
        self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, env=env)
        self.next_id = 0

    def request(self, method, params=None):
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        assert line, self.proc.stderr.read()
        resp = json.loads(line)
        assert resp["id"] == self.next_id
        return resp

    def notify(self, method):
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def call(self, name, **arguments):
        res = self.request("tools/call", {"name": name, "arguments": arguments})["result"]
        return res["isError"], json.loads(res["content"][0]["text"])

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=5)


@pytest.fixture
def env(fake):
    e = dict(os.environ, ODOO_URL=fake.url, ODOO_DB=DEMO_DB, ODOO_USER=DEMO_USER, ODOO_API_KEY=DEMO_KEY,
             EAG_APPROVAL_SECRET=SECRET)
    return e


def cli(*args, env):
    return subprocess.run([sys.executable, "-m", "erp_agent_guard", *args], capture_output=True, text=True,
                          env=env, timeout=20)


def test_full_flow_over_stdio(fake, env, policy_path):
    c = StdioClient([sys.executable, "-m", "erp_agent_guard", "serve", "--policy", str(policy_path),
                     "--agent", "sales-ops"], env)
    try:
        init = c.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                        "clientInfo": {"name": "pytest", "version": "0"}})["result"]
        assert init["protocolVersion"] == "2025-06-18"
        assert init["serverInfo"]["name"] == "erp-agent-guard"
        c.notify("notifications/initialized")

        tools = {t["name"] for t in c.request("tools/list")["result"]["tools"]}
        assert tools == {"erp_describe", "erp_search_read", "erp_propose_write", "erp_propose_create", "erp_commit"}

        err, desc = c.call("erp_describe")
        assert not err and desc["models"]["res.partner"]["write"] == ["phone", "comment"]

        err, res = c.call("erp_search_read", model="res.partner", domain=[["country_code", "=", "EC"]],
                          fields=["name", "vat"])
        assert not err
        assert {r["vat"] for r in res["records"]} == {"***2001", "***5678"}

        err, res = c.call("erp_search_read", model="res.users")
        assert err and res["error"] == "policy_denied"

        err, prop = c.call("erp_propose_write", model="res.partner", ids=[2], values={"comment": "Prefers email"})
        assert not err and prop["diff"][0]["changes"]["comment"]["to"] == "Prefers email"

        err, res = c.call("erp_commit", proposal_id=prop["proposal_id"])
        assert err and res["error"] == "approval_invalid"
        err, res = c.call("erp_commit", proposal_id=prop["proposal_id"], approval_token="forged.9999999999.00")
        assert err and res["error"] == "approval_invalid"
        assert fake.data["res.partner"][2]["comment"] == ""

        pend = cli("pending", "--policy", str(policy_path), env=env)
        assert prop["proposal_id"] in pend.stdout and '"" -> "Prefers email"' in pend.stdout

        no_tty = cli("approve", prop["proposal_id"], "--policy", str(policy_path), env=env)
        assert no_tty.returncode != 0  # refuses without a human at a terminal or --yes

        ap = cli("approve", prop["proposal_id"], "--policy", str(policy_path), "--yes", "--approver", "qa", env=env)
        assert ap.returncode == 0, ap.stderr
        token = ap.stdout.strip().splitlines()[-1]

        err, res = c.call("erp_commit", proposal_id=prop["proposal_id"], approval_token=token)
        assert not err and res["status"] == "committed"
        assert fake.data["res.partner"][2]["comment"] == "Prefers email"

        assert c.request("ping")["result"] == {}
        assert c.request("resources/list")["error"]["code"] == -32601
    finally:
        c.close()

    v = cli("verify-audit", str(policy_path.parent / "audit.jsonl"), env=env)
    assert v.returncode == 0 and v.stdout.startswith("OK:")
    events = [json.loads(l)["event"] for l in (policy_path.parent / "audit.jsonl").read_text().splitlines()]
    assert events.count("approve") == 1 and events[-1] == "commit"


def test_unknown_agent_fails_fast(env, policy_path):
    r = cli("serve", "--policy", str(policy_path), "--agent", "nobody", env=env)
    assert r.returncode != 0 and "not declared" in r.stderr


def test_missing_credentials(policy_path):
    e = {k: v for k, v in os.environ.items() if not k.startswith("ODOO_")}
    r = cli("serve", "--policy", str(policy_path), "--agent", "support-bot", env=e)
    assert r.returncode != 0 and "ODOO_URL" in r.stderr


def test_check_policy_cli(policy_path, env):
    r = cli("check-policy", str(policy_path), env=env)
    assert r.returncode == 0 and "sales-ops" in r.stdout
    bad = policy_path.parent / "bad.yaml"
    bad.write_text("agents:\n  a:\n    models:\n      ir.config_parameter: {read: [key]}\n")
    r = cli("check-policy", str(bad), env=env)
    assert r.returncode != 0 and "deny list" in r.stderr


# ---- protocol edge cases without a subprocess -------------------------

def test_protocol_edges(guard):
    s = MCPServer(guard, "support-bot")
    assert s.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert s.handle({"id": 1, "method": "x"})["error"]["code"] == -32600
    r = s.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}})
    assert r["result"]["protocolVersion"] == "2025-11-25"
    r = s.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "erp_delete"}})
    assert r["error"]["code"] == -32602


def test_serve_loop_handles_garbage(guard):
    import io
    s = MCPServer(guard, "support-bot")
    out = io.StringIO()
    s.serve(io.StringIO('not json\n\n{"jsonrpc":"2.0","id":1,"method":"ping"}\n'), out)
    lines = [json.loads(l) for l in out.getvalue().splitlines()]
    assert lines[0]["error"]["code"] == -32700 and lines[1]["result"] == {}
