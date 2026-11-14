"""Demo: an "agent" talks MCP over stdio to erp-agent-guard, which sits in
front of a fake Odoo with synthetic data. Run: python examples/demo.py"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from erp_agent_guard.fake_odoo import DEMO_DB, DEMO_KEY, DEMO_USER, FakeOdoo

HERE = Path(__file__).resolve().parent
work = Path(tempfile.mkdtemp(prefix="eag-demo-"))
shutil.copy(HERE / "policy.yaml", work / "policy.yaml")
fake = FakeOdoo()
url = fake.start()
env = dict(os.environ, ODOO_URL=url, ODOO_DB=DEMO_DB, ODOO_USER=DEMO_USER, ODOO_API_KEY=DEMO_KEY,
           EAG_APPROVAL_SECRET="demo-secret-change-me-0001")
srv = subprocess.Popen([sys.executable, "-m", "erp_agent_guard", "serve", "--policy", str(work / "policy.yaml"),
                        "--agent", "sales-ops"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env)
n = 0


def rpc(method, params=None):
    global n
    n += 1
    srv.stdin.write(json.dumps({"jsonrpc": "2.0", "id": n, "method": method, "params": params or {}}) + "\n")
    srv.stdin.flush()
    return json.loads(srv.stdout.readline())


def tool(name, **args):
    print(f"\n>>> {name} {json.dumps(args)}")
    res = rpc("tools/call", {"name": name, "arguments": args})["result"]
    body = json.loads(res["content"][0]["text"])
    print(("ERROR " if res["isError"] else "") + json.dumps(body, indent=1, ensure_ascii=False))
    return body


rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "demo", "version": "0"}})
tool("erp_search_read", model="res.partner", domain=[["country_code", "=", "EC"]], fields=["name", "phone", "vat"])
tool("erp_search_read", model="res.partner", domain=[["vat", "=like", "17%"]])
tool("erp_search_read", model="ir.config_parameter")
tool("erp_propose_write", model="res.partner", ids=[1], values={"credit_limit": 999999})
prop = tool("erp_propose_write", model="res.partner", ids=[2], values={"phone": "+593 99 555 0000"})
tool("erp_commit", proposal_id=prop["proposal_id"])

print(f"\n$ erp-agent-guard approve {prop['proposal_id']} --policy policy.yaml --yes")
ap = subprocess.run([sys.executable, "-m", "erp_agent_guard", "approve", prop["proposal_id"], "--policy",
                     str(work / "policy.yaml"), "--yes", "--approver", "maria"], capture_output=True, text=True, env=env)
print(ap.stdout.rstrip())
token = ap.stdout.strip().splitlines()[-1]
tool("erp_commit", proposal_id=prop["proposal_id"], approval_token=token)

srv.stdin.close(); srv.wait()
print("\n$ erp-agent-guard verify-audit audit.jsonl")
print(subprocess.run([sys.executable, "-m", "erp_agent_guard", "verify-audit", str(work / "audit.jsonl")],
                     capture_output=True, text=True).stdout.rstrip())
print("\n$ tail -n 2 audit.jsonl")
for line in (work / "audit.jsonl").read_text().splitlines()[-2:]:
    print(line)
fake.stop()
shutil.rmtree(work)
