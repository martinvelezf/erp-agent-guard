"""Command line: run the MCP server, lint a policy, approve proposals,
verify the audit log, and start a fake Odoo for demos."""

from __future__ import annotations

import argparse
import json
import sys
import time

from . import __version__
from .approval import get_secret, issue_token
from .audit import AuditLog, verify_audit
from .errors import GuardError
from .policy import load_policy
from .proposals import ProposalStore, proposal_digest, render_changes


def _policy(path: str):
    try:
        return load_policy(path)
    except GuardError as exc:
        sys.exit(f"policy error: {exc}")


def cmd_serve(args) -> int:
    from .adapters.odoo import OdooJsonRpcAdapter
    from .guard import Guard
    from .mcp_server import MCPServer

    policy = _policy(args.policy)
    if args.erp != "odoo":
        sys.exit(f"adapter '{args.erp}' not available in this version")
    try:
        adapter = OdooJsonRpcAdapter.from_env()
        MCPServer(Guard(policy, adapter), args.agent).serve()
    except GuardError as exc:
        sys.exit(f"error: {exc}")
    return 0


def cmd_check(args) -> int:
    policy = _policy(args.policy)
    print(f"policy OK: {len(policy.agents)} agent(s); approval required: {policy.approval.required}")
    for name, a in policy.agents.items():
        print(f"\nagent {name}  mode={a.mode}  quota={a.quota.calls_per_minute}/min, "
              f"{a.quota.writes_per_day} writes/day  max_records={a.max_records}")
        for m in a.models:
            mode = policy.effective_mode(name, m)
            line = f"  {m:<20} {mode:<10} read={len(policy.readable_fields(name, m))}"
            if mode == "read-write":
                line += f" write={list(policy.writable_fields(name, m))} create={list(policy.creatable_fields(name, m))}"
            rule = a.models[m]
            if rule.mask:
                line += f" masked={rule.mask}"
            print(line)
    if policy.audit_path is None:
        print("\nwarning: no audit.path set; audit events are kept in memory only", file=sys.stderr)
    return 0


def _show(p: dict) -> None:
    print(f"proposal {p['id']}  agent={p['agent']}  {p['op']} {p['model']}  status={p['status']}")
    print(f"created {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p['created']))}, "
          f"expires {time.strftime('%H:%M:%S', time.localtime(p['expires']))}")
    for d in render_changes(p):
        print(f"  record {d['id'] if d['id'] is not None else '(new)'}:")
        for f, ch in d["changes"].items():
            print(f"    {f}: {json.dumps(ch['from'], ensure_ascii=False)} -> {json.dumps(ch['to'], ensure_ascii=False)}")


def cmd_pending(args) -> int:
    policy = _policy(args.policy)
    items = [p for p in ProposalStore(policy.proposals_path).all() if args.all or p["status"] == "pending"]
    if not items:
        print("no pending proposals")
    for p in items:
        _show(p)
        print()
    return 0


def cmd_approve(args) -> int:
    policy = _policy(args.policy)
    store = ProposalStore(policy.proposals_path)
    p = store.get(args.proposal_id)
    if p is None:
        sys.exit("unknown proposal")
    if p["status"] != "pending":
        sys.exit(f"proposal is {p['status']}, not pending")
    if time.time() > p["expires"]:
        sys.exit("proposal expired")
    if proposal_digest(p) != p["digest"]:
        sys.exit("proposal content does not match its digest (file was edited); not approving")
    _show(p)
    if not args.yes:
        if not sys.stdin.isatty():
            sys.exit("refusing to approve non-interactively without --yes")
        if input("Approve this change? [y/N] ").strip().lower() not in ("y", "yes"):
            print("not approved")
            return 1
    try:
        secret = get_secret(policy.approval.secret_env)
    except GuardError as exc:
        sys.exit(str(exc))
    ttl = max(1, min(policy.approval.ttl_seconds, int(p["expires"] - time.time())))
    token = issue_token(secret, p["id"], p["digest"], ttl)
    AuditLog(policy.audit_path).write("approve", p["agent"], proposal=p["id"], digest=p["digest"],
                                      approver=args.approver)
    print(token)
    return 0


def cmd_verify(args) -> int:
    ok, n, msg = verify_audit(args.path)
    print(("OK: " if ok else "TAMPERED: ") + msg)
    return 0 if ok else 2


def cmd_fake(args) -> int:
    from .fake_odoo import DEMO_DB, DEMO_KEY, DEMO_USER, FakeOdoo

    fake = FakeOdoo()
    url = fake.start(args.host, args.port)
    print(f"fake Odoo on {url}/jsonrpc (synthetic data)\n"
          f"export ODOO_URL={url} ODOO_DB={DEMO_DB} ODOO_USER={DEMO_USER} ODOO_API_KEY={DEMO_KEY}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        fake.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="erp-agent-guard", description=__doc__)
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the MCP server on stdio for one agent")
    s.add_argument("--policy", required=True)
    s.add_argument("--agent", required=True, help="agent identity (fixed for this process)")
    s.add_argument("--erp", default="odoo", choices=["odoo"])
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("check-policy", help="validate a policy file and print what it allows")
    s.add_argument("policy")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("pending", help="list proposals waiting for approval")
    s.add_argument("--policy", required=True)
    s.add_argument("--all", action="store_true", help="include committed/expired/stale")
    s.set_defaults(fn=cmd_pending)

    s = sub.add_parser("approve", help="show a proposal's diff and print an approval token")
    s.add_argument("proposal_id")
    s.add_argument("--policy", required=True)
    s.add_argument("--approver", default="cli", help="name recorded in the audit log")
    s.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("verify-audit", help="check the audit log hash chain")
    s.add_argument("path")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("fake-odoo", help="start an in-memory fake Odoo JSON-RPC server (demo/tests)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8069)
    s.set_defaults(fn=cmd_fake)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
