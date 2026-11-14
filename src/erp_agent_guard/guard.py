"""The gateway core: every agent request goes through ``Guard``.

Order of checks for every call: agent known -> call quota -> model allowed
-> mode -> fields/domain/order allowlisted -> upstream call -> output
filtered and masked -> audit. Refusals are audited too.
"""

from __future__ import annotations

import functools
import os
import secrets
import time
from typing import Any

from .adapters.base import ERPAdapter
from .approval import get_secret, verify_token
from .audit import AuditLog
from .errors import ApprovalError, ConflictError, GuardError, PolicyError
from .masking import mask_record
from .policy import Policy
from .proposals import ProposalStore, proposal_digest
from .quota import QuotaTracker

DOMAIN_OPERATORS = {
    "=", "!=", ">", ">=", "<", "<=", "like", "not like", "ilike", "not ilike",
    "=like", "=ilike", "in", "not in", "child_of", "parent_of",
}
LOGIC_OPERATORS = {"&", "|", "!"}
SCALARS = (str, int, float, bool, type(None))


def _audited(tool: str):
    """Check the call quota and audit refusals for a public Guard method."""

    def deco(fn):
        @functools.wraps(fn)
        def wrapper(self: "Guard", agent: str, *args, **kwargs):
            try:
                a = self.policy.agent(agent)
                self.quotas.check_call(agent, a.quota.calls_per_minute)
                return fn(self, agent, *args, **kwargs)
            except GuardError as exc:
                self.audit.write("denied", agent, tool=tool, code=exc.code, reason=str(exc))
                raise

        return wrapper

    return deco


class Guard:
    def __init__(self, policy: Policy, adapter: ERPAdapter, audit: AuditLog | None = None,
                 quotas: QuotaTracker | None = None, store: ProposalStore | None = None,
                 clock=time.time):
        self.policy = policy
        self.adapter = adapter
        self.audit = audit or AuditLog(policy.audit_path, clock=clock)
        self.quotas = quotas or QuotaTracker()
        self.store = store or ProposalStore(policy.proposals_path)
        self.clock = clock
        self._salt = os.environ.get(policy.mask_salt_env, "")

    # ---- introspection -------------------------------------------------
    @_audited("describe")
    def describe(self, agent: str) -> dict:
        a = self.policy.agent(agent)
        models = {}
        for name, rule in a.models.items():
            if self.policy.is_model_denied(name):
                continue
            mode = self.policy.effective_mode(agent, name)
            models[name] = {
                "mode": mode,
                "read": list(self.policy.readable_fields(agent, name)),
                "write": list(self.policy.writable_fields(agent, name)) if mode == "read-write" else [],
                "create": list(self.policy.creatable_fields(agent, name)) if mode == "read-write" else [],
                "masked": sorted(rule.mask),
                "max_records": self.policy.max_records(agent, name),
            }
        return {"agent": agent, "approval_required": self.policy.approval.required, "models": models}

    # ---- reads ---------------------------------------------------------
    def _check_domain(self, agent: str, model: str, domain: Any) -> list:
        if domain is None:
            return []
        if not isinstance(domain, list):
            raise PolicyError("domain must be a list")
        readable = set(self.policy.readable_fields(agent, model)) | {"id"}
        masked = set(self.policy.model_rule(agent, model).mask)
        for term in domain:
            if isinstance(term, str):
                if term not in LOGIC_OPERATORS:
                    raise PolicyError(f"domain: unknown logical operator {term!r}")
                continue
            if not isinstance(term, (list, tuple)) or len(term) != 3:
                raise PolicyError(f"domain: malformed term {term!r}")
            fname, op, value = term
            if not isinstance(fname, str) or "." in fname:
                raise PolicyError(f"domain: field paths are not allowed ({fname!r}); filter on direct fields")
            if fname not in readable:
                # Filtering on a hidden field leaks it bit by bit (search oracle).
                raise PolicyError(f"domain: field '{fname}' is not readable for this agent")
            if fname in masked:
                raise PolicyError(f"domain: field '{fname}' is masked and cannot be used as a filter")
            if op not in DOMAIN_OPERATORS:
                raise PolicyError(f"domain: operator {op!r} is not allowed")
            vals = value if isinstance(value, (list, tuple)) else [value]
            if not all(isinstance(v, SCALARS) for v in vals):
                raise PolicyError("domain: values must be scalars or lists of scalars")
        return [list(t) if isinstance(t, tuple) else t for t in domain]

    def _check_order(self, agent: str, model: str, order: str | None) -> str | None:
        if not order:
            return None
        readable = set(self.policy.readable_fields(agent, model)) | {"id"}
        masked = set(self.policy.model_rule(agent, model).mask)
        parts = []
        for chunk in order.split(","):
            bits = chunk.split()
            if not bits or len(bits) > 2:
                raise PolicyError(f"order: malformed {order!r}")
            if bits[0] not in readable or bits[0] in masked:
                raise PolicyError(f"order: field '{bits[0]}' is not allowed")
            if len(bits) == 2 and bits[1].lower() not in ("asc", "desc"):
                raise PolicyError(f"order: direction must be asc/desc, got {bits[1]!r}")
            parts.append(" ".join(bits))
        return ", ".join(parts)

    def _project(self, agent: str, model: str, rows: list[dict], fields: list[str]) -> list[dict]:
        keep = set(fields) | {"id"}
        masks = self.policy.model_rule(agent, model).mask
        return [mask_record({k: v for k, v in r.items() if k in keep}, masks, self._salt) for r in rows]

    @_audited("search_read")
    def search_read(self, agent: str, model: str, domain: list | None = None, fields: list[str] | None = None,
                    limit: int | None = None, offset: int = 0, order: str | None = None) -> dict:
        readable = self.policy.readable_fields(agent, model)
        if not readable:
            raise PolicyError(f"no readable fields on '{model}' for agent '{agent}'")
        if fields:
            bad = [f for f in fields if f not in readable and f != "id"]
            if bad:
                raise PolicyError(f"fields not allowed on '{model}': {bad}")
            fields = [f for f in fields if f != "id"] or list(readable)
        else:
            fields = list(readable)
        cap = self.policy.max_records(agent, model)
        if limit is None or limit <= 0:
            limit = cap
        limit = min(int(limit), cap)
        if not isinstance(offset, int) or offset < 0:
            raise PolicyError("offset must be a non-negative integer")
        dom = self._check_domain(agent, model, domain)
        order = self._check_order(agent, model, order)
        rows = self.adapter.search_read(model, dom, fields, limit, offset, order)
        out = self._project(agent, model, rows, fields)
        self.audit.write("read", agent, model=model, domain=dom, fields=fields, limit=limit,
                         offset=offset, returned=len(out), ids=[r.get("id") for r in out])
        return {"model": model, "count": len(out), "limit": limit, "records": out}

    # ---- writes: dry-run ---------------------------------------------
    def _require_rw(self, agent: str, model: str) -> None:
        if self.policy.effective_mode(agent, model) != "read-write":
            raise PolicyError(f"'{model}' is read-only for agent '{agent}'")

    @staticmethod
    def _check_values(values: Any, allowed: tuple[str, ...], what: str) -> dict:
        if not isinstance(values, dict) or not values:
            raise PolicyError(f"{what}: values must be a non-empty object")
        bad = [k for k in values if k not in allowed]
        if bad:
            raise PolicyError(f"{what}: fields not allowed: {bad}")
        for k, v in values.items():
            # x2many command lists ([(6,0,ids)], [(2,id)]...) can delete or relink
            # records the diff would not show, so only scalars are accepted.
            if not isinstance(v, SCALARS):
                raise PolicyError(f"{what}: field '{k}' must be a scalar (relational commands are not supported)")
        return values

    def _new_proposal(self, agent: str, model: str, op: str, ids: list[int], values: dict,
                      before: dict, diff: list[dict]) -> dict:
        body = {"agent": agent, "model": model, "op": op, "ids": ids, "values": values, "before": before}
        digest = proposal_digest(body)
        now = self.clock()
        proposal = {
            "id": "p_" + secrets.token_hex(8),
            **body,
            "diff": diff,
            "digest": digest,
            "created": now,
            "expires": now + self.policy.approval.ttl_seconds,
            "status": "pending",
            "approval_required": self.policy.approval.required,
        }
        self.store.put(proposal)
        self.audit.write("propose", agent, proposal=proposal["id"], model=model, op=op, ids=ids,
                         diff=diff, digest=digest)
        return proposal

    @staticmethod
    def _public(p: dict) -> dict:
        hint = ("ask a human to run: erp-agent-guard approve " + p["id"] +
                ", then call erp_commit with the token") if p["approval_required"] else "call erp_commit"
        return {"proposal_id": p["id"], "model": p["model"], "op": p["op"], "diff": p["diff"],
                "digest": p["digest"], "expires": p["expires"],
                "approval_required": p["approval_required"], "next": hint}

    @_audited("propose_write")
    def propose_write(self, agent: str, model: str, ids: list[int], values: dict) -> dict:
        self._require_rw(agent, model)
        if not isinstance(ids, list) or not ids or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
            raise PolicyError("ids must be a non-empty list of integers")
        ids = sorted(set(ids))
        if len(ids) > self.policy.max_records(agent, model):
            raise PolicyError(f"too many records in one write (max {self.policy.max_records(agent, model)})")
        values = self._check_values(values, self.policy.writable_fields(agent, model), "write")
        fields = sorted(values)
        current = {r["id"]: r for r in self.adapter.read(model, ids, fields)}
        missing = [i for i in ids if i not in current]
        if missing:
            raise PolicyError(f"records not found or not visible: {missing}")
        before = {str(i): {f: current[i].get(f) for f in fields} for i in ids}
        diff = []
        for i in ids:
            changes = {f: {"from": before[str(i)][f], "to": values[f]}
                       for f in fields if before[str(i)][f] != values[f]}
            if changes:
                diff.append({"id": i, "changes": changes})
        if not diff:
            raise PolicyError("no-op: the values already match the current records")
        return self._public(self._new_proposal(agent, model, "write", ids, values, before, diff))

    @_audited("propose_create")
    def propose_create(self, agent: str, model: str, values: dict) -> dict:
        self._require_rw(agent, model)
        values = self._check_values(values, self.policy.creatable_fields(agent, model), "create")
        diff = [{"id": None, "changes": {f: {"from": None, "to": values[f]} for f in sorted(values)}}]
        return self._public(self._new_proposal(agent, model, "create", [], values, {}, diff))

    # ---- writes: commit ------------------------------------------------
    @_audited("commit")
    def commit(self, agent: str, proposal_id: str, approval_token: str | None = None) -> dict:
        p = self.store.get(proposal_id)
        if p is None or p["agent"] != agent:
            raise ApprovalError("unknown proposal")
        if p["status"] != "pending":
            raise ApprovalError(f"proposal already {p['status']}")
        if proposal_digest(p) != p["digest"]:
            # The stored proposal was edited after the dry-run.
            raise ApprovalError("proposal content does not match its digest")
        if self.clock() > p["expires"]:
            self.store.update(proposal_id, status="expired")
            raise ApprovalError("proposal expired; create a new dry-run")
        # The policy may have changed since the dry-run: check again.
        self._require_rw(agent, p["model"])
        allowed = (self.policy.writable_fields if p["op"] == "write" else self.policy.creatable_fields)(agent, p["model"])
        self._check_values(p["values"], allowed, p["op"])

        if self.policy.approval.required:
            if not approval_token:
                raise ApprovalError("this write needs a human approval token")
            verify_token(get_secret(self.policy.approval.secret_env), approval_token, p["id"], p["digest"],
                         now=self.clock())

        a = self.policy.agent(agent)
        n = max(1, len(p["ids"]))
        self.quotas.check_write(agent, a.quota.writes_per_day, n)

        if p["op"] == "write":
            fields = sorted(p["values"])
            now_rows = {r["id"]: r for r in self.adapter.read(p["model"], p["ids"], fields)}
            for i in p["ids"]:
                cur = {f: now_rows.get(i, {}).get(f) for f in fields}
                if cur != p["before"][str(i)]:
                    self.store.update(proposal_id, status="stale")
                    raise ConflictError(f"record {i} changed since the dry-run; create a new proposal")
            self.adapter.write(p["model"], p["ids"], p["values"])
            result = {"written": p["ids"]}
        else:
            new_id = self.adapter.create(p["model"], p["values"])
            result = {"created": new_id}

        self.quotas.record_write(agent, n)
        self.store.update(proposal_id, status="committed", committed=self.clock())
        self.audit.write("commit", agent, proposal=p["id"], model=p["model"], op=p["op"],
                         digest=p["digest"], approved=bool(approval_token), **result)
        return {"proposal_id": p["id"], "status": "committed", **result}
