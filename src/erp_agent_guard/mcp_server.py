"""Minimal MCP server over stdio (newline-delimited JSON-RPC 2.0).

Implements the subset of the Model Context Protocol an MCP client needs
to use tools: ``initialize``, ``notifications/initialized``, ``ping``,
``tools/list`` and ``tools/call``. Stdlib only, so the gateway has no
dependency on a particular SDK version; see ROADMAP.md for the plan to
offer the official ``mcp`` SDK as an optional transport.

The agent identity is fixed when the server starts (``--agent``); the
model on the other side of the pipe cannot choose or change it.
"""

from __future__ import annotations

import json
import sys
from typing import IO, Any

from . import __version__
from .errors import GuardError
from .guard import Guard

SUPPORTED_PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")

_DOMAIN_SCHEMA = {
    "type": "array",
    "description": "Odoo-style domain, e.g. [[\"customer_rank\", \">\", 0], [\"country_code\", \"=\", \"EC\"]]. "
                   "Only readable, unmasked, direct fields.",
    "items": {},
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "erp_describe",
        "description": "List the ERP models and fields this agent may read or change, which are masked, and whether writes need human approval. Call this first.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "erp_search_read",
        "description": "Search records of an allowed model and return allowed fields (PII fields are masked).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "model": {"type": "string"},
                "domain": _DOMAIN_SCHEMA,
                "fields": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer", "minimum": 1},
                "offset": {"type": "integer", "minimum": 0},
                "order": {"type": "string", "description": "e.g. \"name asc\""},
            },
            "required": ["model"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "erp_propose_write",
        "description": "Dry-run an update. Nothing is written: returns a proposal id and a field-by-field diff to show the user. Commit it with erp_commit.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "model": {"type": "string"},
                "ids": {"type": "array", "items": {"type": "integer"}, "minItems": 1},
                "values": {"type": "object"},
            },
            "required": ["model", "ids", "values"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "erp_propose_create",
        "description": "Dry-run a record creation. Nothing is written: returns a proposal id and the values to show the user. Commit it with erp_commit.",
        "inputSchema": {
            "type": "object",
            "properties": {"model": {"type": "string"}, "values": {"type": "object"}},
            "required": ["model", "values"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "erp_commit",
        "description": "Apply a proposal created by erp_propose_write/erp_propose_create. If approval is required, pass the token a human generated with `erp-agent-guard approve <proposal_id>`. Fails if the records changed since the dry-run.",
        "inputSchema": {
            "type": "object",
            "properties": {"proposal_id": {"type": "string"}, "approval_token": {"type": "string"}},
            "required": ["proposal_id"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False},
    },
]


class MCPServer:
    def __init__(self, guard: Guard, agent: str):
        self.guard = guard
        self.agent = agent
        guard.policy.agent(agent)  # fail fast on an unknown agent

    # ---- tool dispatch -------------------------------------------------
    def call_tool(self, name: str, args: dict) -> Any:
        g, a = self.guard, self.agent
        if not isinstance(args, dict):
            raise GuardError("arguments must be an object")
        if name == "erp_describe":
            return g.describe(a)
        if name == "erp_search_read":
            return g.search_read(a, args.get("model", ""), args.get("domain"), args.get("fields"),
                                 args.get("limit"), args.get("offset", 0), args.get("order"))
        if name == "erp_propose_write":
            return g.propose_write(a, args.get("model", ""), args.get("ids"), args.get("values"))
        if name == "erp_propose_create":
            return g.propose_create(a, args.get("model", ""), args.get("values"))
        if name == "erp_commit":
            return g.commit(a, args.get("proposal_id", ""), args.get("approval_token"))
        raise KeyError(name)

    # ---- JSON-RPC ----------------------------------------------------
    def handle(self, msg: Any) -> dict | None:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
            return _error(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid Request")
        mid = msg.get("id")
        method = msg["method"]
        params = msg.get("params") or {}
        is_notification = "id" not in msg

        if method.startswith("notifications/"):
            return None
        if method == "initialize":
            requested = params.get("protocolVersion")
            version = requested if requested in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[0]
            result = {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "erp-agent-guard", "version": __version__},
                "instructions": (
                    "ERP access is policy-restricted. Call erp_describe first. Writes are two-step: "
                    "propose (dry-run diff, show it to the user) then erp_commit."
                ),
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            name = params.get("name")
            if name not in {t["name"] for t in TOOLS}:
                return _error(mid, -32602, f"Unknown tool: {name}")
            try:
                data = self.call_tool(name, params.get("arguments") or {})
                result = {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, default=str)}],
                          "structuredContent": data, "isError": False}
            except GuardError as exc:
                # Tool-level errors go back to the model so it can adapt.
                err = {"error": exc.code, "message": str(exc)}
                result = {"content": [{"type": "text", "text": json.dumps(err)}], "isError": True}
        else:
            return None if is_notification else _error(mid, -32601, f"Method not found: {method}")
        return None if is_notification else {"jsonrpc": "2.0", "id": mid, "result": result}

    def _safe_handle(self, msg: Any) -> dict | None:
        try:
            return self.handle(msg)
        except Exception as exc:  # never crash the pipe; never leak internals
            return _error(msg.get("id") if isinstance(msg, dict) else None, -32603,
                          f"Internal error: {type(exc).__name__}")

    def serve(self, stdin: IO[str] = sys.stdin, stdout: IO[str] = sys.stdout) -> None:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                resp = _error(None, -32700, "Parse error")
            else:
                if isinstance(msg, list):  # JSON-RPC batch (older protocol revisions)
                    resps = [r for r in (self._safe_handle(m) for m in msg) if r is not None]
                    resp = resps or None
                else:
                    resp = self._safe_handle(msg)
            if resp is not None:
                stdout.write(json.dumps(resp, ensure_ascii=False, default=str) + "\n")
                stdout.flush()


def _error(mid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}
